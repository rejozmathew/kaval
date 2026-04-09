"""Deterministic proactive admin recommendations for Phase 3C."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from kaval.credentials.models import VaultCredentialRecord
from kaval.models import Service, ServiceType

_DESCRIPTOR_ELIGIBLE_SERVICE_TYPES = {
    ServiceType.CONTAINER,
    ServiceType.VM,
}
_STALE_CREDENTIAL_AFTER_DAYS = 30
_MAX_NOISY_CHECK_SUGGESTIONS = 3
_MISSING_DESCRIPTOR_BASE_SCORE = 400
_STALE_CREDENTIAL_BASE_SCORE = 300
_NOISY_CHECK_BASE_SCORE = 250
_CLOUD_MODEL_BASE_SCORE = 200


class RecommendationKind(StrEnum):
    """Supported proactive recommendation categories."""

    MISSING_DESCRIPTOR = "missing_descriptor"
    STALE_CREDENTIAL = "stale_credential"
    NOISY_CHECK = "noisy_check"
    CLOUD_MODEL = "cloud_model"


class RecommendationActionTarget(StrEnum):
    """Existing admin surfaces a recommendation can point at."""

    SERVICE_DETAIL = "service_detail"
    FINDING_REVIEW = "finding_review"
    CREDENTIAL_VAULT = "credential_vault"
    MODEL_SETTINGS = "model_settings"


@dataclass(frozen=True, slots=True)
class RecommendationAction:
    """One deterministic follow-up path for a recommendation."""

    label: str
    target: RecommendationActionTarget
    service_id: str | None = None


@dataclass(frozen=True, slots=True)
class NoisyCheckPattern:
    """One advisory noisy-check pattern derived from finding feedback."""

    service_id: str
    service_name: str
    check_id: str
    check_label: str
    dismissal_count: int
    message: str


@dataclass(frozen=True, slots=True)
class RecommendationCandidate:
    """One ranked recommendation before API serialization."""

    id: str
    kind: RecommendationKind
    title: str
    detail: str
    action: RecommendationAction
    score: int


def build_proactive_recommendations(
    *,
    services: Sequence[Service],
    vault_credentials: Sequence[VaultCredentialRecord],
    noisy_check_patterns: Sequence[NoisyCheckPattern],
    local_model_configured: bool,
    cloud_model_configured: bool,
    now: datetime,
) -> list[RecommendationCandidate]:
    """Build ranked proactive recommendations from existing persisted state."""
    services_by_id = {service.id: service for service in services}
    candidates: list[RecommendationCandidate] = []

    missing_descriptor = build_missing_descriptor_recommendation(
        services=services,
        local_model_configured=local_model_configured,
    )
    if missing_descriptor is not None:
        candidates.append(missing_descriptor)

    stale_credential = build_stale_credential_recommendation(
        vault_credentials=vault_credentials,
        services_by_id=services_by_id,
        now=now,
    )
    if stale_credential is not None:
        candidates.append(stale_credential)

    candidates.extend(
        build_noisy_check_recommendations(
            noisy_check_patterns=noisy_check_patterns,
            services_by_id=services_by_id,
        )
    )

    cloud_model = build_cloud_model_recommendation(
        local_model_configured=local_model_configured,
        cloud_model_configured=cloud_model_configured,
    )
    if cloud_model is not None:
        candidates.append(cloud_model)

    return sorted(
        candidates,
        key=lambda candidate: (-candidate.score, candidate.title.casefold(), candidate.id),
    )


def build_missing_descriptor_recommendation(
    *,
    services: Sequence[Service],
    local_model_configured: bool,
) -> RecommendationCandidate | None:
    """Build the aggregated missing-descriptor recommendation, if any."""
    unmatched_services = [
        service
        for service in services
        if service.type in _DESCRIPTOR_ELIGIBLE_SERVICE_TYPES
        and service.descriptor_id is None
    ]
    if not unmatched_services:
        return None

    ordered_services = sorted(
        unmatched_services,
        key=lambda service: (-len(service.dependents), service.name.casefold(), service.id),
    )
    primary_service = ordered_services[0]
    service_count = len(ordered_services)
    total_dependents = sum(len(service.dependents) for service in ordered_services)
    generation_note = (
        " Local descriptor generation is available after review."
        if local_model_configured
        else " Review the highest-impact service from Service Detail first."
    )
    title = (
        f"{service_count} services are missing descriptors"
        if service_count != 1
        else f"{primary_service.name} is missing a descriptor"
    )
    detail = (
        f"{primary_service.name} is the highest-impact unmatched service with "
        f"{len(primary_service.dependents)} downstream dependents."
        f"{generation_note}"
    )
    return RecommendationCandidate(
        id="missing-descriptors",
        kind=RecommendationKind.MISSING_DESCRIPTOR,
        title=title,
        detail=detail,
        action=RecommendationAction(
            label=f"Review {primary_service.name}",
            target=RecommendationActionTarget.SERVICE_DETAIL,
            service_id=primary_service.id,
        ),
        score=_MISSING_DESCRIPTOR_BASE_SCORE + service_count * 20 + total_dependents * 10,
    )


def build_stale_credential_recommendation(
    *,
    vault_credentials: Sequence[VaultCredentialRecord],
    services_by_id: dict[str, Service],
    now: datetime,
    threshold_days: int = _STALE_CREDENTIAL_AFTER_DAYS,
) -> RecommendationCandidate | None:
    """Build the aggregated stale-credential recommendation, if any."""
    threshold = now - timedelta(days=threshold_days)
    stale_credentials = [
        record
        for record in vault_credentials
        if (record.last_tested_at or record.updated_at) <= threshold
    ]
    if not stale_credentials:
        return None

    def stale_credential_sort_key(
        record: VaultCredentialRecord,
    ) -> tuple[datetime, str, str]:
        """Return a stable oldest-first sort key for stale credential recommendations."""
        service = services_by_id.get(record.service_id)
        service_name = service.name if service is not None else record.service_id
        return (
            record.last_tested_at or record.updated_at,
            service_name,
            record.reference_id,
        )

    ordered_credentials = sorted(
        stale_credentials,
        key=stale_credential_sort_key,
    )
    oldest = ordered_credentials[0]
    service = services_by_id.get(oldest.service_id)
    service_name = service.name if service is not None else oldest.service_id
    credential_label = oldest.credential_key.replace("_", " ")
    last_checked_at = oldest.last_tested_at or oldest.updated_at
    days_since = max(0, (now - last_checked_at).days)
    credential_count = len(ordered_credentials)
    title = (
        f"{credential_count} stored credentials need verification"
        if credential_count != 1
        else f"Credential test overdue for {service_name}"
    )
    detail = (
        f"{credential_count} stored credentials have not been tested in at least "
        f"{threshold_days} days. Oldest: {service_name}'s {credential_label} "
        f"({days_since} days)."
        if credential_count != 1
        else f"{service_name}'s {credential_label} has not been tested in {days_since} days."
    )
    return RecommendationCandidate(
        id="stale-credentials",
        kind=RecommendationKind.STALE_CREDENTIAL,
        title=title,
        detail=detail,
        action=RecommendationAction(
            label="Open vault",
            target=RecommendationActionTarget.CREDENTIAL_VAULT,
        ),
        score=_STALE_CREDENTIAL_BASE_SCORE + credential_count * 15 + max(0, days_since - 30),
    )


def build_noisy_check_recommendations(
    *,
    noisy_check_patterns: Sequence[NoisyCheckPattern],
    services_by_id: dict[str, Service],
) -> list[RecommendationCandidate]:
    """Build ranked noisy-check recommendations from repeated dismissal patterns."""
    def noisy_pattern_sort_key(pattern: NoisyCheckPattern) -> tuple[int, int, str, str]:
        """Return a stable highest-impact sort key for noisy-check recommendations."""
        service = services_by_id.get(pattern.service_id)
        dependent_count = 0 if service is None else len(service.dependents)
        return (
            -pattern.dismissal_count,
            -dependent_count,
            pattern.service_name.casefold(),
            pattern.check_id,
        )

    ordered_patterns = sorted(
        noisy_check_patterns,
        key=noisy_pattern_sort_key,
    )
    candidates: list[RecommendationCandidate] = []
    for pattern in ordered_patterns[:_MAX_NOISY_CHECK_SUGGESTIONS]:
        service = services_by_id.get(pattern.service_id)
        dependent_count = 0 if service is None else len(service.dependents)
        candidates.append(
            RecommendationCandidate(
                id=f"noisy-check:{pattern.service_id}:{pattern.check_id}",
                kind=RecommendationKind.NOISY_CHECK,
                title=f"{pattern.service_name}: {pattern.check_label} is likely noisy",
                detail=pattern.message,
                action=RecommendationAction(
                    label="Review noise controls",
                    target=RecommendationActionTarget.FINDING_REVIEW,
                    service_id=pattern.service_id,
                ),
                score=(
                    _NOISY_CHECK_BASE_SCORE
                    + pattern.dismissal_count * 5
                    + dependent_count * 3
                ),
            )
        )
    return candidates


def build_cloud_model_recommendation(
    *,
    local_model_configured: bool,
    cloud_model_configured: bool,
) -> RecommendationCandidate | None:
    """Build the bounded cloud-escalation recommendation, if applicable."""
    if not local_model_configured or cloud_model_configured:
        return None
    return RecommendationCandidate(
        id="cloud-model",
        kind=RecommendationKind.CLOUD_MODEL,
        title="Cloud escalation is not configured",
        detail=(
            "Investigations are currently local-only. For complex multi-service incidents, "
            "consider adding a bounded cloud escalation path."
        ),
        action=RecommendationAction(
            label="Open model settings",
            target=RecommendationActionTarget.MODEL_SETTINGS,
        ),
        score=_CLOUD_MODEL_BASE_SCORE,
    )
