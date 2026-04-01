"""Deterministic remediation risk assessment for Phase 2B investigations."""

from __future__ import annotations

from collections.abc import Sequence

from kaval.investigation.prompts import InvestigationRecommendation
from kaval.investigation.research import ServiceResearchResult, Tier2ResearchBundle
from kaval.models import (
    Change,
    ChangeType,
    Incident,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServiceStatus,
)

_MIGRATION_KEYWORDS = ("migration", "migrate", "schema", "database", "db")
_BEHAVIOR_CHANGE_KEYWORDS = (
    "breaking",
    "openssl",
    "cipher",
    "tls",
    "oauth",
    "auth",
    "session",
)
_OFFLINE_RISK_WARNING = (
    "Unable to verify changelog/migration risk because Tier 2 research was unavailable offline."
)


def apply_deterministic_risk_assessment(
    *,
    recommendation: InvestigationRecommendation,
    incident: Incident,
    services: Sequence[Service],
    changes: Sequence[Change],
    research: Tier2ResearchBundle,
) -> InvestigationRecommendation:
    """Replace model-authored risk output with deterministic, reviewable checks."""
    deterministic_risk = build_risk_assessment(
        recommendation=recommendation,
        incident=incident,
        services=services,
        changes=changes,
        research=research,
    )
    return recommendation.model_copy(update={"risk": deterministic_risk})


def build_risk_assessment(
    *,
    recommendation: InvestigationRecommendation,
    incident: Incident,
    services: Sequence[Service],
    changes: Sequence[Change],
    research: Tier2ResearchBundle,
) -> RiskAssessment:
    """Build a deterministic risk assessment for the current recommendation."""
    if recommendation.action_type != "restart_container" or recommendation.target is None:
        return RiskAssessment(
            overall_risk=RiskLevel.MEDIUM,
            checks=[
                RiskCheck(
                    check="restart_proposed",
                    result=RiskCheckResult.FAIL,
                    detail="No bounded restart action was proposed from the current evidence.",
                )
            ],
            reversible=True,
            warnings=["Investigation should continue with additional evidence."],
        )

    target_service = _find_target_service(recommendation.target, services)
    image_update_changes = _correlated_image_updates(
        incident=incident,
        recommendation_target=recommendation.target,
        target_service=target_service,
        changes=changes,
    )
    service_research = _matching_service_research(
        recommendation_target=recommendation.target,
        target_service=target_service,
        research=research,
    )

    checks = [
        _bounded_scope_check(target_service=target_service),
        _service_state_check(target_service=target_service),
        RiskCheck(
            check="reversible_restart",
            result=RiskCheckResult.PASS,
            detail="A single container restart is reversible and does not mutate configuration.",
        ),
        _image_update_context_check(image_update_changes=image_update_changes),
        _release_review_check(
            image_update_changes=image_update_changes,
            research=research,
            service_research=service_research,
        ),
    ]
    warnings = _build_risk_warnings(
        image_update_changes=image_update_changes,
        research=research,
        service_research=service_research,
    )
    return RiskAssessment(
        overall_risk=_overall_risk(checks=checks),
        checks=checks,
        reversible=True,
        warnings=warnings,
    )


def build_release_note_warnings(
    service_research: ServiceResearchResult | None,
) -> list[str]:
    """Extract deterministic warnings from release-note text."""
    if service_research is None or service_research.github_current_release is None:
        return []
    body = (service_research.github_current_release.body or "").casefold()
    if not body:
        return []

    warnings: list[str] = []
    matched_migration_keywords = [
        keyword for keyword in _MIGRATION_KEYWORDS if keyword in body
    ]
    if matched_migration_keywords:
        warnings.append(
            "Release notes mention migration/schema changes "
            f"({', '.join(sorted(set(matched_migration_keywords)))})."
        )

    matched_behavior_keywords = [
        keyword for keyword in _BEHAVIOR_CHANGE_KEYWORDS if keyword in body
    ]
    if matched_behavior_keywords:
        warnings.append(
            "Release notes mention behavioral/runtime changes "
            f"({', '.join(sorted(set(matched_behavior_keywords)))})."
        )
    return warnings


def _bounded_scope_check(target_service: Service | None) -> RiskCheck:
    """Assess whether the proposed restart stays inside one affected container."""
    if target_service is None:
        return RiskCheck(
            check="bounded_action_scope",
            result=RiskCheckResult.FAIL,
            detail="The proposed restart target did not resolve to an affected container service.",
        )
    return RiskCheck(
        check="bounded_action_scope",
        result=RiskCheckResult.PASS,
        detail="The proposed action stays inside one affected container service.",
    )


def _service_state_check(target_service: Service | None) -> RiskCheck:
    """Assess whether the target service state supports a restart verification action."""
    if target_service is None:
        return RiskCheck(
            check="target_service_state",
            result=RiskCheckResult.FAIL,
            detail="No target service record was available for restart-state verification.",
        )
    if target_service.status in {
        ServiceStatus.DEGRADED,
        ServiceStatus.DOWN,
        ServiceStatus.STOPPED,
    }:
        return RiskCheck(
            check="target_service_state",
            result=RiskCheckResult.PASS,
            detail=(
                f"Target service {target_service.name} is currently "
                f"{target_service.status.value}, so a restart is a bounded verification step."
            ),
        )
    return RiskCheck(
        check="target_service_state",
        result=RiskCheckResult.UNKNOWN,
        detail=(
            f"Target service {target_service.name} is currently {target_service.status.value}; "
            "restart may be lower signal than additional evidence gathering."
        ),
    )


def _image_update_context_check(image_update_changes: Sequence[Change]) -> RiskCheck:
    """Assess whether a recent image update increases restart uncertainty."""
    if not image_update_changes:
        return RiskCheck(
            check="recent_image_update_context",
            result=RiskCheckResult.PASS,
            detail="No correlated image update was recorded for the proposed restart target.",
        )
    latest_change = image_update_changes[-1]
    return RiskCheck(
        check="recent_image_update_context",
        result=RiskCheckResult.UNKNOWN,
        detail=(
            "A correlated image update was recorded just before the incident "
            f"({latest_change.id}); restart may confirm recovery but will not undo that update."
        ),
    )


def _release_review_check(
    *,
    image_update_changes: Sequence[Change],
    research: Tier2ResearchBundle,
    service_research: ServiceResearchResult | None,
) -> RiskCheck:
    """Assess whether changelog and release-note risk could be reviewed deterministically."""
    if not image_update_changes:
        return RiskCheck(
            check="changelog_migration_review",
            result=RiskCheckResult.PASS,
            detail=(
                "No correlated image update was recorded, so changelog migration review "
                "was not required."
            ),
        )
    if research.skipped_offline:
        return RiskCheck(
            check="changelog_migration_review",
            result=RiskCheckResult.UNKNOWN,
            detail=_OFFLINE_RISK_WARNING,
        )
    if service_research is None:
        return RiskCheck(
            check="changelog_migration_review",
            result=RiskCheckResult.UNKNOWN,
            detail="No Tier 2 research record was available for the correlated image update.",
        )

    release_note_warnings = build_release_note_warnings(service_research)
    if release_note_warnings:
        return RiskCheck(
            check="changelog_migration_review",
            result=RiskCheckResult.FAIL,
            detail=" ".join(release_note_warnings),
        )

    if service_research.github_current_release is not None:
        return RiskCheck(
            check="changelog_migration_review",
            result=RiskCheckResult.PASS,
            detail="Release notes were reviewed and no migration/schema keywords were detected.",
        )

    return RiskCheck(
        check="changelog_migration_review",
        result=RiskCheckResult.UNKNOWN,
        detail="Public release metadata was unavailable for the correlated image update.",
    )


def _build_risk_warnings(
    *,
    image_update_changes: Sequence[Change],
    research: Tier2ResearchBundle,
    service_research: ServiceResearchResult | None,
) -> list[str]:
    """Render explicit warnings that complement the deterministic risk checks."""
    warnings: list[str] = ["Restart may briefly interrupt service availability."]
    if image_update_changes:
        warnings.append(
            "A correlated image update is in scope; restart can verify recovery but will "
            "not revert that change."
        )
    if research.skipped_offline:
        warnings.append(_OFFLINE_RISK_WARNING)
        return warnings
    if service_research is None:
        if image_update_changes:
            warnings.append(
                "Public changelog metadata was unavailable for the correlated image update."
            )
        return warnings

    warnings.extend(build_release_note_warnings(service_research))
    if service_research.github_current_release is None and image_update_changes:
        warnings.append("Public release notes were unavailable for the correlated image update.")
    return warnings


def _overall_risk(*, checks: Sequence[RiskCheck]) -> RiskLevel:
    """Map explicit checks into an overall remediation risk level."""
    failing_checks = {check.check for check in checks if check.result == RiskCheckResult.FAIL}
    if "bounded_action_scope" in failing_checks or "target_service_state" in failing_checks:
        return RiskLevel.HIGH
    if failing_checks or any(check.result == RiskCheckResult.UNKNOWN for check in checks):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _find_target_service(recommendation_target: str, services: Sequence[Service]) -> Service | None:
    """Resolve the canonical restart target back to its service record."""
    normalized_target = recommendation_target.casefold()
    for service in services:
        if service.id.removeprefix("svc-").casefold() == normalized_target:
            return service
    return None


def _correlated_image_updates(
    *,
    incident: Incident,
    recommendation_target: str,
    target_service: Service | None,
    changes: Sequence[Change],
) -> list[Change]:
    """Return correlated image updates relevant to the proposed restart target."""
    target_service_id = target_service.id if target_service is not None else None
    target_alias = recommendation_target.casefold()
    return [
        change
        for change in changes
        if change.type == ChangeType.IMAGE_UPDATE
        and change.id in incident.changes_correlated
        and (
            change.service_id == target_service_id
            or (
                change.service_id is not None
                and change.service_id.removeprefix("svc-").casefold() == target_alias
            )
        )
    ]


def _matching_service_research(
    *,
    recommendation_target: str,
    target_service: Service | None,
    research: Tier2ResearchBundle,
) -> ServiceResearchResult | None:
    """Return Tier 2 research associated with the proposed restart target."""
    target_service_id = target_service.id if target_service is not None else None
    normalized_target = recommendation_target.casefold()
    for service_result in research.service_results:
        if target_service_id is not None and service_result.target.service_id == target_service_id:
            return service_result
        if service_result.target.service_id.removeprefix("svc-").casefold() == normalized_target:
            return service_result
    return None
