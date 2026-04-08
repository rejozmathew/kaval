"""Webhook event normalization, matching, and finding/incident wiring."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence
from uuid import uuid4

from kaval.database import KavalDatabase
from kaval.grouping import transition_incident
from kaval.incident_manager import IncidentManager, IncidentManagerResult
from kaval.integrations.webhooks.dedup import (
    WebhookDedupResult,
    WebhookEventDeduplicator,
)
from kaval.integrations.webhooks.matching import (
    WebhookServiceMatcher,
    WebhookServiceMatchResult,
)
from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookEvent,
    WebhookMatchingOutcome,
    WebhookProcessingStatus,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers import (
    normalize_alertmanager_payload,
    normalize_grafana_payload,
    normalize_netdata_payload,
    normalize_uptime_kuma_payload,
)
from kaval.integrations.webhooks.normalizers.generic_json import (
    GenericJsonNormalizerConfig,
    normalize_generic_json_payload,
)
from kaval.memory.redaction import redact_json_value
from kaval.models import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    JsonValue,
    RedactionLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)

_INACTIVE_FINDING_STATUSES = {
    FindingStatus.RESOLVED,
    FindingStatus.DISMISSED,
    FindingStatus.STALE,
}
_INACTIVE_INCIDENT_STATUSES = {
    IncidentStatus.RESOLVED,
    IncidentStatus.DISMISSED,
}
_EXTERNAL_ALERT_SERVICE_ID = "svc-external-alerts"


class WebhookPipelineError(RuntimeError):
    """Raised when a webhook cannot be normalized or processed safely."""


@dataclass(frozen=True, slots=True)
class WebhookPipelineResult:
    """Artifacts produced by processing one webhook event end to end."""

    event: WebhookEvent
    dedup_result: WebhookDedupResult
    match_result: WebhookServiceMatchResult | None
    findings: list[Finding]
    created_services: list[Service]
    incident_result: IncidentManagerResult | None
    resolved_findings: list[Finding]
    resolved_incidents: list[Incident]

    @property
    def incident_id(self) -> str | None:
        """Return one representative incident identifier tied to the webhook payload."""
        if self.incident_result is not None:
            incidents = (
                self.incident_result.created_incidents
                or self.incident_result.updated_incidents
                or self.incident_result.dismissed_incidents
            )
            if incidents:
                return incidents[0].id
        if self.resolved_incidents:
            return self.resolved_incidents[0].id
        resolved_incident_ids = [
            finding.incident_id
            for finding in self.resolved_findings
            if finding.incident_id is not None
        ]
        if resolved_incident_ids:
            return resolved_incident_ids[0]
        finding_incident_ids = [
            finding.incident_id
            for finding in self.findings
            if finding.incident_id is not None
        ]
        if finding_incident_ids:
            return finding_incident_ids[0]
        return None


@dataclass(slots=True)
class WebhookPipelineProcessor:
    """Run one webhook event through normalization, matching, and incident wiring."""

    matcher: WebhookServiceMatcher = field(default_factory=WebhookServiceMatcher)
    deduplicator: WebhookEventDeduplicator = field(default_factory=WebhookEventDeduplicator)
    incident_manager: IncidentManager = field(default_factory=IncidentManager)

    def process(
        self,
        *,
        database: KavalDatabase,
        source_id: str,
        source_type: WebhookSourceType,
        payload: dict[str, JsonValue],
        received_at: datetime,
        raw_payload_retention_until: datetime | None,
        generic_json_config: GenericJsonNormalizerConfig | None = None,
    ) -> WebhookPipelineResult:
        """Normalize, deduplicate, match, and persist one webhook payload."""
        event = _normalize_webhook_event(
            source_id=source_id,
            source_type=source_type,
            payload=payload,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
            generic_json_config=generic_json_config,
        )
        dedup_result = self.deduplicator.apply(database=database, event=event)
        if not dedup_result.should_process:
            return WebhookPipelineResult(
                event=dedup_result.event,
                dedup_result=dedup_result,
                match_result=None,
                findings=[],
                created_services=[],
                incident_result=None,
                resolved_findings=[],
                resolved_incidents=[],
            )

        services = database.list_services()
        match_result = self.matcher.match(event=dedup_result.event, services=services)
        if dedup_result.event.alert_state == WebhookAlertState.RESOLVED:
            resolved_findings, resolved_incidents = _resolve_webhook_records(
                database=database,
                source_id=source_id,
                dedup_key=dedup_result.event.dedup_key,
                resolved_at=received_at,
            )
            return WebhookPipelineResult(
                event=match_result.event,
                dedup_result=dedup_result,
                match_result=match_result,
                findings=[],
                created_services=[],
                incident_result=None,
                resolved_findings=resolved_findings,
                resolved_incidents=resolved_incidents,
            )

        findings, created_services = _build_findings_for_event(
            event=match_result.event,
            services=services,
            created_at=received_at,
        )
        if created_services:
            for service in created_services:
                database.upsert_service(service)
            services = list(services) + created_services

        incident_result = self.incident_manager.process_findings(
            database,
            findings,
            services,
            now=received_at,
        )
        return WebhookPipelineResult(
            event=_event_after_finding_creation(match_result.event),
            dedup_result=dedup_result,
            match_result=match_result,
            findings=incident_result.findings,
            created_services=created_services,
            incident_result=incident_result,
            resolved_findings=[],
            resolved_incidents=[],
        )


def _normalize_webhook_event(
    *,
    source_id: str,
    source_type: WebhookSourceType,
    payload: dict[str, JsonValue],
    received_at: datetime,
    raw_payload_retention_until: datetime | None,
    generic_json_config: GenericJsonNormalizerConfig | None,
) -> WebhookEvent:
    """Dispatch one raw payload to the source-specific webhook normalizer."""
    if source_type is WebhookSourceType.UPTIME_KUMA:
        return normalize_uptime_kuma_payload(
            source_id=source_id,
            payload=payload,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
        )
    if source_type is WebhookSourceType.GRAFANA:
        return normalize_grafana_payload(
            source_id=source_id,
            payload=payload,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
        )
    if source_type is WebhookSourceType.PROMETHEUS_ALERTMANAGER:
        return normalize_alertmanager_payload(
            source_id=source_id,
            payload=payload,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
        )
    if source_type is WebhookSourceType.NETDATA:
        return normalize_netdata_payload(
            source_id=source_id,
            payload=payload,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
        )
    if source_type is WebhookSourceType.GENERIC_JSON:
        if generic_json_config is None:
            msg = "generic JSON webhook source requires a field-mapping configuration"
            raise WebhookPipelineError(msg)
        return normalize_generic_json_payload(
            source_id=source_id,
            payload=payload,
            config=generic_json_config,
            received_at=received_at,
            raw_payload_retention_until=raw_payload_retention_until,
        )
    msg = f"unsupported webhook source type: {source_type}"
    raise WebhookPipelineError(msg)


def _build_findings_for_event(
    *,
    event: WebhookEvent,
    services: Sequence[Service],
    created_at: datetime,
) -> tuple[list[Finding], list[Service]]:
    """Return findings and any synthetic services required for the matched event."""
    service_names = {service.id: service.name for service in services}
    if event.matching_outcome is WebhookMatchingOutcome.SINGLE:
        service_id = event.matched_service_ids[0]
        finding = _build_webhook_finding(
            event=event,
            service_id=service_id,
            impact=(
                f"Webhook alert from {event.source_id} matched "
                f"{service_names.get(service_id, service_id)}."
            ),
            created_at=created_at,
        )
        return [finding], []

    if event.matching_outcome is WebhookMatchingOutcome.MULTI:
        matched_names = [
            service_names.get(service_id, service_id)
            for service_id in event.matched_service_ids
        ]
        group_service = _build_group_service(
            event=event,
            service_names=service_names,
        )
        finding = _build_webhook_finding(
            event=event,
            service_id=group_service.id,
            impact=(
                f"Webhook alert from {event.source_id} matched multiple services: "
                f"{', '.join(matched_names)}."
            ),
            created_at=created_at,
        )
        return [finding], [group_service]

    external_service = _build_external_alert_service()
    finding = _build_webhook_finding(
        event=event,
        service_id=external_service.id,
        impact=(
            f"Webhook alert from {event.source_id} did not match a known service."
        ),
        created_at=created_at,
    )
    return [finding], [external_service]


def _build_webhook_finding(
    *,
    event: WebhookEvent,
    service_id: str,
    impact: str,
    created_at: datetime,
) -> Finding:
    """Build one finding from a processed webhook event."""
    evidence = Evidence(
        kind=EvidenceKind.EVENT,
        source=f"webhook:{event.source_id}",
        summary=event.body or event.title,
        observed_at=event.received_at,
        data=_webhook_evidence_data(event),
    )
    return Finding(
        id=f"find-{uuid4()}",
        title=event.title,
        severity=_finding_severity(event),
        domain=f"webhook:{event.source_type.value}",
        service_id=service_id,
        summary=event.body or event.title,
        evidence=[evidence],
        impact=impact,
        confidence=1.0,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=[],
        created_at=created_at,
        resolved_at=None,
    )


def _webhook_evidence_data(event: WebhookEvent) -> dict[str, JsonValue]:
    """Return a redacted evidence payload safe to persist on webhook findings."""
    matched_service_ids: list[JsonValue] = [
        service_id
        for service_id in event.matched_service_ids
    ]
    tags: dict[str, JsonValue] = {
        key: value
        for key, value in event.tags.items()
    }
    evidence_payload: dict[str, JsonValue] = {
        "source_type": event.source_type.value,
        "source_id": event.source_id,
        "source_event_id": event.source_event_id,
        "dedup_key": event.dedup_key,
        "alert_state": event.alert_state.value,
        "severity": event.severity.value,
        "url": event.url,
        "tags": tags,
        "matched_service_ids": matched_service_ids,
        "matching_outcome": event.matching_outcome.value,
        "raw_payload": event.raw_payload,
    }
    redacted = redact_json_value(
        evidence_payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value
    return redacted if isinstance(redacted, dict) else {}


def _build_external_alert_service() -> Service:
    """Return the generic external-alert pseudo-service required by the requirements."""
    return Service(
        id=_EXTERNAL_ALERT_SERVICE_ID,
        name="External Alerts",
        type=ServiceType.EXTERNAL,
        category="webhook",
        status=ServiceStatus.UNKNOWN,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _build_group_service(
    *,
    event: WebhookEvent,
    service_names: dict[str, str],
) -> Service:
    """Return a stable pseudo-service representing one matched webhook alert group."""
    group_hash = hashlib.sha1(
        f"{event.source_id}:{event.dedup_key}".encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()[:12]
    matched_names = [
        service_names.get(service_id, service_id)
        for service_id in event.matched_service_ids
    ]
    name_suffix = ", ".join(matched_names[:3]) or "External alerts"
    if len(matched_names) > 3:
        name_suffix = f"{name_suffix}, +{len(matched_names) - 3} more"
    return Service(
        id=f"svc-whkgrp-{group_hash}",
        name=f"Webhook group: {name_suffix}",
        type=ServiceType.EXTERNAL,
        category="webhook",
        status=ServiceStatus.UNKNOWN,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _finding_severity(event: WebhookEvent) -> Severity:
    """Map normalized webhook severities into the finding severity ladder."""
    if event.severity.value == "critical":
        return Severity.CRITICAL
    if event.severity.value == "high":
        return Severity.HIGH
    if event.severity.value == "medium":
        return Severity.MEDIUM
    return Severity.LOW


def _event_after_finding_creation(event: WebhookEvent) -> WebhookEvent:
    """Mark matched webhook events once they have been turned into findings."""
    if event.matching_outcome not in {
        WebhookMatchingOutcome.SINGLE,
        WebhookMatchingOutcome.MULTI,
    }:
        return event
    return event.model_copy(
        update={"processing_status": WebhookProcessingStatus.FINDING_CREATED}
    )


def _resolve_webhook_records(
    *,
    database: KavalDatabase,
    source_id: str,
    dedup_key: str,
    resolved_at: datetime,
) -> tuple[list[Finding], list[Incident]]:
    """Resolve active findings and incidents associated with one webhook dedup key."""
    active_findings = [
        finding
        for finding in database.list_findings()
        if finding.status not in _INACTIVE_FINDING_STATUSES
        and _finding_matches_webhook(finding, source_id=source_id, dedup_key=dedup_key)
    ]
    if not active_findings:
        return [], []

    resolved_findings = [
        finding.model_copy(
            update={
                "status": FindingStatus.RESOLVED,
                "resolved_at": resolved_at,
            }
        )
        for finding in active_findings
    ]
    for finding in resolved_findings:
        database.upsert_finding(finding)

    resolved_incidents: list[Incident] = []
    incident_ids = sorted(
        {
            finding.incident_id
            for finding in resolved_findings
            if finding.incident_id is not None
        }
    )
    for incident_id in incident_ids:
        incident = database.get_incident(incident_id)
        if incident is None or incident.status in _INACTIVE_INCIDENT_STATUSES:
            continue
        if not _incident_has_active_findings(database, incident_id=incident_id):
            resolved_incident = _resolve_incident(incident, resolved_at=resolved_at)
            database.upsert_incident(resolved_incident)
            resolved_incidents.append(resolved_incident)
    return resolved_findings, resolved_incidents


def _finding_matches_webhook(
    finding: Finding,
    *,
    source_id: str,
    dedup_key: str,
) -> bool:
    """Return whether a finding carries evidence for the target webhook identity."""
    for evidence in finding.evidence:
        if evidence.kind is not EvidenceKind.EVENT or not evidence.source.startswith("webhook:"):
            continue
        if not isinstance(evidence.data, dict):
            continue
        if evidence.data.get("source_id") != source_id:
            continue
        if evidence.data.get("dedup_key") != dedup_key:
            continue
        return True
    return False


def _incident_has_active_findings(database: KavalDatabase, *, incident_id: str) -> bool:
    """Return whether the incident still has any non-terminal findings."""
    return any(
        finding.incident_id == incident_id and finding.status not in _INACTIVE_FINDING_STATUSES
        for finding in database.list_findings()
    )


def _resolve_incident(incident: Incident, *, resolved_at: datetime) -> Incident:
    """Move one incident through the allowed lifecycle until it becomes resolved."""
    if incident.status is IncidentStatus.RESOLVED:
        return incident.model_copy(update={"updated_at": resolved_at})
    working = incident
    if working.status is IncidentStatus.AWAITING_APPROVAL:
        working = transition_incident(
            working,
            IncidentStatus.REMEDIATING,
            changed_at=resolved_at,
        )
    if working.status is IncidentStatus.OPEN:
        working = transition_incident(
            working,
            IncidentStatus.INVESTIGATING,
            changed_at=resolved_at,
        )
    resolved = transition_incident(
        working,
        IncidentStatus.RESOLVED,
        changed_at=resolved_at,
    )
    return resolved.model_copy(update={"resolution_mechanism": "Source alert resolved."})
