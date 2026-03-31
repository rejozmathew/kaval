"""Proof-of-life pipeline from mock finding to incident."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence
from uuid import uuid4

from kaval.database import KavalDatabase
from kaval.grouping import FindingGroup, group_findings
from kaval.mock_check import run_mock_check
from kaval.models import (
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


@dataclass(frozen=True, slots=True)
class PipelineRunResult:
    """Artifacts produced by the proof-of-life pipeline."""

    finding: Finding
    incident: Incident
    console_output: str


def build_mock_services() -> list[Service]:
    """Return a small service graph for the proof-of-life pipeline."""
    from kaval.models import DependencyConfidence, DependencyEdge, DependencySource

    return [
        Service(
            id="svc-delugevpn",
            name="DelugeVPN",
            type=ServiceType.CONTAINER,
            category="downloads",
            status=ServiceStatus.DEGRADED,
            descriptor_id="downloads/delugevpn",
            descriptor_source=None,
            container_id="container-delugevpn",
            vm_id=None,
            image="binhex/arch-delugevpn:2.1.1",
            endpoints=[],
            dependencies=[],
            dependents=["svc-radarr", "svc-sonarr"],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        ),
        Service(
            id="svc-radarr",
            name="Radarr",
            type=ServiceType.CONTAINER,
            category="arr",
            status=ServiceStatus.DEGRADED,
            descriptor_id="arr/radarr",
            descriptor_source=None,
            container_id="container-radarr",
            vm_id=None,
            image="linuxserver/radarr:5.0.0",
            endpoints=[],
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-delugevpn",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.DESCRIPTOR,
                    description="Radarr uses DelugeVPN as its download client.",
                )
            ],
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        ),
        Service(
            id="svc-sonarr",
            name="Sonarr",
            type=ServiceType.CONTAINER,
            category="arr",
            status=ServiceStatus.HEALTHY,
            descriptor_id="arr/sonarr",
            descriptor_source=None,
            container_id="container-sonarr",
            vm_id=None,
            image="linuxserver/sonarr:5.0.0",
            endpoints=[],
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-delugevpn",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.DESCRIPTOR,
                    description="Sonarr uses DelugeVPN as its download client.",
                )
            ],
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        ),
    ]


def run_mock_pipeline(
    database: KavalDatabase,
    *,
    services: list[Service] | None = None,
    now: datetime | None = None,
) -> PipelineRunResult:
    """Run the proof-of-life pipeline and persist its artifacts."""
    effective_now = now or datetime.now(tz=UTC)
    service_catalog = services or build_mock_services()
    for service in service_catalog:
        database.upsert_service(service)

    finding = run_mock_check(effective_now)
    database.upsert_finding(finding)

    active_findings = [
        stored_finding
        for stored_finding in database.list_findings()
        if stored_finding.status not in {FindingStatus.RESOLVED, FindingStatus.DISMISSED}
    ]
    target_group = _group_for_finding(
        finding.id,
        active_findings,
        service_catalog,
    )

    incident = _build_incident_for_group(target_group, service_catalog, effective_now)
    database.upsert_incident(incident)

    persisted_finding = finding.model_copy(
        update={
            "incident_id": incident.id,
            "status": FindingStatus.GROUPED,
        }
    )
    database.upsert_finding(persisted_finding)

    console_output = render_pipeline_output(persisted_finding, incident, service_catalog)
    return PipelineRunResult(
        finding=persisted_finding,
        incident=incident,
        console_output=console_output,
    )


def render_pipeline_output(
    finding: Finding,
    incident: Incident,
    services: list[Service],
) -> str:
    """Render a console-friendly proof-of-life summary."""
    service_names = {service.id: service.name for service in services}
    affected_names = ", ".join(
        service_names.get(service_id, service_id) for service_id in incident.affected_services
    )
    return "\n".join(
        [
            "Kaval Phase 0 Proof of Life",
            f"Finding: {finding.title} ({finding.id})",
            f"Incident: {incident.title} ({incident.id})",
            f"Affected services: {affected_names}",
            "Persisted: finding and incident stored in SQLite",
        ]
    )


def _group_for_finding(
    finding_id: str,
    findings: list[Finding],
    services: list[Service],
) -> FindingGroup:
    """Return the grouped finding cluster that contains the requested finding."""
    groups = group_findings(findings, services)
    for group in groups:
        if any(grouped_finding.id == finding_id for grouped_finding in group.findings):
            return group
    msg = f"no finding group found for {finding_id}"
    raise ValueError(msg)


def _build_incident_for_group(
    group: FindingGroup,
    services: list[Service],
    created_at: datetime,
) -> Incident:
    """Create an incident from a grouped set of findings."""
    service_names = {service.id: service.name for service in services}
    affected_service_ids = list(group.affected_services)
    title = _title_for_services(affected_service_ids, service_names)
    highest_severity = _highest_severity(group.findings)
    trigger_findings = [finding.id for finding in group.findings]
    change_ids = sorted(
        {
            change.id
            for finding in group.findings
            for change in finding.related_changes
        }
    )
    return Incident(
        id=f"inc-{uuid4()}",
        title=title,
        severity=highest_severity,
        status=IncidentStatus.OPEN,
        trigger_findings=trigger_findings,
        all_findings=trigger_findings,
        affected_services=affected_service_ids,
        triggering_symptom=group.findings[0].summary,
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=max(finding.confidence for finding in group.findings),
        investigation_id=None,
        approved_actions=[],
        changes_correlated=change_ids,
        grouping_window_start=group.window_start,
        grouping_window_end=group.window_end,
        created_at=created_at,
        updated_at=created_at,
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def _title_for_services(
    affected_service_ids: list[str],
    service_names: dict[str, str],
) -> str:
    """Create a readable incident title from affected services."""
    names = [service_names.get(service_id, service_id) for service_id in affected_service_ids]
    if len(names) == 1:
        return f"{names[0]} degraded"
    if len(names) == 2:
        return f"{names[0]} and {names[1]} degraded"
    prefix = ", ".join(names[:-1])
    return f"{prefix}, and {names[-1]} degraded"


def _highest_severity(findings: Sequence[Finding]) -> Severity:
    """Return the highest severity present in a finding group."""
    priority = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
    }
    return max(findings, key=lambda finding: priority[finding.severity]).severity
