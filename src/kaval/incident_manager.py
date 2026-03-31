"""Database-backed incident grouping and lifecycle orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence
from uuid import uuid4

from kaval.database import KavalDatabase
from kaval.grouping import FindingGroup, group_findings, transition_incident
from kaval.models import (
    Finding,
    FindingStatus,
    Incident,
    IncidentGroupingRule,
    IncidentStatus,
    Service,
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


@dataclass(frozen=True, slots=True)
class IncidentManagerResult:
    """The persisted incident-manager outcome for one processing pass."""

    findings: list[Finding]
    created_incidents: list[Incident]
    updated_incidents: list[Incident]
    dismissed_incidents: list[Incident]


class IncidentManager:
    """Group active findings into incidents and persist the result."""

    def __init__(self, *, grouping_rule: IncidentGroupingRule | None = None) -> None:
        """Store the optional grouping rule override."""
        self._grouping_rule = grouping_rule

    def process_findings(
        self,
        database: KavalDatabase,
        findings: Sequence[Finding],
        services: Sequence[Service],
        *,
        now: datetime | None = None,
    ) -> IncidentManagerResult:
        """Persist findings, group active findings, and create or update incidents."""
        effective_now = now or datetime.now(tz=UTC)
        for finding in findings:
            database.upsert_finding(finding)

        active_findings = [
            finding
            for finding in database.list_findings()
            if finding.status not in _INACTIVE_FINDING_STATUSES
        ]
        active_incidents = {
            incident.id: incident
            for incident in database.list_incidents()
            if incident.status not in _INACTIVE_INCIDENT_STATUSES
        }

        grouped_findings: dict[str, Finding] = {}
        created_incidents: list[Incident] = []
        updated_incidents: list[Incident] = []
        dismissed_incidents: list[Incident] = []

        for group in group_findings(active_findings, services, rule=self._grouping_rule):
            referenced_incidents = _referenced_incidents(group.findings, active_incidents)
            primary_incident = _primary_incident(referenced_incidents)

            if primary_incident is None:
                incident = _build_incident_for_group(group, services, effective_now)
                created_incidents.append(incident)
            else:
                incident = _update_incident_for_group(
                    incident=primary_incident,
                    group=group,
                    services=services,
                    updated_at=effective_now,
                )
                updated_incidents.append(incident)

            database.upsert_incident(incident)
            active_incidents[incident.id] = incident

            for secondary_incident in referenced_incidents[1:]:
                dismissed_incident = transition_incident(
                    secondary_incident,
                    IncidentStatus.DISMISSED,
                    changed_at=effective_now,
                )
                database.upsert_incident(dismissed_incident)
                active_incidents[dismissed_incident.id] = dismissed_incident
                dismissed_incidents.append(dismissed_incident)

            for finding in group.findings:
                grouped_finding = finding.model_copy(
                    update={
                        "status": FindingStatus.GROUPED,
                        "incident_id": incident.id,
                    }
                )
                database.upsert_finding(grouped_finding)
                grouped_findings[grouped_finding.id] = grouped_finding

        return IncidentManagerResult(
            findings=sorted(grouped_findings.values(), key=lambda finding: finding.id),
            created_incidents=sorted(created_incidents, key=lambda incident: incident.id),
            updated_incidents=sorted(updated_incidents, key=lambda incident: incident.id),
            dismissed_incidents=sorted(
                dismissed_incidents,
                key=lambda incident: incident.id,
            ),
        )


def _referenced_incidents(
    findings: Sequence[Finding],
    active_incidents: dict[str, Incident],
) -> list[Incident]:
    """Return active incidents already referenced by the grouped findings."""
    incident_ids = {
        finding.incident_id
        for finding in findings
        if finding.incident_id is not None and finding.incident_id in active_incidents
    }
    return sorted(
        (active_incidents[incident_id] for incident_id in incident_ids),
        key=lambda incident: (incident.created_at, incident.id),
    )


def _primary_incident(incidents: Sequence[Incident]) -> Incident | None:
    """Return the oldest referenced incident, if any."""
    if not incidents:
        return None
    return incidents[0]


def _build_incident_for_group(
    group: FindingGroup,
    services: Sequence[Service],
    created_at: datetime,
) -> Incident:
    """Create an incident from one grouped set of findings."""
    service_names = {service.id: service.name for service in services}
    affected_service_ids = list(group.affected_services)
    grouped_finding_ids = [finding.id for finding in group.findings]
    return Incident(
        id=f"inc-{uuid4()}",
        title=_title_for_services(affected_service_ids, service_names),
        severity=_highest_severity(group.findings),
        status=IncidentStatus.OPEN,
        trigger_findings=grouped_finding_ids,
        all_findings=grouped_finding_ids,
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
        changes_correlated=_group_change_ids(group.findings),
        grouping_window_start=group.window_start,
        grouping_window_end=group.window_end,
        created_at=created_at,
        updated_at=created_at,
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def _update_incident_for_group(
    *,
    incident: Incident,
    group: FindingGroup,
    services: Sequence[Service],
    updated_at: datetime,
) -> Incident:
    """Return an updated incident that reflects the current grouped findings."""
    service_names = {service.id: service.name for service in services}
    grouped_finding_ids = [finding.id for finding in group.findings]
    all_finding_ids = sorted(set(incident.all_findings) | set(grouped_finding_ids))
    trigger_findings = sorted(
        set(incident.trigger_findings)
        | {
            finding.id
            for finding in group.findings
            if finding.status == FindingStatus.NEW or finding.incident_id != incident.id
        }
    )
    affected_services = sorted(set(incident.affected_services) | set(group.affected_services))
    return incident.model_copy(
        update={
            "title": _title_for_services(affected_services, service_names),
            "severity": _highest_severity(group.findings),
            "trigger_findings": trigger_findings,
            "all_findings": all_finding_ids,
            "affected_services": affected_services,
            "triggering_symptom": incident.triggering_symptom or group.findings[0].summary,
            "confidence": max(finding.confidence for finding in group.findings),
            "changes_correlated": sorted(
                set(incident.changes_correlated) | set(_group_change_ids(group.findings))
            ),
            "grouping_window_start": group.window_start,
            "grouping_window_end": group.window_end,
            "updated_at": updated_at,
        }
    )


def _group_change_ids(findings: Sequence[Finding]) -> list[str]:
    """Return distinct related change identifiers referenced by the findings."""
    return sorted(
        {
            change.id
            for finding in findings
            for change in finding.related_changes
        }
    )


def _title_for_services(
    affected_service_ids: Sequence[str],
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
    """Return the highest severity present in the grouped findings."""
    priority = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
    }
    return max(findings, key=lambda finding: priority[finding.severity]).severity
