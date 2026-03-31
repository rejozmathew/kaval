"""Unit tests for incident-manager orchestration helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.grouping import FindingGroup
from kaval.incident_manager import _build_incident_for_group, _update_incident_for_group
from kaval.models import (
    Change,
    ChangeType,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_build_incident_for_group_uses_grouped_findings_and_changes() -> None:
    """New incidents should reflect grouped findings and related change ids."""
    services = [build_service("svc-radarr", "Radarr")]
    finding = build_finding(
        "find-radarr",
        service_id="svc-radarr",
        severity=Severity.HIGH,
        summary="Radarr cannot reach DelugeVPN.",
        related_change_id="chg-radarr",
    )

    incident = _build_incident_for_group(
        FindingGroup(findings=(finding,)),
        services,
        ts(22, 0),
    )

    assert incident.status == IncidentStatus.OPEN
    assert incident.severity == Severity.HIGH
    assert incident.trigger_findings == ["find-radarr"]
    assert incident.all_findings == ["find-radarr"]
    assert incident.changes_correlated == ["chg-radarr"]
    assert incident.triggering_symptom == "Radarr cannot reach DelugeVPN."


def test_update_incident_for_group_merges_new_findings_into_existing_incident() -> None:
    """Existing incidents should absorb newly grouped findings and changes."""
    services = [
        build_service("svc-radarr", "Radarr"),
        build_service("svc-sonarr", "Sonarr"),
    ]
    existing_incident = Incident(
        id="inc-existing",
        title="Radarr degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=["find-radarr"],
        all_findings=["find-radarr"],
        affected_services=["svc-radarr"],
        triggering_symptom="Radarr cannot reach DelugeVPN.",
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=["chg-radarr"],
        grouping_window_start=ts(22, 0),
        grouping_window_end=ts(22, 0),
        created_at=ts(22, 0),
        updated_at=ts(22, 0),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    grouped_findings = FindingGroup(
        findings=(
            build_finding(
                "find-radarr",
                service_id="svc-radarr",
                severity=Severity.HIGH,
                summary="Radarr cannot reach DelugeVPN.",
                related_change_id="chg-radarr",
                status=FindingStatus.GROUPED,
                incident_id="inc-existing",
            ),
            build_finding(
                "find-sonarr",
                service_id="svc-sonarr",
                severity=Severity.MEDIUM,
                summary="Sonarr cannot reach DelugeVPN.",
                related_change_id="chg-sonarr",
            ),
        )
    )

    updated = _update_incident_for_group(
        incident=existing_incident,
        group=grouped_findings,
        services=services,
        updated_at=ts(22, 5),
    )

    assert updated.title == "Radarr and Sonarr degraded"
    assert updated.trigger_findings == ["find-radarr", "find-sonarr"]
    assert updated.all_findings == ["find-radarr", "find-sonarr"]
    assert updated.affected_services == ["svc-radarr", "svc-sonarr"]
    assert updated.changes_correlated == ["chg-radarr", "chg-sonarr"]
    assert updated.updated_at == ts(22, 5)


def build_service(service_id: str, name: str) -> Service:
    """Build a minimal service payload for incident-manager tests."""
    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="test",
        status=ServiceStatus.HEALTHY,
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


def build_finding(
    finding_id: str,
    *,
    service_id: str,
    severity: Severity,
    summary: str,
    related_change_id: str,
    status: FindingStatus = FindingStatus.NEW,
    incident_id: str | None = None,
) -> Finding:
    """Build a minimal finding payload for incident-manager tests."""
    return Finding(
        id=finding_id,
        title=summary,
        severity=severity,
        domain="test",
        service_id=service_id,
        summary=summary,
        evidence=[],
        impact="Test impact",
        confidence=0.9,
        status=status,
        incident_id=incident_id,
        related_changes=[
            Change(
                id=related_change_id,
                type=ChangeType.CONTAINER_RESTART,
                service_id=service_id,
                description="Restart count increased.",
                old_value="1",
                new_value="2",
                timestamp=ts(21, 55),
                correlated_incidents=[],
            )
        ],
        created_at=ts(22, 0 if finding_id == "find-radarr" else 2),
        resolved_at=None,
    )
