"""Unit tests for finding grouping and incident lifecycle transitions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.grouping import (
    can_transition_incident_status,
    common_upstream_services,
    group_findings,
    in_same_dependency_chain,
    transition_incident,
)
from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    Finding,
    FindingStatus,
    Incident,
    IncidentGroupingRule,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for grouping tests."""
    return datetime(2026, 3, 30, hour, minute, tzinfo=UTC)


def build_service(
    service_id: str,
    *,
    name: str,
    dependencies: list[str] | None = None,
) -> Service:
    """Create a service with optional dependency edges."""
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
        dependencies=[
            DependencyEdge(
                target_service_id=dependency_id,
                confidence=DependencyConfidence.CONFIGURED,
                source=DependencySource.DESCRIPTOR,
                description="Test dependency",
            )
            for dependency_id in (dependencies or [])
        ],
        dependents=[],
        last_check=ts(14),
        active_findings=0,
        active_incidents=0,
    )


def build_finding(finding_id: str, *, service_id: str, created_at: datetime) -> Finding:
    """Create a finding for grouping tests."""
    return Finding(
        id=finding_id,
        title=f"{service_id} degraded",
        severity=Severity.HIGH,
        domain="test",
        service_id=service_id,
        summary=f"{service_id} reported an issue.",
        evidence=[],
        impact="Test impact.",
        confidence=0.9,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=[],
        created_at=created_at,
        resolved_at=None,
    )


def build_incident() -> Incident:
    """Create an incident for lifecycle tests."""
    return Incident(
        id="inc-1",
        title="Radarr failing",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-1"],
        all_findings=["find-1"],
        affected_services=["svc-radarr"],
        triggering_symptom="Health check failed",
        suspected_cause="DelugeVPN down",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id="inv-1",
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(14, 23),
        grouping_window_end=ts(14, 24),
        created_at=ts(14, 23),
        updated_at=ts(14, 24),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def test_group_findings_with_common_upstream() -> None:
    """Sibling services sharing an upstream dependency should group."""
    services = [
        build_service("svc-delugevpn", name="DelugeVPN"),
        build_service("svc-radarr", name="Radarr", dependencies=["svc-delugevpn"]),
        build_service("svc-sonarr", name="Sonarr", dependencies=["svc-delugevpn"]),
        build_service("svc-immich", name="Immich"),
    ]
    findings = [
        build_finding("find-radarr", service_id="svc-radarr", created_at=ts(14, 23)),
        build_finding("find-sonarr", service_id="svc-sonarr", created_at=ts(14, 25)),
        build_finding("find-immich", service_id="svc-immich", created_at=ts(14, 24)),
    ]

    grouped = group_findings(findings, services)
    grouped_ids = [{finding.id for finding in group.findings} for group in grouped]

    assert {"find-radarr", "find-sonarr"} in grouped_ids
    assert {"find-immich"} in grouped_ids


def test_group_findings_respects_dependency_chain_and_window() -> None:
    """A service and its upstream dependency should group only within the window."""
    services = [
        build_service("svc-delugevpn", name="DelugeVPN"),
        build_service("svc-radarr", name="Radarr", dependencies=["svc-delugevpn"]),
    ]
    within_window = [
        build_finding("find-deluge", service_id="svc-delugevpn", created_at=ts(14, 23)),
        build_finding("find-radarr", service_id="svc-radarr", created_at=ts(14, 27)),
    ]
    outside_window = [
        build_finding("find-deluge", service_id="svc-delugevpn", created_at=ts(14, 23)),
        build_finding("find-radarr", service_id="svc-radarr", created_at=ts(14, 30)),
    ]

    grouped_within = group_findings(
        within_window,
        services,
        rule=IncidentGroupingRule(group_by_common_upstream=False, group_by_dependency_chain=True),
    )
    grouped_outside = group_findings(
        outside_window,
        services,
        rule=IncidentGroupingRule(group_by_common_upstream=False, group_by_dependency_chain=True),
    )

    assert len(grouped_within) == 1
    assert len(grouped_outside) == 2


def test_grouping_graph_helpers_identify_relationships() -> None:
    """Graph helper functions should reflect common upstream and chain membership."""
    services = {
        service.id: service
        for service in [
            build_service("svc-delugevpn", name="DelugeVPN"),
            build_service("svc-radarr", name="Radarr", dependencies=["svc-delugevpn"]),
            build_service("svc-sonarr", name="Sonarr", dependencies=["svc-delugevpn"]),
        ]
    }

    assert common_upstream_services("svc-radarr", "svc-sonarr", services) == {"svc-delugevpn"}
    assert in_same_dependency_chain("svc-radarr", "svc-delugevpn", services) is True
    assert in_same_dependency_chain("svc-radarr", "svc-sonarr", services) is False


def test_incident_lifecycle_transitions_follow_prd_state_machine() -> None:
    """Lifecycle helpers should accept valid PRD transitions only."""
    incident = build_incident()

    assert can_transition_incident_status(
        IncidentStatus.INVESTIGATING,
        IncidentStatus.AWAITING_APPROVAL,
    )
    assert not can_transition_incident_status(IncidentStatus.OPEN, IncidentStatus.REMEDIATING)

    approved = transition_incident(
        incident,
        IncidentStatus.AWAITING_APPROVAL,
        changed_at=ts(14, 26),
    )
    assert approved.status == IncidentStatus.AWAITING_APPROVAL
    assert approved.updated_at == ts(14, 26)

    resolved = transition_incident(
        approved,
        IncidentStatus.DISMISSED,
        changed_at=ts(14, 27),
    )
    assert resolved.status == IncidentStatus.DISMISSED

    with pytest.raises(ValueError):
        transition_incident(incident, IncidentStatus.REMEDIATING, changed_at=ts(14, 26))
