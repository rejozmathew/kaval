"""Integration tests for the database-backed incident manager flow."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.incident_manager import IncidentManager
from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    Finding,
    FindingStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_incident_manager_groups_related_findings_into_one_persisted_incident(
    tmp_path: Path,
) -> None:
    """Related findings across the same dependency chain should share one incident."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    manager = IncidentManager()
    services = build_services()

    first_result = manager.process_findings(
        database,
        [build_finding("find-radarr", "svc-radarr", ts(22, 0))],
        services,
        now=ts(22, 0),
    )
    second_result = manager.process_findings(
        database,
        [build_finding("find-sonarr", "svc-sonarr", ts(22, 2))],
        services,
        now=ts(22, 2),
    )

    incidents = database.list_incidents()
    stored_findings = database.list_findings()

    assert len(first_result.created_incidents) == 1
    assert len(second_result.updated_incidents) == 1
    assert len(incidents) == 1
    assert incidents[0].all_findings == ["find-radarr", "find-sonarr"]
    assert incidents[0].affected_services == ["svc-radarr", "svc-sonarr"]
    assert {finding.incident_id for finding in stored_findings} == {incidents[0].id}
    assert {finding.status for finding in stored_findings} == {FindingStatus.GROUPED}


def build_services() -> list[Service]:
    """Build a small dependency chain for incident-manager integration tests."""
    upstream_edge = DependencyEdge(
        target_service_id="svc-delugevpn",
        confidence=DependencyConfidence.CONFIGURED,
        source=DependencySource.DOCKER_NETWORK,
        description="Shared Docker network confirms DelugeVPN.",
    )
    return [
        Service(
            id="svc-delugevpn",
            name="DelugeVPN",
            type=ServiceType.CONTAINER,
            category="downloads",
            status=ServiceStatus.DEGRADED,
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=None,
            image=None,
            endpoints=[],
            dns_targets=[],
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
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=None,
            image=None,
            endpoints=[],
            dns_targets=[],
            dependencies=[upstream_edge],
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
            status=ServiceStatus.DEGRADED,
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=None,
            image=None,
            endpoints=[],
            dns_targets=[],
            dependencies=[upstream_edge.model_copy()],
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        ),
    ]


def build_finding(finding_id: str, service_id: str, created_at: datetime) -> Finding:
    """Build a minimal finding payload for incident-manager integration tests."""
    return Finding(
        id=finding_id,
        title=f"{service_id} degraded",
        severity=Severity.HIGH,
        domain="test",
        service_id=service_id,
        summary=f"{service_id} cannot reach DelugeVPN.",
        evidence=[],
        impact="Download pipeline degraded.",
        confidence=0.92,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=[],
        created_at=created_at,
        resolved_at=None,
    )
