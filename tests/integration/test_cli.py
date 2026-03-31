"""Integration tests for the Phase 1 CLI."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.cli import main
from kaval.database import KavalDatabase
from kaval.models import (
    ArrayProfile,
    Change,
    ChangeType,
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Finding,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentStatus,
    NetworkingProfile,
    Service,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for CLI tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_status_command_renders_phase1_summary(tmp_path: Path, capsys: object) -> None:
    """The status command should summarize the persisted monitoring state."""
    database_path = tmp_path / "kaval.db"
    seed_cli_database(database_path)

    exit_code = main(["--database", str(database_path), "status"])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Services: 2 total" in output
    assert "Service states: 1 healthy, 1 degraded, 0 down, 0 stopped, 0 unknown" in output
    assert "Findings: 1 active / 1 total" in output
    assert "Incidents: 1 active / 1 total" in output
    assert "System profile: zactower (Unraid 7.2.1)" in output


def test_findings_command_lists_persisted_findings(tmp_path: Path, capsys: object) -> None:
    """The findings command should print persisted findings."""
    database_path = tmp_path / "kaval.db"
    seed_cli_database(database_path)

    exit_code = main(["--database", str(database_path), "findings"])
    output = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert output == [
        "find-1 [high/grouped] svc-delugevpn: Download client unavailable",
    ]


def test_incidents_command_lists_persisted_incidents(tmp_path: Path, capsys: object) -> None:
    """The incidents command should print persisted incidents."""
    database_path = tmp_path / "kaval.db"
    seed_cli_database(database_path)

    exit_code = main(["--database", str(database_path), "incidents"])
    output = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert output == [
        "inc-1 [high/open] DelugeVPN degraded",
    ]


def seed_cli_database(database_path: Path) -> None:
    """Seed one database with representative CLI-visible state."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        for service in build_services():
            database.upsert_service(service)
        database.upsert_finding(build_finding())
        database.upsert_incident(build_incident())
        database.upsert_change(build_change())
        database.upsert_system_profile(build_system_profile())
    finally:
        database.close()


def build_services() -> list[Service]:
    """Build a small persisted service graph for CLI tests."""
    return [
        Service(
            id="svc-delugevpn",
            name="DelugeVPN",
            type=ServiceType.CONTAINER,
            category="downloads",
            status=ServiceStatus.DEGRADED,
            descriptor_id="downloads/delugevpn",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-123",
            vm_id=None,
            image="binhex/arch-delugevpn:2.1.1",
            endpoints=[
                Endpoint(
                    name="web",
                    protocol=EndpointProtocol.HTTP,
                    host="delugevpn",
                    port=8112,
                    path="/",
                    url=None,
                    auth_required=False,
                    expected_status=200,
                )
            ],
            dns_targets=[],
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-downloads-share",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.SHARED_VOLUME,
                    description="Mounted downloads share confirms dependency.",
                )
            ],
            dependents=[],
            last_check=ts(12, 0),
            active_findings=1,
            active_incidents=1,
        ),
        Service(
            id="svc-downloads-share",
            name="downloads",
            type=ServiceType.SHARE,
            category="storage",
            status=ServiceStatus.HEALTHY,
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=None,
            image=None,
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=["svc-delugevpn"],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        ),
    ]


def build_finding() -> Finding:
    """Build one persisted finding for CLI tests."""
    return Finding(
        id="find-1",
        title="Download client unavailable",
        severity=Severity.HIGH,
        domain="arr",
        service_id="svc-delugevpn",
        summary="DelugeVPN cannot mount the downloads share cleanly.",
        evidence=[],
        impact="Download pipeline degraded.",
        confidence=0.9,
        status=FindingStatus.GROUPED,
        incident_id="inc-1",
        related_changes=[],
        created_at=ts(12, 1),
        resolved_at=None,
    )


def build_incident() -> Incident:
    """Build one persisted incident for CLI tests."""
    return Incident(
        id="inc-1",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=["find-1"],
        all_findings=["find-1"],
        affected_services=["svc-delugevpn"],
        triggering_symptom="Container health degraded.",
        suspected_cause="Downloads share dependency unstable.",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=["chg-1"],
        grouping_window_start=ts(12, 0),
        grouping_window_end=ts(12, 5),
        created_at=ts(12, 1),
        updated_at=ts(12, 2),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_change() -> Change:
    """Build one persisted change for CLI tests."""
    return Change(
        id="chg-1",
        type=ChangeType.CONTAINER_RESTART,
        service_id="svc-delugevpn",
        description="Restart count increased from 1 to 2.",
        old_value="1",
        new_value="2",
        timestamp=ts(11, 58),
        correlated_incidents=["inc-1"],
    )


def build_system_profile() -> SystemProfile:
    """Build one persisted system profile for CLI tests."""
    return SystemProfile(
        hostname="zactower",
        unraid_version="7.2.1",
        hardware=HardwareProfile(
            cpu="Intel i3-12100T",
            memory_gb=32.0,
            gpu=None,
            ups=None,
        ),
        storage=StorageProfile(
            array=ArrayProfile(
                parity_drives=1,
                data_drives=4,
                cache=None,
                total_tb=12.0,
                used_tb=4.2,
            )
        ),
        networking=NetworkingProfile(
            domain=None,
            dns_provider=None,
            reverse_proxy=None,
            tunnel=None,
            vpn="delugevpn",
            dns_resolver=None,
            ssl_strategy=None,
        ),
        services_summary=ServicesSummary(
            total_containers=1,
            total_vms=0,
            matched_descriptors=1,
        ),
        vms=[],
        last_updated=ts(12, 3),
    )
