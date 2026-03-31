"""Integration tests for the Phase 1 FastAPI application."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
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
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    ModelUsed,
    NetworkingProfile,
    Service,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    VMProfile,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for API tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_fastapi_core_endpoints_expose_phase1_state(tmp_path: Path) -> None:
    """The FastAPI app should expose read-only Phase 1 monitoring state."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        health_response = client.get("/healthz")
        services_response = client.get("/api/v1/services")
        findings_response = client.get("/api/v1/findings")
        incidents_response = client.get("/api/v1/incidents")
        investigations_response = client.get("/api/v1/investigations")
        changes_response = client.get("/api/v1/changes")
        graph_response = client.get("/api/v1/graph")
        widget_response = client.get("/api/v1/widget")
        system_profile_response = client.get("/api/v1/system-profile")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok", "database_ready": True}

    services_payload = services_response.json()
    assert services_response.status_code == 200
    assert [service["id"] for service in services_payload] == [
        "svc-delugevpn",
        "svc-downloads-share",
    ]

    findings_payload = findings_response.json()
    assert findings_response.status_code == 200
    assert [finding["id"] for finding in findings_payload] == ["find-1"]

    incidents_payload = incidents_response.json()
    assert incidents_response.status_code == 200
    assert [incident["id"] for incident in incidents_payload] == ["inc-1"]

    investigations_payload = investigations_response.json()
    assert investigations_response.status_code == 200
    assert [investigation["id"] for investigation in investigations_payload] == ["inv-1"]

    changes_payload = changes_response.json()
    assert changes_response.status_code == 200
    assert [change["id"] for change in changes_payload] == ["chg-1"]

    graph_payload = graph_response.json()
    assert graph_response.status_code == 200
    assert [service["id"] for service in graph_payload["services"]] == [
        "svc-delugevpn",
        "svc-downloads-share",
    ]
    assert graph_payload["edges"] == [
        {
            "source_service_id": "svc-delugevpn",
            "target_service_id": "svc-downloads-share",
            "confidence": "configured",
            "source": "shared_volume",
            "description": "Mounted downloads share confirms dependency.",
        }
    ]

    widget_payload = widget_response.json()
    assert widget_response.status_code == 200
    assert widget_payload == {
        "total_services": 2,
        "active_findings": 1,
        "active_incidents": 1,
        "healthy_services": 1,
        "degraded_services": 1,
        "down_services": 0,
        "stopped_services": 0,
        "unknown_services": 0,
        "last_updated": "2026-03-31T12:00:00Z",
    }

    profile_payload = system_profile_response.json()
    assert system_profile_response.status_code == 200
    assert profile_payload["hostname"] == "zactower"
    assert profile_payload["services_summary"]["matched_descriptors"] == 1


def test_system_profile_endpoint_returns_not_found_when_missing(tmp_path: Path) -> None:
    """System profile requests should fail cleanly before P1-18 data exists."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.close()
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        response = client.get("/api/v1/system-profile")

    assert response.status_code == 404
    assert response.json() == {"detail": "system profile not found"}


def test_fastapi_serves_static_ui_when_dist_exists(tmp_path: Path) -> None:
    """The FastAPI app should serve the built UI when a dist directory exists."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.close()
    web_dist = tmp_path / "dist"
    web_dist.mkdir()
    (web_dist / "index.html").write_text("<html><body>Kaval UI</body></html>", encoding="utf-8")
    app = create_app(database_path=tmp_path / "kaval.db", web_dist_dir=web_dist)

    with TestClient(app) as client:
        root_response = client.get("/")
        health_response = client.get("/healthz")

    assert root_response.status_code == 200
    assert "Kaval UI" in root_response.text
    assert health_response.status_code == 200


def test_websocket_endpoint_streams_initial_snapshot(tmp_path: Path) -> None:
    """The WebSocket endpoint should emit one initial UI snapshot."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path, websocket_poll_interval=0.01)

    with TestClient(app) as client:
        with client.websocket_connect("/api/v1/ws") as websocket:
            payload = websocket.receive_json()

    assert payload["kind"] == "snapshot"
    assert payload["widget"]["total_services"] == 2
    assert len(payload["graph"]["services"]) == 2
    assert len(payload["incidents"]) == 1


def test_websocket_endpoint_streams_updates_after_database_changes(tmp_path: Path) -> None:
    """The WebSocket endpoint should push a new snapshot after persisted state changes."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path, websocket_poll_interval=0.01)

    with TestClient(app) as client:
        with client.websocket_connect("/api/v1/ws") as websocket:
            initial_payload = websocket.receive_json()
            update_database_with_second_incident(database_path)
            updated_payload = websocket.receive_json()

    assert len(initial_payload["incidents"]) == 1
    assert len(updated_payload["incidents"]) == 2
    assert updated_payload["widget"]["active_incidents"] == 2


def seed_api_database(database_path: Path) -> None:
    """Seed one database with representative Phase 1 state."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        for service in build_services():
            database.upsert_service(service)
        database.upsert_finding(build_finding())
        database.upsert_incident(build_incident())
        database.upsert_investigation(build_investigation())
        database.upsert_change(build_change())
        database.upsert_system_profile(build_system_profile())
    finally:
        database.close()


def update_database_with_second_incident(database_path: Path) -> None:
    """Persist one additional open incident for WebSocket update tests."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_incident(
            Incident(
                id="inc-2",
                title="downloads share degraded",
                severity=Severity.MEDIUM,
                status=IncidentStatus.OPEN,
                trigger_findings=["find-1"],
                all_findings=["find-1"],
                affected_services=["svc-downloads-share"],
                triggering_symptom="Share latency increased.",
                suspected_cause="Disk contention.",
                confirmed_cause=None,
                root_cause_service="svc-downloads-share",
                resolution_mechanism=None,
                cause_confirmation_source=None,
                confidence=0.72,
                investigation_id=None,
                approved_actions=[],
                changes_correlated=[],
                grouping_window_start=ts(12, 6),
                grouping_window_end=ts(12, 10),
                created_at=ts(12, 6),
                updated_at=ts(12, 7),
                resolved_at=None,
                mttr_seconds=None,
                journal_entry_id=None,
            )
        )
    finally:
        database.close()


def build_services() -> list[Service]:
    """Build a small persisted service graph for API tests."""
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
    """Build one persisted finding for API tests."""
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
    """Build one persisted incident for API tests."""
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
        investigation_id="inv-1",
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


def build_investigation() -> Investigation:
    """Build one persisted investigation for API tests."""
    return Investigation(
        id="inv-1",
        incident_id="inc-1",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[],
        research_steps=[],
        root_cause="Share-mount instability.",
        confidence=0.81,
        model_used=ModelUsed.NONE,
        cloud_model_calls=0,
        journal_entries_referenced=[],
        user_notes_referenced=[],
        recurrence_count=0,
        remediation=None,
        started_at=ts(12, 2),
        completed_at=ts(12, 4),
    )


def build_change() -> Change:
    """Build one persisted timeline event for API tests."""
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
    """Build the persisted system profile for API tests."""
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
        vms=[
            VMProfile(
                name="ubuntu",
                purpose="unknown",
                os="Ubuntu 24.04",
                type=None,
                quirks=None,
                gpu_passthrough=False,
            )
        ],
        last_updated=ts(12, 3),
    )
