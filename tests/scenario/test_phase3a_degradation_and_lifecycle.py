"""Phase 3A scenario coverage for fallback visibility and lifecycle history."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api.app import create_app
from kaval.credentials.models import VaultStatus
from kaval.database import KavalDatabase
from kaval.integrations import (
    AdapterDiagnosticCheck,
    AdapterDiagnosticCheckResult,
    AdapterDiagnosticOutcome,
    AdapterDiagnosticResult,
    AdapterDiagnosticStatus,
    AdapterStalenessPolicy,
    apply_adapter_fallback_to_insight_level,
    evaluate_adapter_fallback,
)
from kaval.models import (
    Change,
    ChangeType,
    DescriptorSource,
    Service,
    ServiceInsightLevel,
    ServiceStatus,
    ServiceType,
)
from kaval.pipeline import build_mock_services
from kaval.runtime import (
    CapabilityHealthDisplayState,
    CapabilityHealthLayer,
    build_capability_health_report,
    build_discovery_pipeline_runtime_signal,
    build_executor_process_runtime_signal,
    build_scheduler_runtime_signal,
)
from kaval.service_lifecycle import apply_service_lifecycle


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Phase 3A scenario assertions."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_adapter_degradation_is_visible_in_capability_health_and_caps_insight() -> None:
    """A degraded adapter should surface fallback in the health panel and insight level."""
    fallback = evaluate_adapter_fallback(
        adapter_id="radarr_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.AUTH_FAILED,
        observed_at=ts(12, 45),
        now=ts(13, 0),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=15),
    )

    effective_level = apply_adapter_fallback_to_insight_level(
        insight_level=ServiceInsightLevel.DEEP_INSPECTED,
        fallback_decision=fallback,
    )

    report = build_capability_health_report(
        checked_at=ts(13, 0),
        discovery_signal=build_discovery_pipeline_runtime_signal(
            recorded_at=ts(12, 55),
            last_succeeded_at=ts(12, 55),
            unraid_api_reachable=True,
            docker_api_reachable=True,
            trigger="periodic_reconciliation",
        ),
        scheduler_signal=build_scheduler_runtime_signal(
            recorded_at=ts(12, 56),
            last_completed_at=ts(12, 56),
            executed_check_ids=["endpoint_probe"],
        ),
        executor_signal=build_executor_process_runtime_signal(
            recorded_at=ts(12, 57),
            listener_started_at=ts(12, 30),
            socket_path=Path("/tmp/executor.sock"),
            docker_socket_path=Path("/tmp/docker.sock"),
            socket_reachable=True,
            docker_accessible=True,
        ),
        executor_socket_reachable=True,
        local_model_configured=False,
        cloud_model_configured=False,
        notification_channel_count=0,
        vault_status=VaultStatus(
            initialized=True,
            unlocked=True,
            unlock_expires_at=ts(13, 30),
            stored_credentials=1,
        ),
        database_reachable=True,
        migrations_current=True,
        adapter_diagnostics=[
            AdapterDiagnosticResult(
                adapter_id="radarr_api",
                status=AdapterDiagnosticStatus.AUTH_FAILED,
                checks=[
                    AdapterDiagnosticCheckResult(
                        check=AdapterDiagnosticCheck.CONNECTION,
                        outcome=AdapterDiagnosticOutcome.PASS,
                        detail="Adapter reached Radarr successfully.",
                    ),
                    AdapterDiagnosticCheckResult(
                        check=AdapterDiagnosticCheck.AUTH,
                        outcome=AdapterDiagnosticOutcome.FAIL,
                        detail="API key rejected by the Radarr endpoint.",
                    ),
                    AdapterDiagnosticCheckResult(
                        check=AdapterDiagnosticCheck.SCHEMA,
                        outcome=AdapterDiagnosticOutcome.UNKNOWN,
                        detail="Schema validation did not run after auth failure.",
                    ),
                    AdapterDiagnosticCheckResult(
                        check=AdapterDiagnosticCheck.VERSION,
                        outcome=AdapterDiagnosticOutcome.UNKNOWN,
                        detail="Version validation did not run after auth failure.",
                    ),
                ],
                checked_at=ts(12, 58),
                reason="401 Unauthorized",
            )
        ],
    )

    adapters_layer = next(
        layer
        for layer in report.layers
        if layer.layer == CapabilityHealthLayer.DEEP_INSPECTION_ADAPTERS
    )

    assert fallback.state.value == "degraded"
    assert fallback.use_base_inference is True
    assert fallback.allow_adapter_facts is False
    assert effective_level == ServiceInsightLevel.INVESTIGATION_READY
    assert adapters_layer.display_state == CapabilityHealthDisplayState.DEGRADED
    assert adapters_layer.summary == "Deep inspection adapters are degraded."
    assert "radarr_api" in adapters_layer.detail
    assert "fall back to base inference" in adapters_layer.user_impact


def test_service_lifecycle_graph_and_history_cover_add_remove_and_update(
    tmp_path: Path,
) -> None:
    """Lifecycle refreshes should expose add/remove/update semantics via graph and history."""
    database_path = tmp_path / "phase3a-lifecycle.db"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        previous_services = services_with_container_ids()
        lifecycle_update = apply_service_lifecycle(
            previous_services=previous_services,
            discovered_services=refreshed_services(previous_services),
            now=ts(12, 0),
            changes=[
                Change(
                    id="chg-radarr-image",
                    type=ChangeType.IMAGE_UPDATE,
                    service_id="svc-radarr",
                    description="Radarr image updated from 5.0.0 to 5.0.1.",
                    old_value="5.0.0",
                    new_value="5.0.1",
                    timestamp=ts(11, 55),
                    correlated_incidents=[],
                ),
                Change(
                    id="chg-sonarr-restart",
                    type=ChangeType.CONTAINER_RESTART,
                    service_id="svc-sonarr",
                    description="Sonarr restarted after a health-check failure.",
                    old_value="4",
                    new_value="5",
                    timestamp=ts(11, 56),
                    correlated_incidents=[],
                ),
            ],
        )

        for service in lifecycle_update.services:
            database.upsert_service(service)
        for change in lifecycle_update.changes:
            database.upsert_change(change)
    finally:
        database.close()

    app = create_app(database_path=database_path)
    with TestClient(app) as client:
        graph_response = client.get("/api/v1/graph")
        changes_response = client.get("/api/v1/changes")

    assert graph_response.status_code == 200
    assert changes_response.status_code == 200

    graph_payload = graph_response.json()
    changes_payload = changes_response.json()
    services_by_id = {
        service["id"]: service for service in graph_payload["services"]
    }
    change_types = [change["type"] for change in changes_payload]

    assert services_by_id["svc-prowlarr"]["lifecycle"]["state"] == "active"
    assert services_by_id["svc-delugevpn"]["lifecycle"]["state"] == "missing"
    assert services_by_id["svc-delugevpn"]["status"] == ServiceStatus.DOWN.value
    assert services_by_id["svc-sonarr"]["name"] == "Sonarr 4K"
    assert services_by_id["svc-sonarr"]["lifecycle"]["last_event"] == (
        "service_renamed_or_rematched"
    )
    assert services_by_id["svc-sonarr"]["lifecycle"]["previous_names"] == ["Sonarr"]
    assert "service_added" in change_types
    assert "service_missing" in change_types
    assert "service_renamed_or_rematched" in change_types
    assert "image_update" in change_types
    assert "container_restart" in change_types


def services_with_container_ids() -> list[Service]:
    """Attach deterministic container ids to the shared mock service graph."""
    container_ids = {
        "svc-delugevpn": "def456",
        "svc-radarr": "abc123",
        "svc-sonarr": "ghi789",
    }
    return [
        service.model_copy(update={"container_id": container_ids[service.id]})
        for service in build_mock_services()
    ]


def refreshed_services(previous_services: list[Service]) -> list[Service]:
    """Return one discovery refresh containing an add, a removal, and a rename/rematch."""
    refreshed: list[Service] = []
    for service in previous_services:
        if service.id == "svc-delugevpn":
            continue
        if service.id == "svc-sonarr":
            refreshed.append(
                service.model_copy(
                    update={
                        "id": "svc-sonarr-4k",
                        "name": "Sonarr 4K",
                        "descriptor_id": "arr/sonarr",
                        "descriptor_source": DescriptorSource.SHIPPED,
                        "status": ServiceStatus.HEALTHY,
                    }
                )
            )
            continue
        refreshed.append(service)

    refreshed.append(
        Service(
            id="svc-prowlarr",
            name="Prowlarr",
            type=ServiceType.CONTAINER,
            category="arr",
            status=ServiceStatus.HEALTHY,
            descriptor_id="arr/prowlarr",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="jkl012",
            vm_id=None,
            image="lscr.io/linuxserver/prowlarr:latest",
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=[],
            last_check=ts(11, 58),
            active_findings=0,
            active_incidents=0,
        )
    )
    return refreshed
