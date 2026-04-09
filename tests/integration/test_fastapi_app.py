"""Integration tests for the Phase 1 FastAPI application."""

from __future__ import annotations

import importlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.credentials import build_credential_request_callback_id
from kaval.credentials.models import CredentialRequestMode, VaultCredentialRecord
from kaval.database import KavalDatabase
from kaval.discovery.descriptors import (
    load_service_descriptors,
    loaded_descriptor_identifier,
    write_user_descriptor,
)
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
    FindingFeedbackReason,
    FindingFeedbackRecord,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
    NetworkingProfile,
    PluginImpactService,
    PluginProfile,
    Service,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    UserNote,
    VMProfile,
)
from kaval.runtime import (
    build_discovery_pipeline_runtime_signal,
    build_executor_process_runtime_signal,
    build_scheduler_runtime_signal,
)

api_app_module = importlib.import_module("kaval.api.app")
WEBHOOK_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"
REPO_SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for API tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class FrozenApiDateTime(datetime):
    """Deterministic datetime shim for audit-retention endpoint tests."""

    @classmethod
    def now(cls, tz: object | None = None) -> datetime:
        """Return a fixed current time for retention-aware API reads."""
        frozen = datetime(2026, 4, 8, 12, 0, tzinfo=UTC)
        if tz is None:
            return frozen.replace(tzinfo=None)
        return frozen.astimezone(tz)


def load_webhook_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture used by FastAPI webhook tests."""
    return json.loads((WEBHOOK_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def build_model_settings_payload(
    *,
    local_enabled: bool,
    local_model: str | None,
    local_api_key: str | None = None,
    cloud_enabled: bool = False,
    cloud_provider: str = "anthropic",
    cloud_model: str | None = None,
    cloud_api_key: str | None = None,
) -> dict[str, object]:
    """Build a complete model-settings request payload for API tests."""
    return {
        "local": {
            "enabled": local_enabled,
            "model": local_model,
            "base_url": "http://localhost:11434",
            "timeout_seconds": 12.0,
            "api_key": local_api_key,
            "clear_stored_api_key": False,
        },
        "cloud": {
            "enabled": cloud_enabled,
            "provider": cloud_provider,
            "model": cloud_model,
            "base_url": (
                "https://api.anthropic.com"
                if cloud_provider == "anthropic"
                else "https://api.openai.com"
            ),
            "timeout_seconds": 25.0,
            "max_output_tokens": 800,
            "api_key": cloud_api_key,
            "clear_stored_api_key": False,
        },
        "escalation": {
            "finding_count_gt": 4,
            "local_confidence_lt": 0.55,
            "escalate_on_multiple_domains": True,
            "escalate_on_changelog_research": True,
            "escalate_on_user_request": False,
            "max_cloud_calls_per_day": 20,
            "max_cloud_calls_per_incident": 3,
        },
    }


def build_notification_settings_payload(
    *,
    channels: list[dict[str, object]],
    quiet_hours_enabled: bool = True,
) -> dict[str, object]:
    """Build a complete notification-settings request payload for API tests."""
    return {
        "channels": channels,
        "routing": {
            "critical": "immediate",
            "high": "immediate_with_dedup",
            "medium": "hourly_digest",
            "low": "dashboard_only",
            "dedup_window_minutes": 15,
            "digest_window_minutes": 60,
        },
        "quiet_hours": {
            "enabled": quiet_hours_enabled,
            "start_time_local": "22:00",
            "end_time_local": "07:00",
            "timezone": "UTC",
        },
    }


def build_monitoring_settings_payload(
    *,
    endpoint_probe_interval: int = 120,
    endpoint_probe_timeout_seconds: float = 5.0,
    restart_delta_threshold: int = 3,
    tls_cert_enabled: bool = True,
    tls_warning_days: int = 7,
    service_overrides: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a complete monitoring-settings request payload for API tests."""
    return {
        "checks": [
            {
                "check_id": "container_health",
                "enabled": True,
                "interval_seconds": 60,
            },
            {
                "check_id": "restart_storm",
                "enabled": True,
                "interval_seconds": 60,
                "restart_delta_threshold": restart_delta_threshold,
            },
            {
                "check_id": "endpoint_probe",
                "enabled": True,
                "interval_seconds": endpoint_probe_interval,
                "probe_timeout_seconds": endpoint_probe_timeout_seconds,
            },
            {
                "check_id": "vm_health",
                "enabled": True,
                "interval_seconds": 120,
            },
            {
                "check_id": "tls_cert",
                "enabled": tls_cert_enabled,
                "interval_seconds": 21600,
                "tls_warning_days": tls_warning_days,
            },
            {
                "check_id": "dns_resolution",
                "enabled": True,
                "interval_seconds": 300,
            },
            {
                "check_id": "log_pattern",
                "enabled": True,
                "interval_seconds": 300,
            },
            {
                "check_id": "unraid_system",
                "enabled": True,
                "interval_seconds": 600,
            },
            {
                "check_id": "dependency_chain",
                "enabled": True,
                "interval_seconds": 600,
            },
        ],
        "service_overrides": service_overrides or [],
    }


def build_system_settings_payload(
    *,
    log_level: str,
    audit_detail_retention_days: int = 90,
    audit_summary_retention_days: int = 365,
) -> dict[str, object]:
    """Build a complete system-settings request payload for API tests."""
    return {
        "log_level": log_level,
        "audit_detail_retention_days": audit_detail_retention_days,
        "audit_summary_retention_days": audit_summary_retention_days,
    }


class FakeAppriseAdapter:
    """Deterministic Apprise adapter for notification-settings API tests."""

    def __init__(self) -> None:
        """Initialize the captured destination and notification lists."""
        self.added_urls: list[str] = []
        self.notifications: list[dict[str, str]] = []

    def add(self, servers: str) -> bool:
        """Capture one configured Apprise destination URL."""
        self.added_urls.append(servers)
        return True

    def notify(self, *, title: str, body: str) -> bool:
        """Capture one notification payload and report success."""
        self.notifications.append({"title": title, "body": body})
        return True


def test_fastapi_core_endpoints_expose_phase1_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The FastAPI app should expose read-only Phase 1 monitoring state."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
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
        journal_entries_response = client.get("/api/v1/journal-entries")
        graph_response = client.get("/api/v1/graph")
        widget_response = client.get("/api/v1/widget")
        system_profile_response = client.get("/api/v1/system-profile")
        user_notes_response = client.get("/api/v1/user-notes")
        memory_notes_response = client.get("/api/v1/memory/notes")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok", "database_ready": True}

    services_payload = services_response.json()
    assert services_response.status_code == 200
    assert [service["id"] for service in services_payload] == [
        "svc-delugevpn",
        "svc-downloads-share",
    ]
    assert services_payload[0]["insight"] == {"level": 2}
    assert services_payload[0]["lifecycle"]["state"] == "active"
    assert services_payload[1]["insight"] == {"level": 0}
    assert services_payload[1]["lifecycle"]["state"] == "active"

    findings_payload = findings_response.json()
    assert findings_response.status_code == 200
    assert [finding["id"] for finding in findings_payload] == ["find-1"]

    incidents_payload = incidents_response.json()
    assert incidents_response.status_code == 200
    assert [incident["id"] for incident in incidents_payload] == ["inc-1"]

    investigations_payload = investigations_response.json()
    assert investigations_response.status_code == 200
    assert [investigation["id"] for investigation in investigations_payload] == ["inv-1"]
    assert investigations_payload[0]["cloud_model_calls"] == 0
    assert investigations_payload[0]["local_input_tokens"] == 0
    assert investigations_payload[0]["cloud_input_tokens"] == 0
    assert investigations_payload[0]["estimated_total_cost_usd"] == 0.0
    assert investigations_payload[0]["cloud_escalation_reason"] is None

    changes_payload = changes_response.json()
    assert changes_response.status_code == 200
    assert [change["id"] for change in changes_payload] == ["chg-1"]

    journal_payload = journal_entries_response.json()
    assert journal_entries_response.status_code == 200
    assert journal_payload == [
        {
            "id": "jrnl-1",
            "incident_id": "inc-0",
            "date": "2026-03-31",
            "services": ["svc-delugevpn"],
            "summary": "DelugeVPN degraded after a dependency restart.",
            "root_cause": "Downloads share dependency became unavailable.",
            "resolution": "Restarted DelugeVPN after the share recovered.",
            "time_to_resolution_minutes": 7.0,
            "model_used": "local",
            "tags": ["delugevpn", "storage"],
            "lesson": "Watch the downloads share before restarting clients.",
            "recurrence_count": 1,
            "confidence": "confirmed",
            "user_confirmed": True,
            "last_verified_at": "2026-03-31T11:50:00Z",
            "applies_to_version": None,
            "superseded_by": None,
            "stale_after_days": 180,
        }
    ]

    graph_payload = graph_response.json()
    assert graph_response.status_code == 200
    assert [service["id"] for service in graph_payload["services"]] == [
        "svc-delugevpn",
        "svc-downloads-share",
    ]
    assert graph_payload["services"][0]["insight"] == {"level": 2}
    assert graph_payload["services"][0]["lifecycle"]["state"] == "active"
    assert graph_payload["services"][1]["insight"] == {"level": 0}
    assert graph_payload["services"][1]["lifecycle"]["state"] == "active"
    assert graph_payload["edges"] == [
        {
            "source_service_id": "svc-delugevpn",
            "target_service_id": "svc-downloads-share",
            "confidence": "configured",
            "source": "shared_volume",
            "description": "Mounted downloads share confirms dependency.",
        }
    ]
    assert graph_payload["node_meta"] == [
        {
            "service_id": "svc-delugevpn",
            "target_insight_level": 3,
            "improve_available": True,
        },
        {
            "service_id": "svc-downloads-share",
            "target_insight_level": 0,
            "improve_available": False,
        },
    ]

    widget_payload = widget_response.json()
    assert widget_response.status_code == 200
    assert widget_payload == {
        "status": "degraded",
        "total_services": 2,
        "active_findings": 1,
        "active_incidents": 1,
        "healthy_services": 1,
        "degraded_services": 1,
        "down_services": 0,
        "stopped_services": 0,
        "unknown_services": 0,
        "last_updated": "2026-03-31T12:00:00Z",
        "services_total": 2,
        "services_healthy": 1,
        "services_degraded": 1,
        "services_down": 0,
        "last_investigation": "2026-03-31T12:04:00Z",
        "effectiveness_score": 50,
        "adapters_healthy": 0,
        "adapters_degraded": 0,
        "pending_approvals": 0,
        "url": "http://testserver",
        "refresh_interval_seconds": 60,
    }
    assert widget_response.headers["x-kaval-widget-refresh-seconds"] == "60"

    profile_payload = system_profile_response.json()
    assert system_profile_response.status_code == 200
    assert profile_payload["hostname"] == "zactower"
    assert profile_payload["services_summary"]["matched_descriptors"] == 1
    assert profile_payload["plugins"] == [
        {
            "name": "community.applications",
            "version": "2026.03.30",
            "enabled": True,
            "update_available": False,
            "impacted_services": [
                {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "descriptor_id": "downloads/delugevpn",
                }
            ],
        }
    ]

    notes_payload = user_notes_response.json()
    assert user_notes_response.status_code == 200
    assert notes_payload == [
        {
            "id": "note-1",
            "service_id": "svc-delugevpn",
            "note": "Provider endpoint rotates often during maintenance windows.",
            "safe_for_model": True,
            "last_verified_at": "2026-03-31T12:00:00Z",
            "stale": False,
            "added_at": "2026-03-31T12:00:00Z",
            "updated_at": "2026-03-31T12:05:00Z",
        }
    ]

    memory_notes_payload = memory_notes_response.json()
    assert memory_notes_response.status_code == 200
    assert memory_notes_payload == notes_payload


def test_fastapi_service_insight_upgrades_when_local_model_is_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Service responses should surface Level 3 once the local model is configured."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "llama3.2")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        services_response = client.get("/api/v1/services")

    assert services_response.status_code == 200
    assert services_response.json()[0]["insight"] == {"level": 3}


def test_graph_edge_confirmation_logs_a_config_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Confirming an edge should persist a user override and an audit change."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.put(
            "/api/v1/graph/edges",
            json={
                "source_service_id": "svc-delugevpn",
                "target_service_id": "svc-downloads-share",
            },
        )
        graph_response = client.get("/api/v1/graph")
        changes_response = client.get("/api/v1/changes")

    assert response.status_code == 200
    payload = response.json()
    assert payload["edge"] == {
        "source_service_id": "svc-delugevpn",
        "target_service_id": "svc-downloads-share",
        "confidence": "user_confirmed",
        "source": "user",
        "description": "Mounted downloads share confirms dependency.",
    }
    assert payload["audit_change"]["type"] == "config_change"
    assert (
        "Confirmed dependency edge DelugeVPN -> downloads."
        in payload["audit_change"]["description"]
    )
    graph_edges = graph_response.json()["edges"]
    assert graph_edges == [payload["edge"]]
    latest_change = changes_response.json()[-1]
    assert latest_change["id"] == payload["audit_change"]["id"]


def test_graph_endpoint_preserves_vm_service_shape_for_vm_graph_ui(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """VM graph entries should preserve the identity fields the frontend renders."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    database = KavalDatabase(database_path)
    database.upsert_service(
        Service(
            id="svc-vm-ubuntu",
            name="Ubuntu Server",
            type=ServiceType.VM,
            category="virtualization",
            status=ServiceStatus.HEALTHY,
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id="vm-ubuntu",
            image=None,
            endpoints=[
                Endpoint(
                    name="Home Assistant",
                    protocol=EndpointProtocol.HTTP,
                    host="ubuntu-vm",
                    port=8123,
                    path="/",
                    url=None,
                    auth_required=True,
                    expected_status=200,
                )
            ],
            dns_targets=[],
            dependencies=[],
            dependents=[],
            last_check=ts(12, 6),
            active_findings=0,
            active_incidents=0,
        )
    )
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        graph_response = client.get("/api/v1/graph")

    assert graph_response.status_code == 200
    vm_service = next(
        service
        for service in graph_response.json()["services"]
        if service["id"] == "svc-vm-ubuntu"
    )
    assert vm_service["type"] == "vm"
    assert vm_service["vm_id"] == "vm-ubuntu"
    assert vm_service["endpoints"] == [
        {
            "name": "Home Assistant",
            "protocol": "http",
            "host": "ubuntu-vm",
            "port": 8123,
            "path": "/",
            "url": None,
            "auth_required": True,
            "expected_status": 200,
        }
    ]


def test_graph_edge_edit_and_remove_routes_update_the_effective_graph(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Editing and removing an edge should persist effective-graph overrides."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        edit_response = client.put(
            "/api/v1/graph/edges",
            json={
                "previous_source_service_id": "svc-delugevpn",
                "previous_target_service_id": "svc-downloads-share",
                "source_service_id": "svc-delugevpn",
                "target_service_id": "svc-radarr",
                "description": (
                    "Admin corrected this edge after reviewing the actual dependency path."
                ),
            },
        )
        graph_after_edit = client.get("/api/v1/graph")
        remove_response = client.delete("/api/v1/graph/edges/svc-delugevpn/svc-radarr")
        graph_after_remove = client.get("/api/v1/graph")

    assert edit_response.status_code == 200
    assert edit_response.json()["edge"] == {
        "source_service_id": "svc-delugevpn",
        "target_service_id": "svc-radarr",
        "confidence": "user_confirmed",
        "source": "user",
        "description": "Admin corrected this edge after reviewing the actual dependency path.",
    }
    assert graph_after_edit.status_code == 200
    assert graph_after_edit.json()["edges"] == [edit_response.json()["edge"]]
    assert remove_response.status_code == 200
    assert remove_response.json()["edge"] is None
    assert (
        "Removed dependency edge DelugeVPN -> Radarr."
        in remove_response.json()["audit_change"]["description"]
    )
    assert graph_after_remove.status_code == 200
    assert graph_after_remove.json()["edges"] == []


def test_graph_edge_add_route_persists_across_subsequent_graph_reads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Adding a new edge should survive later graph reloads through the override layer."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.put(
            "/api/v1/graph/edges",
            json={
                "source_service_id": "svc-downloads-share",
                "target_service_id": "svc-radarr",
                "description": "Added manually after reviewing the downstream dependency.",
            },
        )
        first_graph = client.get("/api/v1/graph")
        second_graph = client.get("/api/v1/graph")

    assert response.status_code == 200
    expected_edge = {
        "source_service_id": "svc-downloads-share",
        "target_service_id": "svc-radarr",
        "confidence": "user_confirmed",
        "source": "user",
        "description": "Added manually after reviewing the downstream dependency.",
    }
    assert response.json()["edge"] == expected_edge
    assert expected_edge in first_graph.json()["edges"]
    assert expected_edge in second_graph.json()["edges"]


def test_webhook_receiver_accepts_bearer_auth_for_configured_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Configured webhook sources should accept bearer-authenticated POSTs."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    monkeypatch.delenv("KAVAL_WEBHOOK_KEY_GRAFANA", raising=False)
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=load_webhook_fixture("uptime_kuma_down.json"),
        )

    assert response.status_code == 202
    assert response.text == ""


def test_webhook_receiver_accepts_query_key_fallback_for_configured_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The query-string key should work as a compatibility fallback."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_GRAFANA", "grafana-secret")
    monkeypatch.delenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", raising=False)
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/grafana?key=grafana-secret",
            json=load_webhook_fixture("grafana_firing.json"),
        )

    assert response.status_code == 202
    assert response.text == ""


def test_webhook_receiver_returns_not_found_for_unconfigured_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Webhook routes should fail cleanly when the source is not configured."""
    monkeypatch.delenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", raising=False)
    monkeypatch.delenv("KAVAL_WEBHOOK_KEY_GRAFANA", raising=False)
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer missing"},
            json={"status": "down"},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "webhook source not configured"}


def test_service_detail_endpoint_returns_minimum_insight_section_for_service_without_adapter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Service detail should expose the minimum insight section even without an adapter."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/services/svc-delugevpn/detail")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service"]["id"] == "svc-delugevpn"
    assert payload["insight_section"] == {
        "current_level": 2,
        "adapter_available": False,
        "adapters": [],
        "improve_actions": [
            {
                "kind": "configure_local_model",
                "title": "Configure a local model",
                "detail": (
                    "Add a local investigation model endpoint to unlock "
                    "investigation-ready insight for this service."
                ),
            }
        ],
        "fact_summary_available": False,
    }


def test_service_detail_endpoint_surfaces_unconfigured_configured_and_locked_adapter_states(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Service detail should expose adapter state transitions without leaking secrets."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        initial_detail = client.get("/api/v1/services/svc-radarr/detail")
        create_response = client.post(
            "/api/v1/credential-requests",
            json={
                "incident_id": "inc-1",
                "investigation_id": "inv-1",
                "service_id": "svc-radarr",
                "credential_key": "api_key",
                "reason": "Need the diagnostics API to narrow the fault.",
            },
        )
        request_id = create_response.json()["id"]
        client.post(
            f"/api/v1/credential-requests/{request_id}/choice",
            json={
                "mode": "vault",
                "decided_by": "user_via_telegram",
            },
        )
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "radarr-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )
        configured_detail = client.get("/api/v1/services/svc-radarr/detail")
        client.post("/api/v1/vault/lock")
        locked_detail = client.get("/api/v1/services/svc-radarr/detail")

    assert initial_detail.status_code == 200
    initial_payload = initial_detail.json()
    assert initial_payload["insight_section"]["current_level"] == 2
    assert initial_payload["insight_section"]["adapter_available"] is True
    assert initial_payload["insight_section"]["fact_summary_available"] is False
    assert initial_payload["insight_section"]["adapters"] == [
        {
            "adapter_id": "radarr_api",
            "display_name": "Radarr API",
            "configuration_state": "unconfigured",
            "configuration_summary": "Required adapter inputs have not been configured yet.",
            "health_state": "unknown",
            "health_summary": "Health will remain unknown until the adapter is configured.",
            "missing_credentials": ["api_key"],
            "supported_fact_names": [
                "download_client_status",
                "download_clients",
                "health_issues",
                "indexer_status",
                "indexers",
                "queue_items",
                "queue_status",
                "runtime_info",
                "startup_path",
                "version",
            ],
        }
    ]
    assert initial_payload["insight_section"]["improve_actions"] == [
        {
            "kind": "configure_local_model",
            "title": "Configure a local model",
            "detail": (
                "Add a local investigation model endpoint to unlock "
                "investigation-ready insight for this service."
            ),
        },
        {
            "kind": "configure_adapter",
            "title": "Configure Radarr API",
            "detail": "Provide Radarr API Key to enable deep inspection for this service.",
        },
    ]

    assert configured_detail.status_code == 200
    configured_payload = configured_detail.json()
    assert (
        configured_payload["insight_section"]["adapters"][0]["configuration_state"]
        == "configured"
    )
    assert configured_payload["insight_section"]["adapters"][0]["missing_credentials"] == []
    assert configured_payload["insight_section"]["adapters"][0]["health_state"] == "unknown"
    assert configured_payload["insight_section"]["improve_actions"] == [
        {
            "kind": "configure_local_model",
            "title": "Configure a local model",
            "detail": (
                "Add a local investigation model endpoint to unlock "
                "investigation-ready insight for this service."
            ),
        }
    ]

    assert locked_detail.status_code == 200
    locked_payload = locked_detail.json()
    assert locked_payload["insight_section"]["adapters"][0]["configuration_state"] == "locked"
    assert locked_payload["insight_section"]["adapters"][0]["health_summary"] == (
        "Unlock the vault before adapter diagnostics can evaluate health."
    )
    assert locked_payload["insight_section"]["improve_actions"] == [
        {
            "kind": "configure_local_model",
            "title": "Configure a local model",
            "detail": (
                "Add a local investigation model endpoint to unlock "
                "investigation-ready insight for this service."
            ),
        },
        {
            "kind": "unlock_vault",
            "title": "Unlock the credential vault",
            "detail": (
                "Unlock the vault so Radarr API can use stored deep-inspection "
                "credentials."
            ),
        },
    ]
    assert "radarr-secret-value" not in locked_detail.text


def test_service_check_suppression_route_updates_service_detail_monitoring_and_audit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Per-service suppression should be visible in service detail and audit history."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        initial_detail = client.get("/api/v1/services/svc-delugevpn/detail")
        suppress_response = client.put(
            "/api/v1/services/svc-delugevpn/checks/endpoint_probe/suppression",
            json={"suppressed": True},
        )
        monitoring_response = client.get("/api/v1/settings/monitoring")
        unsuppress_response = client.put(
            "/api/v1/services/svc-delugevpn/checks/endpoint_probe/suppression",
            json={"suppressed": False},
        )
        changes_response = client.get("/api/v1/changes")

    assert initial_detail.status_code == 200
    initial_check = next(
        item
        for item in initial_detail.json()["monitoring_section"]["checks"]
        if item["check_id"] == "endpoint_probe"
    )
    assert initial_check["suppressed"] is False
    assert initial_check["effective_enabled"] is True
    assert initial_check["source"] == "global_default"

    assert suppress_response.status_code == 200
    suppress_payload = suppress_response.json()
    suppressed_check = next(
        item
        for item in suppress_payload["detail"]["monitoring_section"]["checks"]
        if item["check_id"] == "endpoint_probe"
    )
    assert suppressed_check["suppressed"] is True
    assert suppressed_check["effective_enabled"] is False
    assert suppressed_check["source"] == "service_override"
    assert suppressed_check["override_enabled"] is False
    assert suppress_payload["audit_change"]["type"] == "config_change"
    assert suppress_payload["audit_change"]["service_id"] == "svc-delugevpn"
    assert "Endpoint probe" in suppress_payload["audit_change"]["description"]

    assert monitoring_response.status_code == 200
    monitoring_payload = monitoring_response.json()
    assert any(
        item["service_id"] == "svc-delugevpn"
        and item["check_id"] == "endpoint_probe"
        and item["enabled"] is False
        for item in monitoring_payload["active"]["service_overrides"]
    )
    assert any(
        item["service_id"] == "svc-delugevpn"
        and item["check_id"] == "endpoint_probe"
        and item["enabled"] is False
        for item in monitoring_payload["staged"]["service_overrides"]
    )

    assert unsuppress_response.status_code == 200
    unsuppress_payload = unsuppress_response.json()
    restored_check = next(
        item
        for item in unsuppress_payload["detail"]["monitoring_section"]["checks"]
        if item["check_id"] == "endpoint_probe"
    )
    assert restored_check["suppressed"] is False
    assert restored_check["effective_enabled"] is True
    assert restored_check["source"] == "global_default"
    assert restored_check["override_enabled"] is None

    change_ids = {item["id"] for item in changes_response.json()}
    assert suppress_payload["audit_change"]["id"] in change_ids
    assert unsuppress_payload["audit_change"]["id"] in change_ids


def test_service_check_suppression_route_rejects_explicit_enabled_service_override(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Service-detail suppression should not trample explicit enabled overrides."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
    )

    with TestClient(app) as client:
        client.put(
            "/api/v1/settings/monitoring",
            json=build_monitoring_settings_payload(
                tls_cert_enabled=False,
                service_overrides=[
                    {
                        "service_id": "svc-delugevpn",
                        "check_id": "endpoint_probe",
                        "enabled": True,
                        "interval_seconds": 45,
                    }
                ],
            ),
        )
        client.post("/api/v1/settings/monitoring/apply")
        response = client.put(
            "/api/v1/services/svc-delugevpn/checks/endpoint_probe/suppression",
            json={"suppressed": True},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": (
            "service check has an explicit enabled override; edit monitoring settings instead"
        )
    }


def test_service_descriptor_view_endpoint_returns_rendered_descriptor_sections(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Descriptor view should expose a structured rendered descriptor payload."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/services/svc-radarr/descriptor")

    assert response.status_code == 200
    payload = response.json()
    assert payload["descriptor_id"] == "arr/radarr"
    assert payload["file_path"].endswith("services/arr/radarr.yaml")
    assert payload["source"] == "shipped"
    assert payload["verified"] is True
    assert payload["generated_at"] is None
    assert payload["match"]["image_patterns"][:2] == [
        "lscr.io/linuxserver/radarr*",
        "hotio/radarr*",
    ]
    assert payload["endpoints"][0]["name"] == "health_api"
    assert payload["typical_dependency_containers"][0] == {
        "name": "prowlarr",
        "alternatives": [],
    }
    assert payload["credential_hints"] == [
        {
            "key": "api_key",
            "description": "Radarr API Key",
            "location": "Radarr Web UI -> Settings -> General -> API Key",
            "prompt": "Provide the Radarr API key to enable deep inspection.",
        }
    ]
    assert any(
        surface["id"] == "health_api"
        and surface["confidence_effect"] == "upgrade_to_runtime_observed"
        for surface in payload["inspection_surfaces"]
    )


def test_service_descriptor_view_endpoint_returns_404_for_unmatched_service(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Descriptor view should reject services without a matched descriptor."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/services/svc-downloads-share/descriptor")

    assert response.status_code == 404
    assert response.json() == {"detail": "descriptor not found"}


def test_service_descriptor_save_endpoint_writes_user_override_without_mutating_shipped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Descriptor saves should land in services/user and immediately become active."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    original_shipped_descriptor = (services_dir / "arr" / "radarr.yaml").read_text(
        encoding="utf-8"
    )
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        response = client.put(
            "/api/v1/services/svc-radarr/descriptor",
            json={
                "mode": "form",
                "match": {
                    "image_patterns": [
                        "lscr.io/linuxserver/radarr*",
                        "hotio/radarr*",
                        "custom/radarr*",
                    ],
                    "container_name_patterns": [],
                },
                "endpoints": [
                    {
                        "name": "health_api",
                        "port": 7878,
                        "path": "/ping",
                        "auth": "api_key",
                        "auth_header": "X-Api-Key",
                        "healthy_when": "status_ok",
                    }
                ],
                "typical_dependency_containers": [
                    {
                        "name": "prowlarr",
                        "alternatives": [],
                    },
                    {
                        "name": "delugevpn",
                        "alternatives": ["qbittorrent"],
                    },
                ],
                "typical_dependency_shares": ["data", "downloads"],
            },
        )
        detail_response = client.get("/api/v1/services/svc-radarr/detail")
        descriptor_response = client.get("/api/v1/services/svc-radarr/descriptor")

    assert response.status_code == 200
    payload = response.json()
    assert payload["descriptor"]["source"] == "user"
    assert payload["descriptor"]["file_path"].endswith("services/user/arr/radarr.yaml")
    assert payload["descriptor"]["write_target_path"].endswith("services/user/arr/radarr.yaml")
    assert payload["descriptor"]["raw_yaml"].find("custom/radarr*") != -1
    assert payload["audit_change"]["type"] == "config_change"
    assert payload["audit_change"]["new_value"].endswith("services/user/arr/radarr.yaml")

    assert detail_response.status_code == 200
    assert detail_response.json()["service"]["descriptor_source"] == "user"

    assert descriptor_response.status_code == 200
    assert descriptor_response.json()["source"] == "user"

    saved_override = (services_dir / "user" / "arr" / "radarr.yaml").read_text(
        encoding="utf-8"
    )
    shipped_descriptor = (services_dir / "arr" / "radarr.yaml").read_text(encoding="utf-8")
    assert "source: user" in saved_override
    assert "custom/radarr*" in saved_override
    assert shipped_descriptor == original_shipped_descriptor


def test_service_descriptor_save_endpoint_rejects_yaml_identity_changes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Advanced YAML edits must stay bound to the current descriptor identity."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        initial_descriptor = client.get("/api/v1/services/svc-radarr/descriptor")
        response = client.put(
            "/api/v1/services/svc-radarr/descriptor",
            json={
                "mode": "yaml",
                "raw_yaml": initial_descriptor.json()["raw_yaml"].replace(
                    "id: radarr",
                    "id: radarr_override",
                    1,
                ),
            },
        )

    assert initial_descriptor.status_code == 200
    assert response.status_code == 400
    assert response.json() == {"detail": "descriptor id cannot change during edit mode"}


def test_service_descriptor_validate_endpoint_returns_preview_and_warnings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Validation should preview bounded match and dependency impact before save."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        response = client.put(
            "/api/v1/services/svc-radarr/descriptor/validate",
            json={
                "mode": "form",
                "match": {
                    "image_patterns": ["custom/radarr*"],
                    "container_name_patterns": [],
                },
                "endpoints": [
                    {
                        "name": "health_api",
                        "port": 7878,
                        "path": "/ping",
                        "auth": "api_key",
                        "auth_header": "X-Api-Key",
                        "healthy_when": "status_ok",
                    }
                ],
                "typical_dependency_containers": [
                    {
                        "name": "prowlarr",
                        "alternatives": [],
                    }
                ],
                "typical_dependency_shares": ["downloads"],
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is True
    assert payload["errors"] == []
    assert payload["preview"]["descriptor_id"] == "arr/radarr"
    assert payload["preview"]["write_target_path"].endswith("services/user/arr/radarr.yaml")
    assert payload["preview"]["match"]["current_service_likely_matches"] is False
    assert payload["preview"]["dependency_impact"]["removed_container_dependencies"] == [
        "delugevpn"
    ]
    assert payload["preview"]["dependency_impact"]["removed_share_dependencies"] == ["media"]
    assert any(
        "leave the shipped descriptor unchanged" in warning
        for warning in payload["warnings"]
    )
    assert any("no longer appears to match" in warning for warning in payload["warnings"])


def test_service_descriptor_validate_endpoint_returns_understandable_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Validation should report schema or policy failures without saving."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        response = client.put(
            "/api/v1/services/svc-radarr/descriptor/validate",
            json={
                "mode": "form",
                "match": {
                    "image_patterns": [],
                    "container_name_patterns": [],
                },
                "endpoints": [],
                "typical_dependency_containers": [],
                "typical_dependency_shares": [],
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "valid": False,
        "errors": [
            "descriptor validation failed: descriptor match rules require at least one pattern"
        ],
        "warnings": [],
        "preview": None,
    }


def test_auto_generate_service_descriptor_endpoint_writes_quarantined_candidate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Auto-generation should persist a quarantined candidate without activating it."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:8b")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)

    def transport(http_request, timeout_seconds):
        del http_request, timeout_seconds
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "id": "custom_app",
                                    "name": "Custom App",
                                    "category": "custom",
                                    "project_url": "https://example.test/custom-app",
                                    "icon": "custom-app.svg",
                                    "match": {
                                        "image_patterns": ["ghcr.io/example/custom-app*"],
                                        "container_name_patterns": ["custom-app"],
                                    },
                                    "endpoints": {
                                        "web_ui": {
                                            "port": 8080,
                                            "path": "/",
                                        }
                                    },
                                    "dns_targets": [],
                                    "log_signals": {"errors": [], "warnings": []},
                                    "typical_dependencies": {
                                        "containers": ["postgres"],
                                        "shares": ["media"],
                                    },
                                    "common_failure_modes": [],
                                    "investigation_context": (
                                        "Custom App exposes a web UI on port 8080."
                                    ),
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        services_dir=services_dir,
        local_model_transport=transport,
    )

    with TestClient(app) as client:
        response = client.post("/api/v1/services/svc-custom-app/descriptor/auto-generate")
        services_response = client.get("/api/v1/services")
        changes_response = client.get("/api/v1/changes")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service_id"] == "svc-custom-app"
    assert payload["descriptor"]["descriptor_id"] == "custom/custom_app"
    assert payload["descriptor"]["source"] == "auto_generated"
    assert payload["descriptor"]["verified"] is False
    assert payload["descriptor"]["generated_at"] is not None
    assert payload["descriptor"]["file_path"].endswith(
        "services/auto_generated/custom/custom_app.yaml"
    )
    assert payload["audit_change"]["type"] == "config_change"
    assert any(
        "inactive until review and promotion" in warning
        for warning in payload["warnings"]
    )

    descriptor_path = services_dir / "auto_generated" / "custom" / "custom_app.yaml"
    assert descriptor_path.exists()
    descriptor_text = descriptor_path.read_text(encoding="utf-8")
    assert "source: auto_generated" in descriptor_text
    assert "verified: false" in descriptor_text
    assert "generated_at:" in descriptor_text

    active_descriptor_ids = {
        loaded_descriptor_identifier(item)
        for item in load_service_descriptors([services_dir])
    }
    assert "custom/custom_app" not in active_descriptor_ids

    services_payload = services_response.json()
    generated_service = next(
        item for item in services_payload if item["id"] == "svc-custom-app"
    )
    assert generated_service["descriptor_id"] is None
    assert generated_service["descriptor_source"] is None

    changes_payload = changes_response.json()
    assert any(
        change["description"].startswith(
            "Generated quarantined descriptor candidate custom/custom_app"
        )
        for change in changes_payload
    )


def test_auto_generate_service_descriptor_endpoint_requires_local_model(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Auto-generation should fail cleanly when the local model path is unavailable."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        response = client.post("/api/v1/services/svc-custom-app/descriptor/auto-generate")

    assert response.status_code == 409
    assert response.json() == {
        "detail": "local model is not configured for descriptor generation"
    }
    assert not (services_dir / "auto_generated" / "custom" / "custom_app.yaml").exists()


def test_auto_generated_descriptor_queue_supports_defer_edit_and_promote(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The review queue should expose auditable defer, edit, and promote actions."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:8b")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)

    def transport(http_request, timeout_seconds):
        del http_request, timeout_seconds
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "id": "custom_app",
                                    "name": "Custom App",
                                    "category": "custom",
                                    "match": {
                                        "image_patterns": ["ghcr.io/example/custom-app*"],
                                        "container_name_patterns": ["custom-app"],
                                    },
                                    "endpoints": {
                                        "web_ui": {
                                            "port": 8080,
                                            "path": "/",
                                        }
                                    },
                                    "dns_targets": [],
                                    "log_signals": {"errors": [], "warnings": []},
                                    "typical_dependencies": {
                                        "containers": [],
                                        "shares": [],
                                    },
                                    "common_failure_modes": [],
                                    "investigation_context": "Custom App candidate",
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        services_dir=services_dir,
        local_model_transport=transport,
    )

    with TestClient(app) as client:
        generate_response = client.post(
            "/api/v1/services/svc-custom-app/descriptor/auto-generate"
        )
        queue_response = client.get("/api/v1/descriptors/auto-generated")
        defer_response = client.post(
            "/api/v1/descriptors/auto-generated/custom/custom_app/defer"
        )
        edit_response = client.put(
            "/api/v1/descriptors/auto-generated/custom/custom_app",
            json={
                "mode": "yaml",
                "raw_yaml": (
                    "id: custom_app\n"
                    "name: Custom App Reviewed\n"
                    "category: custom\n"
                    "match:\n"
                    "  image_patterns:\n"
                    "    - ghcr.io/example/custom-app*\n"
                    "  container_name_patterns:\n"
                    "    - custom-app\n"
                    "endpoints:\n"
                    "  web_ui:\n"
                    "    port: 8080\n"
                    "    path: /\n"
                    "log_signals:\n"
                    "  errors: []\n"
                    "  warnings: []\n"
                    "typical_dependencies:\n"
                    "  containers: []\n"
                    "  shares: []\n"
                    "source: auto_generated\n"
                    "verified: false\n"
                    "generated_at: 2026-04-08T09:30:00Z\n"
                ),
            },
        )
        promote_response = client.post(
            "/api/v1/descriptors/auto-generated/custom/custom_app/promote"
        )
        final_queue_response = client.get("/api/v1/descriptors/auto-generated")
        changes_response = client.get("/api/v1/changes")

    assert generate_response.status_code == 200

    assert queue_response.status_code == 200
    queue_payload = queue_response.json()
    assert len(queue_payload) == 1
    assert queue_payload[0]["review_state"] == "pending"
    assert [service["id"] for service in queue_payload[0]["matching_services"]] == [
        "svc-custom-app"
    ]

    assert defer_response.status_code == 200
    assert defer_response.json()["review_state"] == "deferred"

    assert edit_response.status_code == 200
    assert edit_response.json()["action"] == "edited"
    assert edit_response.json()["review_state"] == "pending"
    assert edit_response.json()["descriptor"]["name"] == "Custom App Reviewed"
    assert (
        edit_response.json()["descriptor"]["source"] == "auto_generated"
    )

    assert promote_response.status_code == 200
    assert promote_response.json()["action"] == "promoted"
    assert promote_response.json()["descriptor"]["source"] == "user"
    assert promote_response.json()["descriptor"]["verified"] is True
    assert promote_response.json()["descriptor"]["file_path"].endswith(
        "services/user/custom/custom_app.yaml"
    )

    assert final_queue_response.status_code == 200
    assert final_queue_response.json() == []
    assert not (services_dir / "auto_generated" / "custom" / "custom_app.yaml").exists()
    assert (services_dir / "user" / "custom" / "custom_app.yaml").exists()

    change_descriptions = [change["description"] for change in changes_response.json()]
    assert any(
        description.startswith(
            "Deferred review for quarantined descriptor candidate custom/custom_app."
        )
        for description in change_descriptions
    )
    assert any(
        description.startswith("Edited quarantined descriptor candidate custom/custom_app.")
        for description in change_descriptions
    )
    assert any(
        description.startswith(
            "Promoted quarantined descriptor candidate custom/custom_app"
        )
        for description in change_descriptions
    )


def test_auto_generated_descriptor_queue_supports_dismiss(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Dismiss should remove the candidate from the queue and leave the service unmatched."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:8b")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)

    def transport(http_request, timeout_seconds):
        del http_request, timeout_seconds
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "id": "custom_app",
                                    "name": "Custom App",
                                    "category": "custom",
                                    "match": {
                                        "image_patterns": ["ghcr.io/example/custom-app*"],
                                        "container_name_patterns": ["custom-app"],
                                    },
                                    "endpoints": {},
                                    "dns_targets": [],
                                    "log_signals": {"errors": [], "warnings": []},
                                    "typical_dependencies": {
                                        "containers": [],
                                        "shares": [],
                                    },
                                    "common_failure_modes": [],
                                    "investigation_context": None,
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        services_dir=services_dir,
        local_model_transport=transport,
    )

    with TestClient(app) as client:
        client.post("/api/v1/services/svc-custom-app/descriptor/auto-generate")
        dismiss_response = client.post(
            "/api/v1/descriptors/auto-generated/custom/custom_app/dismiss"
        )
        queue_response = client.get("/api/v1/descriptors/auto-generated")
        services_response = client.get("/api/v1/services")

    assert dismiss_response.status_code == 200
    assert dismiss_response.json()["action"] == "dismissed"
    assert queue_response.status_code == 200
    assert queue_response.json() == []
    assert not (services_dir / "auto_generated" / "custom" / "custom_app.yaml").exists()
    service_payload = next(
        item for item in services_response.json() if item["id"] == "svc-custom-app"
    )
    assert service_payload["descriptor_id"] is None
    assert service_payload["descriptor_source"] is None


def test_promoted_auto_generated_descriptor_supports_community_export(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Community export should sanitize promoted auto-generated descriptor YAML."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:8b")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)

    def transport(http_request, timeout_seconds):
        del http_request, timeout_seconds
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "id": "custom_app",
                                    "name": "Custom App",
                                    "category": "custom",
                                    "match": {
                                        "image_patterns": ["ghcr.io/example/custom-app*"],
                                        "container_name_patterns": ["custom-app"],
                                    },
                                    "endpoints": {
                                        "web_ui": {
                                            "port": 8080,
                                            "path": "/",
                                        }
                                    },
                                    "dns_targets": [],
                                    "log_signals": {"errors": [], "warnings": []},
                                    "typical_dependencies": {
                                        "containers": [],
                                        "shares": [],
                                    },
                                    "common_failure_modes": [],
                                    "investigation_context": "Custom App candidate",
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        services_dir=services_dir,
        local_model_transport=transport,
    )

    with TestClient(app) as client:
        client.post("/api/v1/services/svc-custom-app/descriptor/auto-generate")
        promote_response = client.post(
            "/api/v1/descriptors/auto-generated/custom/custom_app/promote"
        )
        export_response = client.get(
            "/api/v1/descriptors/user/custom/custom_app/community-export"
        )

    assert promote_response.status_code == 200
    assert export_response.status_code == 200
    payload = export_response.json()
    assert payload["descriptor_id"] == "custom/custom_app"
    assert payload["target_path"] == "services/custom/custom_app.yaml"
    assert payload["omitted_fields"] == ["source", "verified", "generated_at"]
    assert "id: custom_app" in payload["yaml_text"]
    assert "name: Custom App" in payload["yaml_text"]
    assert "source:" not in payload["yaml_text"]
    assert "verified:" not in payload["yaml_text"]
    assert "generated_at:" not in payload["yaml_text"]


def test_community_export_rejects_user_descriptors_without_auto_generated_provenance(
    tmp_path: Path,
) -> None:
    """Community export should stay scoped to promoted auto-generated descriptors."""
    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    radarr_descriptor = next(
        item
        for item in load_service_descriptors([services_dir])
        if loaded_descriptor_identifier(item) == "arr/radarr"
    )
    write_user_descriptor(
        services_dir=services_dir,
        descriptor=radarr_descriptor.descriptor.model_copy(
            update={
                "source": DescriptorSource.USER,
                "verified": True,
            }
        ),
    )
    app = create_app(database_path=database_path, services_dir=services_dir)

    with TestClient(app) as client:
        response = client.get("/api/v1/descriptors/user/arr/radarr/community-export")

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "only promoted auto-generated descriptors can be exported through this path"
    )


def test_capability_health_endpoint_reports_missing_runtime_layers_as_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Capability health should not guess missing runtime telemetry as healthy."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/capability-health")

    assert response.status_code == 200
    payload = response.json()
    layers = {layer["layer"]: layer for layer in payload["layers"]}
    assert layers["discovery_pipeline"]["display_state"] == "unavailable"
    assert layers["check_scheduler"]["display_state"] == "unavailable"
    assert layers["executor_process"]["display_state"] == "unavailable"


def test_capability_health_endpoint_uses_persisted_runtime_signals(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Capability health should expose runtime-backed healthy and stale states."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    monkeypatch.setattr(api_app_module, "probe_unix_socket", lambda _: True)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    seed_capability_runtime_signals(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/capability-health")

    assert response.status_code == 200
    payload = response.json()
    layers = {layer["layer"]: layer for layer in payload["layers"]}
    assert payload["overall_status"] == "degraded"
    assert layers["discovery_pipeline"]["display_state"] == "healthy"
    assert layers["check_scheduler"]["display_state"] == "stale"
    assert layers["executor_process"]["display_state"] == "healthy"
    assert layers["executor_process"]["summary"] == "Executor process is healthy."


def test_model_settings_api_stages_applies_and_tests_local_model(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Model settings should persist staged changes, require apply, and drive runtime insight."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)

    def local_transport(http_request, timeout_seconds):
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        assert timeout_seconds == 12.0
        assert http_request.full_url == "http://localhost:11434/v1/chat/completions"
        assert body["messages"][1]["content"] == '{"connection_ok": true}'
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"connection_ok": true}',
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        local_model_transport=local_transport,
    )

    with TestClient(app) as client:
        unlock_response = client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        initial_settings = client.get("/api/v1/settings/models")
        save_response = client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(
                local_enabled=True,
                local_model="qwen3:14b",
                local_api_key="local-secret",
            ),
        )
        services_before_apply = client.get("/api/v1/services")
        apply_response = client.post("/api/v1/settings/models/apply")
        services_after_apply = client.get("/api/v1/services")
        capability_response = client.get("/api/v1/capability-health")
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "local", "scope": "active"},
        )

    assert unlock_response.status_code == 200
    assert initial_settings.status_code == 200
    assert initial_settings.json()["active"]["local"]["configured"] is False

    assert save_response.status_code == 200
    save_payload = save_response.json()
    assert save_payload["settings"]["apply_required"] is True
    assert save_payload["settings"]["active"]["local"]["configured"] is False
    assert save_payload["settings"]["staged"]["local"]["configured"] is True
    assert save_payload["settings"]["staged"]["local"]["api_key_source"] == "vault"
    assert "local-secret" not in json.dumps(save_payload)

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "local-secret" not in persisted_text
    assert "api_key_ref: vault:settings:models:local_api_key" in persisted_text

    assert services_before_apply.status_code == 200
    assert services_before_apply.json()[0]["insight"] == {"level": 2}

    assert apply_response.status_code == 200
    apply_payload = apply_response.json()
    assert apply_payload["settings"]["apply_required"] is False
    assert apply_payload["settings"]["active"]["local"]["configured"] is True

    assert services_after_apply.status_code == 200
    assert services_after_apply.json()[0]["insight"] == {"level": 3}

    assert capability_response.status_code == 200
    capability_layers = {
        layer["layer"]: layer for layer in capability_response.json()["layers"]
    }
    assert capability_layers["local_model"]["display_state"] == "unavailable"
    assert capability_layers["local_model"]["summary"] == "Local model health is unavailable."

    assert test_response.status_code == 200
    assert test_response.json() == {
        "target": "local",
        "scope": "active",
        "ok": True,
        "checked_at": test_response.json()["checked_at"],
        "message": "Local model endpoint accepted the explicit settings test.",
    }


def test_model_settings_api_supports_staged_cloud_connection_tests(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Cloud model settings should support explicit staged testing before apply."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)

    def cloud_transport(http_request, timeout_seconds):
        headers = {key.lower(): value for key, value in http_request.header_items()}
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        assert timeout_seconds == 25.0
        assert http_request.full_url == "https://api.anthropic.com/v1/messages"
        assert headers["x-api-key"] == "cloud-secret"
        assert body["system"] == "Return JSON only."
        assert body["messages"] == [{"role": "user", "content": '{"connection_ok": true}'}]
        return json.dumps(
            {
                "content": [
                    {
                        "type": "text",
                        "text": '{"connection_ok": true}',
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        cloud_model_transport=cloud_transport,
    )

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        save_response = client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(
                local_enabled=False,
                local_model=None,
                cloud_enabled=True,
                cloud_provider="anthropic",
                cloud_model="claude-sonnet-4-20250514",
                cloud_api_key="cloud-secret",
            ),
        )
        staged_test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "staged"},
        )
        active_test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "active"},
        )
        settings_response = client.get("/api/v1/settings/models")

    assert save_response.status_code == 200
    assert staged_test_response.status_code == 200
    assert staged_test_response.json()["ok"] is True
    assert (
        staged_test_response.json()["message"]
        == "Cloud model endpoint accepted the explicit settings test."
    )
    assert active_test_response.status_code == 200
    assert active_test_response.json()["ok"] is False
    assert (
        active_test_response.json()["message"]
        == "Selected cloud model settings are not configured."
    )
    assert settings_response.status_code == 200
    settings_payload = settings_response.json()
    assert settings_payload["active"]["cloud"]["configured"] is False
    assert settings_payload["staged"]["cloud"]["configured"] is True
    assert settings_payload["staged"]["cloud"]["api_key_source"] == "vault"
    assert "cloud-secret" not in json.dumps(settings_payload)


def test_notification_settings_api_stages_applies_and_tests_channels(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Notification settings should stage, explicitly test, and later apply channels."""
    monkeypatch.delenv("KAVAL_NOTIFICATION_URLS", raising=False)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    adapter = FakeAppriseAdapter()

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        notification_bus_adapter_factory=lambda: adapter,
    )

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        initial_settings = client.get("/api/v1/settings/notifications")
        save_response = client.put(
            "/api/v1/settings/notifications",
            json=build_notification_settings_payload(
                channels=[
                    {
                        "id": None,
                        "name": "Primary Discord",
                        "enabled": True,
                        "destination": "discord://tokenA/tokenB",
                    }
                ]
            ),
        )
        capability_before_apply = client.get("/api/v1/capability-health")
        staged_channel_id = save_response.json()["settings"]["staged"]["channels"][0]["id"]
        test_response = client.post(
            "/api/v1/settings/notifications/test",
            json={"channel_id": staged_channel_id, "scope": "staged"},
        )
        apply_response = client.post("/api/v1/settings/notifications/apply")
        capability_after_apply = client.get("/api/v1/capability-health")
        settings_response = client.get("/api/v1/settings/notifications")

    assert initial_settings.status_code == 200
    assert initial_settings.json()["active"]["configured_channel_count"] == 0

    assert save_response.status_code == 200
    save_payload = save_response.json()
    assert save_payload["settings"]["apply_required"] is True
    assert save_payload["settings"]["active"]["configured_channel_count"] == 0
    assert save_payload["settings"]["staged"]["configured_channel_count"] == 1
    assert save_payload["settings"]["staged"]["channels"][0]["destination_source"] == "vault"
    assert save_payload["settings"]["staged"]["quiet_hours"]["timezone"] == "UTC"
    assert "discord://tokenA/tokenB" not in json.dumps(save_payload)

    assert capability_before_apply.status_code == 200
    capability_before_layers = {
        layer["layer"]: layer for layer in capability_before_apply.json()["layers"]
    }
    assert capability_before_layers["notification_channels"]["display_state"] == "disabled"

    assert test_response.status_code == 200
    assert test_response.json()["ok"] is True
    assert (
        test_response.json()["message"]
        == "Explicit notification channel test delivered successfully."
    )
    assert adapter.added_urls == ["discord://tokenA/tokenB"]
    assert adapter.notifications[0]["title"] == "Kaval notification settings test"

    assert apply_response.status_code == 200
    apply_payload = apply_response.json()
    assert apply_payload["settings"]["apply_required"] is False
    assert apply_payload["settings"]["active"]["configured_channel_count"] == 1

    assert capability_after_apply.status_code == 200
    capability_after_layers = {
        layer["layer"]: layer for layer in capability_after_apply.json()["layers"]
    }
    assert capability_after_layers["notification_channels"]["display_state"] == "unavailable"
    assert (
        capability_after_layers["notification_channels"]["summary"]
        == "Notification channel health is unavailable."
    )

    assert settings_response.status_code == 200
    assert settings_response.json()["active"]["channels"][0]["name"] == "Primary Discord"


def test_monitoring_settings_api_stages_applies_and_reports_effective_intervals(
    tmp_path: Path,
) -> None:
    """Monitoring settings should stage and apply global plus service-scoped cadence changes."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
    )

    with TestClient(app) as client:
        initial_settings = client.get("/api/v1/settings/monitoring")
        save_response = client.put(
            "/api/v1/settings/monitoring",
            json=build_monitoring_settings_payload(
                endpoint_probe_interval=240,
                endpoint_probe_timeout_seconds=7.5,
                restart_delta_threshold=5,
                tls_cert_enabled=False,
                tls_warning_days=14,
                service_overrides=[
                    {
                        "service_id": "svc-delugevpn",
                        "check_id": "endpoint_probe",
                        "enabled": True,
                        "interval_seconds": 45,
                        "probe_timeout_seconds": 2.5,
                    },
                    {
                        "service_id": "svc-delugevpn",
                        "check_id": "restart_storm",
                        "enabled": None,
                        "interval_seconds": None,
                        "restart_delta_threshold": 6,
                    },
                ],
            ),
        )
        apply_response = client.post("/api/v1/settings/monitoring/apply")
        settings_response = client.get("/api/v1/settings/monitoring")

    assert initial_settings.status_code == 200
    initial_payload = initial_settings.json()
    assert initial_payload["apply_required"] is False
    assert initial_payload["active"]["checks"][2] == {
        "check_id": "endpoint_probe",
        "label": "Endpoint probe",
        "description": (
            "Probe declared HTTP and HTTPS endpoints that do not require auth."
        ),
        "enabled": True,
        "interval_seconds": 120,
        "tls_warning_days": None,
        "restart_delta_threshold": None,
        "probe_timeout_seconds": 5.0,
        "default_enabled": True,
        "default_interval_seconds": 120,
        "default_tls_warning_days": None,
        "default_restart_delta_threshold": None,
        "default_probe_timeout_seconds": 5.0,
    }
    assert initial_payload["active"]["checks"][1]["restart_delta_threshold"] == 3
    assert initial_payload["active"]["checks"][4]["tls_warning_days"] == 7

    assert save_response.status_code == 200
    save_payload = save_response.json()
    assert save_payload["settings"]["apply_required"] is True
    assert save_payload["settings"]["active"]["checks"][2]["interval_seconds"] == 120
    assert save_payload["settings"]["staged"]["checks"][2]["interval_seconds"] == 240
    assert save_payload["settings"]["staged"]["checks"][2]["probe_timeout_seconds"] == 7.5
    assert save_payload["settings"]["staged"]["checks"][1]["restart_delta_threshold"] == 5
    assert save_payload["settings"]["staged"]["checks"][4]["enabled"] is False
    assert save_payload["settings"]["staged"]["checks"][4]["tls_warning_days"] == 14
    assert save_payload["settings"]["staged"]["service_overrides"][0]["service_id"] == (
        "svc-delugevpn"
    )
    assert (
        save_payload["settings"]["staged"]["service_overrides"][0][
            "probe_timeout_seconds"
        ]
        == 2.5
    )
    staged_delugevpn = next(
        item
        for item in save_payload["settings"]["staged"]["effective_services"]
        if item["service_id"] == "svc-delugevpn"
    )
    staged_endpoint_probe = next(
        item for item in staged_delugevpn["checks"] if item["check_id"] == "endpoint_probe"
    )
    staged_restart_storm = next(
        item for item in staged_delugevpn["checks"] if item["check_id"] == "restart_storm"
    )
    assert staged_endpoint_probe["enabled"] is True
    assert staged_endpoint_probe["base_interval_seconds"] == 45
    assert staged_endpoint_probe["effective_interval_seconds"] == 45
    assert staged_endpoint_probe["source"] == "service_override"
    assert staged_endpoint_probe["probe_timeout_seconds"] == 2.5
    assert staged_endpoint_probe["threshold_source"] == "service_override"
    assert staged_restart_storm["restart_delta_threshold"] == 6
    assert staged_restart_storm["threshold_source"] == "service_override"

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "monitoring:" in persisted_text
    assert "check_id: endpoint_probe" in persisted_text
    assert "interval_seconds: 240" in persisted_text
    assert "probe_timeout_seconds: 7.5" in persisted_text
    assert "tls_warning_days: 14" in persisted_text

    assert apply_response.status_code == 200
    apply_payload = apply_response.json()
    assert apply_payload["settings"]["apply_required"] is False
    active_delugevpn = next(
        item
        for item in apply_payload["settings"]["active"]["effective_services"]
        if item["service_id"] == "svc-delugevpn"
    )
    active_endpoint_probe = next(
        item for item in active_delugevpn["checks"] if item["check_id"] == "endpoint_probe"
    )
    active_restart_storm = next(
        item for item in active_delugevpn["checks"] if item["check_id"] == "restart_storm"
    )
    assert active_endpoint_probe["effective_interval_seconds"] == 45
    assert active_endpoint_probe["probe_timeout_seconds"] == 2.5
    assert active_restart_storm["restart_delta_threshold"] == 6

    assert settings_response.status_code == 200
    active_override_checks = {
        item["check_id"] for item in settings_response.json()["active"]["service_overrides"]
    }
    assert active_override_checks == {"endpoint_probe", "restart_storm"}


def test_findings_review_endpoint_surfaces_repeated_dismissal_suggestions(
    tmp_path: Path,
) -> None:
    """Repeated dismissals should surface advisory suppression or threshold suggestions."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        for index in range(5):
            dismissed_at = ts(12, 10 + index)
            dismissed_finding = build_endpoint_probe_finding(
                finding_id=f"find-endpoint-dismissed-{index}",
                status=FindingStatus.DISMISSED,
                created_at=ts(12, 5 + index),
                resolved_at=dismissed_at,
                incident_id=None,
            )
            database.upsert_finding(dismissed_finding)
            database.upsert_finding_feedback_record(
                FindingFeedbackRecord(
                    id=f"ffb-endpoint-{index}",
                    finding_id=dismissed_finding.id,
                    service_id=dismissed_finding.service_id,
                    finding_domain=dismissed_finding.domain,
                    reason=FindingFeedbackReason.FALSE_POSITIVE,
                    recorded_at=dismissed_at,
                )
            )
        database.upsert_finding(
            build_endpoint_probe_finding(
                finding_id="find-endpoint-active",
                status=FindingStatus.GROUPED,
                created_at=ts(12, 30),
                resolved_at=None,
                incident_id="inc-1",
            )
        )
    finally:
        database.close()

    app = create_app(database_path=database_path)
    with TestClient(app) as client:
        response = client.get("/api/v1/findings/review")

    assert response.status_code == 200
    payload = response.json()
    assert payload["suggestions"] == [
        {
            "service_id": "svc-delugevpn",
            "service_name": "DelugeVPN",
            "check_id": "endpoint_probe",
            "check_label": "Endpoint probe",
            "dismissal_count": 5,
            "action": "adjust_threshold_or_suppress",
            "message": (
                "You've dismissed 5 endpoint probe findings for DelugeVPN. "
                "Consider adjusting the threshold or suppressing this check."
            ),
        }
    ]
    active_item = next(
        item
        for item in payload["active_findings"]
        if item["finding"]["id"] == "find-endpoint-active"
    )
    assert active_item["service_name"] == "DelugeVPN"
    assert active_item["domain_label"] == "Endpoint probe"
    assert active_item["dismissal_count_for_pattern"] == 5
    assert active_item["suggestion"]["action"] == "adjust_threshold_or_suppress"
    assert payload["recently_dismissed"][0]["dismissal_reason"] == "false_positive"


def test_dismiss_finding_endpoint_records_feedback_and_updates_incident_state(
    tmp_path: Path,
) -> None:
    """Explicit finding dismissal should persist feedback and dismiss orphaned incidents."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        dismiss_response = client.post(
            "/api/v1/findings/find-1/dismiss",
            json={"reason": "already_aware"},
        )
        incidents_response = client.get("/api/v1/incidents")
        changes_response = client.get("/api/v1/changes")

    assert dismiss_response.status_code == 200
    payload = dismiss_response.json()
    assert payload["finding"]["status"] == "dismissed"
    assert payload["finding"]["resolved_at"] is not None
    assert payload["review"]["active_findings"] == []
    assert payload["review"]["recently_dismissed"][0]["finding"]["id"] == "find-1"
    assert payload["review"]["recently_dismissed"][0]["dismissal_reason"] == "already_aware"
    assert payload["audit_change"]["type"] == "config_change"
    assert payload["audit_change"]["service_id"] == "svc-delugevpn"
    assert "reason=already_aware" in (payload["audit_change"]["new_value"] or "")

    assert incidents_response.status_code == 200
    assert incidents_response.json()[0]["status"] == "dismissed"

    assert changes_response.status_code == 200
    assert changes_response.json()[-1]["description"] == (
        "Dismissed finding 'Download client unavailable' as already aware."
    )


def test_maintenance_mode_api_sets_and_clears_global_and_service_windows(
    tmp_path: Path,
) -> None:
    """Maintenance mode should expose deterministic global and per-service operations."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        initial_response = client.get("/api/v1/maintenance")
        enable_global_response = client.put(
            "/api/v1/maintenance/global",
            json={"duration_minutes": 30},
        )
        enable_service_response = client.put(
            "/api/v1/services/svc-delugevpn/maintenance",
            json={"duration_minutes": 120},
        )
        current_response = client.get("/api/v1/maintenance")
        clear_global_response = client.delete("/api/v1/maintenance/global")
        clear_service_response = client.delete("/api/v1/services/svc-delugevpn/maintenance")

    assert initial_response.status_code == 200
    initial_payload = initial_response.json()
    assert initial_payload["global_window"] is None
    assert initial_payload["service_windows"] == []
    assert "critical Kaval self-health" in initial_payload["self_health_guardrail"]

    assert enable_global_response.status_code == 200
    enable_global_payload = enable_global_response.json()
    assert enable_global_payload["maintenance"]["global_window"]["scope"] == "global"
    assert enable_global_payload["maintenance"]["global_window"]["minutes_remaining"] == 30
    assert enable_global_payload["audit_change"]["description"] == (
        "Enabled global maintenance for 30 minutes."
    )

    assert enable_service_response.status_code == 200
    enable_service_payload = enable_service_response.json()
    assert enable_service_payload["maintenance"]["service_windows"] == [
        {
            "scope": "service",
            "service_id": "svc-delugevpn",
            "service_name": "DelugeVPN",
            "started_at": enable_service_payload["maintenance"]["service_windows"][0]["started_at"],
            "expires_at": enable_service_payload["maintenance"]["service_windows"][0]["expires_at"],
            "minutes_remaining": 120,
        }
    ]
    assert enable_service_payload["audit_change"]["service_id"] == "svc-delugevpn"

    assert current_response.status_code == 200
    current_payload = current_response.json()
    assert current_payload["global_window"]["minutes_remaining"] == 30
    assert current_payload["service_windows"][0]["service_id"] == "svc-delugevpn"

    assert clear_global_response.status_code == 200
    assert clear_global_response.json()["maintenance"]["global_window"] is None

    assert clear_service_response.status_code == 200
    assert clear_service_response.json()["maintenance"]["service_windows"] == []


def test_recommendations_endpoint_surfaces_ranked_real_state_actions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Recommendations should be derived from current state and ordered predictably."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_ENABLED", "true")
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:14b")
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_NAME", raising=False)

    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)
    add_stale_vault_credential(database_path)
    add_noisy_check_feedback(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/recommendations")

    assert response.status_code == 200
    payload = response.json()
    assert [item["kind"] for item in payload["items"]] == [
        "missing_descriptor",
        "stale_credential",
        "noisy_check",
        "cloud_model",
    ]
    assert payload["items"][0]["action"] == {
        "label": "Review custom-app",
        "target": "service_detail",
        "service_id": "svc-custom-app",
    }
    assert payload["items"][1]["action"]["target"] == "credential_vault"
    assert "DelugeVPN" in payload["items"][1]["detail"]
    assert payload["items"][2]["action"] == {
        "label": "Review noise controls",
        "target": "finding_review",
        "service_id": "svc-delugevpn",
    }
    assert payload["items"][3]["action"]["target"] == "model_settings"


def test_system_settings_api_stages_applies_and_reports_runtime_about_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """System settings should stage, apply, and expose bounded about/admin metadata."""
    monkeypatch.setenv("KAVAL_CORE_LOG_LEVEL", "warning")
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
    )

    with TestClient(app) as client:
        client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(
                local_enabled=True,
                local_model="qwen3:14b",
            ),
        )
        client.post("/api/v1/settings/models/apply")
        initial_settings = client.get("/api/v1/settings/system")
        save_response = client.put(
            "/api/v1/settings/system",
            json=build_system_settings_payload(
                log_level="debug",
                audit_detail_retention_days=120,
                audit_summary_retention_days=400,
            ),
        )
        apply_response = client.post("/api/v1/settings/system/apply")

    assert initial_settings.status_code == 200
    initial_payload = initial_settings.json()
    assert initial_payload["active"]["log_level"] == "warning"
    assert initial_payload["active"]["audit_detail_retention_days"] == 90
    assert initial_payload["active"]["audit_summary_retention_days"] == 365
    assert initial_payload["about"]["runtime_log_level"] == "warning"
    assert initial_payload["about"]["api_version"] == "0.1.0"
    assert initial_payload["about"]["model_status"]["local_model_configured"] is True
    assert initial_payload["database"]["quick_check_ok"] is True
    assert initial_payload["database"]["migrations_current"] is True
    assert "sensitive" in initial_payload["transfer_guidance"]["exports"][0]["warning"].casefold()
    assert initial_payload["transfer_guidance"]["exports"][0]["available"] is False
    assert initial_payload["transfer_guidance"]["imports"][0]["available"] is False

    assert save_response.status_code == 200
    save_payload = save_response.json()
    assert save_payload["settings"]["apply_required"] is True
    assert save_payload["settings"]["active"]["log_level"] == "warning"
    assert save_payload["settings"]["staged"]["log_level"] == "debug"
    assert save_payload["settings"]["staged"]["audit_detail_retention_days"] == 120
    assert save_payload["settings"]["staged"]["audit_summary_retention_days"] == 400
    assert save_payload["audit_change"]["type"] == "config_change"

    assert apply_response.status_code == 200
    apply_payload = apply_response.json()
    assert apply_payload["settings"]["apply_required"] is False
    assert apply_payload["settings"]["active"]["log_level"] == "debug"
    assert apply_payload["settings"]["active"]["audit_detail_retention_days"] == 120
    assert apply_payload["settings"]["active"]["audit_summary_retention_days"] == 400
    assert apply_payload["settings"]["about"]["runtime_log_level"] == "debug"
    assert app.state.runtime_log_level == "debug"

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "system:" in persisted_text
    assert "log_level: debug" in persisted_text
    assert "audit_detail_retention_days: 120" in persisted_text
    assert "audit_summary_retention_days: 400" in persisted_text


def test_changes_endpoint_respects_active_audit_summary_retention(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The changes endpoint should hide events older than the active summary window."""
    monkeypatch.setattr(api_app_module, "datetime", FrozenApiDateTime)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    database = KavalDatabase(database_path)
    database.upsert_change(
        Change(
            id="chg-old",
            type=ChangeType.CONFIG_CHANGE,
            service_id=None,
            description="Saved staged system settings via /data/kaval.yaml.",
            old_value="log_level=info",
            new_value="log_level=debug",
            timestamp=datetime(2026, 2, 1, 8, 0, tzinfo=UTC),
            correlated_incidents=[],
        )
    )
    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
    )

    with TestClient(app) as client:
        initial_response = client.get("/api/v1/changes")
        client.put(
            "/api/v1/settings/system",
            json=build_system_settings_payload(
                log_level="info",
                audit_detail_retention_days=7,
                audit_summary_retention_days=30,
            ),
        )
        client.post("/api/v1/settings/system/apply")
        retained_response = client.get("/api/v1/changes")

    assert initial_response.status_code == 200
    assert "chg-old" in {change["id"] for change in initial_response.json()}

    assert retained_response.status_code == 200
    retained_ids = {change["id"] for change in retained_response.json()}
    assert "chg-1" in retained_ids
    assert "chg-old" not in retained_ids


def test_effectiveness_endpoint_reports_equal_weighted_v1_breakdown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Effectiveness should expose the simple v1 score and bucket breakdown."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/api/v1/effectiveness")

    assert response.status_code == 200
    payload = response.json()
    assert payload["score_percent"] == 33.3
    assert payload["services_at_target"] == 1
    assert payload["total_services"] == 3
    assert payload["improvable_services"] == 2
    assert payload["breakdown"] == [
        {
            "bucket": "discovered_only",
            "label": "Discovered only",
            "target_level": 0,
            "service_count": 1,
            "services_at_target": 1,
            "services_below_target": 0,
        },
        {
            "bucket": "investigation_ready",
            "label": "Investigation-ready",
            "target_level": 3,
            "service_count": 1,
            "services_at_target": 0,
            "services_below_target": 1,
        },
        {
            "bucket": "deep_inspection_ready",
            "label": "Deep-inspection-ready",
            "target_level": 4,
            "service_count": 1,
            "services_at_target": 0,
            "services_below_target": 1,
        },
    ]


def test_fastapi_credential_request_endpoints_manage_request_lifecycle(tmp_path: Path) -> None:
    """Credential-request endpoints should create, list, and resolve UAC choices."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/credential-requests",
            json={
                "incident_id": "inc-1",
                "investigation_id": "inv-1",
                "service_id": "svc-radarr",
                "credential_key": "api_key",
                "reason": "Need the diagnostics API to narrow the fault.",
            },
        )
        request_id = create_response.json()["id"]
        list_response = client.get("/api/v1/credential-requests")
        choice_response = client.post(
            "/api/v1/credential-requests/telegram-callback",
            json={
                "callback_id": build_credential_request_callback_id(
                    request_id=request_id,
                    mode=CredentialRequestMode.VOLATILE,
                ),
                "decided_by": "user_via_telegram",
            },
        )

    assert create_response.status_code == 201
    assert create_response.json()["status"] == "pending"
    assert create_response.json()["credential_description"] == "Radarr API Key"
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [request_id]
    assert choice_response.status_code == 200
    assert choice_response.json()["status"] == "awaiting_input"
    assert choice_response.json()["selected_mode"] == "volatile"


def test_fastapi_vault_endpoints_support_vault_mode_submission(tmp_path: Path) -> None:
    """Vault endpoints should unlock, store encrypted material, and relock cleanly."""
    database_path = tmp_path / "kaval.db"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/credential-requests",
            json={
                "incident_id": "inc-1",
                "investigation_id": "inv-1",
                "service_id": "svc-radarr",
                "credential_key": "api_key",
                "reason": "Need the diagnostics API to narrow the fault.",
            },
        )
        request_id = create_response.json()["id"]
        client.post(
            f"/api/v1/credential-requests/{request_id}/choice",
            json={
                "mode": "vault",
                "decided_by": "user_via_telegram",
            },
        )
        initial_status_response = client.get("/api/v1/vault/status")
        locked_submit_response = client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "radarr-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )
        unlock_response = client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        submit_response = client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "radarr-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )
        unlocked_status_response = client.get("/api/v1/vault/status")
        relock_response = client.post("/api/v1/vault/lock")

    assert create_response.status_code == 201
    assert initial_status_response.status_code == 200
    assert initial_status_response.json() == {
        "initialized": False,
        "unlocked": False,
        "unlock_expires_at": None,
        "stored_credentials": 0,
    }
    assert locked_submit_response.status_code == 423
    assert unlock_response.status_code == 200
    assert unlock_response.json()["initialized"] is True
    assert unlock_response.json()["unlocked"] is True
    assert submit_response.status_code == 200
    assert submit_response.json()["status"] == "satisfied"
    assert submit_response.json()["credential_reference"].startswith("vault:")
    assert unlocked_status_response.status_code == 200
    assert unlocked_status_response.json()["stored_credentials"] == 1
    assert unlocked_status_response.json()["unlocked"] is True
    assert relock_response.status_code == 200
    assert relock_response.json()["initialized"] is True
    assert relock_response.json()["unlocked"] is False


def test_credential_vault_settings_api_lists_tests_and_rotates_credentials(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Vault management settings should expose safe metadata and explicit actions only."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        unlock_response = client.post(
            "/api/v1/settings/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(
                local_enabled=True,
                local_model="qwen3:14b",
                local_api_key="local-secret",
            ),
        )
        create_response = client.post(
            "/api/v1/credential-requests",
            json={
                "incident_id": "inc-1",
                "investigation_id": "inv-1",
                "service_id": "svc-radarr",
                "credential_key": "api_key",
                "reason": "Need diagnostics API access.",
            },
        )
        request_id = create_response.json()["id"]
        client.post(
            f"/api/v1/credential-requests/{request_id}/choice",
            json={
                "mode": "vault",
                "decided_by": "user_via_telegram",
            },
        )
        client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "radarr-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )
        list_response = client.get("/api/v1/settings/vault")
        test_response = client.post("/api/v1/settings/vault/test")
        change_password_response = client.post(
            "/api/v1/settings/vault/change-password",
            json={
                "current_master_passphrase": "correct horse battery staple",
                "new_master_passphrase": "correct horse battery stable",
            },
        )
        old_unlock_response = client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        lock_response = client.post("/api/v1/settings/vault/lock")
        new_unlock_response = client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery stable"},
        )

    assert unlock_response.status_code == 200
    assert unlock_response.json()["vault"]["status"]["initialized"] is True
    assert unlock_response.json()["vault"]["status"]["unlocked"] is True

    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert "local-secret" not in json.dumps(list_payload)
    assert "radarr-secret-value" not in json.dumps(list_payload)
    assert {item["service_name"] for item in list_payload["credentials"]} == {
        "Local model settings",
        "Radarr",
    }

    assert test_response.status_code == 200
    test_payload = test_response.json()
    assert test_payload["ok"] is True
    assert test_payload["tested_credentials"] == 2
    assert test_payload["readable_credentials"] == 2
    assert test_payload["audit_change"]["type"] == "config_change"
    assert "local-secret" not in json.dumps(test_payload)
    assert "radarr-secret-value" not in json.dumps(test_payload)
    assert all(
        item["last_tested_at"] is not None for item in test_payload["vault"]["credentials"]
    )

    assert change_password_response.status_code == 200
    assert change_password_response.json()["vault"]["status"]["unlocked"] is True
    assert change_password_response.json()["audit_change"]["type"] == "config_change"
    assert old_unlock_response.status_code == 403
    assert lock_response.status_code == 200
    assert lock_response.json()["vault"]["status"]["unlocked"] is False
    assert new_unlock_response.status_code == 200
    assert new_unlock_response.json()["unlocked"] is True


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
    assert len(payload["graph"]["node_meta"]) == 2
    assert len(payload["incidents"]) == 1
    assert len(payload["investigations"]) == 1


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
    assert len(initial_payload["investigations"]) == 1
    assert len(updated_payload["incidents"]) == 2
    assert len(updated_payload["investigations"]) == 1
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
        database.upsert_journal_entry(build_journal_entry())
        database.upsert_user_note(build_user_note())
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


def add_radarr_service(database_path: Path) -> None:
    """Add a descriptor-backed Radarr service for credential-request API tests."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id="svc-radarr",
                name="Radarr",
                type=ServiceType.CONTAINER,
                category="arr",
                status=ServiceStatus.DEGRADED,
                descriptor_id="arr/radarr",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-radarr",
                vm_id=None,
                image="lscr.io/linuxserver/radarr:latest",
                endpoints=[],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=ts(12, 1),
                active_findings=1,
                active_incidents=1,
            )
        )
    finally:
        database.close()


def add_unmatched_container_service(database_path: Path) -> None:
    """Add one unmatched container service for auto-generated descriptor tests."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id="svc-custom-app",
                name="custom-app",
                type=ServiceType.CONTAINER,
                category="container",
                status=ServiceStatus.HEALTHY,
                descriptor_id=None,
                descriptor_source=None,
                container_id="container-custom-app",
                vm_id=None,
                image="ghcr.io/example/custom-app:1.0.0",
                endpoints=[
                    Endpoint(
                        name="port_8080_tcp",
                        protocol=EndpointProtocol.TCP,
                        host="custom-app",
                        port=8080,
                        path=None,
                        url=None,
                        auth_required=False,
                        expected_status=None,
                    )
                ],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=ts(12, 2),
                active_findings=0,
                active_incidents=0,
            )
        )
    finally:
        database.close()


def add_stale_vault_credential(database_path: Path) -> None:
    """Add one stale stored credential for recommendations coverage."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_vault_credential(
            VaultCredentialRecord(
                reference_id="vault:delugevpn-api",
                request_id="credreq-delugevpn-api",
                incident_id="inc-1",
                service_id="svc-delugevpn",
                credential_key="api_key",
                ciphertext="gAAAAABvaultciphertext",
                submitted_by="user_via_telegram",
                created_at=ts(8, 0).replace(month=2, day=20),
                updated_at=ts(8, 0).replace(month=2, day=20),
                last_used_at=ts(10, 0),
                last_tested_at=ts(8, 0).replace(month=2, day=22),
            )
        )
    finally:
        database.close()


def add_noisy_check_feedback(database_path: Path) -> None:
    """Add repeated dismissal feedback for one noisy check recommendation."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        for index in range(5):
            database.upsert_finding_feedback_record(
                FindingFeedbackRecord(
                    id=f"ffb-delugevpn-{index}",
                    finding_id=f"find-delugevpn-{index}",
                    service_id="svc-delugevpn",
                    finding_domain="endpoint_probe",
                    reason=FindingFeedbackReason.FALSE_POSITIVE,
                    recorded_at=ts(9, index),
                )
            )
    finally:
        database.close()


def seed_capability_runtime_signals(database_path: Path) -> None:
    """Seed runtime telemetry for capability-health endpoint tests."""
    now = datetime.now(tz=UTC)
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_capability_runtime_signal(
            build_discovery_pipeline_runtime_signal(
                recorded_at=now - timedelta(minutes=2),
                last_succeeded_at=now - timedelta(minutes=2),
                unraid_api_reachable=True,
                docker_api_reachable=True,
                trigger="integration_test",
            )
        )
        database.upsert_capability_runtime_signal(
            build_scheduler_runtime_signal(
                recorded_at=now - timedelta(minutes=30),
                last_completed_at=now - timedelta(minutes=30),
                executed_check_ids=["dns_resolution"],
            )
        )
        database.upsert_capability_runtime_signal(
            build_executor_process_runtime_signal(
                recorded_at=now - timedelta(minutes=1),
                listener_started_at=now - timedelta(minutes=20),
                socket_path=database_path.parent / "executor.sock",
                docker_socket_path=database_path.parent / "docker.sock",
                socket_reachable=True,
                docker_accessible=True,
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


def build_endpoint_probe_finding(
    *,
    finding_id: str,
    status: FindingStatus,
    created_at: datetime,
    resolved_at: datetime | None,
    incident_id: str | None,
) -> Finding:
    """Build one endpoint-probe finding used by finding-feedback tests."""
    return Finding(
        id=finding_id,
        title="DelugeVPN endpoint probe failed",
        severity=Severity.MEDIUM,
        domain="endpoint_probe",
        service_id="svc-delugevpn",
        summary="The DelugeVPN web UI did not respond within the configured timeout.",
        evidence=[],
        impact="The service may be down or timing out.",
        confidence=0.82,
        status=status,
        incident_id=incident_id,
        related_changes=[],
        created_at=created_at,
        resolved_at=resolved_at,
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
        plugins=[
            PluginProfile(
                name="community.applications",
                version="2026.03.30",
                enabled=True,
                update_available=False,
                impacted_services=[
                    PluginImpactService(
                        service_id="svc-delugevpn",
                        service_name="DelugeVPN",
                        descriptor_id="downloads/delugevpn",
                    )
                ],
            )
        ],
        last_updated=ts(12, 3),
    )


def build_journal_entry() -> JournalEntry:
    """Build one persisted journal entry for API tests."""
    return JournalEntry(
        id="jrnl-1",
        incident_id="inc-0",
        date=ts(11, 45).date(),
        services=["svc-delugevpn"],
        summary="DelugeVPN degraded after a dependency restart.",
        root_cause="Downloads share dependency became unavailable.",
        resolution="Restarted DelugeVPN after the share recovered.",
        time_to_resolution_minutes=7.0,
        model_used="local",
        tags=["delugevpn", "storage"],
        lesson="Watch the downloads share before restarting clients.",
        recurrence_count=1,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(11, 50),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=180,
    )


def build_user_note() -> UserNote:
    """Build one persisted user note for API tests."""
    return UserNote(
        id="note-1",
        service_id="svc-delugevpn",
        note="Provider endpoint rotates often during maintenance windows.",
        safe_for_model=True,
        last_verified_at=ts(12, 0),
        stale=False,
        added_at=ts(12, 0),
        updated_at=ts(12, 5),
    )
