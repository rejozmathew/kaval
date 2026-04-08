"""Integration tests for the Homepage/Homarr widget endpoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import (
    ActionType,
    ApprovalToken,
    DescriptorSource,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    ModelUsed,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for widget integration tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_widget_endpoint_requires_api_key_when_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Configured widget auth should reject missing or invalid credentials."""
    monkeypatch.setenv("KAVAL_WIDGET_API_KEY", "widget-secret")
    database_path = tmp_path / "widget-auth.db"
    seed_widget_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        missing_response = client.get("/api/v1/widget")
        wrong_response = client.get(
            "/api/v1/widget",
            headers={"X-Kaval-Widget-Key": "wrong-secret"},
        )
        success_response = client.get(
            "/api/v1/widget",
            headers={"Authorization": "Bearer widget-secret"},
        )

    assert missing_response.status_code == 401
    assert missing_response.json() == {"detail": "widget api key required"}
    assert wrong_response.status_code == 403
    assert wrong_response.json() == {"detail": "invalid widget api key"}
    assert success_response.status_code == 200
    assert success_response.headers["cache-control"] == "private, max-age=60"


def test_widget_endpoint_honors_disable_and_public_url_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Widget config should support explicit disablement and env-backed response hints."""
    database_path = tmp_path / "widget-config.db"
    seed_widget_database(database_path, include_pending_approval=True)

    monkeypatch.setenv("KAVAL_WIDGET_ENABLED", "false")
    disabled_app = create_app(database_path=database_path)
    with TestClient(disabled_app) as client:
        disabled_response = client.get("/api/v1/widget")
    assert disabled_response.status_code == 404
    assert disabled_response.json() == {"detail": "widget api disabled"}

    monkeypatch.setenv("KAVAL_WIDGET_ENABLED", "true")
    monkeypatch.setenv("KAVAL_WIDGET_PUBLIC_URL", "https://kaval.example.test")
    monkeypatch.setenv("KAVAL_WIDGET_REFRESH_INTERVAL_SECONDS", "45")
    configured_app = create_app(database_path=database_path)

    with TestClient(configured_app) as client:
        response = client.get("/api/v1/widget")

    payload = response.json()
    assert response.status_code == 200
    assert response.headers["x-kaval-widget-refresh-seconds"] == "45"
    assert response.headers["cache-control"] == "public, max-age=45"
    assert payload["url"] == "https://kaval.example.test"
    assert payload["refresh_interval_seconds"] == 45
    assert payload["pending_approvals"] == 1


def seed_widget_database(
    database_path: Path,
    *,
    include_pending_approval: bool = False,
) -> None:
    """Seed representative state for widget API integration tests."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id="svc-delugevpn",
                name="DelugeVPN",
                type=ServiceType.CONTAINER,
                category="downloads",
                status=ServiceStatus.DEGRADED,
                descriptor_id="downloads/delugevpn",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-delugevpn",
                vm_id=None,
                image="binhex/arch-delugevpn:latest",
                endpoints=[],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=ts(12, 0),
                active_findings=1,
                active_incidents=1,
            )
        )
        database.upsert_incident(
            Incident(
                id="inc-widget",
                title="DelugeVPN degraded",
                severity=Severity.HIGH,
                status=IncidentStatus.OPEN,
                trigger_findings=[],
                all_findings=[],
                affected_services=["svc-delugevpn"],
                triggering_symptom="Container health degraded.",
                suspected_cause="VPN instability.",
                confirmed_cause=None,
                root_cause_service="svc-delugevpn",
                resolution_mechanism=None,
                cause_confirmation_source=None,
                confidence=0.82,
                investigation_id="inv-widget",
                approved_actions=[],
                changes_correlated=[],
                grouping_window_start=ts(12, 0),
                grouping_window_end=ts(12, 5),
                created_at=ts(12, 1),
                updated_at=ts(12, 2),
                resolved_at=None,
                mttr_seconds=None,
                journal_entry_id=None,
            )
        )
        database.upsert_investigation(
            Investigation(
                id="inv-widget",
                incident_id="inc-widget",
                trigger=InvestigationTrigger.AUTO,
                status=InvestigationStatus.COMPLETED,
                evidence_steps=[],
                research_steps=[],
                root_cause="VPN instability.",
                confidence=0.82,
                model_used=ModelUsed.NONE,
                cloud_model_calls=0,
                journal_entries_referenced=[],
                user_notes_referenced=[],
                recurrence_count=0,
                remediation=None,
                started_at=ts(12, 2),
                completed_at=ts(12, 4),
            )
        )
        if include_pending_approval:
            now = datetime.now(tz=UTC)
            database.upsert_approval_token(
                ApprovalToken(
                    token_id="tok-widget",
                    incident_id="inc-widget",
                    action=ActionType.RESTART_CONTAINER,
                    target="delugevpn",
                    approved_by="user_via_telegram",
                    issued_at=now,
                    expires_at=now + timedelta(minutes=10),
                    nonce="nonce-widget",
                    hmac_signature="deadbeef",
                    used_at=None,
                    result=None,
                )
            )
    finally:
        database.close()
