"""Security-focused tests for the credential-request flow."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.credentials import build_credential_request_callback_id
from kaval.credentials.models import CredentialRequestMode
from kaval.database import KavalDatabase
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for credential security tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_choice_endpoint_rejects_unexpected_secret_fields(tmp_path: Path) -> None:
    """The Phase 2B choice API must not accept secret material before vault handling exists."""
    database_path = tmp_path / "kaval.db"
    seed_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
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
        choice_response = client.post(
            f"/api/v1/credential-requests/{request_id}/choice",
            json={
                "mode": "volatile",
                "decided_by": "user_via_telegram",
                "secret_value": "super-secret",
            },
        )

    assert create_response.status_code == 201
    assert choice_response.status_code == 422


def test_telegram_callback_payload_contains_only_request_id_and_mode() -> None:
    """Telegram callback data should not embed service names, incidents, or secrets."""
    callback_id = build_credential_request_callback_id(
        request_id="credreq-123",
        mode=CredentialRequestMode.VAULT,
    )

    assert callback_id == "credential_request:credreq-123:vault"
    assert "svc-radarr" not in callback_id
    assert "inc-1" not in callback_id
    assert "secret" not in callback_id


def test_vault_submission_does_not_persist_raw_secret(tmp_path: Path) -> None:
    """Vault-backed submission should never store the raw secret in SQLite payloads."""
    database_path = tmp_path / "kaval.db"
    seed_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
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
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        submit_response = client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "super-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        request_row = database.connection().execute(
            "SELECT payload FROM credential_requests WHERE id = ?",
            (request_id,),
        ).fetchone()
        vault_row = database.connection().execute(
            "SELECT payload FROM vault_credentials WHERE request_id = ?",
            (request_id,),
        ).fetchone()
    finally:
        database.close()

    assert submit_response.status_code == 200
    assert "super-secret-value" not in str(request_row["payload"])
    assert "super-secret-value" not in str(vault_row["payload"])
    assert "secret_value" not in submit_response.text


def test_locked_vault_submission_never_echoes_secret(tmp_path: Path) -> None:
    """Locked-vault failures should not echo secret material back to the caller."""
    database_path = tmp_path / "kaval.db"
    seed_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
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
        submit_response = client.post(
            f"/api/v1/credential-requests/{request_id}/submit",
            json={
                "secret_value": "super-secret-value",
                "submitted_by": "user_via_telegram",
            },
        )

    assert submit_response.status_code == 423
    assert "super-secret-value" not in submit_response.text


def seed_database(database_path: Path) -> None:
    """Seed one database with a descriptor-backed Radarr service."""
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
                last_check=ts(18, 0),
                active_findings=1,
                active_incidents=1,
            )
        )
    finally:
        database.close()
