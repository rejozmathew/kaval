"""Security-focused tests for webhook ingress authentication."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def test_webhook_receiver_rejects_missing_credentials(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Configured webhook routes must reject unauthenticated requests."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post("/api/v1/webhooks/uptime_kuma", json={"status": "down"})

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid webhook credentials"}


def test_webhook_receiver_rejects_invalid_bearer_key_without_echoing_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Invalid bearer keys must be rejected without being reflected in the response."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer wrong-secret"},
            json={"status": "down"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid webhook credentials"}
    assert "wrong-secret" not in response.text


def test_webhook_receiver_rejects_cross_source_keys(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Each configured source must require its own key."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_GRAFANA", "grafana-secret")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer grafana-secret"},
            json={"status": "down"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid webhook credentials"}


def test_webhook_receiver_does_not_fall_back_to_query_auth_after_invalid_header(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A malformed or invalid Authorization header must not defer to the query key."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma?key=uptime-secret",
            headers={"Authorization": "Basic not-bearer"},
            json={"status": "down"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid webhook credentials"}


def test_webhook_receiver_rejects_oversize_payloads(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Oversize webhook bodies must be rejected before retention."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    monkeypatch.setenv("KAVAL_WEBHOOK_PAYLOAD_SIZE_LIMIT_BYTES", "8")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            content=b'{"status":"down"}',
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "webhook payload exceeds configured size limit"}


def test_webhook_receiver_rate_limits_per_source(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Configured sources should stop accepting requests beyond the per-minute budget."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    monkeypatch.setenv("KAVAL_WEBHOOK_RATE_LIMIT_PER_MINUTE", "1")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)
    payload = load_fixture("uptime_kuma_down.json")

    with TestClient(app) as client:
        first_response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=payload,
        )
        second_response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=payload,
        )

    assert first_response.status_code == 202
    assert second_response.status_code == 429
    assert second_response.json() == {"detail": "webhook rate limit exceeded"}


def test_webhook_receiver_redacts_secret_like_payload_fields_before_storage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Secret-like fields in raw webhook payloads must be redacted before persistence."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)
    payload = load_fixture("uptime_kuma_down.json")
    payload["api_key"] = "super-secret"
    payload["url"] = "https://example.com/?token=abcdef"

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=payload,
        )

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        stored_payloads = database.list_webhook_payloads()
    finally:
        database.close()

    assert response.status_code == 202
    assert len(stored_payloads) == 1
    stored_payload = stored_payloads[0]
    assert stored_payload.raw_payload_redacted is True
    assert stored_payload.raw_payload["api_key"] == "[REDACTED]"
    assert stored_payload.raw_payload["url"] == "https://example.com/?token=%5BREDACTED%5D"
    assert "super-secret" not in stored_payload.model_dump_json()


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
