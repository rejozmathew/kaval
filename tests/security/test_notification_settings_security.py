"""Security tests for notification-settings secret handling."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase


def build_notification_settings_payload(
    *,
    destination: str,
) -> dict[str, object]:
    """Build a minimal notification-settings save payload for security tests."""
    return {
        "channels": [
            {
                "id": None,
                "name": "Primary Alerts",
                "enabled": True,
                "destination": destination,
            }
        ],
        "routing": {
            "critical": "immediate",
            "high": "immediate_with_dedup",
            "medium": "hourly_digest",
            "low": "dashboard_only",
            "dedup_window_minutes": 15,
            "digest_window_minutes": 60,
        },
        "quiet_hours": {
            "enabled": True,
            "start_time_local": "22:00",
            "end_time_local": "07:00",
            "timezone": "UTC",
        },
    }


def test_notification_settings_save_never_returns_or_persists_raw_destinations(
    tmp_path: Path,
) -> None:
    """Saving notification settings must keep raw destinations out of YAML and responses."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()

    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        save_response = client.put(
            "/api/v1/settings/notifications",
            json=build_notification_settings_payload(
                destination="discord://tokenA/tokenB",
            ),
        )
        get_response = client.get("/api/v1/settings/notifications")

    assert save_response.status_code == 200
    assert get_response.status_code == 200
    assert "discord://tokenA/tokenB" not in json.dumps(save_response.json())
    assert "discord://tokenA/tokenB" not in json.dumps(get_response.json())
    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "discord://tokenA/tokenB" not in persisted_text
    assert "destination_ref: vault:settings:notifications:channels:" in persisted_text


def test_notification_settings_test_requires_unlock_for_vault_backed_destinations(
    tmp_path: Path,
) -> None:
    """Explicit channel tests should fail cleanly when the stored destination is locked."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()

    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        save_response = client.put(
            "/api/v1/settings/notifications",
            json=build_notification_settings_payload(
                destination="discord://tokenA/tokenB",
            ),
        )
        channel_id = save_response.json()["settings"]["staged"]["channels"][0]["id"]
        client.post("/api/v1/vault/lock")
        test_response = client.post(
            "/api/v1/settings/notifications/test",
            json={"channel_id": channel_id, "scope": "staged"},
        )

    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert "locked" in test_response.json()["message"].casefold()
    assert "discord://tokenA/tokenB" not in json.dumps(test_response.json())
