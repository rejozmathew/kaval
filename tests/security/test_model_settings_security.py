"""Security tests for model-settings secret handling."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase


def build_model_settings_payload(*, local_api_key: str) -> dict[str, object]:
    """Build a minimal model-settings save payload for security tests."""
    return {
        "local": {
            "enabled": True,
            "model": "qwen3:14b",
            "base_url": "http://localhost:11434",
            "timeout_seconds": 12.0,
            "api_key": local_api_key,
            "clear_stored_api_key": False,
        },
        "cloud": {
            "enabled": False,
            "provider": "anthropic",
            "model": None,
            "base_url": "https://api.anthropic.com",
            "timeout_seconds": 25.0,
            "max_output_tokens": 800,
            "api_key": None,
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


def test_model_settings_save_never_returns_or_persists_raw_api_keys(tmp_path: Path) -> None:
    """Saving model settings must keep raw API keys out of YAML and API responses."""
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
            "/api/v1/settings/models",
            json=build_model_settings_payload(local_api_key="local-secret-value"),
        )
        get_response = client.get("/api/v1/settings/models")

    assert save_response.status_code == 200
    assert get_response.status_code == 200
    assert "local-secret-value" not in json.dumps(save_response.json())
    assert "local-secret-value" not in json.dumps(get_response.json())
    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "local-secret-value" not in persisted_text
    assert "api_key_ref: vault:settings:models:local_api_key" in persisted_text


def test_model_settings_test_requires_unlock_for_vault_backed_keys_without_leak(
    tmp_path: Path,
) -> None:
    """Explicit settings tests must fail cleanly for locked vault-backed keys."""
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
        client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(local_api_key="local-secret-value"),
        )
        client.post("/api/v1/vault/lock")
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "local", "scope": "staged"},
        )

    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert "locked" in test_response.json()["message"].casefold()
    assert "local-secret-value" not in json.dumps(test_response.json())
