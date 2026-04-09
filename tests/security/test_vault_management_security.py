"""Security tests for the credential-vault management surface."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase


def build_model_settings_payload(*, local_api_key: str) -> dict[str, object]:
    """Build a minimal model-settings payload that stores one managed secret."""
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


def test_vault_management_never_returns_secret_material(tmp_path: Path) -> None:
    """Vault management responses must stay secret-free even after test and lock flows."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()

    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        client.post(
            "/api/v1/settings/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(local_api_key="local-secret-value"),
        )
        list_response = client.get("/api/v1/settings/vault")
        client.post("/api/v1/settings/vault/lock")
        test_response = client.post("/api/v1/settings/vault/test")

    assert list_response.status_code == 200
    assert test_response.status_code == 200
    assert "local-secret-value" not in json.dumps(list_response.json())
    assert "local-secret-value" not in json.dumps(test_response.json())
    assert list_response.json()["credentials"][0]["service_name"] == "Local model settings"
    assert test_response.json()["ok"] is False
    assert "locked" in test_response.json()["message"].casefold()
