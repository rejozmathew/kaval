"""Security tests for model connectivity-test egress policy."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase


def _seed_database(database_path: Path) -> None:
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()


def _model_settings_payload(
    *,
    local_enabled: bool = False,
    local_base_url: str = "http://localhost:11434",
    local_api_key: str | None = None,
    cloud_enabled: bool = False,
    cloud_base_url: str = "https://api.anthropic.com",
    cloud_api_key: str | None = None,
) -> dict[str, object]:
    return {
        "local": {
            "enabled": local_enabled,
            "model": "qwen3:14b" if local_enabled else None,
            "base_url": local_base_url,
            "timeout_seconds": 12.0,
            "api_key": local_api_key,
            "clear_stored_api_key": False,
        },
        "cloud": {
            "enabled": cloud_enabled,
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514" if cloud_enabled else None,
            "base_url": cloud_base_url,
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


def _fake_getaddrinfo(address: str) -> Callable[..., list[tuple[Any, ...]]]:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, 443, 0, 0) if ":" in address else (address, 443),
            )
        ]

    return fake_getaddrinfo


@pytest.mark.parametrize(
    ("base_url", "resolved_ip", "expected"),
    [
        ("https://loopback.example", "127.0.0.1", "loopback"),
        ("https://private.example", "10.1.2.3", "private"),
        ("https://metadata.example", "169.254.169.254", "metadata"),
    ],
)
def test_cloud_model_test_rejects_internal_egress_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base_url: str,
    resolved_ip: str,
    expected: str,
) -> None:
    """Cloud model tests must not send stored keys to internal destinations."""
    monkeypatch.delenv("KAVAL_ALLOW_PRIVATE_MODEL_EGRESS", raising=False)
    monkeypatch.setattr("kaval.api.egress.socket.getaddrinfo", _fake_getaddrinfo(resolved_ip))
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    _seed_database(database_path)
    cloud_called = False

    def cloud_transport(*_args: object, **_kwargs: object) -> bytes:
        nonlocal cloud_called
        cloud_called = True
        return b"{}"

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
            json=_model_settings_payload(
                cloud_enabled=True,
                cloud_base_url=base_url,
                cloud_api_key="cloud-secret-value",
            ),
        )
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "staged"},
        )

    assert save_response.status_code == 200
    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert expected in test_response.json()["message"].casefold()
    assert "cloud-secret-value" not in json.dumps(test_response.json())
    assert cloud_called is False


def test_private_local_model_test_is_allowed_with_explicit_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private-egress opt-in preserves self-hosted local model tests."""
    monkeypatch.setenv("KAVAL_ALLOW_PRIVATE_MODEL_EGRESS", "TrUe")
    monkeypatch.setattr("kaval.api.egress.socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    _seed_database(database_path)
    local_called = False

    def local_transport(http_request: object, _timeout_seconds: float) -> bytes:
        nonlocal local_called
        local_called = True
        assert cast(Any, http_request).full_url == "http://localhost:11434/v1/chat/completions"
        return json.dumps(
            {"choices": [{"message": {"content": '{"connection_ok": true}'}}]}
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        local_model_transport=local_transport,
    )

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        save_response = client.put(
            "/api/v1/settings/models",
            json=_model_settings_payload(
                local_enabled=True,
                local_api_key="local-secret-value",
            ),
        )
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "local", "scope": "staged"},
        )

    assert save_response.status_code == 200
    assert test_response.status_code == 200
    assert test_response.json()["ok"] is True
    assert local_called is True


def test_dns_resolution_failure_is_rejected_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DNS failures must fail closed before the model probe runs."""
    monkeypatch.delenv("KAVAL_ALLOW_PRIVATE_MODEL_EGRESS", raising=False)

    def fail_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        raise OSError("DNS unavailable")

    monkeypatch.setattr("kaval.api.egress.socket.getaddrinfo", fail_getaddrinfo)
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    _seed_database(database_path)
    cloud_called = False

    def cloud_transport(*_args: object, **_kwargs: object) -> bytes:
        nonlocal cloud_called
        cloud_called = True
        return b"{}"

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
        client.put(
            "/api/v1/settings/models",
            json=_model_settings_payload(
                cloud_enabled=True,
                cloud_base_url="https://dns-failure.example",
                cloud_api_key="cloud-secret-value",
            ),
        )
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "staged"},
        )

    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert "could not be resolved" in test_response.json()["message"]
    assert cloud_called is False


def test_stored_vault_secret_is_not_replayed_to_changed_base_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staged endpoint change must not reuse the active vault-backed API key."""
    monkeypatch.setattr("kaval.api.egress.socket.getaddrinfo", _fake_getaddrinfo("8.8.8.8"))
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    _seed_database(database_path)
    cloud_called = False

    def cloud_transport(*_args: object, **_kwargs: object) -> bytes:
        nonlocal cloud_called
        cloud_called = True
        return b"{}"

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
        client.put(
            "/api/v1/settings/models",
            json=_model_settings_payload(
                cloud_enabled=True,
                cloud_base_url="https://api.anthropic.com",
                cloud_api_key="cloud-secret-value",
            ),
        )
        client.post("/api/v1/settings/models/apply")
        save_response = client.put(
            "/api/v1/settings/models",
            json=_model_settings_payload(
                cloud_enabled=True,
                cloud_base_url="https://changed.example",
                cloud_api_key=None,
            ),
        )
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "staged"},
        )

    assert save_response.status_code == 200
    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert "currently-active base_url" in test_response.json()["message"]
    assert "cloud-secret-value" not in json.dumps(test_response.json())
    assert cloud_called is False


def test_local_model_test_blocks_cloud_metadata_even_without_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Local-model tests preserve the loopback workflow but never reach cloud metadata."""
    monkeypatch.delenv("KAVAL_ALLOW_PRIVATE_MODEL_EGRESS", raising=False)
    monkeypatch.setattr(
        "kaval.api.egress.socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254")
    )
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    _seed_database(database_path)
    local_called = False

    def local_transport(*_args: object, **_kwargs: object) -> bytes:
        nonlocal local_called
        local_called = True
        return b"{}"

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        local_model_transport=local_transport,
    )

    with TestClient(app) as client:
        client.post(
            "/api/v1/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )
        client.put(
            "/api/v1/settings/models",
            json=_model_settings_payload(
                local_enabled=True,
                local_base_url="http://metadata.local",
                local_api_key="local-secret-value",
            ),
        )
        test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "local", "scope": "staged"},
        )

    assert test_response.status_code == 200
    assert test_response.json()["ok"] is False
    assert "metadata" in test_response.json()["message"].casefold()
    assert "local-secret-value" not in json.dumps(test_response.json())
    assert local_called is False
