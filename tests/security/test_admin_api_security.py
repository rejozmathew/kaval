"""Security tests for the optional admin-API exposure control (P4-27)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app


def _make_app(tmp_path: Path):
    """Build an app whose admin surface can be exercised in tests."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models: {}\n", encoding="utf-8")
    return create_app(database_path=database_path, settings_path=settings_path)


def _unlock_vault(client: TestClient) -> None:
    """Unlock the app credential vault for admin fallback authorization."""
    response = client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "correct horse battery staple"},
    )
    assert response.status_code == 200
    assert response.json()["unlocked"] is True


def test_admin_backup_denied_when_no_key_configured_and_vault_locked(tmp_path: Path) -> None:
    """With no admin key and a locked vault, backup is default-denied."""
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        response = client.get("/api/v1/admin/backup")
    assert response.status_code == 403
    assert "unlock" in response.json()["detail"]
    assert "KAVAL_ADMIN_API_KEY" in response.json()["detail"]


def test_admin_backup_and_restore_allowed_when_vault_unlocked(tmp_path: Path) -> None:
    """With no admin key, an unlocked vault authorizes backup and restore."""
    app = _make_app(tmp_path)
    with TestClient(app) as client:
        _unlock_vault(client)
        backup = client.get("/api/v1/admin/backup")
        restore = client.post(
            "/api/v1/admin/restore",
            content=backup.content,
            headers={"Content-Type": "application/zip"},
        )
    assert backup.status_code == 200
    assert restore.status_code == 200


def test_admin_backup_requires_key_when_configured(tmp_path: Path, monkeypatch) -> None:
    """When an admin key is configured, the backup endpoint enforces it."""
    monkeypatch.setenv("KAVAL_ADMIN_API_KEY", "admin-secret")
    app = _make_app(tmp_path)

    with TestClient(app) as client:
        missing = client.get("/api/v1/admin/backup")
        wrong = client.get(
            "/api/v1/admin/backup",
            headers={"X-Kaval-Admin-Key": "wrong"},
        )
        header_ok = client.get(
            "/api/v1/admin/backup",
            headers={"X-Kaval-Admin-Key": "admin-secret"},
        )
        bearer_ok = client.get(
            "/api/v1/admin/backup",
            headers={"Authorization": "Bearer admin-secret"},
        )

    assert missing.status_code == 401
    assert missing.json() == {"detail": "admin api key required"}
    assert wrong.status_code == 403
    assert wrong.json() == {"detail": "invalid admin api key"}
    assert header_ok.status_code == 200
    assert bearer_ok.status_code == 200


def test_admin_restore_requires_key_when_configured(tmp_path: Path, monkeypatch) -> None:
    """The restore endpoint enforces the configured admin key before reading the body."""
    monkeypatch.setenv("KAVAL_ADMIN_API_KEY", "admin-secret")
    app = _make_app(tmp_path)

    with TestClient(app) as client:
        missing = client.post(
            "/api/v1/admin/restore",
            content=b"ignored",
            headers={"Content-Type": "application/zip"},
        )
        wrong = client.post(
            "/api/v1/admin/restore",
            content=b"ignored",
            headers={
                "Content-Type": "application/zip",
                "X-Kaval-Admin-Key": "wrong",
            },
        )

    assert missing.status_code == 401
    assert wrong.status_code == 403
