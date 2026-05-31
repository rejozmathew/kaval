"""Integration tests for the admin backup/restore endpoints (P4-04/P4-05)."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import admin_backup, create_app
from kaval.api.admin_backup import BACKUP_MARKER, BACKUP_SENSITIVITY_WARNING
from kaval.database import KavalDatabase
from kaval.models import (
    DescriptorSource,
    Service,
    ServiceStatus,
    ServiceType,
)


def _seed_service(database_path: Path, service_id: str) -> None:
    """Seed one service so backup/restore round-trips can be asserted."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id=service_id,
                name="DelugeVPN",
                type=ServiceType.CONTAINER,
                category="downloads",
                status=ServiceStatus.HEALTHY,
                descriptor_id="downloads/delugevpn",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-delugevpn",
                vm_id=None,
                image="binhex/arch-delugevpn:latest",
                endpoints=[],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=datetime(2026, 4, 7, 12, 0, tzinfo=UTC),
                active_findings=0,
                active_incidents=0,
            )
        )
    finally:
        database.close()


def _unlock_vault(client: TestClient) -> None:
    """Unlock the credential vault for backup/restore default-deny fallback."""
    response = client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "correct horse battery staple"},
    )
    assert response.status_code == 200
    assert response.json()["unlocked"] is True


def test_admin_backup_returns_zip_with_sensitivity_warning(tmp_path: Path) -> None:
    """The backup endpoint returns a Kaval ZIP archive plus an explicit warning."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models: {}\n", encoding="utf-8")
    _seed_service(database_path, "svc-delugevpn")
    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        _unlock_vault(client)
        response = client.get("/api/v1/admin/backup")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["x-kaval-backup-warning"] == BACKUP_SENSITIVITY_WARNING
    assert "attachment; filename=" in response.headers["content-disposition"]

    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = set(archive.namelist())
        assert {"manifest.json", "kaval.db", "kaval.yaml"} <= names
        assert BACKUP_MARKER.encode() in archive.read("manifest.json")


def test_admin_backup_restore_round_trip(tmp_path: Path) -> None:
    """A backup can be restored to recover dropped database state."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models: {}\n", encoding="utf-8")
    _seed_service(database_path, "svc-delugevpn")
    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        _unlock_vault(client)
        backup = client.get("/api/v1/admin/backup")
        assert backup.status_code == 200

        # Simulate data loss: replace the database with an empty bootstrap.
        database_path.unlink()
        empty = KavalDatabase(path=database_path)
        empty.bootstrap()
        empty.close()
        assert client.get("/api/v1/services").json() == []

        restore = client.post(
            "/api/v1/admin/restore",
            content=backup.content,
            headers={"Content-Type": "application/zip"},
        )

    assert restore.status_code == 200
    body = restore.json()
    assert body["restored"] is True
    assert body["restored_database"] is True
    assert body["restored_settings"] is True

    restored = KavalDatabase(path=database_path)
    try:
        assert [service.id for service in restored.list_services()] == ["svc-delugevpn"]
    finally:
        restored.close()


def test_admin_restore_rejects_non_kaval_archive(tmp_path: Path) -> None:
    """A ZIP without the Kaval marker is rejected."""
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", "not a kaval backup")

    with TestClient(app) as client:
        _unlock_vault(client)
        response = client.post(
            "/api/v1/admin/restore",
            content=buffer.getvalue(),
            headers={"Content-Type": "application/zip"},
        )

    assert response.status_code == 400


def test_admin_restore_rejects_non_zip_body(tmp_path: Path) -> None:
    """A non-ZIP body is rejected with a clear error."""
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        _unlock_vault(client)
        response = client.post(
            "/api/v1/admin/restore",
            content=b"this is not a zip",
            headers={"Content-Type": "application/zip"},
        )

    assert response.status_code == 400


def test_admin_restore_rejects_member_over_size_cap(tmp_path: Path, monkeypatch) -> None:
    """Restore rejects members whose declared uncompressed size exceeds the cap."""
    database_path = tmp_path / "kaval.db"
    app = create_app(database_path=database_path)
    monkeypatch.setattr(admin_backup, "_MAX_ARCHIVE_MEMBER_SIZE_BYTES", 8)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", f'{{"marker": "{BACKUP_MARKER}"}}')
        archive.writestr("kaval.yaml", "models: {}\n")

    with TestClient(app) as client:
        _unlock_vault(client)
        response = client.post(
            "/api/v1/admin/restore",
            content=buffer.getvalue(),
            headers={"Content-Type": "application/zip"},
        )

    assert response.status_code == 400
    assert "size limit" in response.json()["detail"]


def test_admin_restore_rejects_invalid_database_and_preserves_current_state(
    tmp_path: Path,
) -> None:
    """Invalid staged SQLite databases are rejected without replacing current files."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models: {}\n", encoding="utf-8")
    _seed_service(database_path, "svc-current")
    original_settings = settings_path.read_text(encoding="utf-8")
    app = create_app(database_path=database_path, settings_path=settings_path)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", f'{{"marker": "{BACKUP_MARKER}"}}')
        archive.writestr("kaval.db", b"not sqlite")
        archive.writestr("kaval.yaml", "models:\n  changed: true\n")

    with TestClient(app) as client:
        _unlock_vault(client)
        response = client.post(
            "/api/v1/admin/restore",
            content=buffer.getvalue(),
            headers={"Content-Type": "application/zip"},
        )

    assert response.status_code == 400
    assert "integrity check" in response.json()["detail"]
    assert settings_path.read_text(encoding="utf-8") == original_settings
    restored = KavalDatabase(path=database_path)
    try:
        assert [service.id for service in restored.list_services()] == ["svc-current"]
    finally:
        restored.close()
    assert not list(tmp_path.glob("*.restore-*"))


def test_admin_restore_snapshots_existing_artifacts_before_successful_swap(
    tmp_path: Path,
) -> None:
    """Successful restore snapshots existing database and settings before replacement."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models: {}\n", encoding="utf-8")
    _seed_service(database_path, "svc-old")
    app = create_app(database_path=database_path, settings_path=settings_path)

    with TestClient(app) as client:
        _unlock_vault(client)
        backup = client.get("/api/v1/admin/backup")
        assert backup.status_code == 200
        settings_path.write_text("models:\n  changed: true\n", encoding="utf-8")
        database_path.unlink()
        _seed_service(database_path, "svc-new")
        restore = client.post(
            "/api/v1/admin/restore",
            content=backup.content,
            headers={"Content-Type": "application/zip"},
        )

    assert restore.status_code == 200
    assert list(tmp_path.glob("kaval.db.bak-*"))
    assert list(tmp_path.glob("kaval.yaml.bak-*"))
    restored = KavalDatabase(path=database_path)
    try:
        assert [service.id for service in restored.list_services()] == ["svc-old"]
    finally:
        restored.close()
    assert settings_path.read_text(encoding="utf-8") == "models: {}\n"
