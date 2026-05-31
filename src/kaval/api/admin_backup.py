"""Admin backup/restore surface and admin-API exposure control.

This module implements the security-sensitive admin endpoints required by P4-04/P4-05 and
the explicit, optional admin-API exposure control described in
``docs/security_requirements.md`` (Area 6) and ``docs/adr/019-admin-api-exposure-model.md``.

The admin key is optional. When ``KAVAL_ADMIN_API_KEY`` is unset the admin surface keeps the
single-admin / local-network default; when set, admin/backup/restore requests must present
the key (``X-Kaval-Admin-Key`` header or a bearer token) compared with a constant-time
comparison.
"""

from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, Field

BACKUP_MANIFEST_NAME = "manifest.json"
BACKUP_MARKER = "kaval-backup"
BACKUP_FORMAT_VERSION = 1
_MAX_ARCHIVE_MEMBER_SIZE_BYTES = 1024 * 1024 * 1024
_MAX_ARCHIVE_TOTAL_SIZE_BYTES = 2 * 1024 * 1024 * 1024

#: Member name -> on-disk artifact kind. Only these names are ever read or written, which
#: prevents path traversal from a crafted archive.
_DATABASE_MEMBER = "kaval.db"
_SETTINGS_MEMBER = "kaval.yaml"

BACKUP_SENSITIVITY_WARNING = (
    "This Kaval backup may contain sensitive data, including encrypted vault contents, "
    "credentials, notification tokens, and operational memory. Store it securely, transfer "
    "it only over trusted channels, and delete copies you no longer need."
)


class RestoreResult(BaseModel):
    """Result of applying a Kaval backup archive."""

    restored: bool = Field(description="Whether the archive was applied.")
    restored_database: bool = Field(description="Whether the database file was restored.")
    restored_settings: bool = Field(description="Whether the settings file was restored.")
    created_at: str | None = Field(
        default=None,
        description="The backup's recorded creation timestamp, if present.",
    )
    warning: str = Field(
        default=BACKUP_SENSITIVITY_WARNING,
        description="Sensitivity warning for the restored data.",
    )


def authorize_admin_request(
    *,
    expected_api_key: str | None,
    authorization: str | None,
    x_kaval_admin_key: str | None,
    vault_unlocked: bool = False,
) -> None:
    """Authorize one admin request using the admin key or unlocked-vault fallback."""
    if expected_api_key is None:
        if vault_unlocked:
            return
        raise HTTPException(
            status_code=403,
            detail=(
                "admin backup/restore requires an unlocked credential vault or a configured "
                "KAVAL_ADMIN_API_KEY"
            ),
        )
    presented_key = x_kaval_admin_key
    if presented_key is None and authorization is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.casefold() == "bearer" and token.strip():
            presented_key = token.strip()
    if presented_key is None:
        raise HTTPException(status_code=401, detail="admin api key required")
    if not secrets.compare_digest(presented_key, expected_api_key):
        raise HTTPException(status_code=403, detail="invalid admin api key")


def build_backup_archive(
    *,
    database_path: Path,
    settings_path: Path,
) -> bytes:
    """Build a ZIP backup archive of the database and settings.

    The archive always carries a manifest with the backup marker and the sensitivity
    warning. Missing artifacts are simply omitted; the manifest records what is present.
    """
    created_at = datetime.now(tz=UTC).isoformat()
    includes_database = database_path.exists()
    includes_settings = settings_path.exists()
    manifest = {
        "marker": BACKUP_MARKER,
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": created_at,
        "warning": BACKUP_SENSITIVITY_WARNING,
        "contents": {
            "database": includes_database,
            "settings": includes_settings,
        },
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(BACKUP_MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=True))
        if includes_database:
            archive.writestr(_DATABASE_MEMBER, database_path.read_bytes())
        if includes_settings:
            archive.writestr(_SETTINGS_MEMBER, settings_path.read_bytes())
    return buffer.getvalue()


def _validate_archive_sizes(archive: zipfile.ZipFile) -> None:
    """Reject archives whose declared uncompressed sizes exceed restore limits."""
    total_size = 0
    for info in archive.infolist():
        if info.file_size > _MAX_ARCHIVE_MEMBER_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"backup member {info.filename!r} exceeds restore size limit",
            )
        total_size += info.file_size
        if total_size > _MAX_ARCHIVE_TOTAL_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail="backup archive exceeds total restore size limit",
            )


def _load_manifest(archive: zipfile.ZipFile) -> dict[str, object]:
    """Return the validated manifest mapping from a backup archive."""
    try:
        raw_manifest = archive.read(BACKUP_MANIFEST_NAME)
    except KeyError as error:
        raise HTTPException(
            status_code=400,
            detail="not a Kaval backup archive: manifest missing",
        ) from error
    try:
        manifest = json.loads(raw_manifest)
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=400,
            detail="not a Kaval backup archive: manifest is not valid JSON",
        ) from error
    if not isinstance(manifest, dict) or manifest.get("marker") != BACKUP_MARKER:
        raise HTTPException(
            status_code=400,
            detail="not a Kaval backup archive: marker missing",
        )
    return manifest


def _staging_path(path: Path, timestamp: str) -> Path:
    """Return a sibling staging path for a restore candidate."""
    return path.with_name(f".{path.name}.restore-{timestamp}")


def _backup_path(path: Path, timestamp: str) -> Path:
    """Return a sibling snapshot path for the current artifact."""
    return path.with_name(f"{path.name}.bak-{timestamp}")


def _validate_sqlite_database(path: Path) -> None:
    """Run SQLite integrity_check on a staged database file."""
    try:
        connection = sqlite3.connect(path)
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise HTTPException(
            status_code=400,
            detail="backup database failed SQLite integrity check",
        ) from error
    if result is None or result[0] != "ok":
        raise HTTPException(
            status_code=400,
            detail="backup database failed SQLite integrity check",
        )


def _snapshot_existing(path: Path, timestamp: str) -> None:
    """Snapshot an existing artifact before replacing it."""
    if path.exists():
        shutil.copy2(path, _backup_path(path, timestamp))


def restore_backup_archive(
    *,
    archive_bytes: bytes,
    database_path: Path,
    settings_path: Path,
) -> RestoreResult:
    """Validate and apply a Kaval backup archive to the configured paths.

    Only the known artifact members are ever written, so a crafted archive cannot escape the
    configured database/settings locations.
    """
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    database_stage = _staging_path(database_path, timestamp)
    settings_stage = _staging_path(settings_path, timestamp)
    staged_paths = (database_stage, settings_stage)
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as error:
        raise HTTPException(
            status_code=400,
            detail="uploaded file is not a valid ZIP archive",
        ) from error
    try:
        with archive:
            _validate_archive_sizes(archive)
            manifest = _load_manifest(archive)
            member_names = set(archive.namelist())
            restored_database = False
            restored_settings = False
            if _DATABASE_MEMBER in member_names:
                database_path.parent.mkdir(parents=True, exist_ok=True)
                database_stage.write_bytes(archive.read(_DATABASE_MEMBER))
                _validate_sqlite_database(database_stage)
                restored_database = True
            if _SETTINGS_MEMBER in member_names:
                settings_path.parent.mkdir(parents=True, exist_ok=True)
                settings_stage.write_bytes(archive.read(_SETTINGS_MEMBER))
                restored_settings = True
            if restored_database:
                _snapshot_existing(database_path, timestamp)
                os.replace(database_stage, database_path)
            if restored_settings:
                _snapshot_existing(settings_path, timestamp)
                os.replace(settings_stage, settings_path)
    finally:
        for staged_path in staged_paths:
            if staged_path.exists():
                staged_path.unlink()
    created_at = manifest.get("created_at")
    return RestoreResult(
        restored=restored_database or restored_settings,
        restored_database=restored_database,
        restored_settings=restored_settings,
        created_at=created_at if isinstance(created_at, str) else None,
    )
