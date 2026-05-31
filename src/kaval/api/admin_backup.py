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
import secrets
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, Field

BACKUP_MANIFEST_NAME = "manifest.json"
BACKUP_MARKER = "kaval-backup"
BACKUP_FORMAT_VERSION = 1

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
) -> None:
    """Authorize one admin request when optional API-key auth is configured.

    When ``expected_api_key`` is ``None`` the admin surface is unguarded, matching the
    documented single-admin / local-network default. When configured, the key must be
    presented and is compared with a constant-time comparison.
    """
    if expected_api_key is None:
        return
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
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as error:
        raise HTTPException(
            status_code=400,
            detail="uploaded file is not a valid ZIP archive",
        ) from error
    with archive:
        manifest = _load_manifest(archive)
        member_names = set(archive.namelist())
        restored_database = False
        restored_settings = False
        if _DATABASE_MEMBER in member_names:
            database_path.parent.mkdir(parents=True, exist_ok=True)
            database_path.write_bytes(archive.read(_DATABASE_MEMBER))
            restored_database = True
        if _SETTINGS_MEMBER in member_names:
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            settings_path.write_bytes(archive.read(_SETTINGS_MEMBER))
            restored_settings = True
    created_at = manifest.get("created_at")
    return RestoreResult(
        restored=restored_database or restored_settings,
        restored_database=restored_database,
        restored_settings=restored_settings,
        created_at=created_at if isinstance(created_at, str) else None,
    )
