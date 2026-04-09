"""Persisted system settings with explicit staged/apply semantics."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import model_validator

from kaval.models import KavalModel
from kaval.settings.store import load_settings_document, write_settings_document

type ManagedSystemLogLevel = Literal[
    "critical",
    "error",
    "warning",
    "info",
    "debug",
    "trace",
]

_ROOT_KEY_SYSTEM = "system"
_VALID_SYSTEM_LOG_LEVELS = {
    "critical",
    "error",
    "warning",
    "info",
    "debug",
    "trace",
}


class ManagedSystemSettings(KavalModel):
    """Persisted non-secret system settings stored beneath ``system`` in YAML."""

    log_level: ManagedSystemLogLevel = "info"
    audit_detail_retention_days: int = 90
    audit_summary_retention_days: int = 365

    @model_validator(mode="after")
    def validate_audit_retention_windows(self) -> Self:
        """Keep audit-detail and audit-summary retention windows coherent."""
        if self.audit_detail_retention_days <= 0:
            msg = "audit_detail_retention_days must be positive"
            raise ValueError(msg)
        if self.audit_summary_retention_days <= 0:
            msg = "audit_summary_retention_days must be positive"
            raise ValueError(msg)
        if self.audit_summary_retention_days < self.audit_detail_retention_days:
            msg = (
                "audit_summary_retention_days must be greater than or equal to "
                "audit_detail_retention_days"
            )
            raise ValueError(msg)
        return self


@dataclass(slots=True)
class SystemSettingsService:
    """Manage staged and active system settings for the current process."""

    settings_path: Path
    environment: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    _active: ManagedSystemSettings = field(init=False, repr=False)
    _staged: ManagedSystemSettings = field(init=False, repr=False)
    _root_document: dict[str, object] = field(init=False, repr=False, default_factory=dict)
    _load_error: str | None = field(init=False, default=None)
    _last_applied_at: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Load bootstrap defaults and any persisted system overrides."""
        bootstrap, bootstrap_error = _build_bootstrap_settings(self.environment)
        root_document, root_error = load_settings_document(self.settings_path)
        persisted, persisted_error = _load_persisted_settings(root_document)
        resolved = bootstrap if persisted is None else persisted
        self._active = resolved.model_copy(deep=True)
        self._staged = resolved.model_copy(deep=True)
        self._root_document = root_document
        self._load_error = "; ".join(
            error for error in (root_error, persisted_error, bootstrap_error) if error
        ) or None
        self._last_applied_at = datetime.now(tz=UTC)

    @property
    def load_error(self) -> str | None:
        """Return the most recent persisted-settings load error."""
        return self._load_error

    @property
    def last_applied_at(self) -> datetime | None:
        """Return when the active snapshot was last applied in-process."""
        return self._last_applied_at

    def staged_snapshot(self) -> ManagedSystemSettings:
        """Return a defensive copy of the staged system settings."""
        return self._staged.model_copy(deep=True)

    def active_snapshot(self) -> ManagedSystemSettings:
        """Return a defensive copy of the active system settings."""
        return self._active.model_copy(deep=True)

    def apply_required(self) -> bool:
        """Return whether staged system settings differ from the active snapshot."""
        return self._staged != self._active

    def apply(self, *, now: datetime | None = None) -> ManagedSystemSettings:
        """Promote staged system settings into the active runtime view."""
        effective_now = now or datetime.now(tz=UTC)
        self._active = self._staged.model_copy(deep=True)
        self._last_applied_at = effective_now
        return self.active_snapshot()

    def update_staged(
        self,
        *,
        log_level: ManagedSystemLogLevel,
        audit_detail_retention_days: int,
        audit_summary_retention_days: int,
    ) -> ManagedSystemSettings:
        """Validate, persist, and stage one complete system-settings snapshot."""
        next_snapshot = ManagedSystemSettings(
            log_level=log_level,
            audit_detail_retention_days=audit_detail_retention_days,
            audit_summary_retention_days=audit_summary_retention_days,
        )
        latest_root_document, latest_root_error = load_settings_document(self.settings_path)
        root_document = (
            latest_root_document
            if latest_root_error is None
            else dict(self._root_document)
        )
        root_document[_ROOT_KEY_SYSTEM] = next_snapshot.model_dump(
            mode="json",
            exclude_none=True,
        )
        write_settings_document(self.settings_path, root_document)
        self._root_document = root_document
        self._staged = next_snapshot
        self._load_error = None
        return self.staged_snapshot()


def _build_bootstrap_settings(
    environment: Mapping[str, str],
) -> tuple[ManagedSystemSettings, str | None]:
    """Build the bootstrap system settings from the environment."""
    raw_log_level = environment.get("KAVAL_CORE_LOG_LEVEL")
    if raw_log_level is None or not raw_log_level.strip():
        return ManagedSystemSettings(), None
    normalized_log_level = raw_log_level.strip().casefold()
    if normalized_log_level not in _VALID_SYSTEM_LOG_LEVELS:
        return (
            ManagedSystemSettings(),
            (
                "Environment bootstrap system settings are invalid: "
                f"unsupported log level {normalized_log_level!r}"
            ),
        )
    return ManagedSystemSettings(
        log_level=cast(ManagedSystemLogLevel, normalized_log_level)
    ), None


def _load_persisted_settings(
    root_document: Mapping[str, object],
) -> tuple[ManagedSystemSettings | None, str | None]:
    """Load the persisted system settings section from the YAML document."""
    raw_settings = root_document.get(_ROOT_KEY_SYSTEM)
    if raw_settings is None:
        return None, None
    if not isinstance(raw_settings, Mapping):
        return None, "persisted system settings must be a mapping"
    try:
        return ManagedSystemSettings.model_validate(raw_settings), None
    except ValueError as exc:
        return None, f"Persisted system settings are invalid: {exc}"
