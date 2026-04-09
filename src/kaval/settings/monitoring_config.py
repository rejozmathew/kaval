"""Persisted monitoring settings with explicit staged/apply semantics."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from kaval.models import KavalModel, ServiceCheckOverride
from kaval.monitoring import (
    MonitoringCadenceConfig,
    MonitoringCheckCadenceRule,
    ServiceMonitoringCadenceOverride,
    default_monitoring_check_cadences,
)
from kaval.monitoring.catalog import monitoring_check_catalog
from kaval.monitoring_thresholds import (
    monitoring_threshold_defaults,
    validate_monitoring_threshold_fields,
)
from kaval.settings.store import load_settings_document, write_settings_document

_ROOT_KEY_MONITORING = "monitoring"


class ManagedMonitoringCheckSettings(KavalModel):
    """Persisted global monitoring settings for one supported check."""

    check_id: str = Field(min_length=1)
    enabled: bool = True
    interval_seconds: int = Field(ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_thresholds(self) -> ManagedMonitoringCheckSettings:
        """Reject threshold fields that do not apply to the selected check."""
        validate_monitoring_threshold_fields(
            self.check_id,
            tls_warning_days=self.tls_warning_days,
            restart_delta_threshold=self.restart_delta_threshold,
            probe_timeout_seconds=self.probe_timeout_seconds,
        )
        return self


class ManagedMonitoringSettings(KavalModel):
    """Persisted monitoring settings stored beneath ``monitoring`` in YAML."""

    checks: list[ManagedMonitoringCheckSettings] = Field(
        default_factory=lambda: list(_default_managed_monitoring_checks())
    )

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedMonitoringSettings:
        """Require unique entries for the supported check set."""
        supported_check_ids = {entry.check_id for entry in monitoring_check_catalog()}
        seen_check_ids: set[str] = set()
        for check in self.checks:
            if check.check_id not in supported_check_ids:
                msg = f"unsupported monitoring check id: {check.check_id}"
                raise ValueError(msg)
            if check.check_id in seen_check_ids:
                msg = f"duplicate monitoring check id: {check.check_id}"
                raise ValueError(msg)
            seen_check_ids.add(check.check_id)
        missing_check_ids = supported_check_ids - seen_check_ids
        if missing_check_ids:
            msg = (
                "monitoring settings must include all supported checks: "
                f"{', '.join(sorted(missing_check_ids))}"
            )
            raise ValueError(msg)
        return self


class ResolvedMonitoringThresholdSettings(KavalModel):
    """Resolved threshold state for one service/check pair."""

    check_id: str = Field(min_length=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)
    source: Literal["global_default", "service_override"]


@dataclass(slots=True)
class MonitoringSettingsService:
    """Manage staged and active monitoring settings for the current process."""

    settings_path: Path
    _active: ManagedMonitoringSettings = field(init=False, repr=False)
    _staged: ManagedMonitoringSettings = field(init=False, repr=False)
    _root_document: dict[str, object] = field(init=False, repr=False, default_factory=dict)
    _load_error: str | None = field(init=False, default=None)
    _last_applied_at: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Load built-in defaults and any persisted monitoring overrides."""
        bootstrap = ManagedMonitoringSettings()
        root_document, root_error = load_settings_document(self.settings_path)
        persisted, persisted_error = _load_persisted_settings(root_document)
        resolved = bootstrap if persisted is None else _merge_settings(bootstrap, persisted)
        self._active = resolved.model_copy(deep=True)
        self._staged = resolved.model_copy(deep=True)
        self._root_document = root_document
        self._load_error = "; ".join(
            error for error in (root_error, persisted_error) if error
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

    def staged_snapshot(self) -> ManagedMonitoringSettings:
        """Return a defensive copy of the staged monitoring settings."""
        return self._staged.model_copy(deep=True)

    def active_snapshot(self) -> ManagedMonitoringSettings:
        """Return a defensive copy of the active monitoring settings."""
        return self._active.model_copy(deep=True)

    def apply_required(self) -> bool:
        """Return whether staged monitoring settings differ from the active snapshot."""
        return self._staged != self._active

    def apply(self, *, now: datetime | None = None) -> ManagedMonitoringSettings:
        """Promote staged monitoring settings into the active runtime view."""
        effective_now = now or datetime.now(tz=UTC)
        self._active = self._staged.model_copy(deep=True)
        self._last_applied_at = effective_now
        return self.active_snapshot()

    def update_staged(
        self,
        *,
        checks: Sequence[ManagedMonitoringCheckSettings],
    ) -> ManagedMonitoringSettings:
        """Validate, persist, and stage one complete monitoring-settings snapshot."""
        next_snapshot = ManagedMonitoringSettings(checks=_canonicalize_checks(checks))
        latest_root_document, latest_root_error = load_settings_document(self.settings_path)
        root_document = (
            latest_root_document
            if latest_root_error is None
            else dict(self._root_document)
        )
        root_document[_ROOT_KEY_MONITORING] = next_snapshot.model_dump(
            mode="json",
            exclude_none=True,
        )
        write_settings_document(self.settings_path, root_document)
        self._root_document = root_document
        self._staged = next_snapshot
        self._load_error = None
        return self.staged_snapshot()

    def resolve_cadence_config(
        self,
        *,
        scope: Literal["active", "staged"],
        service_overrides: Sequence[ServiceCheckOverride],
    ) -> MonitoringCadenceConfig:
        """Build the runtime cadence config for the selected settings scope."""
        snapshot = self._active if scope == "active" else self._staged
        overrides_by_id = {check.check_id: check for check in snapshot.checks}
        global_defaults = [
            MonitoringCheckCadenceRule(
                check_id=rule.check_id,
                enabled=(
                    overrides_by_id[rule.check_id].enabled
                    if rule.check_id in overrides_by_id
                    else rule.enabled
                ),
                interval_seconds=(
                    overrides_by_id[rule.check_id].interval_seconds
                    if rule.check_id in overrides_by_id
                    else rule.interval_seconds
                ),
                rationale=rule.rationale,
            )
            for rule in default_monitoring_check_cadences()
        ]
        return MonitoringCadenceConfig(
            global_defaults=global_defaults,
            service_overrides=[
                ServiceMonitoringCadenceOverride(
                    service_id=override.service_id,
                    check_id=override.check_id,
                    enabled=override.enabled,
                    interval_seconds=override.interval_seconds,
                )
                for override in service_overrides
                if override.enabled is not None or override.interval_seconds is not None
            ],
        )

    def resolve_threshold_settings(
        self,
        *,
        scope: Literal["active", "staged"],
        service_overrides: Sequence[ServiceCheckOverride],
        service_id: str,
        check_id: str,
    ) -> ResolvedMonitoringThresholdSettings:
        """Resolve effective threshold settings for one service/check pair."""
        snapshot = self._active if scope == "active" else self._staged
        check_settings = next(
            (check for check in snapshot.checks if check.check_id == check_id),
            None,
        )
        if check_settings is None:
            msg = f"unsupported monitoring check id: {check_id}"
            raise ValueError(msg)
        override = next(
            (
                item
                for item in service_overrides
                if item.service_id == service_id and item.check_id == check_id
            ),
            None,
        )
        source: Literal["global_default", "service_override"] = "global_default"
        tls_warning_days = check_settings.tls_warning_days
        restart_delta_threshold = check_settings.restart_delta_threshold
        probe_timeout_seconds = check_settings.probe_timeout_seconds
        if override is not None:
            if override.tls_warning_days is not None:
                tls_warning_days = override.tls_warning_days
                source = "service_override"
            if override.restart_delta_threshold is not None:
                restart_delta_threshold = override.restart_delta_threshold
                source = "service_override"
            if override.probe_timeout_seconds is not None:
                probe_timeout_seconds = override.probe_timeout_seconds
                source = "service_override"
        return ResolvedMonitoringThresholdSettings(
            check_id=check_id,
            tls_warning_days=tls_warning_days,
            restart_delta_threshold=restart_delta_threshold,
            probe_timeout_seconds=probe_timeout_seconds,
            source=source,
        )


def _default_managed_monitoring_checks() -> tuple[ManagedMonitoringCheckSettings, ...]:
    """Return the supported monitoring checks with their built-in defaults."""
    defaults_by_id = {
        rule.check_id: rule for rule in default_monitoring_check_cadences()
    }
    return tuple(
        ManagedMonitoringCheckSettings(
            check_id=entry.check_id,
            enabled=defaults_by_id[entry.check_id].enabled,
            interval_seconds=defaults_by_id[entry.check_id].interval_seconds,
            tls_warning_days=monitoring_threshold_defaults(entry.check_id)[0],
            restart_delta_threshold=monitoring_threshold_defaults(entry.check_id)[1],
            probe_timeout_seconds=monitoring_threshold_defaults(entry.check_id)[2],
        )
        for entry in monitoring_check_catalog()
    )


def _canonicalize_checks(
    checks: Sequence[ManagedMonitoringCheckSettings],
) -> list[ManagedMonitoringCheckSettings]:
    """Return checks in the catalog's stable operator-facing order."""
    checks_by_id = {check.check_id: check for check in checks}
    return [
        checks_by_id[entry.check_id]
        for entry in monitoring_check_catalog()
        if entry.check_id in checks_by_id
    ]


def _merge_settings(
    bootstrap: ManagedMonitoringSettings,
    persisted: ManagedMonitoringSettings,
) -> ManagedMonitoringSettings:
    """Merge persisted monitoring settings over the built-in defaults."""
    persisted_by_id = {check.check_id: check for check in persisted.checks}
    merged_checks = [
        (
            check
            if check.check_id not in persisted_by_id
            else ManagedMonitoringCheckSettings(
                check_id=check.check_id,
                enabled=persisted_by_id[check.check_id].enabled,
                interval_seconds=persisted_by_id[check.check_id].interval_seconds,
                tls_warning_days=(
                    check.tls_warning_days
                    if persisted_by_id[check.check_id].tls_warning_days is None
                    else persisted_by_id[check.check_id].tls_warning_days
                ),
                restart_delta_threshold=(
                    check.restart_delta_threshold
                    if persisted_by_id[check.check_id].restart_delta_threshold is None
                    else persisted_by_id[check.check_id].restart_delta_threshold
                ),
                probe_timeout_seconds=(
                    check.probe_timeout_seconds
                    if persisted_by_id[check.check_id].probe_timeout_seconds is None
                    else persisted_by_id[check.check_id].probe_timeout_seconds
                ),
            )
        )
        for check in bootstrap.checks
    ]
    return ManagedMonitoringSettings(checks=merged_checks)


def _load_persisted_settings(
    root_document: Mapping[str, object],
) -> tuple[ManagedMonitoringSettings | None, str | None]:
    """Load the persisted monitoring settings section from the YAML document."""
    raw_settings = root_document.get(_ROOT_KEY_MONITORING)
    if raw_settings is None:
        return None, None
    if not isinstance(raw_settings, Mapping):
        return None, "persisted monitoring settings must be a mapping"
    try:
        return ManagedMonitoringSettings.model_validate(raw_settings), None
    except ValueError as exc:
        return None, f"Persisted monitoring settings are invalid: {exc}"
