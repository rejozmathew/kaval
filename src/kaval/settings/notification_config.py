"""Persisted notification settings with explicit staged/apply semantics."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, model_validator

from kaval.credentials.vault import CredentialVault
from kaval.models import KavalModel
from kaval.notifications.bus import (
    NotificationBusConfig,
    NotificationChannelConfig,
    load_notification_bus_config_from_env,
)
from kaval.notifications.routing import (
    IncidentAlertRoute,
    IncidentAlertRoutingContext,
    IncidentAlertRoutingPolicy,
)
from kaval.settings.store import (
    deep_merge,
    load_settings_document,
    normalize_mapping,
    write_settings_document,
)

type NotificationSettingsSecretSource = Literal["vault", "env", "unset"]

_ROOT_KEY_NOTIFICATIONS = "notifications"
_CHANNEL_SECRET_REF_PREFIX = "vault:settings:notifications:channels"


class ManagedNotificationChannelSettings(KavalModel):
    """Persisted non-secret metadata for one configured notification destination."""

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    enabled: bool = True
    destination_ref: str | None = None

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedNotificationChannelSettings:
        """Reject empty names and kinds after trimming."""
        if not self.name.strip():
            msg = "notification channel name must not be empty"
            raise ValueError(msg)
        if not self.kind.strip():
            msg = "notification channel kind must not be empty"
            raise ValueError(msg)
        return self


class ManagedNotificationQuietHoursSettings(KavalModel):
    """Daily quiet-hours schedule for non-critical notification holding."""

    enabled: bool = False
    start_time_local: str = "22:00"
    end_time_local: str = "07:00"
    timezone: str = "UTC"

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedNotificationQuietHoursSettings:
        """Require parseable quiet-hours time strings and a real timezone."""
        _parse_time_of_day(self.start_time_local)
        _parse_time_of_day(self.end_time_local)
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown quiet-hours timezone: {self.timezone}") from exc
        if self.enabled and self.start_time_local == self.end_time_local:
            msg = "quiet hours start and end must differ when quiet hours are enabled"
            raise ValueError(msg)
        return self

    def quiet_until(self, *, now: datetime) -> datetime | None:
        """Return the UTC release time if quiet hours are active at ``now``."""
        if not self.enabled:
            return None
        timezone = ZoneInfo(self.timezone)
        local_now = now.astimezone(timezone)
        start_time = _parse_time_of_day(self.start_time_local)
        end_time = _parse_time_of_day(self.end_time_local)
        start_today = datetime.combine(local_now.date(), start_time, tzinfo=timezone)
        end_today = datetime.combine(local_now.date(), end_time, tzinfo=timezone)
        if start_today < end_today:
            if start_today <= local_now < end_today:
                return end_today.astimezone(UTC)
            return None
        if local_now >= start_today:
            return (end_today + timedelta(days=1)).astimezone(UTC)
        if local_now < end_today:
            return end_today.astimezone(UTC)
        return None


class ManagedNotificationSettings(KavalModel):
    """Persisted notification settings stored beneath ``notifications`` in YAML."""

    channels: list[ManagedNotificationChannelSettings] = Field(default_factory=list)
    routing: IncidentAlertRoutingPolicy = Field(default_factory=IncidentAlertRoutingPolicy)
    quiet_hours: ManagedNotificationQuietHoursSettings = Field(
        default_factory=ManagedNotificationQuietHoursSettings
    )

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedNotificationSettings:
        """Require stable unique identifiers for each configured channel."""
        seen_ids: set[str] = set()
        for channel in self.channels:
            if channel.id in seen_ids:
                msg = f"duplicate notification channel id: {channel.id}"
                raise ValueError(msg)
            seen_ids.add(channel.id)
        for route_name, route_value in (
            ("critical", self.routing.critical),
            ("high", self.routing.high),
            ("medium", self.routing.medium),
            ("low", self.routing.low),
        ):
            if route_value is IncidentAlertRoute.SUMMARY:
                msg = f"{route_name} notification route cannot use summary directly"
                raise ValueError(msg)
        return self


class NotificationChannelWrite(KavalModel):
    """Writable staged notification channel input including a write-only destination."""

    id: str | None = None
    name: str = Field(min_length=1)
    enabled: bool = True
    destination: str | None = None

    @model_validator(mode="after")
    def validate_settings(self) -> NotificationChannelWrite:
        """Reject empty names once surrounding whitespace is removed."""
        if not self.name.strip():
            msg = "notification channel name must not be empty"
            raise ValueError(msg)
        return self


@dataclass(slots=True)
class NotificationSettingsService:
    """Manage staged and active notification settings for the current process."""

    settings_path: Path
    environment: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    _bootstrap_channel_urls: dict[str, str] = field(
        init=False,
        repr=False,
        default_factory=dict,
    )
    _active: ManagedNotificationSettings = field(init=False, repr=False)
    _staged: ManagedNotificationSettings = field(init=False, repr=False)
    _root_document: dict[str, object] = field(init=False, repr=False, default_factory=dict)
    _load_error: str | None = field(init=False, default=None)
    _last_applied_at: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Load bootstrap defaults and any persisted notification overrides."""
        bootstrap, bootstrap_urls, bootstrap_error = _build_bootstrap_settings(
            self.environment
        )
        root_document, root_error = load_settings_document(self.settings_path)
        persisted, persisted_error = _load_persisted_settings(root_document)
        if persisted is None:
            resolved = bootstrap
        else:
            merged_payload = deep_merge(
                bootstrap.model_dump(mode="json"),
                persisted.model_dump(mode="json"),
            )
            resolved = ManagedNotificationSettings.model_validate(merged_payload)
        self._bootstrap_channel_urls = bootstrap_urls
        self._active = resolved.model_copy(deep=True)
        self._staged = resolved.model_copy(deep=True)
        self._root_document = root_document
        load_errors = [root_error, persisted_error, bootstrap_error]
        self._load_error = "; ".join(error for error in load_errors if error) or None
        self._last_applied_at = datetime.now(tz=UTC)

    @property
    def load_error(self) -> str | None:
        """Return the most recent persisted-settings load error."""
        return self._load_error

    @property
    def last_applied_at(self) -> datetime | None:
        """Return when the active snapshot was last applied in-process."""
        return self._last_applied_at

    def staged_snapshot(self) -> ManagedNotificationSettings:
        """Return a defensive copy of the staged notification settings."""
        return self._staged.model_copy(deep=True)

    def active_snapshot(self) -> ManagedNotificationSettings:
        """Return a defensive copy of the active notification settings."""
        return self._active.model_copy(deep=True)

    def apply_required(self) -> bool:
        """Return whether staged settings differ from the active snapshot."""
        return self._staged != self._active

    def apply(self, *, now: datetime | None = None) -> ManagedNotificationSettings:
        """Promote staged notification settings into the active runtime view."""
        effective_now = now or datetime.now(tz=UTC)
        self._active = self._staged.model_copy(deep=True)
        self._last_applied_at = effective_now
        return self.active_snapshot()

    def update_staged(
        self,
        *,
        channels: Sequence[NotificationChannelWrite],
        routing: IncidentAlertRoutingPolicy,
        quiet_hours: ManagedNotificationQuietHoursSettings,
        vault: CredentialVault,
        submitted_by: str = "admin_ui",
        now: datetime | None = None,
    ) -> ManagedNotificationSettings:
        """Validate, persist, and stage one complete notification-settings snapshot."""
        effective_now = now or datetime.now(tz=UTC)
        existing_by_id = {channel.id: channel for channel in self._staged.channels}
        next_channels: list[ManagedNotificationChannelSettings] = []
        next_channel_ids: set[str] = set()
        for channel_input in channels:
            channel_id = channel_input.id or f"channel-{uuid4().hex[:12]}"
            if channel_id in next_channel_ids:
                msg = f"duplicate notification channel id: {channel_id}"
                raise ValueError(msg)
            next_channel_ids.add(channel_id)

            existing_channel = existing_by_id.get(channel_id)
            destination = _normalize_optional_secret(channel_input.destination)
            if (
                destination is None
                and existing_channel is None
                and channel_id not in self._bootstrap_channel_urls
            ):
                msg = (
                    f"notification channel '{channel_input.name.strip()}' "
                    "needs a destination before it can be saved"
                )
                raise ValueError(msg)

            destination_ref = existing_channel.destination_ref if existing_channel else None
            if destination is not None:
                destination_ref = destination_ref or _channel_secret_reference(channel_id)
                vault.upsert_managed_secret(
                    reference_id=destination_ref,
                    secret_value=destination,
                    service_id=f"settings.notifications.{channel_id}",
                    credential_key="destination",
                    submitted_by=submitted_by,
                    now=effective_now,
                )

            next_channels.append(
                ManagedNotificationChannelSettings(
                    id=channel_id,
                    name=channel_input.name.strip(),
                    kind=(
                        _channel_kind_from_destination(destination)
                        if destination is not None
                        else _existing_channel_kind(
                            channel_id=channel_id,
                            existing_channel=existing_channel,
                            bootstrap_channel_urls=self._bootstrap_channel_urls,
                        )
                    ),
                    enabled=channel_input.enabled,
                    destination_ref=destination_ref,
                )
            )

        for removed_channel in self._staged.channels:
            if removed_channel.id in next_channel_ids:
                continue
            if removed_channel.destination_ref is not None:
                vault.delete_secret(removed_channel.destination_ref)

        next_snapshot = ManagedNotificationSettings(
            channels=next_channels,
            routing=routing,
            quiet_hours=quiet_hours,
        )
        latest_root_document, latest_root_error = load_settings_document(self.settings_path)
        root_document = (
            latest_root_document
            if latest_root_error is None
            else dict(self._root_document)
        )
        root_document[_ROOT_KEY_NOTIFICATIONS] = next_snapshot.model_dump(
            mode="json",
            exclude_none=True,
        )
        write_settings_document(self.settings_path, root_document)
        self._root_document = root_document
        self._staged = next_snapshot
        self._load_error = None
        return self.staged_snapshot()

    def channel_destination_source(
        self,
        *,
        channel_id: str,
        scope: Literal["active", "staged"],
    ) -> NotificationSettingsSecretSource:
        """Return the configured destination source for one channel in one snapshot."""
        channel = self._channel_by_id(channel_id=channel_id, scope=scope)
        if channel is None:
            return "unset"
        if channel.destination_ref is not None:
            return "vault"
        if channel.id in self._bootstrap_channel_urls:
            return "env"
        return "unset"

    def configured_channel_count(self, *, scope: Literal["active", "staged"]) -> int:
        """Return how many enabled channels are configured for the selected snapshot."""
        snapshot = self._select_snapshot(scope)
        return sum(
            1
            for channel in snapshot.channels
            if channel.enabled
            and self.channel_destination_source(channel_id=channel.id, scope=scope)
            != "unset"
        )

    def resolve_bus_config(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
        vault: CredentialVault,
        channel_id: str | None = None,
    ) -> NotificationBusConfig | None:
        """Resolve one notification-bus config from the selected snapshot."""
        snapshot = self._select_snapshot(scope)
        resolved_channels: list[NotificationChannelConfig] = []
        for channel in snapshot.channels:
            if not channel.enabled:
                continue
            if channel_id is not None and channel.id != channel_id:
                continue
            destination = self._resolve_channel_destination(channel=channel, vault=vault)
            if destination is None:
                continue
            resolved_channels.append(
                NotificationChannelConfig(
                    name=channel.name,
                    apprise_url=destination,
                )
            )
        if not resolved_channels:
            return None
        return NotificationBusConfig(channels=resolved_channels)

    def resolve_routing_policy(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
    ) -> IncidentAlertRoutingPolicy:
        """Return the selected staged or active routing policy."""
        snapshot = self._select_snapshot(scope)
        return IncidentAlertRoutingPolicy.model_validate(
            snapshot.routing.model_dump(mode="json")
        )

    def build_routing_context(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
        now: datetime | None = None,
    ) -> IncidentAlertRoutingContext:
        """Build the runtime routing context for the selected snapshot."""
        effective_now = now or datetime.now(tz=UTC)
        snapshot = self._select_snapshot(scope)
        return IncidentAlertRoutingContext(
            quiet_hours_until=snapshot.quiet_hours.quiet_until(now=effective_now)
        )

    def _select_snapshot(
        self,
        scope: Literal["active", "staged"],
    ) -> ManagedNotificationSettings:
        """Return one internal notification snapshot by scope."""
        return self._active if scope == "active" else self._staged

    def _channel_by_id(
        self,
        *,
        channel_id: str,
        scope: Literal["active", "staged"],
    ) -> ManagedNotificationChannelSettings | None:
        """Return one staged or active channel by stable identifier."""
        snapshot = self._select_snapshot(scope)
        return next((channel for channel in snapshot.channels if channel.id == channel_id), None)

    def _resolve_channel_destination(
        self,
        *,
        channel: ManagedNotificationChannelSettings,
        vault: CredentialVault,
    ) -> str | None:
        """Resolve one raw destination URL from the vault or env bootstrap."""
        if channel.destination_ref is not None:
            return vault.get_secret(channel.destination_ref)
        return self._bootstrap_channel_urls.get(channel.id)


def _build_bootstrap_settings(
    environment: Mapping[str, str],
) -> tuple[ManagedNotificationSettings, dict[str, str], str | None]:
    """Build the env-bootstrap notification snapshot and destination-url map."""
    channel_urls: dict[str, str] = {}
    errors: list[str] = []
    channels: list[ManagedNotificationChannelSettings] = []
    try:
        config = load_notification_bus_config_from_env(environment)
        if config is not None:
            for index, channel in enumerate(config.channels, start=1):
                channel_id = f"env-channel-{index}"
                channel_urls[channel_id] = channel.apprise_url
                channels.append(
                    ManagedNotificationChannelSettings(
                        id=channel_id,
                        name=channel.name,
                        kind=_channel_kind_from_destination(channel.apprise_url),
                        enabled=True,
                    )
                )
    except ValueError as exc:
        errors.append(str(exc))

    try:
        quiet_hours = ManagedNotificationQuietHoursSettings(
            timezone=_default_quiet_hours_timezone(environment)
        )
    except ValueError as exc:
        errors.append(str(exc))
        quiet_hours = ManagedNotificationQuietHoursSettings()

    return (
        ManagedNotificationSettings(
            channels=channels,
            routing=IncidentAlertRoutingPolicy(),
            quiet_hours=quiet_hours,
        ),
        channel_urls,
        "; ".join(errors) or None,
    )


def _load_persisted_settings(
    root_document: Mapping[str, object],
) -> tuple[ManagedNotificationSettings | None, str | None]:
    """Load and validate any persisted notification settings section."""
    raw_notifications = root_document.get(_ROOT_KEY_NOTIFICATIONS)
    if raw_notifications is None:
        return None, None
    if not isinstance(raw_notifications, Mapping):
        return None, "Persisted notifications settings must be a mapping."
    try:
        return (
            ManagedNotificationSettings.model_validate(
                normalize_mapping(raw_notifications)
            ),
            None,
        )
    except ValueError as exc:
        return None, f"Persisted notifications settings were invalid: {exc}"


def _parse_time_of_day(raw_value: str) -> time:
    """Parse one persisted quiet-hours ``HH:MM`` local-time string."""
    parts = raw_value.strip().split(":")
    if len(parts) != 2:
        msg = f"invalid quiet-hours time '{raw_value}'; expected HH:MM"
        raise ValueError(msg)
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        msg = f"invalid quiet-hours time '{raw_value}'; expected HH:MM"
        raise ValueError(msg) from exc
    if hour not in range(24) or minute not in range(60):
        msg = f"invalid quiet-hours time '{raw_value}'; expected HH:MM"
        raise ValueError(msg)
    return time(hour=hour, minute=minute)


def _channel_secret_reference(channel_id: str) -> str:
    """Return the stable vault reference for one notification destination."""
    return f"{_CHANNEL_SECRET_REF_PREFIX}:{channel_id}:destination"


def _normalize_optional_secret(secret_value: str | None) -> str | None:
    """Trim one optional write-only secret and collapse empty strings to ``None``."""
    if secret_value is None:
        return None
    stripped = secret_value.strip()
    return stripped or None


def _channel_kind_from_destination(destination: str) -> str:
    """Infer a stable non-secret channel kind from one Apprise destination URL."""
    scheme, separator, _ = destination.partition("://")
    if separator:
        return scheme.strip().casefold() or "apprise"
    return "apprise"


def _existing_channel_kind(
    *,
    channel_id: str,
    existing_channel: ManagedNotificationChannelSettings | None,
    bootstrap_channel_urls: Mapping[str, str],
) -> str:
    """Resolve the persisted or bootstrap kind for one channel without a replacement URL."""
    if existing_channel is not None:
        return existing_channel.kind
    bootstrap_destination = bootstrap_channel_urls.get(channel_id)
    if bootstrap_destination is not None:
        return _channel_kind_from_destination(bootstrap_destination)
    return "apprise"


def _default_quiet_hours_timezone(environment: Mapping[str, str]) -> str:
    """Return the default quiet-hours timezone for bootstrap settings."""
    return environment.get("TZ", "UTC").strip() or "UTC"
