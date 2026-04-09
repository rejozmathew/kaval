"""Unit tests for persisted notification settings."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.credentials import CredentialVault
from kaval.database import KavalDatabase
from kaval.notifications.routing import IncidentAlertRoute, IncidentAlertRoutingPolicy
from kaval.settings.notification_config import (
    ManagedNotificationQuietHoursSettings,
    NotificationChannelWrite,
    NotificationSettingsService,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for notification-settings tests."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


def test_notification_settings_service_persists_channels_and_quiet_hours(
    tmp_path: Path,
) -> None:
    """Notification settings should stage, persist, resolve, and later apply updates."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()
    settings_path.write_text("models:\n  local:\n    enabled: false\n", encoding="utf-8")

    vault = CredentialVault(database_path=database_path, auto_lock_minutes=5)
    vault.unlock("correct horse battery staple", now=ts(10, 0))

    service = NotificationSettingsService(
        settings_path=settings_path,
        environment={
            "KAVAL_NOTIFICATION_URLS": "ntfy://bootstrap-topic",
            "TZ": "UTC",
        },
    )

    assert service.active_snapshot().channels[0].id == "env-channel-1"
    assert service.active_snapshot().channels[0].kind == "ntfy"
    assert service.apply_required() is False

    service.update_staged(
        channels=[
            NotificationChannelWrite(
                id="env-channel-1",
                name="Bootstrap Ntfy",
                enabled=True,
            ),
            NotificationChannelWrite(
                name="Discord Alerts",
                enabled=True,
                destination="discord://tokenA/tokenB",
            ),
        ],
        routing=IncidentAlertRoutingPolicy(
            critical=IncidentAlertRoute.IMMEDIATE,
            high=IncidentAlertRoute.IMMEDIATE_WITH_DEDUP,
            medium=IncidentAlertRoute.HOURLY_DIGEST,
            low=IncidentAlertRoute.DASHBOARD_ONLY,
            dedup_window_minutes=20,
            digest_window_minutes=30,
        ),
        quiet_hours=ManagedNotificationQuietHoursSettings(
            enabled=True,
            start_time_local="22:00",
            end_time_local="07:00",
            timezone="UTC",
        ),
        vault=vault,
        now=ts(10, 1),
    )

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "discord://tokenA/tokenB" not in persisted_text
    assert "models:" in persisted_text
    assert "Bootstrap Ntfy" in persisted_text
    assert service.apply_required() is True
    assert service.configured_channel_count(scope="staged") == 2

    vault.unlock("correct horse battery staple")
    resolved = service.resolve_bus_config(scope="staged", vault=vault)
    assert resolved is not None
    assert [channel.name for channel in resolved.channels] == [
        "Bootstrap Ntfy",
        "Discord Alerts",
    ]
    assert [channel.apprise_url for channel in resolved.channels] == [
        "ntfy://bootstrap-topic",
        "discord://tokenA/tokenB",
    ]

    context = service.build_routing_context(scope="staged", now=ts(23, 0))
    assert context.quiet_hours_until == datetime(2026, 4, 9, 7, 0, tzinfo=UTC)

    service.apply(now=ts(10, 2))

    assert service.apply_required() is False
    assert service.last_applied_at == ts(10, 2)
