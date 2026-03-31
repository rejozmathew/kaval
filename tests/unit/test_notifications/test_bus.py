"""Unit tests for the Apprise-backed notification bus."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import NotificationPayload, NotificationSourceType, Severity
from kaval.notifications.bus import (
    NotificationBus,
    NotificationBusConfig,
    NotificationChannelConfig,
    NotificationDeliveryStatus,
    load_notification_bus_config_from_env,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for notification tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_load_notification_bus_config_parses_multiple_urls() -> None:
    """Notification URLs should load from simple environment-driven configuration."""
    config = load_notification_bus_config_from_env(
        {
            "KAVAL_NOTIFICATION_URLS": (
                "mailto://alerts@example.com, discord://tokenA/tokenB\n"
                "ntfy://topic-name"
            )
        }
    )

    assert config is not None
    assert [channel.apprise_url for channel in config.channels] == [
        "mailto://alerts@example.com",
        "discord://tokenA/tokenB",
        "ntfy://topic-name",
    ]


def test_notification_bus_skips_when_not_configured() -> None:
    """The bus should no-op cleanly when no notification channels are enabled."""
    result = NotificationBus(config=None).send(build_payload())

    assert result.status == NotificationDeliveryStatus.SKIPPED
    assert result.attempted_channels == 0
    assert result.delivered_channels == 0


def test_notification_bus_adds_channels_and_sends_payload() -> None:
    """Configured Apprise channels should receive the incident payload title/body."""
    adapter = FakeAppriseAdapter()
    bus = NotificationBus(
        config=NotificationBusConfig(
            channels=[
                NotificationChannelConfig(
                    name="primary",
                    apprise_url="mailto://alerts@example.com",
                ),
                NotificationChannelConfig(
                    name="secondary",
                    apprise_url="discord://tokenA/tokenB",
                ),
            ]
        ),
        adapter_factory=lambda: adapter,
    )

    result = bus.send(build_payload())

    assert result.status == NotificationDeliveryStatus.SENT
    assert result.attempted_channels == 2
    assert result.delivered_channels == 2
    assert adapter.added_urls == [
        "mailto://alerts@example.com",
        "discord://tokenA/tokenB",
    ]
    assert adapter.notifications == [
        {
            "title": "Radarr and DelugeVPN degraded",
            "body": "Root cause likely DelugeVPN VPN tunnel dropped.",
        }
    ]


def test_notification_bus_reports_adapter_failures() -> None:
    """Adapter add/notify failures should be surfaced as failed delivery results."""
    adapter = FakeAppriseAdapter(
        rejected_urls={"mailto://alerts@example.com"},
        raise_on_notify=True,
    )
    bus = NotificationBus(
        config=NotificationBusConfig(
            channels=[
                NotificationChannelConfig(
                    name="mail",
                    apprise_url="mailto://alerts@example.com",
                ),
                NotificationChannelConfig(
                    name="discord",
                    apprise_url="discord://tokenA/tokenB",
                ),
            ]
        ),
        adapter_factory=lambda: adapter,
    )

    result = bus.send(build_payload())

    assert result.status == NotificationDeliveryStatus.FAILED
    assert result.attempted_channels == 2
    assert result.delivered_channels == 0
    assert result.failed_channels == ["mail", "discord"]


class FakeAppriseAdapter:
    """Deterministic Apprise test double."""

    def __init__(
        self,
        *,
        rejected_urls: set[str] | None = None,
        notify_result: bool = True,
        raise_on_notify: bool = False,
    ) -> None:
        """Store the fake adapter behavior."""
        self._rejected_urls = rejected_urls or set()
        self._notify_result = notify_result
        self._raise_on_notify = raise_on_notify
        self.added_urls: list[str] = []
        self.notifications: list[dict[str, str]] = []

    def add(self, servers: str) -> bool:
        """Accept or reject one configured URL."""
        self.added_urls.append(servers)
        return servers not in self._rejected_urls

    def notify(self, *, title: str, body: str) -> bool:
        """Capture the notification payload or simulate an adapter failure."""
        self.notifications.append({"title": title, "body": body})
        if self._raise_on_notify:
            raise RuntimeError("simulated notify failure")
        return self._notify_result


def build_payload() -> NotificationPayload:
    """Build a representative incident-level notification payload."""
    return NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id="inc-delugevpn",
        incident_id="inc-delugevpn",
        severity=Severity.HIGH,
        title="Radarr and DelugeVPN degraded",
        summary="Download pipeline blocked.",
        body="Root cause likely DelugeVPN VPN tunnel dropped.",
        evidence_lines=[
            'DelugeVPN logs: "VPN tunnel inactive"',
            'Radarr: "Download client not available"',
        ],
        recommended_action="Restart DelugeVPN",
        action_buttons=[],
        dedup_key="incident:inc-delugevpn",
        created_at=ts(14, 30),
    )
