"""Apprise-backed notification bus for incident-level delivery."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Protocol, cast

from pydantic import Field

from kaval.models import KavalModel, NotificationPayload


class NotificationDeliveryStatus(StrEnum):
    """Outcomes reported by the notification bus."""

    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"


class NotificationChannelConfig(KavalModel):
    """One configured Apprise destination for incident notifications."""

    name: str
    apprise_url: str


class NotificationBusConfig(KavalModel):
    """Runtime configuration for the Apprise-backed notification bus."""

    channels: list[NotificationChannelConfig] = Field(default_factory=list)


class NotificationDeliveryResult(KavalModel):
    """The outcome of one notification-bus send attempt."""

    status: NotificationDeliveryStatus
    attempted_channels: int = Field(ge=0)
    delivered_channels: int = Field(ge=0)
    failed_channels: list[str] = Field(default_factory=list)
    detail: str


class AppriseAdapter(Protocol):
    """The small adapter surface the bus uses from Apprise."""

    def add(self, servers: str) -> bool:
        """Register one Apprise destination."""

    def notify(self, *, title: str, body: str) -> bool:
        """Send one notification to all configured destinations."""


@dataclass(frozen=True, slots=True)
class NotificationBus:
    """Send incident-level notification payloads through Apprise."""

    config: NotificationBusConfig | None = None
    adapter_factory: Callable[[], AppriseAdapter] | None = None

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Deliver one notification payload or skip cleanly when the bus is disabled."""
        if self.config is None or not self.config.channels:
            return NotificationDeliveryResult(
                status=NotificationDeliveryStatus.SKIPPED,
                attempted_channels=0,
                delivered_channels=0,
                failed_channels=[],
                detail="Notification bus is not configured.",
            )

        adapter = self._adapter_factory()
        added_channel_names: list[str] = []
        failed_channel_names: list[str] = []
        for channel in self.config.channels:
            if adapter.add(channel.apprise_url):
                added_channel_names.append(channel.name)
                continue
            failed_channel_names.append(channel.name)

        if not added_channel_names:
            return NotificationDeliveryResult(
                status=NotificationDeliveryStatus.FAILED,
                attempted_channels=len(self.config.channels),
                delivered_channels=0,
                failed_channels=failed_channel_names,
                detail="No notification channels could be registered with Apprise.",
            )

        try:
            delivered = adapter.notify(title=payload.title, body=payload.body)
        except Exception:
            return NotificationDeliveryResult(
                status=NotificationDeliveryStatus.FAILED,
                attempted_channels=len(self.config.channels),
                delivered_channels=0,
                failed_channels=[
                    *failed_channel_names,
                    *[
                        channel_name
                        for channel_name in added_channel_names
                        if channel_name not in failed_channel_names
                    ],
                ],
                detail="Apprise notification delivery raised an exception.",
            )

        if not delivered:
            return NotificationDeliveryResult(
                status=NotificationDeliveryStatus.FAILED,
                attempted_channels=len(self.config.channels),
                delivered_channels=0,
                failed_channels=[*failed_channel_names, *added_channel_names],
                detail="Apprise notification delivery returned failure.",
            )

        return NotificationDeliveryResult(
            status=NotificationDeliveryStatus.SENT,
            attempted_channels=len(self.config.channels),
            delivered_channels=len(added_channel_names),
            failed_channels=failed_channel_names,
            detail="Notification delivered through Apprise.",
        )

    def _adapter_factory(self) -> AppriseAdapter:
        """Create the configured adapter or the production default adapter."""
        factory = self.adapter_factory or _default_adapter_factory
        return factory()


def load_notification_bus_config_from_env(
    env: Mapping[str, str] | None = None,
) -> NotificationBusConfig | None:
    """Load an optional notification-bus config from the environment."""
    source = env or os.environ
    enabled = source.get("KAVAL_NOTIFICATION_ENABLED", "").strip().casefold()
    if enabled in {"0", "false", "no"}:
        return None

    urls_raw = source.get("KAVAL_NOTIFICATION_URLS", "")
    urls = _split_notification_urls(urls_raw)
    if not urls:
        return None

    return NotificationBusConfig(
        channels=[
            NotificationChannelConfig(
                name=f"channel-{index}",
                apprise_url=url,
            )
            for index, url in enumerate(urls, start=1)
        ]
    )


def _split_notification_urls(raw_value: str) -> list[str]:
    """Split comma- or newline-delimited Apprise URLs."""
    normalized = raw_value.replace("\n", ",")
    return [part.strip() for part in normalized.split(",") if part.strip()]


def _default_adapter_factory() -> AppriseAdapter:
    """Create a real Apprise adapter lazily so tests can inject doubles."""
    import apprise

    return cast(AppriseAdapter, apprise.Apprise())
