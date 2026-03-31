"""Incident-grouped notification dispatch for Phase 2A."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from kaval.models import Incident, Investigation, KavalModel, NotificationPayload
from kaval.notifications.bus import NotificationDeliveryResult, NotificationDeliveryStatus
from kaval.notifications.formatter import format_incident_notification


class NotificationSender(Protocol):
    """The minimal send surface required by the grouped dispatcher."""

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Send one formatted notification payload."""


class IncidentNotificationDispatchStatus(StrEnum):
    """Grouped-dispatch outcomes for one incident notification attempt."""

    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"


class IncidentNotificationDispatchResult(KavalModel):
    """The outcome of dispatching one incident notification."""

    status: IncidentNotificationDispatchStatus
    payload: NotificationPayload
    delivery: NotificationDeliveryResult
    detail: str


@dataclass(slots=True)
class IncidentNotificationDispatcher:
    """Send at most one notification per incident inside the dedup window."""

    sender: NotificationSender
    dedup_window: timedelta = timedelta(minutes=15)
    _last_sent_at: dict[str, datetime] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        """Reject non-positive dedup windows."""
        if self.dedup_window <= timedelta(0):
            msg = "dedup_window must be positive"
            raise ValueError(msg)

    def dispatch(
        self,
        *,
        incident: Incident,
        investigation: Investigation,
        now: datetime | None = None,
    ) -> IncidentNotificationDispatchResult:
        """Format and send one incident notification unless it is within the dedup window."""
        effective_now = now or datetime.now(tz=UTC)
        payload = format_incident_notification(
            incident=incident,
            investigation=investigation,
            now=effective_now,
        )
        last_sent_at = self._last_sent_at.get(payload.dedup_key)
        if last_sent_at is not None and effective_now - last_sent_at < self.dedup_window:
            return IncidentNotificationDispatchResult(
                status=IncidentNotificationDispatchStatus.SKIPPED,
                payload=payload,
                delivery=NotificationDeliveryResult(
                    status=NotificationDeliveryStatus.SKIPPED,
                    attempted_channels=0,
                    delivered_channels=0,
                    failed_channels=[],
                    detail="Incident notification suppressed by dedup window.",
                ),
                detail="Incident notification suppressed by dedup window.",
            )

        delivery = self.sender.send(payload)
        dispatch_status = _dispatch_status(delivery.status)
        if dispatch_status == IncidentNotificationDispatchStatus.SENT:
            self._last_sent_at[payload.dedup_key] = effective_now

        return IncidentNotificationDispatchResult(
            status=dispatch_status,
            payload=payload,
            delivery=delivery,
            detail=delivery.detail,
        )


def _dispatch_status(
    delivery_status: NotificationDeliveryStatus,
) -> IncidentNotificationDispatchStatus:
    """Translate bus-level outcomes into grouped-dispatch outcomes."""
    if delivery_status == NotificationDeliveryStatus.SENT:
        return IncidentNotificationDispatchStatus.SENT
    if delivery_status == NotificationDeliveryStatus.FAILED:
        return IncidentNotificationDispatchStatus.FAILED
    return IncidentNotificationDispatchStatus.SKIPPED
