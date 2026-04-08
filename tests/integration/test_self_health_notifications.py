"""Integration tests for Kaval self-health notifications."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import NotificationPayload
from kaval.notifications.bus import NotificationDeliveryResult, NotificationDeliveryStatus
from kaval.notifications.self_health import (
    SelfHealthNotificationDispatcher,
    SelfHealthNotificationPolicy,
)
from kaval.runtime import (
    CapabilityHealthDisplayState,
    CapabilityHealthLayer,
    CapabilityHealthReport,
    CapabilityHealthStatus,
    CapabilityLayerReport,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for self-health tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_critical_self_health_issue_sends_by_default() -> None:
    """Critical self-health issues should notify even without opt-in changes."""
    sender = FakeNotificationSender()
    dispatcher = SelfHealthNotificationDispatcher(sender=sender)

    results = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Database health is critical.",
            detail="SQLite reported corruption.",
        ),
        now=ts(8, 0),
    )

    assert len(results) == 1
    assert results[0].status == "sent"
    assert len(sender.payloads) == 1
    assert sender.payloads[0].severity == "critical"
    assert sender.payloads[0].source_id == "capability:database"


def test_degraded_self_health_issue_is_opt_in() -> None:
    """Degraded self-health should stay silent until explicitly enabled."""
    sender = FakeNotificationSender()
    dispatcher = SelfHealthNotificationDispatcher(sender=sender)

    skipped = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Notification channels are degraded.",
            detail="Telegram delivery failed.",
        ),
        now=ts(8, 10),
    )
    enabled = SelfHealthNotificationDispatcher(
        sender=sender,
        policy=SelfHealthNotificationPolicy(
            critical_enabled=True,
            degraded_enabled=True,
        ),
    ).dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Notification channels are degraded.",
            detail="Telegram delivery failed.",
        ),
        now=ts(8, 15),
    )

    assert skipped[0].status == "skipped"
    assert enabled[0].status == "sent"
    assert len(sender.payloads) == 1
    assert sender.payloads[0].severity == "high"


def test_self_health_notifications_dedup_until_recovery() -> None:
    """Repeated unchanged issues should not resend until the layer recovers."""
    sender = FakeNotificationSender()
    dispatcher = SelfHealthNotificationDispatcher(sender=sender)

    first = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Database health is critical.",
            detail="SQLite reported corruption.",
        ),
        now=ts(8, 20),
    )
    repeated = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Database health is critical.",
            detail="SQLite reported corruption.",
        ),
        now=ts(8, 25),
    )
    recovered = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.HEALTHY,
            summary="Database is healthy.",
            detail="No issue remains.",
        ),
        now=ts(8, 30),
    )
    regressed = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Database health is critical.",
            detail="SQLite reported corruption.",
        ),
        now=ts(8, 35),
    )

    assert first[0].status == "sent"
    assert repeated[0].status == "skipped"
    assert recovered == []
    assert regressed[0].status == "sent"
    assert len(sender.payloads) == 2


def test_global_maintenance_only_suppresses_non_critical_self_health() -> None:
    """Critical self-health must still notify through global maintenance."""
    sender = FakeNotificationSender()
    dispatcher = SelfHealthNotificationDispatcher(
        sender=sender,
        policy=SelfHealthNotificationPolicy(
            critical_enabled=True,
            degraded_enabled=True,
        ),
    )

    suppressed = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Notification channels are degraded.",
            detail="Telegram delivery failed.",
        ),
        now=ts(8, 40),
        global_maintenance_active=True,
    )
    critical = dispatcher.dispatch_report(
        build_report(
            layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Executor process is critical.",
            detail="Executor socket is unreachable.",
        ),
        now=ts(8, 45),
        global_maintenance_active=True,
    )

    assert suppressed[0].status == "suppressed"
    assert critical[0].status == "sent"
    assert len(sender.payloads) == 1


class FakeNotificationSender:
    """Deterministic sender that captures self-health payloads."""

    def __init__(self) -> None:
        """Initialize the captured payload list."""
        self.payloads: list[NotificationPayload] = []

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Capture one payload and report a successful delivery."""
        self.payloads.append(payload)
        return NotificationDeliveryResult(
            status=NotificationDeliveryStatus.SENT,
            attempted_channels=1,
            delivered_channels=1,
            failed_channels=[],
            detail="sent",
        )


def build_report(
    *,
    layer: CapabilityHealthLayer,
    status: CapabilityHealthStatus,
    summary: str,
    detail: str,
) -> CapabilityHealthReport:
    """Build a minimal capability-health report for self-health notification tests."""
    return CapabilityHealthReport(
        checked_at=ts(8, 0),
        overall_status=status,
        layers=[
                CapabilityLayerReport(
                    layer=layer,
                    status=status,
                    display_state=CapabilityHealthDisplayState.UNAVAILABLE
                    if status == CapabilityHealthStatus.CRITICAL
                    else CapabilityHealthDisplayState.DEGRADED
                    if status == CapabilityHealthStatus.DEGRADED
                    else CapabilityHealthDisplayState.HEALTHY,
                summary=summary,
                detail=detail,
                user_impact="Kaval capability is affected.",
                guidance="Restore the degraded layer.",
                metadata={},
            )
        ],
    )
