"""Integration tests for webhook deduplication and resolution persistence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.integrations.webhooks.dedup import WebhookEventDeduplicator
from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookEvent,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.state import WebhookEventTransition


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for webhook-dedup integration tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_deduplicator_marks_duplicates_without_reprocessing(tmp_path: Path) -> None:
    """A second firing event inside the dedup window should be recorded as a duplicate."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    deduplicator = WebhookEventDeduplicator()
    first_event = build_event(
        event_id="whk-1",
        source_event_id="heartbeat-1",
        received_at=ts(12, 0),
        alert_state=WebhookAlertState.FIRING,
    )
    duplicate_event = build_event(
        event_id="whk-2",
        source_event_id="heartbeat-1-retry",
        received_at=ts(12, 5),
        alert_state=WebhookAlertState.FIRING,
    )
    try:
        first_result = deduplicator.apply(database=database, event=first_event)
        duplicate_result = deduplicator.apply(database=database, event=duplicate_event)
        state_record = database.list_webhook_event_states()[0]
    finally:
        database.close()

    assert first_result.transition == WebhookEventTransition.PROCESS
    assert first_result.should_process is True
    assert duplicate_result.transition == WebhookEventTransition.DUPLICATE
    assert duplicate_result.should_process is False
    assert duplicate_result.event.processing_status == "duplicate"
    assert state_record.duplicate_count == 1
    assert state_record.last_event_id == "whk-2"
    assert state_record.last_processed_at == ts(12, 0)


def test_webhook_deduplicator_applies_resolution_and_flap_reopen_transitions(
    tmp_path: Path,
) -> None:
    """A resolve followed by a quick firing event should reopen deterministically."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    deduplicator = WebhookEventDeduplicator()
    firing_event = build_event(
        event_id="whk-1",
        source_event_id="alert-1",
        received_at=ts(13, 0),
        alert_state=WebhookAlertState.FIRING,
    )
    resolved_event = build_event(
        event_id="whk-2",
        source_event_id="alert-1-resolved",
        received_at=ts(13, 1),
        alert_state=WebhookAlertState.RESOLVED,
    )
    reopened_event = build_event(
        event_id="whk-3",
        source_event_id="alert-1-reopen",
        received_at=ts(13, 2),
        alert_state=WebhookAlertState.FIRING,
    )
    try:
        deduplicator.apply(database=database, event=firing_event)
        resolved_result = deduplicator.apply(database=database, event=resolved_event)
        reopened_result = deduplicator.apply(database=database, event=reopened_event)
        state_record = database.list_webhook_event_states()[0]
    finally:
        database.close()

    assert resolved_result.transition == WebhookEventTransition.RESOLVE
    assert resolved_result.should_process is True
    assert resolved_result.state_record.active is False
    assert resolved_result.state_record.resolved_at == ts(13, 1)

    assert reopened_result.transition == WebhookEventTransition.REOPEN
    assert reopened_result.should_process is True
    assert reopened_result.state_record.active is True
    assert reopened_result.state_record.resolved_at is None
    assert state_record.flap_count == 1
    assert state_record.active_since == ts(13, 2)


def test_webhook_deduplicator_reprocesses_same_state_outside_window(tmp_path: Path) -> None:
    """A repeated firing event outside the dedup window should re-enter processing."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    deduplicator = WebhookEventDeduplicator(dedup_window=timedelta(minutes=15))
    first_event = build_event(
        event_id="whk-1",
        source_event_id="alert-1",
        received_at=ts(14, 0),
        alert_state=WebhookAlertState.FIRING,
    )
    later_event = build_event(
        event_id="whk-2",
        source_event_id="alert-1-later",
        received_at=ts(14, 20),
        alert_state=WebhookAlertState.FIRING,
    )
    try:
        deduplicator.apply(database=database, event=first_event)
        later_result = deduplicator.apply(database=database, event=later_event)
        state_record = database.list_webhook_event_states()[0]
    finally:
        database.close()

    assert later_result.transition == WebhookEventTransition.PROCESS
    assert later_result.should_process is True
    assert state_record.duplicate_count == 0
    assert state_record.last_processed_at == ts(14, 20)


def build_event(
    *,
    event_id: str,
    source_event_id: str,
    received_at: datetime,
    alert_state: WebhookAlertState,
) -> WebhookEvent:
    """Build a minimal normalized webhook event for dedup tests."""
    return WebhookEvent(
        id=event_id,
        source_type=WebhookSourceType.UPTIME_KUMA,
        source_id="uptime_kuma",
        source_event_id=source_event_id,
        dedup_key="uptime-kuma:immich",
        received_at=received_at,
        alert_state=alert_state,
        severity=WebhookSeverity.HIGH,
        title="Immich down",
        body="Monitor reported service unavailable.",
        tags={"monitor": "Immich"},
        service_hints=["Immich"],
        raw_payload={"status": "down"},
        raw_payload_redacted=True,
    )
