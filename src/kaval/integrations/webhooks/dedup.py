"""Deduplication and resolution handling for normalized webhook events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from kaval.database import KavalDatabase
from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookEvent,
    WebhookProcessingStatus,
)
from kaval.integrations.webhooks.state import (
    WebhookEventStateRecord,
    WebhookEventTransition,
    build_webhook_state_key,
)
from kaval.models import KavalModel


class WebhookDedupResult(KavalModel):
    """The outcome of applying dedup/resolution logic to one webhook event."""

    event: WebhookEvent
    transition: WebhookEventTransition
    should_process: bool
    state_record: WebhookEventStateRecord


@dataclass(slots=True)
class WebhookEventDeduplicator:
    """Persist source-specific webhook state and suppress duplicate processing."""

    dedup_window: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        """Reject non-positive dedup windows."""
        if self.dedup_window <= timedelta(0):
            msg = "dedup_window must be positive"
            raise ValueError(msg)

    def apply(
        self,
        *,
        database: KavalDatabase,
        event: WebhookEvent,
        now: datetime | None = None,
    ) -> WebhookDedupResult:
        """Apply dedup/resolution handling and persist the updated state."""
        effective_now = now or event.received_at or datetime.now(tz=UTC)
        state_key = build_webhook_state_key(
            source_id=event.source_id,
            dedup_key=event.dedup_key,
        )
        existing = database.get_webhook_event_state(state_key)

        if existing is None:
            transition = (
                WebhookEventTransition.RESOLVE
                if event.alert_state == WebhookAlertState.RESOLVED
                else WebhookEventTransition.PROCESS
            )
            state_record = _new_state_record(
                state_key=state_key,
                event=event,
                processed_at=effective_now,
            )
        else:
            transition, state_record = _transition_state(
                existing=existing,
                event=event,
                dedup_window=self.dedup_window,
                processed_at=effective_now,
            )

        database.upsert_webhook_event_state(state_record)
        updated_event = _event_with_transition(event=event, transition=transition)
        return WebhookDedupResult(
            event=updated_event,
            transition=transition,
            should_process=transition != WebhookEventTransition.DUPLICATE,
            state_record=state_record,
        )


def _new_state_record(
    *,
    state_key: str,
    event: WebhookEvent,
    processed_at: datetime,
) -> WebhookEventStateRecord:
    """Create the initial persisted state for one webhook dedup key."""
    if event.alert_state == WebhookAlertState.FIRING:
        return WebhookEventStateRecord(
            state_key=state_key,
            source_id=event.source_id,
            source_type=event.source_type,
            dedup_key=event.dedup_key,
            last_event_id=event.id,
            last_source_event_id=event.source_event_id,
            last_received_at=event.received_at,
            last_alert_state=WebhookAlertState.FIRING,
            active=True,
            active_since=event.received_at,
            resolved_at=None,
            last_processed_at=processed_at,
            duplicate_count=0,
            flap_count=0,
        )
    return WebhookEventStateRecord(
        state_key=state_key,
        source_id=event.source_id,
        source_type=event.source_type,
        dedup_key=event.dedup_key,
        last_event_id=event.id,
        last_source_event_id=event.source_event_id,
        last_received_at=event.received_at,
        last_alert_state=WebhookAlertState.RESOLVED,
        active=False,
        active_since=None,
        resolved_at=event.received_at,
        last_processed_at=processed_at,
        duplicate_count=0,
        flap_count=0,
    )


def _transition_state(
    *,
    existing: WebhookEventStateRecord,
    event: WebhookEvent,
    dedup_window: timedelta,
    processed_at: datetime,
) -> tuple[WebhookEventTransition, WebhookEventStateRecord]:
    """Return the transition and updated state for one subsequent webhook event."""
    within_window = event.received_at - existing.last_received_at <= dedup_window
    common_updates = {
        "last_event_id": event.id,
        "last_source_event_id": event.source_event_id,
        "last_received_at": event.received_at,
    }

    if event.alert_state == existing.last_alert_state and within_window:
        return (
            WebhookEventTransition.DUPLICATE,
            existing.model_copy(
                update={
                    **common_updates,
                    "duplicate_count": existing.duplicate_count + 1,
                }
            ),
        )

    if event.alert_state == WebhookAlertState.RESOLVED:
        return (
            WebhookEventTransition.RESOLVE,
            existing.model_copy(
                update={
                    **common_updates,
                    "last_alert_state": WebhookAlertState.RESOLVED,
                    "active": False,
                    "active_since": None,
                    "resolved_at": event.received_at,
                    "last_processed_at": processed_at,
                }
            ),
        )

    reopened_from_recent_resolution = (
        existing.last_alert_state == WebhookAlertState.RESOLVED
        and existing.resolved_at is not None
        and event.received_at - existing.resolved_at <= dedup_window
    )
    transition = (
        WebhookEventTransition.REOPEN
        if existing.last_alert_state == WebhookAlertState.RESOLVED
        else WebhookEventTransition.PROCESS
    )
    return (
        transition,
        existing.model_copy(
            update={
                **common_updates,
                "last_alert_state": WebhookAlertState.FIRING,
                "active": True,
                "active_since": event.received_at,
                "resolved_at": None,
                "last_processed_at": processed_at,
                "flap_count": (
                    existing.flap_count + 1
                    if reopened_from_recent_resolution
                    else existing.flap_count
                ),
            }
        ),
    )


def _event_with_transition(
    *,
    event: WebhookEvent,
    transition: WebhookEventTransition,
) -> WebhookEvent:
    """Return the event annotated with its dedup-processing outcome."""
    processing_status = (
        WebhookProcessingStatus.DUPLICATE
        if transition == WebhookEventTransition.DUPLICATE
        else WebhookProcessingStatus.NEW
    )
    return event.model_copy(update={"processing_status": processing_status})
