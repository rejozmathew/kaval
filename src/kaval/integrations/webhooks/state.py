"""Persistent state models for normalized webhook deduplication."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from kaval.integrations.webhooks.models import WebhookAlertState, WebhookSourceType
from kaval.models import KavalModel, NonNegativeInt


class WebhookEventTransition(StrEnum):
    """Deduplication outcomes for one normalized webhook event."""

    PROCESS = "process"
    DUPLICATE = "duplicate"
    RESOLVE = "resolve"
    REOPEN = "reopen"


class WebhookEventStateRecord(KavalModel):
    """Persisted dedup/resolution state for one source-specific webhook key."""

    state_key: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    source_type: WebhookSourceType
    dedup_key: str = Field(min_length=1)
    last_event_id: str = Field(min_length=1)
    last_source_event_id: str | None = Field(default=None, min_length=1)
    last_received_at: datetime
    last_alert_state: WebhookAlertState
    active: bool
    active_since: datetime | None = None
    resolved_at: datetime | None = None
    last_processed_at: datetime | None = None
    duplicate_count: int = NonNegativeInt
    flap_count: int = NonNegativeInt

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        """Keep active/resolved webhook state transitions coherent."""
        if self.active and self.last_alert_state != WebhookAlertState.FIRING:
            msg = "active webhook state must have last_alert_state=firing"
            raise ValueError(msg)
        if self.active and self.active_since is None:
            msg = "active webhook state requires active_since"
            raise ValueError(msg)
        if self.active and self.resolved_at is not None:
            msg = "active webhook state cannot include resolved_at"
            raise ValueError(msg)
        if not self.active and self.last_alert_state != WebhookAlertState.RESOLVED:
            msg = "inactive webhook state must have last_alert_state=resolved"
            raise ValueError(msg)
        if not self.active and self.resolved_at is None:
            msg = "inactive webhook state requires resolved_at"
            raise ValueError(msg)
        if self.last_processed_at is not None and self.last_processed_at > self.last_received_at:
            msg = "last_processed_at cannot be later than last_received_at"
            raise ValueError(msg)
        return self


def build_webhook_state_key(*, source_id: str, dedup_key: str) -> str:
    """Return the stable persistence key for one source-specific dedup entry."""
    return f"{source_id}:{dedup_key}"
