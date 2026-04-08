"""Unit tests for webhook deduplication state models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kaval.integrations.webhooks.models import WebhookAlertState, WebhookSourceType
from kaval.integrations.webhooks.state import WebhookEventStateRecord, build_webhook_state_key


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for webhook-dedup tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_build_webhook_state_key_keeps_source_scope_explicit() -> None:
    """Dedup state keys should preserve the source identity boundary."""
    assert (
        build_webhook_state_key(source_id="uptime_kuma", dedup_key="heartbeat-1")
        == "uptime_kuma:heartbeat-1"
    )


def test_webhook_event_state_record_rejects_inconsistent_active_flags() -> None:
    """Persisted webhook dedup state should keep active and resolved fields coherent."""
    with pytest.raises(ValidationError):
        WebhookEventStateRecord(
            state_key="uptime_kuma:heartbeat-1",
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            dedup_key="heartbeat-1",
            last_event_id="whk-1",
            last_source_event_id="heartbeat-1",
            last_received_at=ts(12),
            last_alert_state=WebhookAlertState.RESOLVED,
            active=True,
            active_since=ts(12),
            resolved_at=None,
            last_processed_at=ts(12),
            duplicate_count=0,
            flap_count=0,
        )
