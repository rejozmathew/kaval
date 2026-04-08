"""Unit tests for Uptime Kuma webhook normalization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers import normalize_uptime_kuma_payload

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for normalizer tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_uptime_kuma_down_payload_normalizes_to_firing_event() -> None:
    """Down payloads should normalize into a firing webhook event."""
    payload = load_fixture("uptime_kuma_down.json")

    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=payload,
        received_at=ts(15),
    )

    assert event.source_type == WebhookSourceType.UPTIME_KUMA
    assert event.source_id == "uptime_kuma"
    assert event.source_event_id == "10:2026-04-07T14:06:38.000Z:0"
    assert event.dedup_key == "monitor:10"
    assert event.received_at == ts(15)
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.severity == WebhookSeverity.HIGH
    assert event.title == "Immich is down"
    assert event.body == "[Immich] [DOWN] PING immich.example.com failed after 3 retries."
    assert event.url == "https://immich.example.com/health"
    assert event.service_hints == ["Immich", "immich", "immich.example.com"]
    assert event.tags["monitor_id"] == "10"
    assert event.tags["monitor_type"] == "http"
    assert event.tags["heartbeat_status"] == "down"
    assert event.tags["tag:media"] == "true"
    assert event.tags["tag:external"] == "#ffcc00"
    assert event.raw_payload_redacted is True
    assert event.raw_payload["monitor"]["name"] == "Immich"


def test_uptime_kuma_up_payload_normalizes_to_resolved_event() -> None:
    """Up payloads should normalize into a resolved webhook event."""
    payload = load_fixture("uptime_kuma_up.json")

    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=payload,
        received_at=ts(15, 1),
    )

    assert event.source_event_id == "10:2026-04-07T14:08:05.000Z:1"
    assert event.dedup_key == "monitor:10"
    assert event.alert_state == WebhookAlertState.RESOLVED
    assert event.severity == WebhookSeverity.INFO
    assert event.title == "Immich recovered"
    assert event.body == "[Immich] [UP] OK"
    assert event.tags["heartbeat_status"] == "up"
    assert event.tags["heartbeat_duration_seconds"] == "27"


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
