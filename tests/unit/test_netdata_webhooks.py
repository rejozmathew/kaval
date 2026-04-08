"""Unit tests for Netdata webhook normalization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers import normalize_netdata_payload

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for normalizer tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_netdata_critical_alarm_normalizes_to_firing_event() -> None:
    """Critical Netdata alarms should normalize into firing webhook events."""
    payload = load_fixture("netdata_alarm_critical.json")
    expected_dedup_key = "alarm:ImmichCPUHigh:cgroup.immich_cpu:cgroup.cpu:containers"

    event = normalize_netdata_payload(
        source_id="netdata",
        payload=payload,
        received_at=ts(18, 3),
    )

    assert event.source_type == WebhookSourceType.NETDATA
    assert event.source_id == "netdata"
    assert event.dedup_key == expected_dedup_key
    assert event.source_event_id == f"{expected_dedup_key}:critical:2026-04-07T18:03:00Z"
    assert event.received_at == ts(18, 3)
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.severity == WebhookSeverity.CRITICAL
    assert event.title == "ImmichCPUHigh is critical"
    assert event.body == "Immich CPU usage triggered a critical Netdata alarm."
    assert (
        event.url
        == "https://app.netdata.cloud/spaces/homelab/rooms/apps/alerts/immich-cpu?access_token=secret-1"
    )
    assert event.service_hints == [
        "cgroup.immich_cpu",
        "cgroup.cpu",
        "containers",
        "app.netdata.cloud",
    ]
    assert event.tags["class"] == "System"
    assert event.tags["rooms"] == "Apps"
    assert event.tags["additional_active_critical_alerts"] == "1"
    assert event.raw_payload_redacted is True
    alert_url = event.raw_payload["alert_url"]
    assert isinstance(alert_url, str)
    assert "secret-1" not in alert_url


def test_netdata_clear_alarm_normalizes_to_resolved_event() -> None:
    """Clear Netdata alarms should normalize into resolved webhook events."""
    payload = load_fixture("netdata_alarm_clear.json")
    expected_dedup_key = "alarm:ImmichCPUHigh:cgroup.immich_cpu:cgroup.cpu:containers"

    event = normalize_netdata_payload(
        source_id="netdata",
        payload=payload,
        received_at=ts(18, 7),
    )

    assert event.source_event_id == f"{expected_dedup_key}:clear:2026-04-07T18:07:00Z"
    assert event.alert_state == WebhookAlertState.RESOLVED
    assert event.severity == WebhookSeverity.INFO
    assert event.title == "ImmichCPUHigh cleared"
    assert event.body == "CPU usage on immich returned to normal."
    assert event.tags["severity"] == "clear"
    assert event.tags["additional_active_warning_alerts"] == "1"


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
