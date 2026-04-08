"""Unit tests for Alertmanager webhook normalization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers import normalize_alertmanager_payload

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for normalizer tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_alertmanager_group_firing_payload_preserves_multi_service_hints() -> None:
    """Grouped firing payloads should preserve later-matchable multi-service data."""
    payload = load_fixture("alertmanager_firing_group.json")
    expected_group_key = (
        'group:{}/{alertname="SharedStorageLatency",cluster="homelab"}:'
        '{alertname="SharedStorageLatency",cluster="homelab"}'
    )

    event = normalize_alertmanager_payload(
        source_id="prometheus_alertmanager",
        payload=payload,
        received_at=ts(17, 11),
    )

    assert event.source_type == WebhookSourceType.PROMETHEUS_ALERTMANAGER
    assert event.source_id == "prometheus_alertmanager"
    assert event.dedup_key == expected_group_key
    assert (
        event.source_event_id
        == f"{expected_group_key}:firing:2026-04-07T17:10:20Z"
    )
    assert event.received_at == ts(17, 11)
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.severity == WebhookSeverity.MEDIUM
    assert event.title == "SharedStorageLatency firing (2 alerts)"
    assert event.body == "Shared storage latency is elevated for multiple services."
    assert (
        event.url
        == "https://prometheus.example.com/graph?g0.expr=immich_io_latency_seconds&auth_token=secret-1"
    )
    assert event.service_hints == [
        "immich",
        "immich-api",
        "immich.example.com:443",
        "immich.example.com",
        "redis",
        "redis.example.com:6379",
        "redis.example.com",
    ]
    assert event.tags["group_service_count"] == "2"
    assert event.tags["group_services"] == "immich,redis"
    assert event.tags["label:severity"] == "warning"
    assert event.tags["group_label:cluster"] == "homelab"
    assert event.raw_payload_redacted is True
    generator_url = event.raw_payload["alerts"][0]["generatorURL"]
    assert isinstance(generator_url, str)
    assert "secret-1" not in generator_url


def test_alertmanager_group_resolved_payload_uses_resolved_state() -> None:
    """Resolved grouped payloads should normalize into resolved webhook events."""
    payload = load_fixture("alertmanager_resolved_group.json")
    expected_group_key = (
        'group:{}/{alertname="SharedStorageLatency",cluster="homelab"}:'
        '{alertname="SharedStorageLatency",cluster="homelab"}'
    )

    event = normalize_alertmanager_payload(
        source_id="prometheus_alertmanager",
        payload=payload,
        received_at=ts(17, 16),
    )

    assert event.source_event_id == f"{expected_group_key}:resolved:2026-04-07T17:16:30Z"
    assert event.alert_state == WebhookAlertState.RESOLVED
    assert event.severity == WebhookSeverity.MEDIUM
    assert event.title == "SharedStorageLatency resolved (2 alerts)"
    assert event.body == "Shared storage latency returned to normal."
    assert event.tags["group_instance_count"] == "2"
    assert (
        event.tags["group_instances"]
        == "immich.example.com:443,redis.example.com:6379"
    )


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
