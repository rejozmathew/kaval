"""Unit tests for Grafana webhook normalization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers import normalize_grafana_payload

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for normalizer tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_grafana_firing_payload_normalizes_to_firing_event() -> None:
    """Firing Grafana payloads should normalize into firing webhook events."""
    payload = load_fixture("grafana_firing.json")

    event = normalize_grafana_payload(
        source_id="grafana",
        payload=payload,
        received_at=ts(16, 19),
    )

    assert event.source_type == WebhookSourceType.GRAFANA
    assert event.source_id == "grafana"
    assert (
        event.dedup_key
        == 'group:{}:{alertname="ImmichHighLatency",service="immich"}'
    )
    assert (
        event.source_event_id
        == 'group:{}:{alertname="ImmichHighLatency",service="immich"}:firing:2026-04-07T16:18:00Z'
    )
    assert event.received_at == ts(16, 19)
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.severity == WebhookSeverity.CRITICAL
    assert event.title == "[FIRING:1] ImmichHighLatency (immich critical)"
    assert event.body == "Immich latency exceeded the configured threshold."
    assert (
        event.url
        == "https://grafana.example.com/d/immich-overview/immich-overview?orgId=1&viewPanel=7"
    )
    assert event.service_hints == [
        "immich",
        "immich.example.com:443",
        "immich.example.com",
        "grafana.example.com",
    ]
    assert event.tags["label:severity"] == "critical"
    assert event.tags["annotation:runbook_url"] == "https://runbooks.example.com/immich/latency"
    assert event.tags["panel_url"] == event.url
    assert event.tags["fingerprint"] == "4fd6e0b8f342a1e7"
    assert event.raw_payload_redacted is True
    silence_url = event.raw_payload["alerts"][0]["silenceURL"]
    assert isinstance(silence_url, str)
    assert "secret-token" not in silence_url


def test_grafana_resolved_payload_normalizes_to_resolved_event() -> None:
    """Resolved Grafana payloads should normalize into resolved webhook events."""
    payload = load_fixture("grafana_resolved.json")

    event = normalize_grafana_payload(
        source_id="grafana",
        payload=payload,
        received_at=ts(16, 25),
    )

    assert event.dedup_key == 'group:{}:{alertname="ImmichHighLatency",service="immich"}'
    assert (
        event.source_event_id
        == 'group:{}:{alertname="ImmichHighLatency",service="immich"}:resolved:2026-04-07T16:25:00Z'
    )
    assert event.alert_state == WebhookAlertState.RESOLVED
    assert event.severity == WebhookSeverity.CRITICAL
    assert event.title == "[RESOLVED:1] ImmichHighLatency (immich critical)"
    assert event.body == "Immich latency is back within the SLO."
    assert event.tags["grafana_state"] == "ok"
    assert event.tags["label:service"] == "immich"
    assert event.tags["alert_label:instance"] == "immich.example.com:443"


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
