"""Unit tests for normalized webhook-event models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from kaval.integrations.webhooks import (
    WebhookAlertState,
    WebhookEvent,
    WebhookMatchingOutcome,
    WebhookProcessingStatus,
    WebhookSeverity,
    WebhookSourceType,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_event_defaults_support_single_service_receipt() -> None:
    """A newly received webhook should default to the pre-match processing state."""
    event = WebhookEvent(
        source_type=WebhookSourceType.UPTIME_KUMA,
        source_id="uptime-kuma-main",
        source_event_id="heartbeat-123",
        dedup_key="uptime-kuma-main:heartbeat-123",
        severity=WebhookSeverity.HIGH,
        title="Immich is down",
        body="Monitor reported service unavailable.",
        tags={"monitor": "Immich"},
        service_hints=["Immich"],
        raw_payload={"monitorID": 12, "status": "down"},
        raw_payload_redacted=True,
        raw_payload_retention_until=ts(14),
    )

    assert event.id.startswith("whk-")
    assert event.received_at.tzinfo == UTC
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.matching_outcome == WebhookMatchingOutcome.PENDING
    assert event.processing_status == WebhookProcessingStatus.NEW
    assert event.matched_service_ids == []


def test_webhook_event_allows_multi_service_group_matches() -> None:
    """Grouped alerts should preserve multiple matched services cleanly."""
    event = WebhookEvent(
        source_type=WebhookSourceType.PROMETHEUS_ALERTMANAGER,
        source_id="prometheus-main",
        source_event_id="group-abc",
        dedup_key="prometheus-main:group-abc",
        received_at=ts(15),
        alert_state=WebhookAlertState.FIRING,
        severity=WebhookSeverity.CRITICAL,
        title="ARR pipeline degraded",
        body="Grouped alert for Radarr and Sonarr.",
        tags={"alertname": "ArrPipelineDown"},
        service_hints=["Radarr", "Sonarr"],
        matched_service_ids=["svc-radarr", "svc-sonarr"],
        matching_outcome=WebhookMatchingOutcome.MULTI,
        raw_payload={"alerts": [{"service": "radarr"}, {"service": "sonarr"}]},
        raw_payload_redacted=True,
        processing_status=WebhookProcessingStatus.FINDING_CREATED,
    )

    assert event.matching_outcome == WebhookMatchingOutcome.MULTI
    assert event.matched_service_ids == ["svc-radarr", "svc-sonarr"]


def test_webhook_event_rejects_invalid_matched_state_without_matches() -> None:
    """Matched processing states must not remain in a pending match outcome."""
    with pytest.raises(ValidationError):
        WebhookEvent(
            source_type=WebhookSourceType.GRAFANA,
            source_id="grafana-main",
            source_event_id="alert-42",
            dedup_key="grafana-main:alert-42",
            received_at=ts(16),
            alert_state=WebhookAlertState.RESOLVED,
            severity=WebhookSeverity.MEDIUM,
            title="Proxy latency recovered",
            body="Grafana marked the alert resolved.",
            matching_outcome=WebhookMatchingOutcome.PENDING,
            processing_status=WebhookProcessingStatus.MATCHED,
            raw_payload={"state": "ok"},
            raw_payload_redacted=True,
        )


def test_webhook_event_rejects_duplicate_match_lists() -> None:
    """Match hints and matched services should stay deduplicated."""
    with pytest.raises(ValidationError):
        WebhookEvent(
            source_type=WebhookSourceType.NETDATA,
            source_id="netdata-main",
            source_event_id="alarm-99",
            dedup_key="netdata-main:alarm-99",
            severity=WebhookSeverity.LOW,
            title="Disk usage warning",
            body="Duplicate hints should fail validation.",
            service_hints=["Unraid", "Unraid"],
            raw_payload={"status": "warning"},
            raw_payload_redacted=True,
        )
