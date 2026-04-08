"""Unit tests for webhook ingress security helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kaval.database import KavalDatabase
from kaval.integrations.webhooks import (
    WebhookPayloadTooLargeError,
    WebhookRateLimiter,
    WebhookRateLimitError,
    WebhookSourceConfig,
    WebhookSourceType,
    build_webhook_payload_record,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for webhook-security tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_rate_limiter_enforces_per_source_window() -> None:
    """Sources should be throttled independently inside the configured window."""
    limiter = WebhookRateLimiter(max_events_per_minute=2)

    limiter.enforce(source_id="uptime_kuma", now=ts(12, 0))
    limiter.enforce(source_id="uptime_kuma", now=ts(12, 0))

    with pytest.raises(WebhookRateLimitError):
        limiter.enforce(source_id="uptime_kuma", now=ts(12, 0))

    limiter.enforce(source_id="grafana", now=ts(12, 0))


def test_build_webhook_payload_record_redacts_secret_like_values() -> None:
    """Raw webhook payloads should be redacted before they are stored."""
    source = WebhookSourceConfig(
        source_id="uptime_kuma",
        source_type=WebhookSourceType.UPTIME_KUMA,
        api_key="uptime-secret",
    )

    record = build_webhook_payload_record(
        source=source,
        raw_body=b'{"status":"down","api_key":"super-secret","note":"Authorization: Bearer abc"}',
        received_at=ts(13),
        payload_size_limit_bytes=1024,
        retention_days=30,
    )

    assert record.payload_size_bytes > 0
    assert record.raw_payload_redacted is True
    assert record.raw_payload["api_key"] == "[REDACTED]"
    assert record.raw_payload["note"] == "Authorization: Bearer [REDACTED]"
    assert record.raw_payload_retention_until == ts(13) + timedelta(days=30)


def test_build_webhook_payload_record_rejects_oversize_bodies() -> None:
    """Payloads larger than the configured limit must fail validation."""
    source = WebhookSourceConfig(
        source_id="grafana",
        source_type=WebhookSourceType.GRAFANA,
        api_key="grafana-secret",
    )

    with pytest.raises(WebhookPayloadTooLargeError):
        build_webhook_payload_record(
            source=source,
            raw_body=b'{"status":"alerting"}',
            received_at=ts(14),
            payload_size_limit_bytes=8,
            retention_days=30,
        )


def test_database_purge_expired_webhook_payloads_keeps_open_incident_records(
    tmp_path: Path,
) -> None:
    """Expired raw payloads tied to open incidents should survive retention purges."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    source = WebhookSourceConfig(
        source_id="netdata",
        source_type=WebhookSourceType.NETDATA,
        api_key="netdata-secret",
    )
    expired_record = build_webhook_payload_record(
        source=source,
        raw_body=b'{"status":"warning"}',
        received_at=ts(10),
        payload_size_limit_bytes=1024,
        retention_days=1,
    )
    retained_record = build_webhook_payload_record(
        source=source,
        raw_body=b'{"status":"warning"}',
        received_at=ts(10),
        payload_size_limit_bytes=1024,
        retention_days=1,
    ).model_copy(update={"incident_id": "inc-open"})
    try:
        database.upsert_webhook_payload(expired_record)
        database.upsert_webhook_payload(retained_record)

        deleted_count = database.purge_expired_webhook_payloads(
            now=ts(10) + timedelta(days=2),
            open_incident_ids={"inc-open"},
        )
        remaining_ids = [record.id for record in database.list_webhook_payloads()]
    finally:
        database.close()

    assert deleted_count == 1
    assert remaining_ids == [retained_record.id]
