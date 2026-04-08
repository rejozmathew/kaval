"""Uptime Kuma webhook payload normalization."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookEvent,
    WebhookMatchingOutcome,
    WebhookProcessingStatus,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.memory.redaction import redact_json_value
from kaval.models import JsonValue, KavalModel, RedactionLevel


class UptimeKumaWebhookPayload(KavalModel):
    """The subset of the Uptime Kuma webhook payload Kaval relies on."""

    model_config = ConfigDict(extra="ignore")

    heartbeat: "UptimeKumaHeartbeat"
    monitor: "UptimeKumaMonitor"
    msg: str | None = None


class UptimeKumaHeartbeat(KavalModel):
    """Heartbeat details attached to an Uptime Kuma webhook."""

    model_config = ConfigDict(extra="ignore")

    monitorID: int
    status: int
    time: str = Field(min_length=1)
    msg: str | None = None
    important: bool | None = None
    duration: int | None = None


class UptimeKumaMonitorTag(KavalModel):
    """One tag object attached to an Uptime Kuma monitor."""

    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    value: str | None = None
    color: str | None = None


class UptimeKumaMonitor(KavalModel):
    """Monitor details attached to an Uptime Kuma webhook."""

    model_config = ConfigDict(extra="ignore")

    id: int
    name: str = Field(min_length=1)
    url: str | None = None
    hostname: str | None = None
    port: int | None = None
    type: str | None = None
    tags: list[UptimeKumaMonitorTag | str] = Field(default_factory=list)


def normalize_uptime_kuma_payload(
    *,
    source_id: str,
    payload: dict[str, JsonValue],
    received_at: datetime | None = None,
    raw_payload_retention_until: datetime | None = None,
) -> WebhookEvent:
    """Normalize one Uptime Kuma webhook into Kaval's canonical event contract."""
    parsed = UptimeKumaWebhookPayload.model_validate(payload)
    status_name = _status_name(parsed.heartbeat.status)
    redacted_payload = redact_json_value(
        payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value

    return WebhookEvent(
        source_type=WebhookSourceType.UPTIME_KUMA,
        source_id=source_id,
        source_event_id=(
            f"{parsed.monitor.id}:{parsed.heartbeat.time}:{parsed.heartbeat.status}"
        ),
        dedup_key=f"monitor:{parsed.monitor.id}",
        received_at=received_at or datetime.now(tz=UTC),
        alert_state=_alert_state(parsed.heartbeat.status),
        severity=_severity(parsed.heartbeat.status),
        title=_title(monitor_name=parsed.monitor.name, status_name=status_name),
        body=_body(parsed),
        url=_normalized_url(parsed.monitor.url),
        tags=_tags(parsed, status_name=status_name),
        service_hints=_service_hints(parsed.monitor),
        matching_outcome=WebhookMatchingOutcome.PENDING,
        raw_payload=redacted_payload if isinstance(redacted_payload, dict) else {},
        raw_payload_redacted=True,
        raw_payload_retention_until=raw_payload_retention_until,
        processing_status=WebhookProcessingStatus.NEW,
    )


def _alert_state(status: int) -> WebhookAlertState:
    """Map Uptime Kuma heartbeat status values into firing/resolved state."""
    if status in {0, 2}:
        return WebhookAlertState.FIRING
    if status in {1, 3}:
        return WebhookAlertState.RESOLVED
    msg = f"unsupported Uptime Kuma heartbeat status: {status}"
    raise ValueError(msg)


def _severity(status: int) -> WebhookSeverity:
    """Map Uptime Kuma heartbeat status values into normalized severity."""
    if status == 0:
        return WebhookSeverity.HIGH
    if status == 2:
        return WebhookSeverity.MEDIUM
    if status in {1, 3}:
        return WebhookSeverity.INFO
    msg = f"unsupported Uptime Kuma heartbeat status: {status}"
    raise ValueError(msg)


def _status_name(status: int) -> str:
    """Return a readable label for the Uptime Kuma heartbeat status value."""
    mapping = {
        0: "down",
        1: "up",
        2: "pending",
        3: "maintenance",
    }
    if status not in mapping:
        msg = f"unsupported Uptime Kuma heartbeat status: {status}"
        raise ValueError(msg)
    return mapping[status]


def _title(*, monitor_name: str, status_name: str) -> str:
    """Build a readable incident title from the monitor name and status."""
    if status_name == "up":
        return f"{monitor_name} recovered"
    if status_name == "maintenance":
        return f"{monitor_name} in maintenance"
    return f"{monitor_name} is {status_name}"


def _body(payload: UptimeKumaWebhookPayload) -> str:
    """Select the most useful body text from the Uptime Kuma payload."""
    for candidate in (payload.msg, payload.heartbeat.msg):
        if candidate is not None and candidate.strip():
            return candidate.strip()
    return _title(
        monitor_name=payload.monitor.name,
        status_name=_status_name(payload.heartbeat.status),
    )


def _normalized_url(raw_url: str | None) -> str | None:
    """Return the monitor URL if it is present and non-empty."""
    if raw_url is None:
        return None
    normalized = raw_url.strip()
    return normalized or None


def _service_hints(monitor: UptimeKumaMonitor) -> list[str]:
    """Build stable match hints from the monitor's visible identity fields."""
    hints: list[str] = [monitor.name]
    if monitor.hostname is not None and monitor.hostname.strip():
        hints.append(monitor.hostname.strip())
    if monitor.url is not None:
        hostname = urlsplit(monitor.url).hostname
        if hostname:
            hints.append(hostname)
    deduped: list[str] = []
    for hint in hints:
        if hint not in deduped:
            deduped.append(hint)
    return deduped


def _tags(
    payload: UptimeKumaWebhookPayload,
    *,
    status_name: str,
) -> dict[str, str]:
    """Build later-matchable tags from the Uptime Kuma monitor and heartbeat metadata."""
    monitor = payload.monitor
    tags: dict[str, str] = {
        "monitor_id": str(monitor.id),
        "monitor_name": monitor.name,
        "heartbeat_status": status_name,
    }
    if monitor.type:
        tags["monitor_type"] = monitor.type
    if monitor.hostname:
        tags["monitor_hostname"] = monitor.hostname
    if monitor.port is not None:
        tags["monitor_port"] = str(monitor.port)
    normalized_url = _normalized_url(monitor.url)
    if normalized_url is not None:
        tags["monitor_url"] = normalized_url
    if payload.heartbeat.important is not None:
        tags["heartbeat_important"] = str(payload.heartbeat.important).lower()
    if payload.heartbeat.duration is not None:
        tags["heartbeat_duration_seconds"] = str(payload.heartbeat.duration)
    for tag in monitor.tags:
        if isinstance(tag, str):
            normalized_name = tag.strip()
            if normalized_name:
                tags[f"tag:{normalized_name}"] = "true"
            continue
        if tag.name is None or not tag.name.strip():
            continue
        tags[f"tag:{tag.name.strip()}"] = tag.value or tag.color or "true"
    return tags
