"""Netdata webhook payload normalization."""

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


class NetdataRoom(KavalModel):
    """One Netdata room reference embedded in a webhook payload."""

    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    url: str | None = None


class NetdataWebhookPayload(KavalModel):
    """The subset of the Netdata webhook payload Kaval relies on."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    message: str | None = None
    alert: str = Field(min_length=1)
    info: str | None = None
    chart: str | None = None
    context: str | None = None
    space: str | None = None
    rooms: list[NetdataRoom] = Field(default_factory=list, alias="Rooms")
    family: str | None = None
    class_name: str | None = Field(default=None, alias="class")
    severity: str = Field(min_length=1)
    date: str = Field(min_length=1)
    duration: str | None = None
    additional_active_critical_alerts: int | None = None
    additional_active_warning_alerts: int | None = None
    alert_url: str | None = None


def normalize_netdata_payload(
    *,
    source_id: str,
    payload: dict[str, JsonValue],
    received_at: datetime | None = None,
    raw_payload_retention_until: datetime | None = None,
) -> WebhookEvent:
    """Normalize one Netdata alarm webhook into Kaval's canonical event contract."""
    parsed = NetdataWebhookPayload.model_validate(payload)
    alert_state = _alert_state(parsed.severity)
    redacted_payload = redact_json_value(
        payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value

    return WebhookEvent(
        source_type=WebhookSourceType.NETDATA,
        source_id=source_id,
        source_event_id=(
            f"{_dedup_key(parsed)}:{parsed.severity.strip().casefold()}:{parsed.date}"
        ),
        dedup_key=_dedup_key(parsed),
        received_at=received_at or datetime.now(tz=UTC),
        alert_state=alert_state,
        severity=_severity(parsed.severity),
        title=_title(parsed, alert_state=alert_state),
        body=_body(parsed),
        url=_normalize_text(parsed.alert_url),
        tags=_tags(parsed),
        service_hints=_service_hints(parsed),
        matching_outcome=WebhookMatchingOutcome.PENDING,
        raw_payload=redacted_payload if isinstance(redacted_payload, dict) else {},
        raw_payload_redacted=True,
        raw_payload_retention_until=raw_payload_retention_until,
        processing_status=WebhookProcessingStatus.NEW,
    )


def _alert_state(severity: str) -> WebhookAlertState:
    """Map Netdata severity values into firing or resolved state."""
    normalized = severity.strip().casefold()
    if normalized in {"warning", "critical"}:
        return WebhookAlertState.FIRING
    if normalized == "clear":
        return WebhookAlertState.RESOLVED
    msg = f"unsupported Netdata severity: {severity}"
    raise ValueError(msg)


def _severity(severity: str) -> WebhookSeverity:
    """Map Netdata severities into normalized Kaval severities."""
    normalized = severity.strip().casefold()
    if normalized == "critical":
        return WebhookSeverity.CRITICAL
    if normalized == "warning":
        return WebhookSeverity.MEDIUM
    if normalized == "clear":
        return WebhookSeverity.INFO
    msg = f"unsupported Netdata severity: {severity}"
    raise ValueError(msg)


def _title(
    payload: NetdataWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Build a readable title from one Netdata alarm webhook."""
    if alert_state == WebhookAlertState.RESOLVED:
        return f"{payload.alert} cleared"
    return f"{payload.alert} is {payload.severity.strip().casefold()}"


def _body(payload: NetdataWebhookPayload) -> str:
    """Select the most useful body text from the Netdata alarm webhook."""
    for candidate in (payload.message, payload.info):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            return normalized
    return payload.alert


def _dedup_key(payload: NetdataWebhookPayload) -> str:
    """Return the stable deduplication key for one Netdata alarm."""
    components = [
        payload.alert,
        _normalize_text(payload.chart),
        _normalize_text(payload.context),
        _normalize_text(payload.family),
    ]
    return "alarm:" + ":".join(
        component
        for component in components
        if component is not None
    )


def _service_hints(payload: NetdataWebhookPayload) -> list[str]:
    """Build match hints from Netdata chart and context metadata."""
    hints: list[str] = []
    for candidate in (payload.chart, payload.context, payload.family):
        normalized = _normalize_text(candidate)
        if normalized is not None and normalized not in hints:
            hints.append(normalized)

    alert_url = _normalize_text(payload.alert_url)
    if alert_url is not None:
        hostname = urlsplit(alert_url).hostname
        if hostname is not None and hostname not in hints:
            hints.append(hostname)
    return hints


def _tags(payload: NetdataWebhookPayload) -> dict[str, str]:
    """Flatten Netdata alarm metadata into deterministic tags."""
    tags: dict[str, str] = {
        "alert": payload.alert,
        "severity": payload.severity.strip().casefold(),
        "date": payload.date,
    }
    for key, value in (
        ("chart", payload.chart),
        ("context", payload.context),
        ("space", payload.space),
        ("family", payload.family),
        ("class", payload.class_name),
        ("duration", payload.duration),
        ("alert_url", payload.alert_url),
    ):
        normalized = _normalize_text(value)
        if normalized is not None:
            tags[key] = normalized

    if payload.additional_active_critical_alerts is not None:
        tags["additional_active_critical_alerts"] = str(
            payload.additional_active_critical_alerts
        )
    if payload.additional_active_warning_alerts is not None:
        tags["additional_active_warning_alerts"] = str(
            payload.additional_active_warning_alerts
        )

    room_names = [
        room.name.strip()
        for room in payload.rooms
        if room.name is not None and room.name.strip()
    ]
    if room_names:
        tags["room_count"] = str(len(room_names))
        tags["rooms"] = ",".join(room_names)
    return tags


def _normalize_text(value: str | None) -> str | None:
    """Trim a string-like value and collapse blanks to None."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
