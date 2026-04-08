"""Prometheus Alertmanager webhook payload normalization."""

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

_SERVICE_HINT_LABEL_KEYS = (
    "service",
    "service_name",
    "app",
    "application",
    "job",
    "container",
    "container_name",
    "instance",
    "host",
    "hostname",
    "node",
    "pod",
)
_SEVERITY_LABEL_KEYS = (
    "severity",
    "severity_level",
    "alert_severity",
    "priority",
    "level",
)


class AlertmanagerWebhookPayload(KavalModel):
    """The subset of the Alertmanager webhook payload Kaval relies on."""

    model_config = ConfigDict(extra="ignore")

    version: str | None = None
    groupKey: str | None = None
    truncatedAlerts: int = 0
    status: str
    receiver: str | None = None
    groupLabels: dict[str, str] = Field(default_factory=dict)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)
    externalURL: str | None = None
    alerts: list["AlertmanagerAlert"] = Field(default_factory=list)


class AlertmanagerAlert(KavalModel):
    """One grouped alert entry from an Alertmanager webhook delivery."""

    model_config = ConfigDict(extra="ignore")

    status: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    generatorURL: str | None = None
    fingerprint: str | None = None


def normalize_alertmanager_payload(
    *,
    source_id: str,
    payload: dict[str, JsonValue],
    received_at: datetime | None = None,
    raw_payload_retention_until: datetime | None = None,
) -> WebhookEvent:
    """Normalize one Alertmanager webhook delivery into Kaval's webhook contract."""
    parsed = AlertmanagerWebhookPayload.model_validate(payload)
    if not parsed.alerts:
        msg = "Alertmanager webhook payload must include at least one alert"
        raise ValueError(msg)

    alert_state = _alert_state(parsed.status)
    primary_alert = parsed.alerts[0]
    dedup_key = _dedup_key(parsed)
    redacted_payload = redact_json_value(
        payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value

    return WebhookEvent(
        source_type=WebhookSourceType.PROMETHEUS_ALERTMANAGER,
        source_id=source_id,
        source_event_id=_source_event_id(
            payload=parsed,
            alert_state=alert_state,
            dedup_key=dedup_key,
        ),
        dedup_key=dedup_key,
        received_at=received_at or datetime.now(tz=UTC),
        alert_state=alert_state,
        severity=_severity(parsed, alert_state=alert_state),
        title=_title(parsed, alert_state=alert_state),
        body=_body(parsed, alert_state=alert_state),
        url=_event_url(parsed, primary_alert),
        tags=_tags(parsed, primary_alert, alert_state=alert_state),
        service_hints=_service_hints(parsed),
        matching_outcome=WebhookMatchingOutcome.PENDING,
        raw_payload=redacted_payload if isinstance(redacted_payload, dict) else {},
        raw_payload_redacted=True,
        raw_payload_retention_until=raw_payload_retention_until,
        processing_status=WebhookProcessingStatus.NEW,
    )


def _alert_state(status: str) -> WebhookAlertState:
    """Map Alertmanager status strings into firing or resolved state."""
    normalized = status.strip().casefold()
    if normalized == "firing":
        return WebhookAlertState.FIRING
    if normalized == "resolved":
        return WebhookAlertState.RESOLVED
    msg = f"unsupported Alertmanager webhook status: {status}"
    raise ValueError(msg)


def _severity(
    payload: AlertmanagerWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> WebhookSeverity:
    """Map Alertmanager labels into normalized severity values."""
    severity_label = _severity_label(payload)
    if severity_label is None:
        return (
            WebhookSeverity.INFO
            if alert_state == WebhookAlertState.RESOLVED
            else WebhookSeverity.MEDIUM
        )

    normalized = severity_label.casefold()
    if normalized in {"critical", "crit", "sev0", "sev1", "p1", "emergency"}:
        return WebhookSeverity.CRITICAL
    if normalized in {"high", "error", "sev2", "p2", "major"}:
        return WebhookSeverity.HIGH
    if normalized in {"medium", "warning", "warn", "sev3", "p3"}:
        return WebhookSeverity.MEDIUM
    if normalized in {"low", "minor", "sev4", "p4"}:
        return WebhookSeverity.LOW
    if normalized in {"info", "informational", "notice", "resolved", "ok"}:
        return WebhookSeverity.INFO
    return (
        WebhookSeverity.INFO
        if alert_state == WebhookAlertState.RESOLVED
        else WebhookSeverity.MEDIUM
    )


def _severity_label(payload: AlertmanagerWebhookPayload) -> str | None:
    """Return the first explicit severity label available in the payload."""
    label_maps = [payload.commonLabels]
    label_maps.extend(alert.labels for alert in payload.alerts)
    for labels in label_maps:
        for key in _SEVERITY_LABEL_KEYS:
            value = _label_value(labels, key)
            if value is not None:
                return value
    return None


def _title(
    payload: AlertmanagerWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Build a deterministic title for one Alertmanager webhook delivery."""
    alert_name = _alert_name(payload)
    state_name = (
        "resolved"
        if alert_state == WebhookAlertState.RESOLVED
        else "firing"
    )
    alert_count = len(payload.alerts)
    if alert_name is not None:
        suffix = f" ({alert_count} alerts)" if alert_count > 1 else ""
        return f"{alert_name} {state_name}{suffix}"

    receiver = _normalize_text(payload.receiver)
    if receiver is not None:
        suffix = f" ({alert_count} alerts)" if alert_count > 1 else ""
        return f"{receiver} {state_name}{suffix}"
    return f"Alertmanager {state_name} ({alert_count} alerts)"


def _body(
    payload: AlertmanagerWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Select the most useful explanatory text from an Alertmanager delivery."""
    primary_alert = payload.alerts[0]
    for candidate in (
        _label_value(payload.commonAnnotations, "summary"),
        _label_value(payload.commonAnnotations, "description"),
        _label_value(primary_alert.annotations, "summary"),
        _label_value(primary_alert.annotations, "description"),
        _label_value(primary_alert.annotations, "message"),
    ):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            return normalized
    return _title(payload, alert_state=alert_state)


def _dedup_key(payload: AlertmanagerWebhookPayload) -> str:
    """Return the stable deduplication key for one Alertmanager group."""
    group_key = _normalize_text(payload.groupKey)
    if group_key is not None:
        return f"group:{group_key}"

    fingerprint = _normalize_text(payload.alerts[0].fingerprint)
    if fingerprint is not None:
        return f"alert:{fingerprint}"

    receiver = _normalize_text(payload.receiver) or "alertmanager"
    alert_name = _alert_name(payload) or "alert"
    return f"receiver:{receiver}:{alert_name}"


def _source_event_id(
    *,
    payload: AlertmanagerWebhookPayload,
    alert_state: WebhookAlertState,
    dedup_key: str,
) -> str:
    """Build a replay-stable source event identifier for the grouped delivery."""
    reference_timestamp = _event_reference_timestamp(
        payload,
        alert_state=alert_state,
    )
    return f"{dedup_key}:{alert_state.value}:{reference_timestamp}"


def _event_reference_timestamp(
    payload: AlertmanagerWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Choose the alert timestamp that best identifies the current delivery state."""
    if alert_state == WebhookAlertState.RESOLVED:
        resolved_times: list[str] = []
        for alert in payload.alerts:
            normalized_end = _normalize_text(alert.endsAt)
            if normalized_end is not None:
                resolved_times.append(normalized_end)
        if resolved_times:
            return max(resolved_times)

    firing_times: list[str] = []
    for alert in payload.alerts:
        normalized_start = _normalize_text(alert.startsAt)
        if normalized_start is not None:
            firing_times.append(normalized_start)
    if firing_times:
        return max(firing_times)

    fingerprint = _normalize_text(payload.alerts[0].fingerprint)
    return fingerprint or "unknown"


def _event_url(
    payload: AlertmanagerWebhookPayload,
    primary_alert: AlertmanagerAlert,
) -> str | None:
    """Select the most useful URL from the Alertmanager delivery."""
    for candidate in (primary_alert.generatorURL, payload.externalURL):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            return normalized
    return None


def _service_hints(payload: AlertmanagerWebhookPayload) -> list[str]:
    """Aggregate service-match hints across all grouped alerts."""
    hints: list[str] = []
    label_maps = [payload.commonLabels]
    label_maps.extend(alert.labels for alert in payload.alerts)
    for labels in label_maps:
        for key in _SERVICE_HINT_LABEL_KEYS:
            value = _label_value(labels, key)
            if value is not None:
                _append_hint(hints, value)
    return hints


def _append_hint(hints: list[str], value: str) -> None:
    """Append one candidate hint and a hostname form where available."""
    normalized = _normalize_text(value)
    if normalized is None:
        return
    if normalized not in hints:
        hints.append(normalized)

    if " " in normalized:
        return
    parsed = urlsplit(normalized if "://" in normalized else f"//{normalized}")
    hostname = parsed.hostname
    if hostname is not None and hostname not in hints:
        hints.append(hostname)


def _tags(
    payload: AlertmanagerWebhookPayload,
    primary_alert: AlertmanagerAlert,
    *,
    alert_state: WebhookAlertState,
) -> dict[str, str]:
    """Flatten later-matchable Alertmanager metadata into deterministic tags."""
    tags: dict[str, str] = {
        "receiver": _normalize_text(payload.receiver) or "alertmanager",
        "alertmanager_status": alert_state.value,
        "alert_count": str(len(payload.alerts)),
        "truncated_alerts": str(payload.truncatedAlerts),
    }
    version = _normalize_text(payload.version)
    if version is not None:
        tags["payload_version"] = version
    group_key = _normalize_text(payload.groupKey)
    if group_key is not None:
        tags["group_key"] = group_key
    external_url = _normalize_text(payload.externalURL)
    if external_url is not None:
        tags["external_url"] = external_url

    for key, value in sorted(payload.groupLabels.items()):
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"group_label:{key}"] = normalized_value
    for key, value in sorted(payload.commonLabels.items()):
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"label:{key}"] = normalized_value
    for key, value in sorted(payload.commonAnnotations.items()):
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"annotation:{key}"] = normalized_value

    for tag_key, candidate in (
        ("generator_url", primary_alert.generatorURL),
        ("fingerprint", primary_alert.fingerprint),
    ):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            tags[tag_key] = normalized

    group_services = _group_label_values(payload, label_name="service")
    if group_services:
        tags["group_service_count"] = str(len(group_services))
        tags["group_services"] = ",".join(group_services)
    group_instances = _group_label_values(payload, label_name="instance")
    if group_instances:
        tags["group_instance_count"] = str(len(group_instances))
        tags["group_instances"] = ",".join(group_instances)
    return tags


def _group_label_values(
    payload: AlertmanagerWebhookPayload,
    *,
    label_name: str,
) -> list[str]:
    """Collect one deterministic ordered set of per-alert label values."""
    values: list[str] = []
    for alert in payload.alerts:
        value = _label_value(alert.labels, label_name)
        if value is not None and value not in values:
            values.append(value)
    return values


def _alert_name(payload: AlertmanagerWebhookPayload) -> str | None:
    """Return the most specific alert name available in the payload."""
    for labels in (
        payload.groupLabels,
        payload.commonLabels,
        payload.alerts[0].labels,
    ):
        value = _label_value(labels, "alertname")
        if value is not None:
            return value
    return None


def _label_value(labels: dict[str, str], key: str) -> str | None:
    """Return one case-insensitive label or annotation value if present."""
    expected = key.casefold()
    for actual_key, value in labels.items():
        if actual_key.casefold() != expected:
            continue
        normalized = _normalize_text(value)
        if normalized is not None:
            return normalized
    return None


def _normalize_text(value: str | None) -> str | None:
    """Trim a string-like value and collapse blanks to None."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
