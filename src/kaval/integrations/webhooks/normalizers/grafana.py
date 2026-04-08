"""Grafana webhook payload normalization."""

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


class GrafanaWebhookPayload(KavalModel):
    """The subset of the Grafana webhook payload Kaval relies on."""

    model_config = ConfigDict(extra="ignore")

    receiver: str | None = None
    status: str | None = None
    state: str | None = None
    orgId: int | None = None
    alerts: list["GrafanaAlert"] = Field(default_factory=list)
    groupLabels: dict[str, str] = Field(default_factory=dict)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)
    externalURL: str | None = None
    version: str | None = None
    groupKey: str | None = None
    truncatedAlerts: int = 0
    title: str | None = None
    message: str | None = None


class GrafanaAlert(KavalModel):
    """One alert entry inside a Grafana webhook delivery."""

    model_config = ConfigDict(extra="ignore")

    status: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    generatorURL: str | None = None
    fingerprint: str | None = None
    silenceURL: str | None = None
    dashboardURL: str | None = None
    panelURL: str | None = None
    values: dict[str, JsonValue] = Field(default_factory=dict)
    valueString: str | None = None


def normalize_grafana_payload(
    *,
    source_id: str,
    payload: dict[str, JsonValue],
    received_at: datetime | None = None,
    raw_payload_retention_until: datetime | None = None,
) -> WebhookEvent:
    """Normalize one Grafana webhook payload into Kaval's canonical event contract."""
    parsed = GrafanaWebhookPayload.model_validate(payload)
    if not parsed.alerts:
        msg = "Grafana webhook payload must include at least one alert"
        raise ValueError(msg)

    alert_state = _alert_state(parsed)
    primary_alert = parsed.alerts[0]
    dedup_key = _dedup_key(parsed)
    redacted_payload = redact_json_value(
        payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value

    return WebhookEvent(
        source_type=WebhookSourceType.GRAFANA,
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
        body=_body(parsed),
        url=_event_url(parsed, primary_alert),
        tags=_tags(parsed, primary_alert, alert_state=alert_state),
        service_hints=_service_hints(parsed),
        matching_outcome=WebhookMatchingOutcome.PENDING,
        raw_payload=redacted_payload if isinstance(redacted_payload, dict) else {},
        raw_payload_redacted=True,
        raw_payload_retention_until=raw_payload_retention_until,
        processing_status=WebhookProcessingStatus.NEW,
    )


def _alert_state(payload: GrafanaWebhookPayload) -> WebhookAlertState:
    """Map Grafana webhook status fields into firing or resolved lifecycle state."""
    for candidate in (payload.status, payload.state):
        normalized = _normalize_text(candidate)
        if normalized is None:
            continue
        lowered = normalized.casefold()
        if lowered in {"firing", "alerting"}:
            return WebhookAlertState.FIRING
        if lowered in {"resolved", "ok"}:
            return WebhookAlertState.RESOLVED
    msg = "unsupported Grafana webhook status"
    raise ValueError(msg)


def _severity(
    payload: GrafanaWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> WebhookSeverity:
    """Map Grafana labels into Kaval severity values with deterministic fallbacks."""
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
    if normalized in {"info", "informational", "notice", "ok", "resolved"}:
        return WebhookSeverity.INFO
    return (
        WebhookSeverity.INFO
        if alert_state == WebhookAlertState.RESOLVED
        else WebhookSeverity.MEDIUM
    )


def _severity_label(payload: GrafanaWebhookPayload) -> str | None:
    """Return the first explicit severity-like label from the webhook payload."""
    label_maps = [payload.commonLabels]
    label_maps.extend(alert.labels for alert in payload.alerts)
    for labels in label_maps:
        for key in _SEVERITY_LABEL_KEYS:
            value = _label_value(labels, key)
            if value is not None:
                return value
    return None


def _title(
    payload: GrafanaWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Build a readable title for one normalized Grafana webhook event."""
    normalized_title = _normalize_text(payload.title)
    if normalized_title is not None:
        return normalized_title

    alert_name = _alert_name(payload)
    if alert_name is not None:
        suffix = (
            "resolved"
            if alert_state == WebhookAlertState.RESOLVED
            else "firing"
        )
        return f"{alert_name} {suffix}"

    receiver = _normalize_text(payload.receiver)
    if receiver is not None:
        return (
            f"{receiver} resolved"
            if alert_state == WebhookAlertState.RESOLVED
            else f"{receiver} firing"
        )
    return "Grafana webhook alert"


def _body(payload: GrafanaWebhookPayload) -> str:
    """Select the most useful explanatory text from the Grafana webhook payload."""
    first_alert = payload.alerts[0]
    annotation_sources = (
        payload.message,
        _label_value(payload.commonAnnotations, "summary"),
        _label_value(payload.commonAnnotations, "description"),
        _label_value(first_alert.annotations, "summary"),
        _label_value(first_alert.annotations, "description"),
        _label_value(first_alert.annotations, "message"),
    )
    for candidate in annotation_sources:
        normalized = _normalize_text(candidate)
        if normalized is not None:
            return normalized
    return _title(payload, alert_state=_alert_state(payload))


def _dedup_key(payload: GrafanaWebhookPayload) -> str:
    """Return the stable deduplication key for one Grafana webhook group."""
    group_key = _normalize_text(payload.groupKey)
    if group_key is not None:
        return f"group:{group_key}"

    fingerprint = _normalize_text(payload.alerts[0].fingerprint)
    if fingerprint is not None:
        return f"alert:{fingerprint}"

    receiver = _normalize_text(payload.receiver) or "grafana"
    alert_name = _alert_name(payload) or "alert"
    return f"receiver:{receiver}:{alert_name}"


def _source_event_id(
    *,
    payload: GrafanaWebhookPayload,
    alert_state: WebhookAlertState,
    dedup_key: str,
) -> str:
    """Build a replay-stable source event identifier for one delivery."""
    reference_timestamp = _event_reference_timestamp(payload, alert_state=alert_state)
    return f"{dedup_key}:{alert_state.value}:{reference_timestamp}"


def _event_reference_timestamp(
    payload: GrafanaWebhookPayload,
    *,
    alert_state: WebhookAlertState,
) -> str:
    """Choose the timestamp that best identifies the current webhook delivery state."""
    if alert_state == WebhookAlertState.RESOLVED:
        candidates: list[str] = []
        for alert in payload.alerts:
            normalized_end = _normalize_text(alert.endsAt)
            if normalized_end is not None:
                candidates.append(normalized_end)
        if candidates:
            return max(candidates)

    candidates = []
    for alert in payload.alerts:
        normalized_start = _normalize_text(alert.startsAt)
        if normalized_start is not None:
            candidates.append(normalized_start)
    if candidates:
        return max(candidates)
    fingerprint = _normalize_text(payload.alerts[0].fingerprint)
    return fingerprint or "unknown"


def _event_url(
    payload: GrafanaWebhookPayload,
    primary_alert: GrafanaAlert,
) -> str | None:
    """Select the most actionable URL from the Grafana webhook payload."""
    for candidate in (
        primary_alert.panelURL,
        primary_alert.dashboardURL,
        primary_alert.generatorURL,
        primary_alert.silenceURL,
        payload.externalURL,
    ):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            return normalized
    return None


def _service_hints(payload: GrafanaWebhookPayload) -> list[str]:
    """Build service-match hints from Grafana labels and URLs."""
    hints: list[str] = []
    label_maps = [payload.commonLabels]
    label_maps.extend(alert.labels for alert in payload.alerts)
    for labels in label_maps:
        for key in _SERVICE_HINT_LABEL_KEYS:
            value = _label_value(labels, key)
            if value is not None:
                _append_hint(hints, value)

    primary_alert = payload.alerts[0]
    for candidate in (
        primary_alert.panelURL,
        primary_alert.dashboardURL,
        primary_alert.generatorURL,
    ):
        normalized = _normalize_text(candidate)
        if normalized is None:
            continue
        hostname = urlsplit(normalized).hostname
        if hostname is not None:
            _append_hint(hints, hostname)
    return hints


def _append_hint(hints: list[str], value: str) -> None:
    """Add one service-hint candidate and any hostname variant deterministically."""
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
    payload: GrafanaWebhookPayload,
    primary_alert: GrafanaAlert,
    *,
    alert_state: WebhookAlertState,
) -> dict[str, str]:
    """Flatten the later-matchable Grafana metadata into normalized tags."""
    tags: dict[str, str] = {
        "receiver": _normalize_text(payload.receiver) or "grafana",
        "grafana_status": alert_state.value,
        "alert_count": str(len(payload.alerts)),
        "truncated_alerts": str(payload.truncatedAlerts),
    }
    if payload.orgId is not None:
        tags["org_id"] = str(payload.orgId)
    if payload.version is not None:
        tags["payload_version"] = payload.version
    group_key = _normalize_text(payload.groupKey)
    if group_key is not None:
        tags["group_key"] = group_key
    state = _normalize_text(payload.state)
    if state is not None:
        tags["grafana_state"] = state
    external_url = _normalize_text(payload.externalURL)
    if external_url is not None:
        tags["external_url"] = external_url

    for key, value in sorted(payload.commonLabels.items()):
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"label:{key}"] = normalized_value
    for key, value in sorted(payload.commonAnnotations.items()):
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"annotation:{key}"] = normalized_value

    for key, value in sorted(primary_alert.labels.items()):
        if key in payload.commonLabels:
            continue
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"alert_label:{key}"] = normalized_value
    for key, value in sorted(primary_alert.annotations.items()):
        if key in payload.commonAnnotations:
            continue
        normalized_value = _normalize_text(value)
        if normalized_value is not None:
            tags[f"alert_annotation:{key}"] = normalized_value

    for tag_key, candidate in (
        ("fingerprint", primary_alert.fingerprint),
        ("generator_url", primary_alert.generatorURL),
        ("silence_url", primary_alert.silenceURL),
        ("dashboard_url", primary_alert.dashboardURL),
        ("panel_url", primary_alert.panelURL),
    ):
        normalized = _normalize_text(candidate)
        if normalized is not None:
            tags[tag_key] = normalized
    return tags


def _alert_name(payload: GrafanaWebhookPayload) -> str | None:
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
    """Return one case-insensitive label value if it is present and non-empty."""
    expected = key.casefold()
    for actual_key, value in labels.items():
        if actual_key.casefold() != expected:
            continue
        normalized = _normalize_text(value)
        if normalized is not None:
            return normalized
    return None


def _normalize_text(value: str | None) -> str | None:
    """Trim a string-like value and collapse blank strings to None."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
