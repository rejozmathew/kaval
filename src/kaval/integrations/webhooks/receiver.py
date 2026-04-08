"""Webhook receiver configuration, authentication, and ingress hardening helpers."""

from __future__ import annotations

import json
import os
import secrets
from collections import defaultdict, deque
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import Field

from kaval.integrations.webhooks.models import WebhookSourceType
from kaval.memory.redaction import redact_json_value
from kaval.models import JsonValue, KavalModel, NonNegativeInt, RedactionLevel

_WEBHOOK_SOURCE_ENV_VARS: dict[str, tuple[WebhookSourceType, str]] = {
    "uptime_kuma": (
        WebhookSourceType.UPTIME_KUMA,
        "KAVAL_WEBHOOK_KEY_UPTIME_KUMA",
    ),
    "grafana": (
        WebhookSourceType.GRAFANA,
        "KAVAL_WEBHOOK_KEY_GRAFANA",
    ),
    "prometheus_alertmanager": (
        WebhookSourceType.PROMETHEUS_ALERTMANAGER,
        "KAVAL_WEBHOOK_KEY_PROMETHEUS_ALERTMANAGER",
    ),
    "netdata": (
        WebhookSourceType.NETDATA,
        "KAVAL_WEBHOOK_KEY_NETDATA",
    ),
    "generic_json": (
        WebhookSourceType.GENERIC_JSON,
        "KAVAL_WEBHOOK_KEY_GENERIC_JSON",
    ),
}


def _new_webhook_payload_id() -> str:
    """Return a stable identifier for one retained raw webhook payload."""
    return f"whp-{uuid4()}"


class WebhookSourceConfig(KavalModel):
    """One webhook source configured for ingress authentication."""

    source_id: str = Field(min_length=1)
    source_type: WebhookSourceType
    api_key: str = Field(min_length=1)


class WebhookStoredPayload(KavalModel):
    """One redacted raw webhook payload retained for debugging."""

    id: str = Field(default_factory=_new_webhook_payload_id, min_length=1)
    source_id: str = Field(min_length=1)
    source_type: WebhookSourceType
    received_at: datetime
    payload_size_bytes: int = NonNegativeInt
    raw_payload: dict[str, JsonValue] = Field(default_factory=dict)
    raw_payload_redacted: bool = True
    raw_payload_retention_until: datetime
    incident_id: str | None = None


class WebhookAuthenticationError(RuntimeError):
    """Raised when a webhook request fails source-authentication checks."""


class WebhookPayloadValidationError(RuntimeError):
    """Raised when a webhook payload cannot be safely accepted."""


class WebhookPayloadTooLargeError(WebhookPayloadValidationError):
    """Raised when a webhook body exceeds the configured size limit."""


class WebhookRateLimitError(RuntimeError):
    """Raised when a source exceeds the configured webhook ingress rate."""


class WebhookRateLimiter:
    """A small in-memory per-source rate limiter for webhook ingress."""

    def __init__(
        self,
        *,
        max_events_per_minute: int,
        window: timedelta | None = None,
    ) -> None:
        """Initialize the limiter with a bounded per-minute allowance."""
        if max_events_per_minute <= 0:
            msg = "max_events_per_minute must be positive"
            raise ValueError(msg)
        self.max_events_per_minute = max_events_per_minute
        self.window = window or timedelta(minutes=1)
        self._events_by_source: dict[str, deque[datetime]] = defaultdict(deque)

    def enforce(self, *, source_id: str, now: datetime | None = None) -> None:
        """Raise when the source has exceeded the configured request budget."""
        effective_now = now or datetime.now(tz=UTC)
        events = self._events_by_source[source_id]
        cutoff = effective_now - self.window
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= self.max_events_per_minute:
            msg = "webhook rate limit exceeded"
            raise WebhookRateLimitError(msg)
        events.append(effective_now)


def load_webhook_source_configs_from_env(
    env: Mapping[str, str] | None = None,
) -> dict[str, WebhookSourceConfig]:
    """Load per-source webhook credentials from the environment."""
    source = env or os.environ
    configs: dict[str, WebhookSourceConfig] = {}
    for source_id, (source_type, env_var) in _WEBHOOK_SOURCE_ENV_VARS.items():
        api_key = source.get(env_var, "").strip()
        if not api_key:
            continue
        configs[source_id] = WebhookSourceConfig(
            source_id=source_id,
            source_type=source_type,
            api_key=api_key,
        )
    return configs


def authorize_webhook_request(
    *,
    config: WebhookSourceConfig,
    authorization_header: str | None,
    query_key: str | None,
) -> None:
    """Validate one webhook request against the configured source key."""
    header_value = authorization_header.strip() if authorization_header is not None else None
    if header_value:
        provided_token = _parse_bearer_token(header_value)
        if provided_token is None:
            msg = "invalid webhook credentials"
            raise WebhookAuthenticationError(msg)
        if secrets.compare_digest(config.api_key, provided_token):
            return
        msg = "invalid webhook credentials"
        raise WebhookAuthenticationError(msg)

    query_value = query_key.strip() if query_key is not None else None
    if query_value and secrets.compare_digest(config.api_key, query_value):
        return

    msg = "invalid webhook credentials"
    raise WebhookAuthenticationError(msg)


def build_webhook_payload_record(
    *,
    source: WebhookSourceConfig,
    raw_body: bytes,
    received_at: datetime,
    payload_size_limit_bytes: int,
    retention_days: int,
) -> WebhookStoredPayload:
    """Validate, redact, and wrap one raw webhook body for retention."""
    if payload_size_limit_bytes <= 0:
        msg = "payload_size_limit_bytes must be positive"
        raise ValueError(msg)
    if retention_days <= 0:
        msg = "retention_days must be positive"
        raise ValueError(msg)
    if len(raw_body) > payload_size_limit_bytes:
        msg = "webhook payload exceeds configured size limit"
        raise WebhookPayloadTooLargeError(msg)

    try:
        decoded_payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = "webhook payload must be a valid UTF-8 JSON object"
        raise WebhookPayloadValidationError(msg) from exc
    if not isinstance(decoded_payload, dict):
        msg = "webhook payload must be a JSON object"
        raise WebhookPayloadValidationError(msg)

    redaction_result = redact_json_value(
        decoded_payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    )
    redacted_payload = redaction_result.redacted_value
    if not isinstance(redacted_payload, dict):
        msg = "webhook payload redaction must preserve a JSON object"
        raise WebhookPayloadValidationError(msg)

    return WebhookStoredPayload(
        source_id=source.source_id,
        source_type=source.source_type,
        received_at=received_at,
        payload_size_bytes=len(raw_body),
        raw_payload=redacted_payload,
        raw_payload_redacted=True,
        raw_payload_retention_until=received_at + timedelta(days=retention_days),
    )


def _parse_bearer_token(authorization_header: str) -> str | None:
    """Extract a bearer token from one Authorization header value."""
    scheme, _, token = authorization_header.partition(" ")
    if scheme.casefold() != "bearer":
        return None
    normalized_token = token.strip()
    if not normalized_token:
        return None
    return normalized_token
