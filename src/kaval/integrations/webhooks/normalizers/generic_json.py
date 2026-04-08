"""Configurable generic JSON webhook normalization."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Self, cast

from pydantic import Field, model_validator

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

_PATH_TOKEN_RE = re.compile(r"([^\.\[\]]+)|\[(\d+)\]")
_GENERIC_JSON_MAPPING_ENV_VAR = "KAVAL_WEBHOOK_GENERIC_JSON_MAPPING"


class GenericJsonNormalizerConfig(KavalModel):
    """Config-driven field mapping for the generic JSON webhook normalizer."""

    dedup_key_path: str = Field(min_length=1)
    title_path: str = Field(min_length=1)
    body_path: str | None = None
    url_path: str | None = None
    source_event_id_path: str | None = None
    alert_state_path: str | None = None
    alert_state_mapping: dict[str, WebhookAlertState] = Field(default_factory=dict)
    severity_path: str | None = None
    severity_mapping: dict[str, WebhookSeverity] = Field(default_factory=dict)
    service_hint_paths: list[str] = Field(default_factory=list)
    tag_paths: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        """Reject blank configured paths so mappings stay deterministic."""
        path_values = [
            self.dedup_key_path,
            self.title_path,
            self.body_path,
            self.url_path,
            self.source_event_id_path,
            self.alert_state_path,
            self.severity_path,
            *self.service_hint_paths,
            *self.tag_paths.values(),
        ]
        if any(path is not None and not path.strip() for path in path_values):
            msg = "generic JSON field-mapping paths must be non-empty"
            raise ValueError(msg)
        if any(not key.strip() for key in self.tag_paths):
            msg = "generic JSON tag names must be non-empty"
            raise ValueError(msg)
        return self


def load_generic_json_normalizer_config_from_env(
    env: Mapping[str, str] | None = None,
) -> GenericJsonNormalizerConfig | None:
    """Load the generic JSON field-mapping config from the environment."""
    source = env or os.environ
    raw_config = source.get(_GENERIC_JSON_MAPPING_ENV_VAR, "").strip()
    if not raw_config:
        return None

    try:
        decoded = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        msg = "generic JSON webhook mapping must be valid JSON"
        raise ValueError(msg) from exc
    if not isinstance(decoded, dict):
        msg = "generic JSON webhook mapping must decode to a JSON object"
        raise ValueError(msg)
    return GenericJsonNormalizerConfig.model_validate(decoded)


def normalize_generic_json_payload(
    *,
    source_id: str,
    payload: dict[str, JsonValue],
    config: GenericJsonNormalizerConfig,
    received_at: datetime | None = None,
    raw_payload_retention_until: datetime | None = None,
) -> WebhookEvent:
    """Normalize one generic JSON payload using the provided field-mapping config."""
    dedup_key = _required_path_string(
        payload,
        path=config.dedup_key_path,
        field_name="dedup_key_path",
    )
    title = _required_path_string(
        payload,
        path=config.title_path,
        field_name="title_path",
    )
    alert_state = _alert_state(payload, config=config)
    redacted_payload = redact_json_value(
        payload,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    ).redacted_value

    return WebhookEvent(
        source_type=WebhookSourceType.GENERIC_JSON,
        source_id=source_id,
        source_event_id=(
            _optional_path_string(
                payload,
                path=config.source_event_id_path,
            )
            or dedup_key
        ),
        dedup_key=dedup_key,
        received_at=received_at or datetime.now(tz=UTC),
        alert_state=alert_state,
        severity=_severity(payload, config=config, alert_state=alert_state),
        title=title,
        body=_optional_path_string(payload, path=config.body_path) or title,
        url=_optional_path_string(payload, path=config.url_path),
        tags=_tags(payload, config=config),
        service_hints=_service_hints(payload, config=config),
        matching_outcome=WebhookMatchingOutcome.PENDING,
        raw_payload=redacted_payload if isinstance(redacted_payload, dict) else {},
        raw_payload_redacted=True,
        raw_payload_retention_until=raw_payload_retention_until,
        processing_status=WebhookProcessingStatus.NEW,
    )


def _alert_state(
    payload: dict[str, JsonValue],
    *,
    config: GenericJsonNormalizerConfig,
) -> WebhookAlertState:
    """Resolve the configured alert-state path into the canonical lifecycle state."""
    if config.alert_state_path is None:
        return WebhookAlertState.FIRING

    raw_state = _required_path_string(
        payload,
        path=config.alert_state_path,
        field_name="alert_state_path",
    )
    return cast(
        WebhookAlertState,
        _mapped_enum_value(
            raw_value=raw_state,
            configured_mapping=config.alert_state_mapping,
            enum_type=WebhookAlertState,
            field_name="alert_state_path",
        ),
    )


def _severity(
    payload: dict[str, JsonValue],
    *,
    config: GenericJsonNormalizerConfig,
    alert_state: WebhookAlertState,
) -> WebhookSeverity:
    """Resolve the configured severity path into the canonical normalized severity."""
    if config.severity_path is None:
        return (
            WebhookSeverity.INFO
            if alert_state == WebhookAlertState.RESOLVED
            else WebhookSeverity.MEDIUM
        )

    raw_severity = _required_path_string(
        payload,
        path=config.severity_path,
        field_name="severity_path",
    )
    return cast(
        WebhookSeverity,
        _mapped_enum_value(
            raw_value=raw_severity,
            configured_mapping=config.severity_mapping,
            enum_type=WebhookSeverity,
            field_name="severity_path",
        ),
    )


def _mapped_enum_value(
    *,
    raw_value: str,
    configured_mapping: Mapping[str, WebhookAlertState | WebhookSeverity],
    enum_type: type[WebhookAlertState] | type[WebhookSeverity],
    field_name: str,
) -> WebhookAlertState | WebhookSeverity:
    """Resolve one raw configured string into the requested enum type."""
    normalized_mapping = {
        key.casefold(): value
        for key, value in configured_mapping.items()
    }
    raw_key = raw_value.casefold()
    if raw_key in normalized_mapping:
        return normalized_mapping[raw_key]
    try:
        return enum_type(raw_key)
    except ValueError as exc:
        msg = f"unsupported {field_name} value: {raw_value}"
        raise ValueError(msg) from exc


def _service_hints(
    payload: dict[str, JsonValue],
    *,
    config: GenericJsonNormalizerConfig,
) -> list[str]:
    """Build unique service hints from the configured generic JSON paths."""
    hints: list[str] = []
    for path in config.service_hint_paths:
        value = _resolve_path(payload, path)
        normalized = _json_value_to_string(value)
        if normalized is None or normalized in hints:
            continue
        hints.append(normalized)
    return hints


def _tags(
    payload: dict[str, JsonValue],
    *,
    config: GenericJsonNormalizerConfig,
) -> dict[str, str]:
    """Resolve configured tag mappings into flat string tags."""
    tags: dict[str, str] = {}
    for tag_name, path in sorted(config.tag_paths.items()):
        value = _resolve_path(payload, path)
        normalized = _json_value_to_string(value)
        if normalized is not None:
            tags[tag_name] = normalized
    return tags


def _required_path_string(
    payload: dict[str, JsonValue],
    *,
    path: str,
    field_name: str,
) -> str:
    """Resolve one required path from the payload and return its string form."""
    normalized = _json_value_to_string(_resolve_path(payload, path))
    if normalized is None:
        msg = f"generic JSON mapping path did not resolve a value: {field_name}"
        raise ValueError(msg)
    return normalized


def _optional_path_string(
    payload: dict[str, JsonValue],
    *,
    path: str | None,
) -> str | None:
    """Resolve one optional path from the payload and return its string form."""
    if path is None:
        return None
    return _json_value_to_string(_resolve_path(payload, path))


def _resolve_path(value: JsonValue, path: str) -> JsonValue:
    """Resolve a dotted path with optional list indexes against a JSON value."""
    tokens = _parse_path(path)
    current = value
    for token in tokens:
        if isinstance(token, str):
            if not isinstance(current, dict) or token not in current:
                return None
            current = current[token]
            continue
        if not isinstance(current, list) or token >= len(current):
            return None
        current = current[token]
    return current


def _parse_path(path: str) -> list[str | int]:
    """Parse one dotted/list-indexed path into traversal tokens."""
    tokens: list[str | int] = []
    position = 0
    while position < len(path):
        if path[position] == ".":
            position += 1
            continue
        match = _PATH_TOKEN_RE.match(path, position)
        if match is None:
            msg = f"invalid generic JSON path: {path}"
            raise ValueError(msg)
        field_name, index = match.groups()
        if field_name is not None:
            tokens.append(field_name)
        else:
            tokens.append(int(index))
        position = match.end()
    return tokens


def _json_value_to_string(value: JsonValue) -> str | None:
    """Convert one JSON value into a deterministic string representation."""
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
