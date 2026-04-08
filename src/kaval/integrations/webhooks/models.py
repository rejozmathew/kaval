"""Typed normalized webhook-event contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Self
from uuid import uuid4

from pydantic import Field, model_validator

from kaval.models import JsonValue, KavalModel


def _new_webhook_event_id() -> str:
    """Return a stable identifier for one normalized webhook event."""
    return f"whk-{uuid4()}"


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(tz=UTC)


class WebhookSourceType(StrEnum):
    """Supported normalized webhook source types."""

    UPTIME_KUMA = "uptime_kuma"
    GRAFANA = "grafana"
    PROMETHEUS_ALERTMANAGER = "prometheus_alertmanager"
    NETDATA = "netdata"
    GENERIC_JSON = "generic_json"


class WebhookSeverity(StrEnum):
    """Normalized webhook severities prior to finding creation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WebhookAlertState(StrEnum):
    """Lifecycle states preserved from the source alert."""

    FIRING = "firing"
    RESOLVED = "resolved"


class WebhookMatchingOutcome(StrEnum):
    """Current matching outcome for one webhook event."""

    PENDING = "pending"
    UNMATCHED = "unmatched"
    SINGLE = "single"
    MULTI = "multi"


class WebhookProcessingStatus(StrEnum):
    """Lifecycle states for webhook ingestion and downstream processing."""

    NEW = "new"
    MATCHED = "matched"
    FINDING_CREATED = "finding_created"
    DUPLICATE = "duplicate"
    IGNORED = "ignored"


class WebhookEvent(KavalModel):
    """Canonical internal event used across webhook ingestion."""

    id: str = Field(default_factory=_new_webhook_event_id, min_length=1)
    source_type: WebhookSourceType
    source_id: str = Field(min_length=1)
    source_event_id: str | None = Field(default=None, min_length=1)
    dedup_key: str = Field(min_length=1)
    received_at: datetime = Field(default_factory=_utc_now)
    alert_state: WebhookAlertState = WebhookAlertState.FIRING
    severity: WebhookSeverity
    title: str = Field(min_length=1)
    body: str = ""
    url: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    service_hints: list[str] = Field(default_factory=list)
    matched_service_ids: list[str] = Field(default_factory=list)
    matching_outcome: WebhookMatchingOutcome = WebhookMatchingOutcome.PENDING
    raw_payload: dict[str, JsonValue] = Field(default_factory=dict)
    raw_payload_redacted: bool = False
    raw_payload_retention_until: datetime | None = None
    processing_status: WebhookProcessingStatus = WebhookProcessingStatus.NEW

    @model_validator(mode="after")
    def validate_matching(self) -> Self:
        """Keep matching status and matched-service data coherent."""
        _validate_unique_non_empty_strings(
            values=self.service_hints,
            field_name="service_hints",
        )
        _validate_unique_non_empty_strings(
            values=self.matched_service_ids,
            field_name="matched_service_ids",
        )

        matched_count = len(self.matched_service_ids)
        if self.matching_outcome == WebhookMatchingOutcome.PENDING and matched_count != 0:
            msg = "pending webhook matching cannot include matched_service_ids"
            raise ValueError(msg)
        if self.matching_outcome == WebhookMatchingOutcome.UNMATCHED and matched_count != 0:
            msg = "unmatched webhook events cannot include matched_service_ids"
            raise ValueError(msg)
        if self.matching_outcome == WebhookMatchingOutcome.SINGLE and matched_count != 1:
            msg = "single-match webhook events must include exactly one matched_service_id"
            raise ValueError(msg)
        if self.matching_outcome == WebhookMatchingOutcome.MULTI and matched_count < 2:
            msg = "multi-match webhook events must include at least two matched_service_ids"
            raise ValueError(msg)
        if self.processing_status in {
            WebhookProcessingStatus.MATCHED,
            WebhookProcessingStatus.FINDING_CREATED,
        } and self.matching_outcome not in {
            WebhookMatchingOutcome.SINGLE,
            WebhookMatchingOutcome.MULTI,
        }:
            msg = "matched webhook processing states require a single or multi match outcome"
            raise ValueError(msg)
        return self


def _validate_unique_non_empty_strings(*, values: list[str], field_name: str) -> None:
    """Reject blank or duplicate string entries in list-like webhook fields."""
    normalized: list[str] = []
    for value in values:
        if not value.strip():
            msg = f"{field_name} entries must be non-empty"
            raise ValueError(msg)
        if value in normalized:
            msg = f"{field_name} entries must be unique"
            raise ValueError(msg)
        normalized.append(value)
