"""Typed request and response contracts for the Kaval API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field

from kaval.credentials.models import CredentialRequestMode
from kaval.integrations.adapter_fallback import AdapterFactFreshness
from kaval.integrations.service_adapters import AdapterStatus
from kaval.memory.note_models import UserNoteCreate, UserNoteUpdate
from kaval.models import (
    DependencyConfidence,
    DependencySource,
    Incident,
    Investigation,
    JsonValue,
    KavalModel,
    RedactionLevel,
    Service,
)


class HealthResponse(KavalModel):
    """Readiness status for the FastAPI application."""

    status: Literal["ok"]
    database_ready: bool


class ServiceGraphEdge(KavalModel):
    """One directed edge in the service graph response."""

    source_service_id: str
    target_service_id: str
    confidence: DependencyConfidence
    source: DependencySource
    description: str | None


class ServiceGraphResponse(KavalModel):
    """Read-only graph view built from persisted services."""

    services: list[Service]
    edges: list[ServiceGraphEdge]


class WidgetOverallStatus(StrEnum):
    """Overall health states exposed through the widget summary."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"


class WidgetSummaryResponse(KavalModel):
    """Compact health summary for homepage-style consumers."""

    status: WidgetOverallStatus = WidgetOverallStatus.HEALTHY
    total_services: int
    active_findings: int
    active_incidents: int
    healthy_services: int
    degraded_services: int
    down_services: int
    stopped_services: int
    unknown_services: int
    last_updated: datetime | None
    services_total: int = 0
    services_healthy: int = 0
    services_degraded: int = 0
    services_down: int = 0
    last_investigation: datetime | None = None
    effectiveness_score: int = Field(default=0, ge=0, le=100)
    adapters_healthy: int = Field(default=0, ge=0)
    adapters_degraded: int = Field(default=0, ge=0)
    pending_approvals: int = Field(default=0, ge=0)
    url: str | None = None
    refresh_interval_seconds: int | None = Field(default=None, ge=1)


class RealtimeSnapshotResponse(KavalModel):
    """WebSocket payload carrying the latest Phase 1 UI state."""

    kind: Literal["snapshot"]
    graph: ServiceGraphResponse
    incidents: list[Incident]
    investigations: list[Investigation]
    widget: WidgetSummaryResponse


class ServiceDetailAdapterConfigurationState(StrEnum):
    """Configuration states shown in the minimum service-detail insight panel."""

    CONFIGURED = "configured"
    UNCONFIGURED = "unconfigured"
    LOCKED = "locked"


class ServiceDetailAdapterHealthState(StrEnum):
    """Current health states currently derivable for one adapter."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ServiceDetailImproveActionKind(StrEnum):
    """Actionable improvement affordances for the minimum service detail view."""

    CONFIGURE_LOCAL_MODEL = "configure_local_model"
    CONFIGURE_ADAPTER = "configure_adapter"
    UNLOCK_VAULT = "unlock_vault"


class ServiceDetailAdapterResponse(KavalModel):
    """One adapter summary shown in the service detail insight section."""

    adapter_id: str
    display_name: str
    configuration_state: ServiceDetailAdapterConfigurationState
    configuration_summary: str
    health_state: ServiceDetailAdapterHealthState
    health_summary: str
    missing_credentials: list[str] = Field(default_factory=list)
    supported_fact_names: list[str] = Field(default_factory=list)


class ServiceDetailImproveActionResponse(KavalModel):
    """One improvement action shown in the service detail insight section."""

    kind: ServiceDetailImproveActionKind
    title: str
    detail: str


class ServiceDetailInsightSectionResponse(KavalModel):
    """The minimum service-detail insight payload for Phase 3A."""

    current_level: int
    adapter_available: bool
    adapters: list[ServiceDetailAdapterResponse] = Field(default_factory=list)
    improve_actions: list[ServiceDetailImproveActionResponse] = Field(default_factory=list)
    fact_summary_available: bool = False


class ServiceDetailResponse(KavalModel):
    """A later-enrichable service-detail response contract."""

    service: Service
    insight_section: ServiceDetailInsightSectionResponse


class AdapterFactSourceType(StrEnum):
    """Provenance source labels for adapter-imported facts."""

    DEEP_INSPECTION_ADAPTER = "deep_inspection_adapter"


class ServiceAdapterFactsItemResponse(KavalModel):
    """One adapter-backed facts payload for a single service."""

    adapter_id: str
    display_name: str
    service_id: str
    service_name: str
    source: AdapterFactSourceType = AdapterFactSourceType.DEEP_INSPECTION_ADAPTER
    read_only: bool = True
    configuration_state: ServiceDetailAdapterConfigurationState
    configuration_summary: str
    health_state: ServiceDetailAdapterHealthState
    health_summary: str
    missing_credentials: list[str] = Field(default_factory=list)
    supported_fact_names: list[str] = Field(default_factory=list)
    execution_status: AdapterStatus | None = None
    facts_available: bool = False
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    excluded_paths: list[str] = Field(default_factory=list)
    applied_redaction_level: RedactionLevel | None = None
    facts_observed_at: datetime | None = None
    stale_at: datetime | None = None
    next_refresh_at: datetime | None = None
    refresh_interval_minutes: int = Field(ge=1)
    freshness: AdapterFactFreshness
    reason: str | None = None


class ServiceAdapterFactsResponse(KavalModel):
    """Read-only adapter-imported facts contract for one service."""

    service_id: str
    service_name: str
    checked_at: datetime
    facts_available: bool = False
    adapters: list[ServiceAdapterFactsItemResponse] = Field(default_factory=list)


class CreateCredentialRequestRequest(KavalModel):
    """API payload for creating one credential request."""

    incident_id: str
    investigation_id: str | None = None
    service_id: str
    credential_key: str
    reason: str


class CredentialRequestChoiceRequest(KavalModel):
    """API payload for recording one user choice on a credential request."""

    mode: CredentialRequestMode
    decided_by: str


class TelegramCredentialCallbackRequest(KavalModel):
    """API payload for replaying one Telegram callback identifier."""

    callback_id: str
    decided_by: str


class TelegramUpdateProcessingStatus(StrEnum):
    """Processing outcomes for inbound Telegram updates."""

    PROCESSED = "processed"
    IGNORED = "ignored"


class TelegramInboundChat(KavalModel):
    """Subset of Telegram chat metadata needed for Phase 3B ingress."""

    model_config = ConfigDict(extra="ignore")

    id: int


class TelegramInboundMessage(KavalModel):
    """Subset of Telegram message metadata needed for command routing."""

    model_config = ConfigDict(extra="ignore")

    message_id: int
    chat: TelegramInboundChat
    text: str | None = None


class TelegramInboundUpdateRequest(KavalModel):
    """Subset of one Telegram update used for inbound memory commands."""

    model_config = ConfigDict(extra="ignore")

    update_id: int
    message: TelegramInboundMessage | None = None


class TelegramInboundUpdateResponse(KavalModel):
    """API response describing how one inbound Telegram update was handled."""

    status: TelegramUpdateProcessingStatus
    detail: str
    reply_delivery_status: Literal["sent", "skipped", "failed"] | None = None


class CredentialSecretSubmissionRequest(KavalModel):
    """API payload for submitting one secret value after mode selection."""

    secret_value: str
    submitted_by: str


class VaultUnlockRequest(KavalModel):
    """API payload for initializing or unlocking the credential vault."""

    master_passphrase: str


class CreateUserNoteRequest(UserNoteCreate):
    """API payload for creating one active user note."""


class UpdateUserNoteRequest(UserNoteUpdate):
    """API payload for updating one active user note."""
