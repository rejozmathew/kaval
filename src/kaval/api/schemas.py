"""Typed request and response contracts for the Kaval API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field

from kaval.credentials.models import CredentialRequestMode
from kaval.models import (
    DependencyConfidence,
    DependencySource,
    Incident,
    Investigation,
    KavalModel,
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


class WidgetSummaryResponse(KavalModel):
    """Compact health summary for homepage-style consumers."""

    total_services: int
    active_findings: int
    active_incidents: int
    healthy_services: int
    degraded_services: int
    down_services: int
    stopped_services: int
    unknown_services: int
    last_updated: datetime | None


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


class CredentialSecretSubmissionRequest(KavalModel):
    """API payload for submitting one secret value after mode selection."""

    secret_value: str
    submitted_by: str


class VaultUnlockRequest(KavalModel):
    """API payload for initializing or unlocking the credential vault."""

    master_passphrase: str
