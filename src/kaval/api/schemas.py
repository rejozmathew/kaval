"""Typed request and response contracts for the Kaval API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

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
