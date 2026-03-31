"""Typed response contracts for the Phase 1 read-only API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from kaval.models import (
    DependencyConfidence,
    DependencySource,
    Incident,
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
    widget: WidgetSummaryResponse
