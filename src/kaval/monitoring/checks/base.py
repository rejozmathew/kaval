"""Base contracts for deterministic monitoring checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Sequence
from uuid import uuid4

from kaval.discovery.docker import DockerDiscoverySnapshot
from kaval.discovery.unraid import UnraidDiscoverySnapshot
from kaval.models import (
    Change,
    Evidence,
    Finding,
    FindingStatus,
    Service,
    Severity,
)


@dataclass(frozen=True, slots=True)
class CheckContext:
    """Discovery and timing context passed to deterministic checks."""

    services: list[Service]
    docker_snapshot: DockerDiscoverySnapshot | None = None
    unraid_snapshot: UnraidDiscoverySnapshot | None = None
    now: datetime = field(default_factory=lambda: datetime.now(tz=UTC))


class MonitoringCheck(ABC):
    """Abstract base class for deterministic monitoring checks."""

    check_id: str
    interval_seconds: int

    @abstractmethod
    def run(self, context: CheckContext) -> list[Finding]:
        """Run the check against the current discovery context."""


def build_finding(
    *,
    check_id: str,
    service: Service,
    title: str,
    severity: Severity,
    summary: str,
    impact: str,
    evidence: Sequence[Evidence],
    now: datetime,
    confidence: float = 1.0,
    related_changes: Sequence[Change] | None = None,
) -> Finding:
    """Build a new Finding emitted by a deterministic monitoring check."""
    return Finding(
        id=f"find-{uuid4()}",
        title=title,
        severity=severity,
        domain=check_id,
        service_id=service.id,
        summary=summary,
        evidence=list(evidence),
        impact=impact,
        confidence=confidence,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=list(related_changes or []),
        created_at=now,
        resolved_at=None,
    )
