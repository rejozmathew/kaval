"""Proof-of-life mock check for the Phase 0 pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from kaval.models import Evidence, EvidenceKind, Finding, FindingStatus, Severity


def run_mock_check(now: datetime | None = None) -> Finding:
    """Create a deterministic mock finding for the proof-of-life pipeline."""
    created_at = now or datetime.now(tz=UTC)
    finding_id = f"find-{uuid4()}"
    return Finding(
        id=finding_id,
        title="Radarr cannot reach download client",
        severity=Severity.HIGH,
        domain="arr",
        service_id="svc-radarr",
        summary="Mock check detected that Radarr cannot reach DelugeVPN.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="mock_check",
                summary='Synthetic log line: "Download client not available"',
                observed_at=created_at,
                data={
                    "kind": "mock_check",
                    "message": "Download client not available",
                },
            )
        ],
        impact="Download pipeline blocked in proof-of-life mode.",
        confidence=0.95,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=[],
        created_at=created_at,
        resolved_at=None,
    )
