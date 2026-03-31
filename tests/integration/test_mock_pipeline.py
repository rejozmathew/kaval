"""Integration test for the Phase 0 proof-of-life pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.models import FindingStatus, IncidentStatus
from kaval.pipeline import build_mock_services, run_mock_pipeline


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for integration tests."""
    return datetime(2026, 3, 30, hour, minute, tzinfo=UTC)


def test_mock_pipeline_persists_finding_and_incident(tmp_path: Path) -> None:
    """The proof-of-life pipeline should persist a finding and its incident."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    try:
        result = run_mock_pipeline(
            database,
            services=build_mock_services(),
            now=ts(14, 30),
        )

        persisted_finding = database.get_finding(result.finding.id)
        persisted_incident = database.get_incident(result.incident.id)

        assert persisted_finding is not None
        assert persisted_finding.status == FindingStatus.GROUPED
        assert persisted_finding.incident_id == result.incident.id

        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.OPEN
        assert persisted_incident.all_findings == [result.finding.id]
        assert persisted_incident.affected_services == ["svc-radarr"]

        assert "Kaval Phase 0 Proof of Life" in result.console_output
        assert result.finding.id in result.console_output
        assert result.incident.id in result.console_output
        assert "Persisted: finding and incident stored in SQLite" in result.console_output
    finally:
        database.close()
