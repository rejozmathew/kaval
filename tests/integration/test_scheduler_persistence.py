"""Integration test for scheduler finding persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.models import Evidence, EvidenceKind, Severity
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.monitoring.scheduler import CheckScheduler, persist_findings
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for integration tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class _PersistentTestCheck(MonitoringCheck):
    """A deterministic test check used to verify SQLite persistence."""

    check_id = "persistent-check"
    interval_seconds = 60

    def run(self, context: CheckContext) -> list:
        """Emit a single finding for the DelugeVPN mock service."""
        service = next(service for service in context.services if service.id == "svc-delugevpn")
        return [
            build_finding(
                check_id=self.check_id,
                service=service,
                title="DelugeVPN: persistent-check",
                severity=Severity.HIGH,
                summary="Synthetic scheduled finding for persistence coverage.",
                impact="Scheduler integration coverage only.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.EVENT,
                        source=self.check_id,
                        summary="Persisted through the scheduler integration test.",
                        observed_at=context.now,
                        data={"service_id": service.id},
                    )
                ],
                now=context.now,
                confidence=0.9,
            )
        ]


def test_scheduler_findings_persist_to_sqlite(tmp_path: Path) -> None:
    """Scheduled findings should persist cleanly into the existing SQLite store."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    try:
        services = build_mock_services()
        for service in services:
            database.upsert_service(service)

        scheduler = CheckScheduler([_PersistentTestCheck()])
        result = scheduler.run_due_checks(CheckContext(services=services, now=ts(11, 15)))
        persist_findings(database, result.findings)

        stored_findings = database.list_findings()

        assert result.executed_checks == ("persistent-check",)
        assert len(result.findings) == 1
        assert len(stored_findings) == 1
        assert stored_findings[0].service_id == "svc-delugevpn"
        assert stored_findings[0].domain == "persistent-check"
    finally:
        database.close()
