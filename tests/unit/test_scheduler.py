"""Unit tests for the Phase 1 check scheduler."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import Evidence, EvidenceKind, Incident, IncidentStatus, Severity
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.monitoring.scheduler import CheckScheduler
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0, second: int = 0) -> datetime:
    """Build a UTC timestamp for scheduler tests."""
    return datetime(2026, 3, 31, hour, minute, second, tzinfo=UTC)


class _StaticFindingCheck(MonitoringCheck):
    """A deterministic test check that always emits one finding."""

    def __init__(self, check_id: str, interval_seconds: int) -> None:
        """Store the check identity and schedule interval."""
        self.check_id = check_id
        self.interval_seconds = interval_seconds

    def run(self, context: CheckContext) -> list:
        """Emit a single finding for the Radarr mock service."""
        service = next(service for service in context.services if service.id == "svc-radarr")
        return [
            build_finding(
                check_id=self.check_id,
                service=service,
                title=f"{service.name}: {self.check_id}",
                severity=Severity.MEDIUM,
                summary=f"{self.check_id} reported a deterministic issue.",
                impact="Used for scheduler tests only.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.EVENT,
                        source=self.check_id,
                        summary="Synthetic scheduler test evidence.",
                        observed_at=context.now,
                        data={"check_id": self.check_id},
                    )
                ],
                now=context.now,
                confidence=0.8,
            )
        ]


def test_scheduler_runs_due_checks_in_deterministic_order() -> None:
    """Checks should run in sorted ID order and skip until their interval elapses."""
    services = build_mock_services()
    scheduler = CheckScheduler(
        [
            _StaticFindingCheck("b-check", interval_seconds=60),
            _StaticFindingCheck("a-check", interval_seconds=60),
        ]
    )

    first_run = scheduler.run_due_checks(CheckContext(services=services, now=ts(10, 0, 0)))
    skipped_run = scheduler.run_due_checks(CheckContext(services=services, now=ts(10, 0, 30)))
    second_run = scheduler.run_due_checks(CheckContext(services=services, now=ts(10, 1, 1)))

    assert first_run.executed_checks == ("a-check", "b-check")
    assert [finding.domain for finding in first_run.findings] == ["a-check", "b-check"]
    assert skipped_run.executed_checks == ()
    assert skipped_run.findings == []
    assert second_run.executed_checks == ("a-check", "b-check")
    assert scheduler.last_run_at("a-check") == ts(10, 1, 1)


def test_scheduler_rejects_duplicate_check_ids() -> None:
    """Duplicate check registrations should fail fast."""
    scheduler = CheckScheduler()
    scheduler.register_check(_StaticFindingCheck("duplicate", interval_seconds=60))

    try:
        scheduler.register_check(_StaticFindingCheck("duplicate", interval_seconds=60))
    except ValueError as exc:
        assert "duplicate check_id" in str(exc)
    else:
        raise AssertionError("expected duplicate check registration to fail")


def test_scheduler_applies_bounded_incident_acceleration() -> None:
    """Active incidents should accelerate related checks inside the policy window."""
    services = build_mock_services()
    scheduler = CheckScheduler([_StaticFindingCheck("a-check", interval_seconds=60)])
    incident = _build_incident(
        incident_id="inc-radarr",
        affected_services=["svc-radarr"],
        created_at=ts(10, 0, 0),
    )

    first_run = scheduler.run_due_checks(
        CheckContext(services=services, now=ts(10, 0, 0)),
        incidents=[incident],
    )
    accelerated_run = scheduler.run_due_checks(
        CheckContext(services=services, now=ts(10, 0, 31)),
        incidents=[incident],
    )

    assert first_run.executed_checks == ("a-check",)
    assert accelerated_run.executed_checks == ("a-check",)
    assert scheduler.last_run_at("a-check") == ts(10, 0, 31)


def _build_incident(
    *,
    incident_id: str,
    affected_services: list[str],
    created_at: datetime,
) -> Incident:
    """Build the minimal active incident shape needed by scheduler tests."""
    return Incident(
        id=incident_id,
        title="Synthetic scheduler incident",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=["find-test"],
        all_findings=["find-test"],
        affected_services=affected_services,
        triggering_symptom="Synthetic scheduler coverage.",
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=created_at,
        grouping_window_end=created_at,
        created_at=created_at,
        updated_at=created_at,
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
