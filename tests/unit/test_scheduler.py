"""Unit tests for the Phase 1 check scheduler."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.models import (
    Evidence,
    EvidenceKind,
    Incident,
    IncidentStatus,
    MaintenanceScope,
    MaintenanceWindowRecord,
    Severity,
)
from kaval.monitoring import (
    MonitoringCadenceConfig,
    MonitoringCheckCadenceRule,
    ServiceMonitoringCadenceOverride,
)
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.monitoring.scheduler import CheckScheduler, persist_findings
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
        candidates = [
            service
            for service in context.services
            if context.target_service_ids is None or service.id in context.target_service_ids
        ]
        service = next(
            (service for service in candidates if service.id == "svc-radarr"),
            candidates[0],
        )
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


class _GlobalOnlyCheck(MonitoringCheck):
    """A deterministic test check that can run without registered services."""

    def __init__(self, check_id: str, interval_seconds: int) -> None:
        """Store the check identity and schedule interval."""
        self.check_id = check_id
        self.interval_seconds = interval_seconds

    def can_run_without_services(self, context: CheckContext) -> bool:
        """Allow execution without any service inventory."""
        return True

    def run(self, context: CheckContext) -> list:
        """Emit no findings and assert the scheduler kept global scope intact."""
        assert context.target_service_ids is None
        return []


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


def test_scheduler_runs_global_check_without_registered_services() -> None:
    """Checks that declare global execution should still run without services."""
    scheduler = CheckScheduler([_GlobalOnlyCheck("global-check", interval_seconds=60)])

    first_run = scheduler.run_due_checks(CheckContext(services=[], now=ts(10, 0, 0)))
    skipped_run = scheduler.run_due_checks(CheckContext(services=[], now=ts(10, 0, 30)))
    second_run = scheduler.run_due_checks(CheckContext(services=[], now=ts(10, 1, 1)))

    assert first_run.executed_checks == ("global-check",)
    assert skipped_run.executed_checks == ()
    assert second_run.executed_checks == ("global-check",)
    assert scheduler.last_run_at("global-check") == ts(10, 1, 1)


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


def test_scheduler_respects_disabled_and_service_specific_cadence() -> None:
    """Disabled checks should skip entirely and service overrides should narrow due runs."""
    services = build_mock_services()
    disabled_scheduler = CheckScheduler(
        [_StaticFindingCheck("a-check", interval_seconds=60)],
        cadence=MonitoringCadenceConfig(
            check_overrides=[
                MonitoringCheckCadenceRule(
                    check_id="a-check",
                    enabled=False,
                    interval_seconds=60,
                )
            ]
        ),
    )

    disabled_run = disabled_scheduler.run_due_checks(
        CheckContext(services=services, now=ts(10, 0, 0))
    )

    assert disabled_run.executed_checks == ()
    assert disabled_run.findings == []

    override_scheduler = CheckScheduler(
        [_StaticFindingCheck("a-check", interval_seconds=60)],
        cadence=MonitoringCadenceConfig(
            service_overrides=[
                ServiceMonitoringCadenceOverride(
                    service_id="svc-radarr",
                    check_id="a-check",
                    enabled=True,
                    interval_seconds=30,
                ),
                ServiceMonitoringCadenceOverride(
                    service_id="svc-sonarr",
                    check_id="a-check",
                    enabled=False,
                    interval_seconds=None,
                ),
            ]
        ),
    )

    first_run = override_scheduler.run_due_checks(
        CheckContext(services=services, now=ts(10, 0, 0))
    )
    second_run = override_scheduler.run_due_checks(
        CheckContext(services=services, now=ts(10, 0, 31))
    )

    assert first_run.executed_checks == ("a-check",)
    assert second_run.executed_checks == ("a-check",)
    assert [finding.service_id for finding in second_run.findings] == ["svc-radarr"]


def test_persist_findings_respects_active_maintenance_windows(tmp_path: Path) -> None:
    """Persisted findings should skip service and global maintenance windows."""
    services = build_mock_services()
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    try:
        for service in services:
            database.upsert_service(service)

        database.upsert_maintenance_window(
            MaintenanceWindowRecord(
                scope=MaintenanceScope.SERVICE,
                service_id="svc-radarr",
                started_at=ts(10, 30),
                expires_at=ts(11, 30),
            )
        )
        persist_findings(
            database,
            [
                build_finding(
                    check_id="container_health",
                    service=service,
                    title=f"{service.name}: health degraded",
                    severity=Severity.MEDIUM,
                    summary="Synthetic maintenance persistence coverage.",
                    impact="Used only for scheduler maintenance tests.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.EVENT,
                            source="container_health",
                            summary="Synthetic scheduler maintenance evidence.",
                            observed_at=ts(11, 0),
                            data={"service_id": service.id},
                        )
                    ],
                    now=ts(11, 0),
                    confidence=0.8,
                )
                for service in services
            ],
        )

        stored_after_service_scope = database.list_findings()
        assert {finding.service_id for finding in stored_after_service_scope} == {
            "svc-delugevpn",
            "svc-sonarr",
        }

        database.upsert_maintenance_window(
            MaintenanceWindowRecord(
                scope=MaintenanceScope.GLOBAL,
                started_at=ts(11, 5),
                expires_at=ts(11, 45),
            )
        )
        persist_findings(
            database,
            [
                build_finding(
                    check_id="container_health",
                    service=service,
                    title=f"{service.name}: health degraded again",
                    severity=Severity.MEDIUM,
                    summary="Synthetic global maintenance coverage.",
                    impact="Used only for scheduler maintenance tests.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.EVENT,
                            source="container_health",
                            summary="Synthetic global maintenance evidence.",
                            observed_at=ts(11, 15),
                            data={"service_id": service.id},
                        )
                    ],
                    now=ts(11, 15),
                    confidence=0.8,
                )
                for service in services
            ],
        )

        assert len(database.list_findings()) == 2
    finally:
        database.close()


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
