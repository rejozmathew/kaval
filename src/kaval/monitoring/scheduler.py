"""Deterministic scheduler for Phase 1 and Phase 3A monitoring checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.maintenance import filter_findings_for_maintenance
from kaval.models import Finding, Incident
from kaval.monitoring.cadence import (
    MonitoringCadenceConfig,
    MonitoringCadenceDecision,
    default_monitoring_cadence_config,
    resolve_monitoring_cadence_decision,
    resolve_service_check_execution,
)
from kaval.monitoring.catalog import check_applies_to_service
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck
from kaval.runtime.capability_runtime import build_scheduler_runtime_signal


@dataclass(frozen=True, slots=True)
class SchedulerRunResult:
    """Results from one scheduler tick."""

    executed_checks: tuple[str, ...]
    findings: list[Finding]


class CheckScheduler:
    """Run deterministic checks on their configured interval."""

    def __init__(
        self,
        checks: Sequence[MonitoringCheck] | None = None,
        *,
        cadence: MonitoringCadenceConfig | None = None,
    ) -> None:
        """Initialize the scheduler with an optional initial check set."""
        self._checks: dict[str, MonitoringCheck] = {}
        self._last_run_at: dict[str, datetime] = {}
        self._last_service_run_at: dict[tuple[str, str], datetime] = {}
        self._cadence = cadence or default_monitoring_cadence_config()
        for check in checks or []:
            self.register_check(check)

    def register_check(self, check: MonitoringCheck) -> None:
        """Register one check with the scheduler."""
        if not check.check_id:
            msg = "check_id must be non-empty"
            raise ValueError(msg)
        if check.interval_seconds <= 0:
            msg = "interval_seconds must be positive"
            raise ValueError(msg)
        if check.check_id in self._checks:
            msg = f"duplicate check_id: {check.check_id}"
            raise ValueError(msg)
        self._checks[check.check_id] = check

    def last_run_at(self, check_id: str) -> datetime | None:
        """Return the last execution timestamp for one registered check."""
        return self._last_run_at.get(check_id)

    def run_due_checks(
        self,
        context: CheckContext,
        *,
        incidents: Sequence[Incident] = (),
    ) -> SchedulerRunResult:
        """Run all checks that are due at the given time."""
        findings: list[Finding] = []
        executed_checks: list[str] = []
        for check_id in sorted(self._checks):
            check = self._checks[check_id]
            cadence = resolve_monitoring_cadence_decision(
                config=self._cadence,
                check_id=check.check_id,
                services=context.services,
                now=context.now,
                incidents=list(incidents),
                base_interval_seconds=check.interval_seconds,
            )
            if not cadence.enabled:
                continue
            due_service_ids = _due_service_ids(
                context=context,
                check=check,
                cadence=self._cadence,
                decision=cadence,
                last_service_run_at=self._last_service_run_at,
            )
            if not due_service_ids:
                continue
            findings.extend(
                check.run(
                    CheckContext(
                        services=context.services,
                        docker_snapshot=context.docker_snapshot,
                        unraid_snapshot=context.unraid_snapshot,
                        target_service_ids=frozenset(due_service_ids),
                        now=context.now,
                    )
                )
            )
            for service_id in due_service_ids:
                self._last_service_run_at[(check_id, service_id)] = context.now
            self._last_run_at[check_id] = context.now
            executed_checks.append(check_id)
        return SchedulerRunResult(
            executed_checks=tuple(executed_checks),
            findings=findings,
        )


def persist_findings(database: KavalDatabase, findings: Sequence[Finding]) -> None:
    """Persist scheduler findings into the existing SQLite store."""
    filtered_findings = filter_findings_for_maintenance(
        findings,
        windows=database.list_maintenance_windows(),
    )
    for finding in filtered_findings:
        database.upsert_finding(finding)


def persist_scheduler_runtime_signal(
    database: KavalDatabase,
    *,
    run_at: datetime,
    result: SchedulerRunResult,
) -> None:
    """Persist one completed scheduler tick for capability-health reporting."""
    database.upsert_capability_runtime_signal(
        build_scheduler_runtime_signal(
            recorded_at=run_at,
            last_completed_at=run_at,
            executed_check_ids=result.executed_checks,
        )
    )


def _is_due(
    *,
    now: datetime,
    last_run_at: datetime | None,
    interval_seconds: int,
) -> bool:
    """Return whether a check should execute at the current time."""
    if last_run_at is None:
        return True
    return now - last_run_at >= timedelta(seconds=interval_seconds)


def _due_service_ids(
    *,
    context: CheckContext,
    check: MonitoringCheck,
    cadence: MonitoringCadenceConfig,
    decision: MonitoringCadenceDecision,
    last_service_run_at: dict[tuple[str, str], datetime],
) -> list[str]:
    """Return the service ids that are due for one check execution."""
    due_service_ids: list[str] = []
    accelerated_scope = set(decision.scoped_service_ids)
    for service in context.services:
        try:
            if not check_applies_to_service(check.check_id, service):
                continue
        except ValueError:
            pass
        execution = resolve_service_check_execution(
            config=cadence,
            service_id=service.id,
            check_id=check.check_id,
            base_interval_seconds=check.interval_seconds,
        )
        if not execution.enabled:
            continue
        interval_seconds = execution.interval_seconds
        if decision.accelerated and service.id in accelerated_scope:
            interval_seconds = min(interval_seconds, decision.effective_interval_seconds)
        if _is_due(
            now=context.now,
            last_run_at=last_service_run_at.get((check.check_id, service.id)),
            interval_seconds=interval_seconds,
        ):
            due_service_ids.append(service.id)
    return due_service_ids
