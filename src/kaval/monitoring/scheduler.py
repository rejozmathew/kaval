"""Deterministic scheduler for Phase 1 and Phase 3A monitoring checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.models import Finding, Incident
from kaval.monitoring.cadence import (
    MonitoringCadenceConfig,
    default_monitoring_cadence_config,
    resolve_monitoring_cadence_decision,
)
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck


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
            last_run_at = self._last_run_at.get(check_id)
            cadence = resolve_monitoring_cadence_decision(
                config=self._cadence,
                check_id=check.check_id,
                services=context.services,
                now=context.now,
                incidents=list(incidents),
                base_interval_seconds=check.interval_seconds,
            )
            if not _is_due(
                now=context.now,
                last_run_at=last_run_at,
                interval_seconds=cadence.effective_interval_seconds,
            ):
                continue
            findings.extend(check.run(context))
            self._last_run_at[check_id] = context.now
            executed_checks.append(check_id)
        return SchedulerRunResult(
            executed_checks=tuple(executed_checks),
            findings=findings,
        )


def persist_findings(database: KavalDatabase, findings: Sequence[Finding]) -> None:
    """Persist scheduler findings into the existing SQLite store."""
    for finding in findings:
        database.upsert_finding(finding)


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
