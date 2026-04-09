"""Scenario coverage for per-service check suppression."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import Evidence, EvidenceKind, ServiceCheckOverrideScope, Severity
from kaval.monitoring import CheckScheduler
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for suppression scenarios."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


class _ScenarioContainerHealthCheck(MonitoringCheck):
    """Deterministic container-health check for suppression scenario coverage."""

    def __init__(self) -> None:
        """Initialize the synthetic container-health identity and cadence."""
        self.check_id = "container_health"
        self.interval_seconds = 60

    def run(self, context: CheckContext) -> list:
        """Emit one synthetic finding for each targeted container service."""
        findings = []
        for service in context.services:
            if (
                context.target_service_ids is not None
                and service.id not in context.target_service_ids
            ):
                continue
            findings.append(
                build_finding(
                    check_id=self.check_id,
                    service=service,
                    title=f"{service.name}: container health degraded",
                    severity=Severity.MEDIUM,
                    summary="Synthetic container-health scenario finding.",
                    impact="Used only for service suppression scenario coverage.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.EVENT,
                            source=self.check_id,
                            summary="Synthetic container-health evidence.",
                            observed_at=context.now,
                            data={"service_id": service.id},
                        )
                    ],
                    now=context.now,
                    confidence=0.8,
                )
            )
        return findings


def test_service_detail_suppression_stops_future_findings_for_the_target_service(
    tmp_path: Path,
) -> None:
    """A service-detail suppression toggle should stop later findings for that service."""
    database_path = tmp_path / "kaval.db"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    for service in build_mock_services():
        database.upsert_service(service)
    database.close()
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        database = KavalDatabase(path=database_path)
        services = database.list_services()
        baseline_cadence = client.app.state.monitoring_settings_service.resolve_cadence_config(
            scope="active",
            service_overrides=database.list_service_check_overrides(
                scope=ServiceCheckOverrideScope.ACTIVE
            ),
        )
        baseline_scheduler = CheckScheduler(
            [_ScenarioContainerHealthCheck()],
            cadence=baseline_cadence,
        )
        baseline_run = baseline_scheduler.run_due_checks(
            CheckContext(services=services, now=ts(10, 0))
        )

        suppress_response = client.put(
            "/api/v1/services/svc-delugevpn/checks/container_health/suppression",
            json={"suppressed": True},
        )

        suppressed_cadence = client.app.state.monitoring_settings_service.resolve_cadence_config(
            scope="active",
            service_overrides=database.list_service_check_overrides(
                scope=ServiceCheckOverrideScope.ACTIVE
            ),
        )
        suppressed_scheduler = CheckScheduler(
            [_ScenarioContainerHealthCheck()],
            cadence=suppressed_cadence,
        )
        suppressed_run = suppressed_scheduler.run_due_checks(
            CheckContext(services=services, now=ts(10, 2))
        )
        database.close()

    assert suppress_response.status_code == 200
    assert {finding.service_id for finding in baseline_run.findings} == {
        "svc-delugevpn",
        "svc-radarr",
        "svc-sonarr",
    }
    assert {finding.service_id for finding in suppressed_run.findings} == {
        "svc-radarr",
        "svc-sonarr",
    }
