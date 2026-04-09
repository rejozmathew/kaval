"""Scenario coverage for maintenance-mode suppression behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import Evidence, EvidenceKind, Severity
from kaval.monitoring import CheckScheduler
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.monitoring.scheduler import persist_findings
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for maintenance scenarios."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


class _ScenarioMaintenanceCheck(MonitoringCheck):
    """Deterministic container-health check for maintenance scenario coverage."""

    def __init__(self) -> None:
        """Initialize the synthetic check identity and cadence."""
        self.check_id = "container_health"
        self.interval_seconds = 60

    def run(self, context: CheckContext) -> list:
        """Emit one synthetic finding for each targeted service."""
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
                    title=f"{service.name}: maintenance scenario finding",
                    severity=Severity.MEDIUM,
                    summary="Synthetic maintenance scenario finding.",
                    impact="Used only for maintenance-mode scenario coverage.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.EVENT,
                            source=self.check_id,
                            summary="Synthetic maintenance scenario evidence.",
                            observed_at=context.now,
                            data={"service_id": service.id},
                        )
                    ],
                    now=context.now,
                    confidence=0.8,
                )
            )
        return findings


def test_maintenance_mode_suppresses_scheduler_findings_for_service_and_global_windows(
    tmp_path: Path,
) -> None:
    """Maintenance windows should suppress future persisted findings until expiry."""
    database_path = tmp_path / "kaval.db"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        for service in build_mock_services():
            database.upsert_service(service)
    finally:
        database.close()

    app = create_app(database_path=database_path)
    with TestClient(app) as client:
        enable_service_response = client.put(
            "/api/v1/services/svc-delugevpn/maintenance",
            json={"duration_minutes": 120},
        )
        service_window = enable_service_response.json()["maintenance"]["service_windows"][0]
        service_run_at = datetime.fromisoformat(service_window["started_at"]) + timedelta(
            minutes=1
        )

        database = KavalDatabase(path=database_path)
        try:
            services = database.list_services()
            scheduler = CheckScheduler([_ScenarioMaintenanceCheck()])
            service_scoped_run = scheduler.run_due_checks(
                CheckContext(services=services, now=service_run_at)
            )
            persist_findings(database, service_scoped_run.findings)
            service_scoped_ids = {
                finding.service_id for finding in database.list_findings()
            }

            enable_global_response = client.put(
                "/api/v1/maintenance/global",
                json={"duration_minutes": 30},
            )
            global_window = enable_global_response.json()["maintenance"]["global_window"]
            global_run_at = datetime.fromisoformat(global_window["started_at"]) + timedelta(
                minutes=1
            )
            global_run = scheduler.run_due_checks(
                CheckContext(services=services, now=global_run_at)
            )
            persist_findings(database, global_run.findings)
            final_ids = {
                finding.service_id for finding in database.list_findings()
            }
        finally:
            database.close()

    assert enable_service_response.status_code == 200
    assert service_scoped_ids == {"svc-radarr", "svc-sonarr"}
    assert enable_global_response.status_code == 200
    assert "critical Kaval self-health" in enable_global_response.json()["maintenance"][
        "self_health_guardrail"
    ]
    assert final_ids == {"svc-radarr", "svc-sonarr"}
