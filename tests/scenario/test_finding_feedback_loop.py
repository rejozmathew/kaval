"""Scenario coverage for finding feedback and advisory noise suggestions."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import (
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Finding,
    FindingStatus,
    Service,
    ServiceCheckOverrideScope,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for scenario fixtures."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


def test_repeated_finding_dismissals_surface_suggestions_without_auto_suppression(
    tmp_path,
) -> None:
    """Repeated dismissals should stay advisory and must not auto-create suppressions."""
    database_path = tmp_path / "kaval.db"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id="svc-delugevpn",
                name="DelugeVPN",
                type=ServiceType.CONTAINER,
                category="downloads",
                status=ServiceStatus.DEGRADED,
                descriptor_id="downloads/delugevpn",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-123",
                vm_id=None,
                image="binhex/arch-delugevpn:2.1.1",
                endpoints=[
                    Endpoint(
                        name="web",
                        protocol=EndpointProtocol.HTTP,
                        host="delugevpn",
                        port=8112,
                        path="/",
                        url=None,
                        auth_required=False,
                        expected_status=200,
                    )
                ],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=ts(12, 0),
                active_findings=1,
                active_incidents=0,
            )
        )
        for index in range(5):
            database.upsert_finding(
                Finding(
                    id=f"find-{index}",
                    title="DelugeVPN endpoint probe failed",
                    severity=Severity.MEDIUM,
                    domain="endpoint_probe",
                    service_id="svc-delugevpn",
                    summary="The DelugeVPN web UI did not respond within the configured timeout.",
                    evidence=[],
                    impact="The service may be down or timing out.",
                    confidence=0.82,
                    status=FindingStatus.GROUPED,
                    incident_id=None,
                    related_changes=[],
                    created_at=ts(12, index),
                    resolved_at=None,
                )
            )
    finally:
        database.close()

    app = create_app(database_path=database_path)
    with TestClient(app) as client:
        for index in range(5):
            response = client.post(
                f"/api/v1/findings/find-{index}/dismiss",
                json={"reason": "false_positive"},
            )
            assert response.status_code == 200
        review_response = client.get("/api/v1/findings/review")

    assert review_response.status_code == 200
    payload = review_response.json()
    assert payload["suggestions"][0]["check_id"] == "endpoint_probe"
    assert payload["suggestions"][0]["dismissal_count"] == 5

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        assert database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE
        ) == []
    finally:
        database.close()
