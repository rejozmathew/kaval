"""Integration tests for service lifecycle persistence and history retention."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.models import Evidence, EvidenceKind, Finding, FindingStatus, Severity
from kaval.pipeline import build_mock_services
from kaval.service_lifecycle import apply_service_lifecycle


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for lifecycle persistence tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_removed_services_remain_persisted_with_history(tmp_path: Path) -> None:
    """Removed or missing services should stay in SQLite alongside prior findings."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    try:
        previous_services = services_with_container_ids()
        for service in previous_services:
            database.upsert_service(service)

        database.upsert_finding(
            Finding(
                id="find-delugevpn",
                title="DelugeVPN degraded",
                severity=Severity.HIGH,
                domain="container_health",
                service_id="svc-delugevpn",
                summary="Synthetic lifecycle retention coverage.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.EVENT,
                        source="test",
                        summary="Synthetic lifecycle retention evidence.",
                        observed_at=ts(11, 55),
                        data={"service_id": "svc-delugevpn"},
                    )
                ],
                impact="Lifecycle retention coverage only.",
                confidence=0.9,
                status=FindingStatus.NEW,
                incident_id=None,
                related_changes=[],
                created_at=ts(11, 55),
                resolved_at=None,
            )
        )

        discovered_services = [
            service for service in previous_services if service.id != "svc-delugevpn"
        ]
        update = apply_service_lifecycle(
            previous_services=previous_services,
            discovered_services=discovered_services,
            now=ts(12, 0),
        )

        for service in update.services:
            database.upsert_service(service)
        for change in update.changes:
            database.upsert_change(change)

        stored_services = database.list_services()
        stored_findings = database.list_findings()
        stored_changes = database.list_changes()

        retained = next(service for service in stored_services if service.id == "svc-delugevpn")
        assert retained.lifecycle.state.value == "missing"
        assert retained.status.value == "down"
        assert any(change.type.value == "service_missing" for change in stored_changes)
        assert [finding.id for finding in stored_findings] == ["find-delugevpn"]
    finally:
        database.close()


def services_with_container_ids() -> list:
    """Attach deterministic container ids to the mock service graph."""
    container_ids = {
        "svc-delugevpn": "def456",
        "svc-radarr": "abc123",
        "svc-sonarr": "ghi789",
    }
    return [
        service.model_copy(update={"container_id": container_ids[service.id]})
        for service in build_mock_services()
    ]
