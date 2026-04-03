"""Scenario coverage for unexpected service removal handling."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.pipeline import build_mock_services
from kaval.service_lifecycle import apply_service_lifecycle


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for lifecycle scenarios."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_service_lifecycle_defaults_ambiguous_removal_to_missing() -> None:
    """An absent service should remain retained and flagged missing, not intentional."""
    previous_services = services_with_container_ids()
    discovered_services = [
        service for service in previous_services if service.id != "svc-delugevpn"
    ]

    update = apply_service_lifecycle(
        previous_services=previous_services,
        discovered_services=discovered_services,
        now=ts(12, 0),
    )

    active_service_ids = [
        service.id
        for service in update.services
        if service.lifecycle.state.value == "active"
    ]
    retained = next(service for service in update.services if service.id == "svc-delugevpn")

    assert retained.lifecycle.state.value == "missing"
    assert "svc-delugevpn" not in active_service_ids
    assert any(
        event.event_type.value == "service_removed_unexpectedly"
        for event in update.lifecycle_events
    )


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
