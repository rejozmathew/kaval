"""Unit tests for Phase 3A service lifecycle handling."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import (
    Change,
    ChangeType,
    ServiceLifecycleEventType,
    ServiceLifecycleState,
)
from kaval.pipeline import build_mock_services
from kaval.service_lifecycle import (
    ServiceLifecycleContext,
    apply_service_lifecycle,
    derive_lifecycle_events_from_changes,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for lifecycle tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_service_lifecycle_marks_ambiguous_removal_as_missing() -> None:
    """Absent services should default to missing unless trusted context says otherwise."""
    previous = services_with_container_ids()
    discovered = [service for service in previous if service.id != "svc-delugevpn"]

    update = apply_service_lifecycle(
        previous_services=previous,
        discovered_services=discovered,
        now=ts(12, 0),
    )

    retained = next(service for service in update.services if service.id == "svc-delugevpn")
    assert retained.lifecycle.state == ServiceLifecycleState.MISSING
    assert retained.status.value == "down"
    assert any(
        event.event_type == ServiceLifecycleEventType.SERVICE_REMOVED_UNEXPECTEDLY
        for event in update.lifecycle_events
    )


def test_service_lifecycle_respects_explicit_removal_confirmation() -> None:
    """Trusted user confirmation should classify removal as intentional."""
    previous = services_with_container_ids()
    discovered = [service for service in previous if service.id != "svc-delugevpn"]

    update = apply_service_lifecycle(
        previous_services=previous,
        discovered_services=discovered,
        now=ts(12, 5),
        context=ServiceLifecycleContext(
            confirmed_removed_service_ids=["svc-delugevpn"]
        ),
    )

    retained = next(service for service in update.services if service.id == "svc-delugevpn")
    assert retained.lifecycle.state == ServiceLifecycleState.REMOVED_INTENTIONAL
    assert retained.status.value == "unknown"


def test_service_lifecycle_respects_maintenance_mode_for_removal() -> None:
    """Maintenance-mode removals should stay separate from unexpected disappearance."""
    previous = services_with_container_ids()
    discovered = [service for service in previous if service.id != "svc-delugevpn"]

    update = apply_service_lifecycle(
        previous_services=previous,
        discovered_services=discovered,
        now=ts(12, 10),
        context=ServiceLifecycleContext(maintenance_mode_active=True),
    )

    retained = next(service for service in update.services if service.id == "svc-delugevpn")
    assert retained.lifecycle.state == ServiceLifecycleState.REMOVED_DURING_MAINTENANCE
    assert retained.status.value == "unknown"


def test_service_lifecycle_preserves_identity_across_rename_or_rematch() -> None:
    """Container-stable matches should preserve service identity and prior names."""
    previous = services_with_container_ids()
    current = [
        service
        if service.id != "svc-radarr"
        else service.model_copy(
            update={
                "id": "svc-radarr-renamed",
                "name": "Radarr 4K",
                "descriptor_id": "arr/radarr-4k",
            }
        )
        for service in previous
    ]

    update = apply_service_lifecycle(
        previous_services=previous,
        discovered_services=current,
        now=ts(12, 15),
    )

    renamed = next(service for service in update.services if service.id == "svc-radarr")
    assert renamed.name == "Radarr 4K"
    assert renamed.lifecycle.last_event == (
        ServiceLifecycleEventType.SERVICE_RENAMED_OR_REMATCHED
    )
    assert renamed.lifecycle.previous_names == ["Radarr"]
    assert renamed.lifecycle.previous_descriptor_ids == ["arr/radarr"]


def test_service_lifecycle_derives_update_and_restart_events_from_changes() -> None:
    """Existing change-tracker output should map to lifecycle update semantics."""
    events = derive_lifecycle_events_from_changes(
        [
            Change(
                id="chg-image",
                type=ChangeType.IMAGE_UPDATE,
                service_id="svc-radarr",
                description="Radarr image changed.",
                old_value="1",
                new_value="2",
                timestamp=ts(12, 20),
                correlated_incidents=[],
            ),
            Change(
                id="chg-restart",
                type=ChangeType.CONTAINER_RESTART,
                service_id="svc-delugevpn",
                description="DelugeVPN restarted.",
                old_value="1",
                new_value="2",
                timestamp=ts(12, 21),
                correlated_incidents=[],
            ),
        ]
    )

    assert [event.event_type for event in events] == [
        ServiceLifecycleEventType.SERVICE_UPDATED,
        ServiceLifecycleEventType.SERVICE_RESTARTED,
    ]


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
