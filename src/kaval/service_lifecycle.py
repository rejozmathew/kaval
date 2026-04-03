"""Service lifecycle classification and retention helpers for Phase 3A."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from pydantic import Field, model_validator

from kaval.models import (
    Change,
    ChangeType,
    KavalModel,
    Service,
    ServiceLifecycle,
    ServiceLifecycleEvent,
    ServiceLifecycleEventType,
    ServiceLifecycleState,
    ServiceStatus,
)


class ServiceLifecycleContext(KavalModel):
    """Trusted context used to classify service removal events."""

    maintenance_mode_active: bool = False
    confirmed_removed_service_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_confirmed_removed_ids(self) -> "ServiceLifecycleContext":
        """Reject duplicate removal confirmations."""
        if len(set(self.confirmed_removed_service_ids)) != len(self.confirmed_removed_service_ids):
            msg = "confirmed_removed_service_ids must be unique"
            raise ValueError(msg)
        return self


class ServiceLifecycleUpdate(KavalModel):
    """The lifecycle-classified service catalog plus emitted events."""

    services: list[Service]
    changes: list[Change]
    lifecycle_events: list[ServiceLifecycleEvent]


def apply_service_lifecycle(
    *,
    previous_services: Sequence[Service],
    discovered_services: Sequence[Service],
    now: datetime,
    context: ServiceLifecycleContext | None = None,
    changes: Sequence[Change] = (),
) -> ServiceLifecycleUpdate:
    """Classify service lifecycle transitions across one discovery refresh."""
    effective_context = context or ServiceLifecycleContext()
    retained_changes = list(changes)
    lifecycle_events = derive_lifecycle_events_from_changes(changes)

    previous_by_id = {service.id: service for service in previous_services}
    previous_by_container_id = {
        service.container_id: service
        for service in previous_services
        if service.container_id is not None
    }
    retained_services: list[Service] = []
    matched_previous_ids: set[str] = set()

    for discovered in sorted(discovered_services, key=lambda service: service.id):
        previous = _match_previous_service(
            discovered=discovered,
            previous_by_id=previous_by_id,
            previous_by_container_id=previous_by_container_id,
        )
        if previous is None:
            added_service = discovered.model_copy(
                update={
                    "lifecycle": ServiceLifecycle(
                        state=ServiceLifecycleState.ACTIVE,
                        last_event=ServiceLifecycleEventType.SERVICE_ADDED,
                        changed_at=now,
                    )
                }
            )
            retained_services.append(added_service)
            retained_changes.append(
                _lifecycle_change(
                    service_id=added_service.id,
                    change_type=ChangeType.SERVICE_ADDED,
                    timestamp=now,
                    description=f"Kaval discovered new service: {added_service.name}.",
                )
            )
            lifecycle_events.append(
                ServiceLifecycleEvent(
                    service_id=added_service.id,
                    event_type=ServiceLifecycleEventType.SERVICE_ADDED,
                    timestamp=now,
                    summary=f"New service discovered: {added_service.name}.",
                )
            )
            continue

        matched_previous_ids.add(previous.id)
        renamed_or_rematched = _identity_changed(previous=previous, discovered=discovered)
        updated_service = _active_service(discovered=discovered, previous=previous, now=now)
        retained_services.append(updated_service)

        if renamed_or_rematched:
            retained_changes.append(
                _lifecycle_change(
                    service_id=updated_service.id,
                    change_type=ChangeType.SERVICE_RENAMED_OR_REMATCHED,
                    timestamp=now,
                    description=(
                        f"Service identity updated from {previous.name} to {updated_service.name}."
                    ),
                )
            )
            lifecycle_events.append(
                ServiceLifecycleEvent(
                    service_id=updated_service.id,
                    event_type=ServiceLifecycleEventType.SERVICE_RENAMED_OR_REMATCHED,
                    timestamp=now,
                    summary=(
                        f"Service identity updated from {previous.name} "
                        f"to {updated_service.name}."
                    ),
                )
            )

    for previous in sorted(previous_services, key=lambda service: service.id):
        if previous.id in matched_previous_ids:
            continue
        if previous.lifecycle.state != ServiceLifecycleState.ACTIVE:
            retained_services.append(previous)
            continue

        retained_service, lifecycle_change, lifecycle_event = _removed_service(
            previous=previous,
            now=now,
            context=effective_context,
        )
        retained_services.append(retained_service)
        retained_changes.append(lifecycle_change)
        lifecycle_events.append(lifecycle_event)

    return ServiceLifecycleUpdate(
        services=sorted(
            retained_services,
            key=lambda service: (
                service.lifecycle.state != ServiceLifecycleState.ACTIVE,
                service.id,
            ),
        ),
        changes=sorted(retained_changes, key=lambda change: (change.timestamp, change.id)),
        lifecycle_events=sorted(
            lifecycle_events,
            key=lambda event: (event.timestamp, event.service_id, event.event_type.value),
        ),
    )


def derive_lifecycle_events_from_changes(
    changes: Sequence[Change],
) -> list[ServiceLifecycleEvent]:
    """Map existing change-tracker events into lifecycle events where appropriate."""
    lifecycle_events: list[ServiceLifecycleEvent] = []
    for change in changes:
        if change.service_id is None:
            continue
        event_type = _change_lifecycle_event_type(change.type)
        if event_type is None:
            continue
        lifecycle_events.append(
            ServiceLifecycleEvent(
                service_id=change.service_id,
                event_type=event_type,
                timestamp=change.timestamp,
                summary=change.description,
                change_id=change.id,
            )
        )
    return lifecycle_events


def _match_previous_service(
    *,
    discovered: Service,
    previous_by_id: dict[str, Service],
    previous_by_container_id: dict[str, Service],
) -> Service | None:
    """Resolve the prior persisted service that matches one discovered service."""
    if discovered.container_id is not None:
        previous = previous_by_container_id.get(discovered.container_id)
        if previous is not None:
            return previous
    return previous_by_id.get(discovered.id)


def _active_service(
    *,
    discovered: Service,
    previous: Service,
    now: datetime,
) -> Service:
    """Carry lifecycle history forward for one active service."""
    lifecycle = ServiceLifecycle(
        state=ServiceLifecycleState.ACTIVE,
        last_event=(
            ServiceLifecycleEventType.SERVICE_RENAMED_OR_REMATCHED
            if _identity_changed(previous=previous, discovered=discovered)
            else None
        ),
        changed_at=now if _identity_changed(previous=previous, discovered=discovered) else None,
        previous_names=_merge_previous_names(previous=previous, discovered=discovered),
        previous_descriptor_ids=_merge_previous_descriptor_ids(
            previous=previous,
            discovered=discovered,
        ),
    )
    return discovered.model_copy(
        update={
            "id": previous.id,
            "lifecycle": lifecycle,
        }
    )


def _removed_service(
    *,
    previous: Service,
    now: datetime,
    context: ServiceLifecycleContext,
) -> tuple[Service, Change, ServiceLifecycleEvent]:
    """Classify one service that is no longer present in discovery output."""
    if previous.id in context.confirmed_removed_service_ids:
        lifecycle_state = ServiceLifecycleState.REMOVED_INTENTIONAL
        lifecycle_event_type = ServiceLifecycleEventType.SERVICE_REMOVED_INTENTIONAL
        change_type = ChangeType.SERVICE_REMOVED
        status = ServiceStatus.UNKNOWN
        description = f"Service removed intentionally: {previous.name}."
    elif context.maintenance_mode_active:
        lifecycle_state = ServiceLifecycleState.REMOVED_DURING_MAINTENANCE
        lifecycle_event_type = ServiceLifecycleEventType.SERVICE_REMOVED_DURING_MAINTENANCE
        change_type = ChangeType.SERVICE_REMOVED
        status = ServiceStatus.UNKNOWN
        description = f"Service removed during maintenance: {previous.name}."
    else:
        lifecycle_state = ServiceLifecycleState.MISSING
        lifecycle_event_type = ServiceLifecycleEventType.SERVICE_REMOVED_UNEXPECTEDLY
        change_type = ChangeType.SERVICE_MISSING
        status = ServiceStatus.DOWN
        description = (
            f"Service unexpectedly disappeared and now requires confirmation: {previous.name}."
        )

    retained_service = previous.model_copy(
        update={
            "status": status,
            "lifecycle": previous.lifecycle.model_copy(
                update={
                    "state": lifecycle_state,
                    "last_event": lifecycle_event_type,
                    "changed_at": now,
                }
            ),
        }
    )
    lifecycle_change = _lifecycle_change(
        service_id=previous.id,
        change_type=change_type,
        timestamp=now,
        description=description,
    )
    lifecycle_event = ServiceLifecycleEvent(
        service_id=previous.id,
        event_type=lifecycle_event_type,
        timestamp=now,
        summary=description,
        change_id=lifecycle_change.id,
        related_service_ids=sorted(previous.dependents),
    )
    return retained_service, lifecycle_change, lifecycle_event


def _merge_previous_names(*, previous: Service, discovered: Service) -> list[str]:
    """Carry forward prior names when service identity changes."""
    names = list(previous.lifecycle.previous_names)
    if previous.name != discovered.name and previous.name not in names:
        names.append(previous.name)
    return names


def _merge_previous_descriptor_ids(*, previous: Service, discovered: Service) -> list[str]:
    """Carry forward prior descriptor ids when rematching occurs."""
    descriptor_ids = list(previous.lifecycle.previous_descriptor_ids)
    if (
        previous.descriptor_id is not None
        and previous.descriptor_id != discovered.descriptor_id
        and previous.descriptor_id not in descriptor_ids
    ):
        descriptor_ids.append(previous.descriptor_id)
    return descriptor_ids


def _identity_changed(*, previous: Service, discovered: Service) -> bool:
    """Return whether a discovery refresh renamed or rematched the service."""
    return (
        previous.name != discovered.name
        or previous.descriptor_id != discovered.descriptor_id
    )


def _change_lifecycle_event_type(
    change_type: ChangeType,
) -> ServiceLifecycleEventType | None:
    """Map change-tracker output to lifecycle event types."""
    if change_type in {ChangeType.IMAGE_UPDATE, ChangeType.CONFIG_CHANGE}:
        return ServiceLifecycleEventType.SERVICE_UPDATED
    if change_type == ChangeType.CONTAINER_RESTART:
        return ServiceLifecycleEventType.SERVICE_RESTARTED
    return None


def _lifecycle_change(
    *,
    service_id: str,
    change_type: ChangeType,
    timestamp: datetime,
    description: str,
) -> Change:
    """Build a stable lifecycle change record."""
    return Change(
        id=_change_id(change_type=change_type, service_id=service_id, timestamp=timestamp),
        type=change_type,
        service_id=service_id,
        description=description,
        old_value=None,
        new_value=None,
        timestamp=timestamp,
        correlated_incidents=[],
    )


def _change_id(*, change_type: ChangeType, service_id: str, timestamp: datetime) -> str:
    """Build a stable identifier for one lifecycle change event."""
    return (
        f"chg-{change_type.value}-{_slugify(service_id)}-"
        f"{timestamp.strftime('%Y%m%dT%H%M%SZ')}"
    )


def _slugify(value: str) -> str:
    """Normalize identifiers used in lifecycle change ids."""
    return value.lower().replace("_", "-").strip()
