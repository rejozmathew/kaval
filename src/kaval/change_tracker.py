"""Deterministic Docker-backed change detection for the Phase 1 timeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.discovery.docker import DockerContainerSnapshot, DockerDiscoverySnapshot
from kaval.models import Change, ChangeType, Service


@dataclass(frozen=True, slots=True)
class _ContainerBaseline:
    """The prior observation used to detect Docker-backed timeline changes."""

    image_ref: str
    image_id: str
    restart_count: int


class ChangeTracker:
    """Detect deterministic change events from Docker discovery snapshots."""

    def __init__(self) -> None:
        """Initialize the in-memory baseline store."""
        self._baselines: dict[str, _ContainerBaseline] = {}

    def detect_changes(
        self,
        snapshot: DockerDiscoverySnapshot,
        *,
        services: Sequence[Service] | None = None,
    ) -> list[Change]:
        """Return timeline events emitted by this snapshot relative to the prior baseline."""
        service_ids_by_container = {
            service.container_id: service.id
            for service in services or []
            if service.container_id is not None
        }
        changes: list[Change] = []
        active_container_ids: set[str] = set()

        for container in sorted(snapshot.containers, key=lambda container: container.id):
            active_container_ids.add(container.id)
            baseline = self._baselines.get(container.id)
            if baseline is not None:
                service_id = service_ids_by_container.get(container.id)
                image_change = _image_update_change(
                    container=container,
                    baseline=baseline,
                    timestamp=snapshot.discovered_at,
                    service_id=service_id,
                )
                if image_change is not None:
                    changes.append(image_change)

                restart_change = _restart_change(
                    container=container,
                    baseline=baseline,
                    timestamp=snapshot.discovered_at,
                    service_id=service_id,
                )
                if restart_change is not None:
                    changes.append(restart_change)

            self._baselines[container.id] = _baseline_for_container(container)

        stale_container_ids = set(self._baselines) - active_container_ids
        for container_id in stale_container_ids:
            del self._baselines[container_id]

        return changes


def persist_changes(database: KavalDatabase, changes: Sequence[Change]) -> None:
    """Persist change events into the existing SQLite store."""
    for change in changes:
        database.upsert_change(change)


def _image_update_change(
    *,
    container: DockerContainerSnapshot,
    baseline: _ContainerBaseline,
    timestamp: datetime,
    service_id: str | None,
) -> Change | None:
    """Build an image-update event when the observed image changes."""
    if container.image == baseline.image_ref and container.image_id == baseline.image_id:
        return None

    old_value = _image_value(baseline.image_ref, baseline.image_id)
    new_value = _image_value(container.image, container.image_id)
    return Change(
        id=_change_id(ChangeType.IMAGE_UPDATE, container.id, timestamp),
        type=ChangeType.IMAGE_UPDATE,
        service_id=service_id,
        description=(
            f"{container.name} image changed from {old_value} to {new_value}."
        ),
        old_value=old_value,
        new_value=new_value,
        timestamp=timestamp,
        correlated_incidents=[],
    )


def _restart_change(
    *,
    container: DockerContainerSnapshot,
    baseline: _ContainerBaseline,
    timestamp: datetime,
    service_id: str | None,
) -> Change | None:
    """Build a container-restart event when the restart counter increases."""
    if container.restart_count <= baseline.restart_count:
        return None

    old_value = str(baseline.restart_count)
    new_value = str(container.restart_count)
    return Change(
        id=_change_id(ChangeType.CONTAINER_RESTART, container.id, timestamp),
        type=ChangeType.CONTAINER_RESTART,
        service_id=service_id,
        description=(
            f"{container.name} restart count increased from {old_value} to {new_value}."
        ),
        old_value=old_value,
        new_value=new_value,
        timestamp=timestamp,
        correlated_incidents=[],
    )


def _baseline_for_container(container: DockerContainerSnapshot) -> _ContainerBaseline:
    """Build the current baseline state for one discovered container."""
    return _ContainerBaseline(
        image_ref=container.image,
        image_id=container.image_id,
        restart_count=container.restart_count,
    )


def _image_value(image_ref: str, image_id: str) -> str:
    """Render one Docker image observation for timeline storage."""
    return f"{image_ref} [{image_id}]"


def _change_id(change_type: ChangeType, container_id: str, timestamp: datetime) -> str:
    """Build a stable identifier for one emitted change event."""
    timestamp_token = timestamp.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"chg-{change_type.value}-{_slugify(container_id)}-{timestamp_token}"


def _slugify(value: str) -> str:
    """Normalize identifiers used in change ids."""
    return value.lower().replace("_", "-").strip()
