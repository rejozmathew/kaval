"""Typed topology-refresh planning for Docker-event and reconciliation triggers."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from kaval.discovery.docker import DockerContainerEvent
from kaval.models import KavalModel, Service


class TopologyRefreshTrigger(StrEnum):
    """Supported topology-refresh trigger sources."""

    NONE = "none"
    DOCKER_EVENT = "docker_event"
    PERIODIC_RECONCILIATION = "periodic_reconciliation"


class TopologyRefreshPolicy(KavalModel):
    """Configuration for event-driven refresh and reconciliation backstops."""

    reconciliation_interval_seconds: int = Field(default=600, ge=1)
    watched_docker_actions: list[str] = Field(
        default_factory=lambda: ["start", "stop", "restart", "die"]
    )

    @model_validator(mode="after")
    def validate_actions(self) -> Self:
        """Reject duplicate or empty Docker action filters."""
        seen_actions: set[str] = set()
        for action in self.watched_docker_actions:
            normalized = action.strip()
            if not normalized:
                msg = "watched_docker_actions must not contain empty actions"
                raise ValueError(msg)
            if normalized in seen_actions:
                msg = f"watched_docker_actions must not contain duplicates: {normalized}"
                raise ValueError(msg)
            seen_actions.add(normalized)
        return self


class TopologyRefreshDecision(KavalModel):
    """One explicit topology-refresh decision for the current runtime state."""

    refresh_required: bool
    full_rediscovery: bool
    trigger: TopologyRefreshTrigger
    reasons: list[str] = Field(default_factory=list)
    affected_container_ids: list[str] = Field(default_factory=list)
    affected_service_ids: list[str] = Field(default_factory=list)
    edge_recalculation_service_ids: list[str] = Field(default_factory=list)


def default_topology_refresh_policy() -> TopologyRefreshPolicy:
    """Return the default topology-refresh policy for Phase 3A."""
    return TopologyRefreshPolicy()


def evaluate_topology_refresh(
    *,
    services: list[Service],
    docker_events: list[DockerContainerEvent],
    now: datetime,
    last_reconciled_at: datetime | None,
    policy: TopologyRefreshPolicy | None = None,
) -> TopologyRefreshDecision:
    """Resolve whether topology refresh should run for the current inputs."""
    effective_policy = policy or default_topology_refresh_policy()

    if reconciliation_due(
        now=now,
        last_reconciled_at=last_reconciled_at,
        policy=effective_policy,
    ):
        return TopologyRefreshDecision(
            refresh_required=True,
            full_rediscovery=True,
            trigger=TopologyRefreshTrigger.PERIODIC_RECONCILIATION,
            reasons=["Scheduled topology reconciliation interval elapsed."],
        )

    services_by_container = {
        service.container_id: service
        for service in services
        if service.container_id is not None
    }
    services_by_id = {service.id: service for service in services}
    affected_container_ids: set[str] = set()
    affected_service_ids: set[str] = set()
    edge_scope_ids: set[str] = set()
    reasons: list[str] = []

    for event in docker_events:
        action = (event.action or event.status or "").strip().lower()
        if action not in effective_policy.watched_docker_actions:
            continue

        container_id = event.container_id
        if container_id is None:
            reasons.append(f"Docker event {action} arrived without a container id.")
            continue

        affected_container_ids.add(container_id)
        service = services_by_container.get(container_id)
        if service is None:
            reasons.append(
                f"Docker event {action} observed for unknown container {container_id}."
            )
            continue

        affected_service_ids.add(service.id)
        edge_scope_ids.update(
            edge_recalculation_scope(
                service=service,
                services_by_id=services_by_id,
            )
        )
        reasons.append(
            f"Docker event {action} observed for service {service.name} ({container_id})."
        )

    if not reasons:
        return TopologyRefreshDecision(
            refresh_required=False,
            full_rediscovery=False,
            trigger=TopologyRefreshTrigger.NONE,
        )

    return TopologyRefreshDecision(
        refresh_required=True,
        full_rediscovery=True,
        trigger=TopologyRefreshTrigger.DOCKER_EVENT,
        reasons=reasons,
        affected_container_ids=sorted(affected_container_ids),
        affected_service_ids=sorted(affected_service_ids),
        edge_recalculation_service_ids=sorted(edge_scope_ids),
    )


def reconciliation_due(
    *,
    now: datetime,
    last_reconciled_at: datetime | None,
    policy: TopologyRefreshPolicy,
) -> bool:
    """Return whether the periodic topology backstop is due."""
    if last_reconciled_at is None:
        return True
    return now - last_reconciled_at >= timedelta(
        seconds=policy.reconciliation_interval_seconds
    )


def edge_recalculation_scope(
    *,
    service: Service,
    services_by_id: dict[str, Service],
) -> set[str]:
    """Return services whose dependency edges should be re-evaluated safely."""
    scope = {service.id}
    scope.update(service.dependents)
    for edge in service.dependencies:
        scope.add(edge.target_service_id)
    return {service_id for service_id in scope if service_id in services_by_id}
