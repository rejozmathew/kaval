"""Unit tests for the Phase 3A topology refresh planner."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.discovery.docker import DockerContainerEvent
from kaval.discovery.topology_refresh import (
    TopologyRefreshTrigger,
    evaluate_topology_refresh,
)
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0, second: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for topology refresh tests."""
    return datetime(2026, 4, 3, hour, minute, second, tzinfo=UTC)


def test_topology_refresh_uses_periodic_reconciliation_backstop() -> None:
    """A stale topology should trigger scheduled full reconciliation."""
    decision = evaluate_topology_refresh(
        services=services_with_container_ids(),
        docker_events=[],
        now=ts(12, 10, 1),
        last_reconciled_at=ts(12, 0, 0),
    )

    assert decision.refresh_required is True
    assert decision.full_rediscovery is True
    assert decision.trigger == TopologyRefreshTrigger.PERIODIC_RECONCILIATION
    assert decision.reasons == ["Scheduled topology reconciliation interval elapsed."]


def test_topology_refresh_reacts_to_relevant_docker_events() -> None:
    """Watched Docker events should trigger a safe full rediscovery plan."""
    decision = evaluate_topology_refresh(
        services=services_with_container_ids(),
        docker_events=[
            docker_event(action="die", container_id="def456", container_name="delugevpn")
        ],
        now=ts(12, 1, 0),
        last_reconciled_at=ts(12, 0, 30),
    )

    assert decision.refresh_required is True
    assert decision.full_rediscovery is True
    assert decision.trigger == TopologyRefreshTrigger.DOCKER_EVENT
    assert decision.affected_container_ids == ["def456"]
    assert decision.affected_service_ids == ["svc-delugevpn"]
    assert decision.edge_recalculation_service_ids == [
        "svc-delugevpn",
        "svc-radarr",
        "svc-sonarr",
    ]


def test_topology_refresh_allows_unknown_container_events_to_trigger_refresh() -> None:
    """Unknown-container start events should still force a safe refresh for new services."""
    decision = evaluate_topology_refresh(
        services=services_with_container_ids(),
        docker_events=[
            docker_event(action="start", container_id="new999", container_name="prowlarr")
        ],
        now=ts(12, 2, 0),
        last_reconciled_at=ts(12, 1, 30),
    )

    assert decision.refresh_required is True
    assert decision.full_rediscovery is True
    assert decision.trigger == TopologyRefreshTrigger.DOCKER_EVENT
    assert decision.affected_container_ids == ["new999"]
    assert decision.affected_service_ids == []
    assert decision.edge_recalculation_service_ids == []


def test_topology_refresh_ignores_unwatched_docker_actions() -> None:
    """Non-topology Docker actions should not trigger refresh noise."""
    decision = evaluate_topology_refresh(
        services=services_with_container_ids(),
        docker_events=[
            docker_event(
                action="health_status",
                container_id="def456",
                container_name="delugevpn",
            )
        ],
        now=ts(12, 3, 0),
        last_reconciled_at=ts(12, 2, 30),
    )

    assert decision.refresh_required is False
    assert decision.full_rediscovery is False
    assert decision.trigger == TopologyRefreshTrigger.NONE


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


def docker_event(*, action: str, container_id: str, container_name: str) -> DockerContainerEvent:
    """Build one Docker container event for refresh-planner coverage."""
    return DockerContainerEvent(
        status=action,
        id=container_id,
        from_image="test/image:latest",
        Type="container",
        Action=action,
        Actor={
            "ID": container_id,
            "Attributes": {
                "name": container_name,
                "image": "test/image:latest",
            },
        },
        scope="local",
        time=int(ts(12).timestamp()),
        timeNano=int(ts(12).timestamp() * 1_000_000_000),
    )
