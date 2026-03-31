"""Integration tests for running the container health check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.container_health import ContainerHealthCheck
from kaval.monitoring.scheduler import CheckScheduler

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the scheduler integration test."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_container_health_check_runs_through_scheduler() -> None:
    """The scheduler should execute the health check and surface its findings."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            load_json_fixture("container_inspect_abc123.json"),
            load_json_fixture("container_inspect_def456.json"),
        ],
        {
            "sha256:img-radarr": load_json_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_json_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
    )
    graph = build_dependency_graph(docker_snapshot, descriptors)
    scheduler = CheckScheduler([ContainerHealthCheck(interval_seconds=60)])

    result = scheduler.run_due_checks(
        CheckContext(services=graph.services, docker_snapshot=docker_snapshot, now=ts(13, 0))
    )

    assert result.executed_checks == ("container_health",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-delugevpn"
