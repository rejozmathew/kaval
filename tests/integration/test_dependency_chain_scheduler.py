"""Integration tests for running the dependency-chain check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.models import ServiceStatus
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.dependency_chain import DependencyChainCheck
from kaval.monitoring.scheduler import CheckScheduler

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the dependency scheduler integration test."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_dependency_chain_check_runs_through_scheduler() -> None:
    """The scheduler should execute the dependency-chain check and surface outages."""
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
    services = [
        service.model_copy(update={"status": ServiceStatus.DOWN})
        if service.id == "svc-delugevpn"
        else service
        for service in graph.services
    ]

    scheduler = CheckScheduler([DependencyChainCheck(interval_seconds=120)])

    result = scheduler.run_due_checks(
        CheckContext(
            services=services,
            docker_snapshot=docker_snapshot,
            now=ts(21, 30),
        )
    )

    assert result.executed_checks == ("dependency_chain",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-radarr"
    assert result.findings[0].summary == (
        "Radarr depends on DelugeVPN, which is currently down."
    )
