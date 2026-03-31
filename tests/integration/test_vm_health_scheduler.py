"""Integration tests for running the VM health check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.vm_health import VMHealthCheck
from kaval.monitoring.scheduler import CheckScheduler

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the VM scheduler integration test."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_vm_health_check_runs_through_scheduler() -> None:
    """The scheduler should execute the VM health check and surface VM state failures."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot([], {})
    unraid_snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )
    vm = unraid_snapshot.vms[0].model_copy(update={"state": "stopped"})
    unraid_snapshot = unraid_snapshot.model_copy(update={"vms": [vm]})
    graph = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    )

    scheduler = CheckScheduler([VMHealthCheck(interval_seconds=120)])

    result = scheduler.run_due_checks(
        CheckContext(
            services=graph.services,
            docker_snapshot=docker_snapshot,
            unraid_snapshot=unraid_snapshot,
            now=ts(18, 30),
        )
    )

    assert result.executed_checks == ("vm_health",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-vm-ubuntu"
    assert result.findings[0].title == "Ubuntu Server VM is not running"
