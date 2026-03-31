"""Integration tests for running the log pattern check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.log_pattern import LogPatternCheck
from kaval.monitoring.scheduler import CheckScheduler

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the scheduler integration test."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_text_fixture(name: str) -> str:
    """Load a text fixture used by the scheduler integration test."""
    return (DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8")


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_log_pattern_check_runs_through_scheduler() -> None:
    """The scheduler should execute the log pattern check and surface matches."""
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

    def fake_log_reader(container_id: str, tail_lines: int) -> str:
        assert tail_lines == 200
        if container_id == "def456":
            return load_text_fixture("container_logs_def456.txt")
        return ""

    scheduler = CheckScheduler(
        [LogPatternCheck(descriptors, interval_seconds=300, log_reader=fake_log_reader)]
    )

    result = scheduler.run_due_checks(
        CheckContext(
            services=graph.services,
            docker_snapshot=docker_snapshot,
            now=ts(19, 30),
        )
    )

    assert result.executed_checks == ("log_pattern",)
    assert len(result.findings) == 2
    assert {finding.service_id for finding in result.findings} == {"svc-delugevpn"}
