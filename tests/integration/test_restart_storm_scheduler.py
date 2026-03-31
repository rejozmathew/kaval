"""Integration tests for running the restart storm check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.restart_storm import RestartStormCheck
from kaval.monitoring.scheduler import CheckScheduler

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the scheduler integration test."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_restart_storm_check_runs_through_scheduler() -> None:
    """The scheduler should surface restart storm findings on later observations."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    scheduler = CheckScheduler(
        [
            RestartStormCheck(
                interval_seconds=60,
                restart_delta_threshold=3,
                window_seconds=300,
            )
        ]
    )

    baseline_snapshot = _build_snapshot(deluge_restart_count=4)
    baseline_graph = build_dependency_graph(baseline_snapshot, descriptors)
    baseline_result = scheduler.run_due_checks(
        CheckContext(
            services=baseline_graph.services,
            docker_snapshot=baseline_snapshot,
            now=ts(15, 0),
        )
    )

    assert baseline_result.executed_checks == ("restart_storm",)
    assert baseline_result.findings == []

    followup_snapshot = _build_snapshot(deluge_restart_count=7)
    followup_graph = build_dependency_graph(followup_snapshot, descriptors)
    followup_result = scheduler.run_due_checks(
        CheckContext(
            services=followup_graph.services,
            docker_snapshot=followup_snapshot,
            now=ts(15, 1),
        )
    )

    assert followup_result.executed_checks == ("restart_storm",)
    assert len(followup_result.findings) == 1
    assert followup_result.findings[0].service_id == "svc-delugevpn"


def _build_snapshot(*, deluge_restart_count: int) -> object:
    """Build a discovery snapshot with a configurable DelugeVPN restart count."""
    return build_discovery_snapshot(
        [
            load_json_fixture("container_inspect_abc123.json"),
            _deluge_inspect_payload(restart_count=deluge_restart_count),
        ],
        {
            "sha256:img-radarr": load_json_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_json_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
    )


def _deluge_inspect_payload(*, restart_count: int) -> dict[str, object]:
    """Return the DelugeVPN inspect fixture with an overridden restart count."""
    payload = load_json_fixture("container_inspect_def456.json")
    payload["RestartCount"] = restart_count
    return payload
