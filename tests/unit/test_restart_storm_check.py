"""Unit tests for the restart storm monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.models import Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.restart_storm import RestartStormCheck

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by restart storm tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_restart_storm_check_uses_initial_observation_as_baseline() -> None:
    """The first observation should establish a baseline and emit no findings."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = _build_snapshot(deluge_restart_count=4)
    graph = build_dependency_graph(docker_snapshot, descriptors)

    findings = RestartStormCheck().run(
        CheckContext(services=graph.services, docker_snapshot=docker_snapshot, now=ts(14, 0))
    )

    assert findings == []


def test_restart_storm_check_flags_large_restart_delta() -> None:
    """A large restart-count increase inside the window should emit a finding."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    check = RestartStormCheck(restart_delta_threshold=3, window_seconds=300)

    baseline_snapshot = _build_snapshot(deluge_restart_count=4)
    baseline_graph = build_dependency_graph(baseline_snapshot, descriptors)
    assert (
        check.run(
            CheckContext(
                services=baseline_graph.services,
                docker_snapshot=baseline_snapshot,
                now=ts(14, 0),
            )
        )
        == []
    )

    followup_snapshot = _build_snapshot(deluge_restart_count=7)
    followup_graph = build_dependency_graph(followup_snapshot, descriptors)
    findings = check.run(
        CheckContext(
            services=followup_graph.services,
            docker_snapshot=followup_snapshot,
            now=ts(14, 1),
        )
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-delugevpn"
    assert findings[0].title == "DelugeVPN restart storm detected"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence[0].data["restart_delta"] == 3
    assert findings[0].evidence[0].data["previous_restart_count"] == 4
    assert findings[0].evidence[0].data["current_restart_count"] == 7


def test_restart_storm_check_ignores_small_restart_delta() -> None:
    """Small restart-count increases should not emit restart storm findings."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    check = RestartStormCheck(restart_delta_threshold=3, window_seconds=300)

    baseline_snapshot = _build_snapshot(deluge_restart_count=4)
    baseline_graph = build_dependency_graph(baseline_snapshot, descriptors)
    assert (
        check.run(
            CheckContext(
                services=baseline_graph.services,
                docker_snapshot=baseline_snapshot,
                now=ts(14, 0),
            )
        )
        == []
    )

    followup_snapshot = _build_snapshot(deluge_restart_count=5)
    followup_graph = build_dependency_graph(followup_snapshot, descriptors)
    findings = check.run(
        CheckContext(
            services=followup_graph.services,
            docker_snapshot=followup_snapshot,
            now=ts(14, 1),
        )
    )

    assert findings == []


def test_restart_storm_check_uses_configured_restart_delta_threshold() -> None:
    """A higher configured restart threshold should suppress smaller spikes."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    check = RestartStormCheck(restart_delta_threshold=5, window_seconds=300)

    baseline_snapshot = _build_snapshot(deluge_restart_count=4)
    baseline_graph = build_dependency_graph(baseline_snapshot, descriptors)
    assert (
        check.run(
            CheckContext(
                services=baseline_graph.services,
                docker_snapshot=baseline_snapshot,
                now=ts(14, 0),
            )
        )
        == []
    )

    followup_snapshot = _build_snapshot(deluge_restart_count=8)
    followup_graph = build_dependency_graph(followup_snapshot, descriptors)
    findings = check.run(
        CheckContext(
            services=followup_graph.services,
            docker_snapshot=followup_snapshot,
            now=ts(14, 1),
        )
    )

    assert findings == []


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
