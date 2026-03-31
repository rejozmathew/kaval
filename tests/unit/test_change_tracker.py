"""Unit tests for Docker-backed change detection."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.change_tracker import ChangeTracker
from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import DockerDiscoverySnapshot, build_discovery_snapshot
from kaval.models import ChangeType, Service

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture for change-tracker tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_change_tracker_suppresses_initial_baseline_snapshot() -> None:
    """The first observed snapshot should establish a baseline without changes."""
    tracker = ChangeTracker()

    changes = tracker.detect_changes(_snapshot(discovered_at=ts(20, 0)))

    assert changes == []


def test_change_tracker_emits_image_update_with_service_context() -> None:
    """Image id changes should emit a typed image-update event."""
    tracker = ChangeTracker()
    tracker.detect_changes(_snapshot(discovered_at=ts(20, 0)))

    updated_snapshot = _snapshot(
        discovered_at=ts(20, 5),
        abc123_image_id="sha256:img-radarr-new",
    )
    changes = tracker.detect_changes(updated_snapshot, services=_services(updated_snapshot))

    assert len(changes) == 1
    change = changes[0]
    assert change.type == ChangeType.IMAGE_UPDATE
    assert change.service_id == "svc-radarr"
    assert change.old_value == "lscr.io/linuxserver/radarr:latest [sha256:img-radarr]"
    assert change.new_value == "lscr.io/linuxserver/radarr:latest [sha256:img-radarr-new]"
    assert change.description == (
        "radarr image changed from "
        "lscr.io/linuxserver/radarr:latest [sha256:img-radarr] "
        "to lscr.io/linuxserver/radarr:latest [sha256:img-radarr-new]."
    )


def test_change_tracker_emits_restart_change_without_service_graph() -> None:
    """Restart-count increases should be tracked even without service records."""
    tracker = ChangeTracker()
    tracker.detect_changes(_snapshot(discovered_at=ts(20, 0)))

    restarted_snapshot = _snapshot(
        discovered_at=ts(20, 10),
        def456_restart_count=7,
    )
    changes = tracker.detect_changes(restarted_snapshot)

    assert len(changes) == 1
    change = changes[0]
    assert change.type == ChangeType.CONTAINER_RESTART
    assert change.service_id is None
    assert change.old_value == "4"
    assert change.new_value == "7"
    assert change.description == "delugevpn restart count increased from 4 to 7."


def _services(snapshot: DockerDiscoverySnapshot) -> list[Service]:
    """Build typed service nodes for change-tracker tests."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    graph = build_dependency_graph(snapshot, descriptors)
    return graph.services


def _snapshot(
    *,
    discovered_at: datetime,
    abc123_image_id: str = "sha256:img-radarr",
    def456_restart_count: int = 4,
) -> DockerDiscoverySnapshot:
    """Build a Docker discovery snapshot with configurable change signals."""
    abc123 = copy.deepcopy(load_json_fixture("container_inspect_abc123.json"))
    abc123["Image"] = abc123_image_id
    def456 = copy.deepcopy(load_json_fixture("container_inspect_def456.json"))
    def456["RestartCount"] = def456_restart_count

    image_payloads = {
        abc123_image_id: _image_payload(
            image_id=abc123_image_id,
            repo_tag="lscr.io/linuxserver/radarr:latest",
        ),
        "sha256:img-delugevpn": load_json_fixture("image_inspect_sha256_img-delugevpn.json"),
    }
    return build_discovery_snapshot(
        [abc123, def456],
        image_payloads,
        discovered_at=discovered_at,
    )


def _image_payload(*, image_id: str, repo_tag: str) -> dict[str, object]:
    """Build a minimal Docker image payload for image-update tests."""
    return {
        "Id": image_id,
        "RepoTags": [repo_tag],
        "RepoDigests": [],
        "Created": "2026-03-31T19:00:00Z",
    }
