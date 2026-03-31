"""Unit tests for the Phase 1 Docker discovery adapter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.docker import (
    DockerClientConfig,
    build_container_snapshot,
    build_discovery_snapshot,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"


def load_fixture(name: str) -> dict[str, object] | list[object]:
    """Load a JSON fixture for Docker discovery tests."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_docker_client_config_builds_versioned_endpoint() -> None:
    """The Docker client config should normalize versioned API endpoints."""
    config = DockerClientConfig(base_url="http://tower.local/", api_key="secret")

    assert config.endpoint("/containers/json", {"all": "1"}) == (
        "http://tower.local/v1.43/containers/json?all=1"
    )


def test_build_container_snapshot_parses_inspect_fixture() -> None:
    """Docker inspect fixtures should map cleanly into typed snapshots."""
    inspect_payload = load_fixture("container_inspect_abc123.json")
    image_payload = load_fixture("image_inspect_sha256_img-radarr.json")
    snapshot = build_container_snapshot(inspect_payload, image_payload)

    assert snapshot.name == "radarr"
    assert snapshot.image == "lscr.io/linuxserver/radarr:latest"
    assert snapshot.restart_count == 2
    assert snapshot.state.health is not None
    assert snapshot.state.health.status == "healthy"
    assert snapshot.env_names == ["PUID", "PGID", "TZ", "API_KEY"]
    assert snapshot.mounts[1].read_only is True
    assert snapshot.networks[0].ip_address == "172.17.0.10"
    assert snapshot.ports[0].host_port == 7878
    assert snapshot.image_details is not None
    assert snapshot.image_details.repo_tags == ["lscr.io/linuxserver/radarr:latest"]


def test_build_discovery_snapshot_groups_containers_and_images() -> None:
    """The snapshot builder should preserve container and image discovery results."""
    inspect_payloads = [
        load_fixture("container_inspect_abc123.json"),
        load_fixture("container_inspect_def456.json"),
    ]
    image_payloads = {
        "sha256:img-radarr": load_fixture("image_inspect_sha256_img-radarr.json"),
        "sha256:img-delugevpn": load_fixture("image_inspect_sha256_img-delugevpn.json"),
    }

    snapshot = build_discovery_snapshot(
        inspect_payloads, image_payloads, discovered_at=ts(10, 45)
    )

    assert snapshot.discovered_at == ts(10, 45)
    assert [container.name for container in snapshot.containers] == ["radarr", "delugevpn"]
    assert snapshot.containers[1].state.health is not None
    assert snapshot.containers[1].state.health.status == "unhealthy"
    assert len(snapshot.images) == 2
