"""Unit tests for Operational Memory system-profile materialization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.system_profile import build_system_profile

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_docker_fixture(name: str) -> dict[str, object]:
    """Load a Docker fixture for system-profile tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load an Unraid fixture for system-profile tests."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_build_system_profile_from_phase1_discovery_surfaces() -> None:
    """The system profile should materialize from the existing discovery data."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            load_docker_fixture("container_inspect_abc123.json"),
            load_docker_fixture("container_inspect_def456.json"),
        ],
        {
            "sha256:img-radarr": load_docker_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_docker_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
    )
    unraid_snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )
    services = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    ).services

    profile = build_system_profile(
        unraid_snapshot,
        docker_snapshot,
        services=services,
        now=ts(23, 0),
    )

    assert profile.hostname == "zactower"
    assert profile.unraid_version == "7.2.1"
    assert profile.hardware.cpu == "Intel i3-12100T"
    assert profile.hardware.memory_gb == 32.0
    assert profile.storage.array.parity_drives == 1
    assert profile.storage.array.data_drives == 1
    assert profile.networking.vpn == "delugevpn"
    assert profile.networking.dns_resolver is None
    assert profile.services_summary.total_containers == 2
    assert profile.services_summary.total_vms == 1
    assert profile.services_summary.matched_descriptors == 2
    assert profile.vms[0].name == "Ubuntu Server"
    assert profile.vms[0].purpose == "unknown"
    assert profile.last_updated == ts(23, 0)
