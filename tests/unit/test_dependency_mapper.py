"""Unit tests for dependency graph construction."""

from __future__ import annotations

import json
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.models import DependencyConfidence, DependencySource, ServiceType

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object] | list[object]:
    """Load a JSON fixture used by dependency graph tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by Unraid-backed graph tests."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_build_dependency_graph_infers_descriptor_and_share_edges() -> None:
    """The graph should include descriptor edges and configured share edges."""
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
    services_by_id = {service.id: service for service in graph.services}

    radarr = services_by_id["svc-radarr"]
    assert radarr.type == ServiceType.CONTAINER
    edge_by_target = {edge.target_service_id: edge for edge in radarr.dependencies}

    assert edge_by_target["svc-delugevpn"].confidence == DependencyConfidence.INFERRED
    assert edge_by_target["svc-delugevpn"].source == DependencySource.DESCRIPTOR
    assert edge_by_target["svc-share-media"].confidence == DependencyConfidence.CONFIGURED
    assert edge_by_target["svc-share-media"].source == DependencySource.SHARED_VOLUME

    delugevpn = services_by_id["svc-delugevpn"]
    assert "svc-radarr" in delugevpn.dependents


def test_build_dependency_graph_upgrades_edge_when_non_default_network_matches() -> None:
    """A descriptor dependency should upgrade to configured when Docker corroborates it."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            _inspect_payload(
                container_id="nextcloud-1",
                name="nextcloud",
                image="nextcloud:latest",
                image_id="sha256:img-nextcloud",
                network_name="app-net",
            ),
            _inspect_payload(
                container_id="mariadb-1",
                name="mariadb",
                image="mariadb:latest",
                image_id="sha256:img-mariadb",
                network_name="app-net",
            ),
        ],
        {
            "sha256:img-nextcloud": _image_payload(
                image_id="sha256:img-nextcloud",
                repo_tag="nextcloud:latest",
            ),
            "sha256:img-mariadb": _image_payload(
                image_id="sha256:img-mariadb",
                repo_tag="mariadb:latest",
            ),
        },
    )

    graph = build_dependency_graph(docker_snapshot, descriptors)
    services_by_id = {service.id: service for service in graph.services}
    nextcloud = services_by_id["svc-nextcloud"]
    edge_by_target = {edge.target_service_id: edge for edge in nextcloud.dependencies}

    assert edge_by_target["svc-mariadb"].confidence == DependencyConfidence.CONFIGURED
    assert edge_by_target["svc-mariadb"].source == DependencySource.DOCKER_NETWORK


def test_build_dependency_graph_includes_vm_service_nodes_from_unraid() -> None:
    """Unraid VM summaries should materialize into VM service nodes."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot([], {})
    unraid_snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )

    graph = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    )
    services_by_id = {service.id: service for service in graph.services}

    ubuntu_vm = services_by_id["svc-vm-ubuntu"]
    assert ubuntu_vm.type == ServiceType.VM
    assert ubuntu_vm.vm_id == "vm-ubuntu"
    assert ubuntu_vm.status.value == "healthy"
    assert ubuntu_vm.dependencies == []


def _inspect_payload(
    *,
    container_id: str,
    name: str,
    image: str,
    image_id: str,
    network_name: str,
) -> dict[str, object]:
    """Build a minimal Docker inspect payload for graph tests."""
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Image": image_id,
        "RestartCount": 0,
        "Args": [],
        "Config": {
            "Image": image,
            "Env": [],
            "Labels": {},
        },
        "State": {
            "Status": "running",
            "Running": True,
            "Restarting": False,
            "ExitCode": 0,
            "StartedAt": "2026-03-31T13:00:00Z",
            "FinishedAt": "2026-03-31T12:59:00Z",
        },
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {
                network_name: {
                    "NetworkID": f"network-{network_name}",
                    "EndpointID": f"endpoint-{name}",
                    "Gateway": "172.20.0.1",
                    "IPAddress": f"172.20.0.{10 if name == 'nextcloud' else 11}",
                    "Aliases": [name],
                }
            },
            "Ports": {},
        },
    }


def _image_payload(*, image_id: str, repo_tag: str) -> dict[str, object]:
    """Build a minimal Docker image inspect payload for graph tests."""
    return {
        "Id": image_id,
        "RepoTags": [repo_tag],
        "RepoDigests": [],
        "Created": "2026-03-30T11:00:00Z",
    }
