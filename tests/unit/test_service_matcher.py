"""Unit tests for service descriptor matching."""

from __future__ import annotations

import json
from pathlib import Path

from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_container_snapshot
from kaval.discovery.matcher import build_service, match_service_descriptor
from kaval.models import DescriptorSource, DnsRecordType, ServiceStatus

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by matcher tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_match_service_descriptor_prefers_specific_image_pattern() -> None:
    """The matcher should pick the most specific shipped descriptor."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    container = build_container_snapshot(
        load_json_fixture("container_inspect_abc123.json"),
        load_json_fixture("image_inspect_sha256_img-radarr.json"),
    )

    matched = match_service_descriptor(container, descriptors)

    assert matched is not None
    assert matched.descriptor.id == "radarr"
    assert matched.path == SERVICES_DIR / "arr" / "radarr.yaml"


def test_build_service_uses_matched_descriptor_metadata() -> None:
    """Matched descriptors should populate service metadata and endpoints."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    container = build_container_snapshot(
        load_json_fixture("container_inspect_abc123.json"),
        load_json_fixture("image_inspect_sha256_img-radarr.json"),
    )
    matched = match_service_descriptor(container, descriptors)

    service = build_service(container, matched)

    assert service.id == "svc-radarr"
    assert service.name == "Radarr"
    assert service.status == ServiceStatus.HEALTHY
    assert service.descriptor_id == "arr/radarr"
    assert service.descriptor_source == DescriptorSource.SHIPPED
    assert [endpoint.name for endpoint in service.endpoints] == ["web_ui", "health_api"]


def test_build_service_materializes_descriptor_dns_targets() -> None:
    """Matched descriptors should copy DNS targets onto the materialized service."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    container = build_container_snapshot(
        _pihole_inspect_payload(),
        _image_payload(image_id="sha256:img-pihole", repo_tag="pihole/pihole:latest"),
    )
    matched = match_service_descriptor(container, descriptors)

    service = build_service(container, matched)

    assert matched is not None
    assert matched.descriptor.id == "pihole"
    assert len(service.dns_targets) == 1
    assert service.dns_targets[0].host == "pi.hole"
    assert service.dns_targets[0].record_type == DnsRecordType.A


def _pihole_inspect_payload() -> dict[str, object]:
    """Build a minimal Docker inspect payload for a Pi-hole container."""
    return {
        "Id": "pihole-1",
        "Name": "/pihole",
        "Image": "sha256:img-pihole",
        "RestartCount": 0,
        "Args": [],
        "Config": {
            "Image": "pihole/pihole:latest",
            "Env": [],
            "Labels": {},
        },
        "State": {
            "Status": "running",
            "Running": True,
            "Restarting": False,
            "ExitCode": 0,
            "StartedAt": "2026-03-31T10:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {},
            "Ports": {},
        },
    }


def _image_payload(*, image_id: str, repo_tag: str) -> dict[str, object]:
    """Build a minimal Docker image inspect payload for matcher tests."""
    return {
        "Id": image_id,
        "RepoTags": [repo_tag],
        "RepoDigests": [],
        "Created": "2026-03-30T11:00:00Z",
    }
