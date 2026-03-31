"""Unit tests for the container health monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.models import Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.container_health import ContainerHealthCheck

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by container health tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_container_health_check_skips_healthy_container_and_flags_unhealthy_one() -> None:
    """Healthy containers should be suppressed while unhealthy ones emit findings."""
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

    findings = ContainerHealthCheck().run(
        CheckContext(services=graph.services, docker_snapshot=docker_snapshot, now=ts(12, 0))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-delugevpn"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].summary == "DelugeVPN reports an unhealthy Docker health status."


def test_container_health_check_flags_exited_container() -> None:
    """Exited containers should emit a high-severity finding."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            _inspect_payload(
                container_id="mariadb-1",
                name="mariadb",
                image="mariadb:latest",
                image_id="sha256:img-mariadb",
                state_status="exited",
                running=False,
                restarting=False,
                health_status=None,
            )
        ],
        {
            "sha256:img-mariadb": _image_payload(
                image_id="sha256:img-mariadb",
                repo_tag="mariadb:latest",
            )
        },
    )
    graph = build_dependency_graph(docker_snapshot, descriptors)

    findings = ContainerHealthCheck().run(
        CheckContext(services=graph.services, docker_snapshot=docker_snapshot, now=ts(12, 30))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-mariadb"
    assert findings[0].summary == "MariaDB is in Docker state 'exited'."
    assert findings[0].severity == Severity.HIGH


def _inspect_payload(
    *,
    container_id: str,
    name: str,
    image: str,
    image_id: str,
    state_status: str,
    running: bool,
    restarting: bool,
    health_status: str | None,
) -> dict[str, object]:
    """Build a minimal Docker inspect payload for health tests."""
    state: dict[str, object] = {
        "Status": state_status,
        "Running": running,
        "Restarting": restarting,
        "ExitCode": 1,
        "StartedAt": "2026-03-31T13:00:00Z",
        "FinishedAt": "2026-03-31T13:05:00Z",
    }
    if health_status is not None:
        state["Health"] = {
            "Status": health_status,
            "FailingStreak": 1,
            "Log": [],
        }
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Image": image_id,
        "RestartCount": 2,
        "Args": [],
        "Config": {
            "Image": image,
            "Env": [],
            "Labels": {},
        },
        "State": state,
        "Mounts": [],
        "NetworkSettings": {
            "Networks": {},
            "Ports": {},
        },
    }


def _image_payload(*, image_id: str, repo_tag: str) -> dict[str, object]:
    """Build a minimal Docker image inspect payload for health tests."""
    return {
        "Id": image_id,
        "RepoTags": [repo_tag],
        "RepoDigests": [],
        "Created": "2026-03-30T11:00:00Z",
    }
