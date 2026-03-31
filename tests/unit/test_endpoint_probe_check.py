"""Unit tests for the endpoint probe monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.models import Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.endpoint_probe import (
    EndpointProbeCheck,
    EndpointProbeError,
    EndpointProbeResult,
)

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by endpoint probe tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_endpoint_probe_check_probes_only_non_auth_http_endpoints() -> None:
    """Only declared non-auth HTTP/HTTPS endpoints should be probed."""
    services = _services()
    probed_urls: list[str] = []

    def fake_probe(url: str, timeout_seconds: float) -> EndpointProbeResult:
        del timeout_seconds
        probed_urls.append(url)
        return EndpointProbeResult(url=url, status_code=200)

    findings = EndpointProbeCheck(probe=fake_probe).run(
        CheckContext(services=services, docker_snapshot=None, now=ts(16, 0))
    )

    assert findings == []
    assert probed_urls == [
        "http://delugevpn:8112/",
        "http://radarr:7878/",
    ]


def test_endpoint_probe_check_flags_transport_failures() -> None:
    """Connection failures should emit a high-severity finding."""
    services = _services()

    def fake_probe(url: str, timeout_seconds: float) -> EndpointProbeResult:
        del timeout_seconds
        if url == "http://delugevpn:8112/":
            raise EndpointProbeError("connection refused")
        return EndpointProbeResult(url=url, status_code=200)

    findings = EndpointProbeCheck(probe=fake_probe).run(
        CheckContext(services=services, docker_snapshot=None, now=ts(16, 5))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-delugevpn"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence[0].data["error"] == "connection refused"


def test_endpoint_probe_check_flags_unhealthy_http_statuses() -> None:
    """Unexpected HTTP statuses should emit deterministic findings."""
    services = _services()

    def fake_probe(url: str, timeout_seconds: float) -> EndpointProbeResult:
        del timeout_seconds
        if url == "http://radarr:7878/":
            return EndpointProbeResult(url=url, status_code=503)
        return EndpointProbeResult(url=url, status_code=200)

    findings = EndpointProbeCheck(probe=fake_probe).run(
        CheckContext(services=services, docker_snapshot=None, now=ts(16, 10))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-radarr"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].summary == (
        "Probe to http://radarr:7878/ returned HTTP 503; expected 200."
    )


def _services() -> list[object]:
    """Build the discovered services used by endpoint probe tests."""
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
    return graph.services
