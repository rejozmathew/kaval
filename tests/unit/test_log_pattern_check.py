"""Unit tests for the log pattern monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import DockerTransportError, build_discovery_snapshot
from kaval.models import Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.log_pattern import LogPatternCheck

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by log pattern tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_text_fixture(name: str) -> str:
    """Load a text fixture used by log pattern tests."""
    return (DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8")


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_log_pattern_check_emits_error_and_warning_findings() -> None:
    """Matched descriptor error and warning patterns should emit findings."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    services, docker_snapshot = _services()

    def fake_log_reader(container_id: str, tail_lines: int) -> str:
        assert tail_lines == 200
        if container_id == "def456":
            return load_text_fixture("container_logs_def456.txt")
        return ""

    findings = LogPatternCheck(descriptors, log_reader=fake_log_reader).run(
        CheckContext(
            services=services,
            docker_snapshot=docker_snapshot,
            now=ts(19, 0),
        )
    )

    assert len(findings) == 2
    findings_by_severity = {finding.severity: finding for finding in findings}
    assert findings_by_severity[Severity.HIGH].service_id == "svc-delugevpn"
    assert findings_by_severity[Severity.HIGH].evidence[0].data["matched_patterns"] == [
        "VPN tunnel inactive"
    ]
    assert findings_by_severity[Severity.MEDIUM].service_id == "svc-delugevpn"
    assert findings_by_severity[Severity.MEDIUM].evidence[0].data["matched_patterns"] == [
        "Port forward unavailable"
    ]


def test_log_pattern_check_suppresses_services_without_matches() -> None:
    """Services with no matched descriptor log patterns should stay quiet."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    services, docker_snapshot = _services()

    findings = LogPatternCheck(
        descriptors,
        log_reader=lambda container_id, tail_lines: "normal startup complete",
    ).run(
        CheckContext(
            services=services,
            docker_snapshot=docker_snapshot,
            now=ts(19, 5),
        )
    )

    assert findings == []


def test_log_pattern_check_skips_log_reader_transport_failures() -> None:
    """Transient log read failures should not abort the full check run."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    services, docker_snapshot = _services()

    def fake_log_reader(container_id: str, tail_lines: int) -> str:
        del tail_lines
        if container_id == "def456":
            raise DockerTransportError("failed to reach Docker API")
        return ""

    findings = LogPatternCheck(descriptors, log_reader=fake_log_reader).run(
        CheckContext(
            services=services,
            docker_snapshot=docker_snapshot,
            now=ts(19, 10),
        )
    )

    assert findings == []


def _services() -> tuple[list[object], object]:
    """Build the discovered services used by log pattern tests."""
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
    return graph.services, docker_snapshot
