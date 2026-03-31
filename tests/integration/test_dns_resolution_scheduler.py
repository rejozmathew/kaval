"""Integration tests for running the DNS resolution check through the scheduler."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_container_snapshot
from kaval.discovery.matcher import build_service, match_service_descriptor
from kaval.models import DnsRecordType
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.dns_resolution import DNSResolutionCheck
from kaval.monitoring.scheduler import CheckScheduler

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_dns_resolution_check_runs_through_scheduler() -> None:
    """The scheduler should execute the DNS check for materialized DNS targets."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    container = build_container_snapshot(
        _pihole_inspect_payload(),
        _image_payload(image_id="sha256:img-pihole", repo_tag="pihole/pihole:latest"),
    )
    matched = match_service_descriptor(container, descriptors)
    service = build_service(container, matched)

    resolver_calls: list[tuple[str, DnsRecordType]] = []

    def fake_resolver(host: str, record_type: DnsRecordType) -> list[str]:
        resolver_calls.append((host, record_type))
        return []

    scheduler = CheckScheduler(
        [DNSResolutionCheck(interval_seconds=300, resolver=fake_resolver)]
    )

    result = scheduler.run_due_checks(CheckContext(services=[service], now=ts(17, 30)))

    assert result.executed_checks == ("dns_resolution",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-pihole"
    assert resolver_calls == [("pi.hole", DnsRecordType.A)]


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
    """Build a minimal Docker image inspect payload for the integration test."""
    return {
        "Id": image_id,
        "RepoTags": [repo_tag],
        "RepoDigests": [],
        "Created": "2026-03-30T11:00:00Z",
    }
