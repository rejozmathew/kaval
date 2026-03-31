"""Unit tests for the DNS resolution monitoring check."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import (
    DependencyEdge,
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.dns_resolution import DNSResolutionCheck, DnsResolutionError


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_dns_resolution_check_skips_services_without_dns_targets() -> None:
    """Services with no declared DNS targets should not be queried."""
    resolver_calls: list[tuple[str, DnsRecordType]] = []

    def fake_resolver(host: str, record_type: DnsRecordType) -> list[str]:
        resolver_calls.append((host, record_type))
        return ["192.0.2.10"]

    findings = DNSResolutionCheck(resolver=fake_resolver).run(
        CheckContext(
            services=[_service(service_id="svc-radarr", dns_targets=[])],
            now=ts(17, 0),
        )
    )

    assert findings == []
    assert resolver_calls == []


def test_dns_resolution_check_flags_resolution_failures() -> None:
    """Resolver errors should emit high-severity findings."""
    def fake_resolver(host: str, record_type: DnsRecordType) -> list[str]:
        del host, record_type
        raise DnsResolutionError("name or service not known")

    findings = DNSResolutionCheck(resolver=fake_resolver).run(
        CheckContext(
            services=[
                _service(
                    service_id="svc-pihole",
                    dns_targets=[DnsTarget(host="pi.hole", record_type=DnsRecordType.A)],
                )
            ],
            now=ts(17, 5),
        )
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-pihole"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence[0].data == {
        "host": "pi.hole",
        "record_type": "A",
        "expected_values": [],
        "error": "name or service not known",
    }


def test_dns_resolution_check_flags_answer_mismatches() -> None:
    """Unexpected answers should emit deterministic findings."""
    def fake_resolver(host: str, record_type: DnsRecordType) -> list[str]:
        del host, record_type
        return ["192.0.2.99"]

    findings = DNSResolutionCheck(resolver=fake_resolver).run(
        CheckContext(
            services=[
                _service(
                    service_id="svc-home-assistant",
                    dns_targets=[
                        DnsTarget(
                            host="home.example.test",
                            record_type=DnsRecordType.A,
                            expected_values=["192.0.2.20"],
                        )
                    ],
                )
            ],
            now=ts(17, 10),
        )
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-home-assistant"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].summary == (
        "A lookup for home.example.test returned 192.0.2.99; expected 192.0.2.20."
    )


def _service(*, service_id: str, dns_targets: list[DnsTarget]) -> Service:
    """Build a minimal Service model for DNS check tests."""
    return Service(
        id=service_id,
        name=service_id.removeprefix("svc-").replace("-", " ").title(),
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.HEALTHY,
        descriptor_id="networking/test",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id=f"{service_id}-container",
        vm_id=None,
        image="example:latest",
        endpoints=[],
        dns_targets=dns_targets,
        dependencies=list[DependencyEdge](),
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
