"""Integration tests for running the TLS certificate check through the scheduler."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import (
    DependencyEdge,
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.tls_cert import TLSCertificateCheck, TLSCertificateInfo
from kaval.monitoring.scheduler import CheckScheduler


def ts(day: int, hour: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, day, hour, tzinfo=UTC)


def test_tls_cert_check_runs_through_scheduler() -> None:
    """The scheduler should execute the TLS check and surface expiry findings."""
    services = [
        Service(
            id="svc-gateway",
            name="Gateway",
            type=ServiceType.CONTAINER,
            category="networking",
            status=ServiceStatus.HEALTHY,
            descriptor_id="networking/gateway",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="gateway-1",
            vm_id=None,
            image="gateway:latest",
            endpoints=[
                Endpoint(
                    name="web_ui",
                    protocol=EndpointProtocol.HTTPS,
                    host="gateway.local",
                    port=443,
                    path="/",
                    url=None,
                    auth_required=False,
                    expected_status=200,
                )
            ],
            dependencies=list[DependencyEdge](),
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        )
    ]

    def fake_fetch(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
        del timeout_seconds
        return TLSCertificateInfo(
            host=host,
            port=port,
            not_valid_after=ts(21),
        )

    scheduler = CheckScheduler(
        [TLSCertificateCheck(interval_seconds=21600, fetch_certificate=fake_fetch)]
    )

    result = scheduler.run_due_checks(CheckContext(services=services, now=ts(20)))

    assert result.executed_checks == ("tls_cert",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-gateway"
