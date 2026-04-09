"""Unit tests for the TLS certificate monitoring check."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kaval.models import (
    DependencyEdge,
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.tls_cert import TLSCertificateCheck, TLSCertificateInfo


def ts(day: int, hour: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, day, hour, tzinfo=UTC)


def test_tls_cert_check_probes_only_https_endpoints() -> None:
    """Only HTTPS endpoints should be inspected."""
    services = [
        _service(
            service_id="svc-http",
            name="HTTP Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTP,
                host="http-service",
                port=80,
            ),
        ),
        _service(
            service_id="svc-https",
            name="HTTPS Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTPS,
                host="https-service",
                port=443,
            ),
        ),
    ]
    calls: list[tuple[str, int, float]] = []

    def fake_fetch(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
        calls.append((host, port, timeout_seconds))
        return TLSCertificateInfo(
            host=host,
            port=port,
            not_valid_after=ts(31) + timedelta(days=30),
        )

    findings = TLSCertificateCheck(fetch_certificate=fake_fetch).run(
        CheckContext(services=services, now=ts(20))
    )

    assert findings == []
    assert calls == [("https-service", 443, 5.0)]


def test_tls_cert_check_flags_expired_and_near_expiry_certificates() -> None:
    """Expired and near-expiry certificates should emit findings with thresholds."""
    services = [
        _service(
            service_id="svc-expired",
            name="Expired Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTPS,
                host="expired-service",
                port=443,
            ),
        ),
        _service(
            service_id="svc-warning",
            name="Warning Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTPS,
                host="warning-service",
                port=443,
            ),
        ),
    ]

    def fake_fetch(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
        del timeout_seconds
        if host == "expired-service":
            return TLSCertificateInfo(
                host=host,
                port=port,
                not_valid_after=ts(19, 12),
                subject_common_name="expired.local",
            )
        return TLSCertificateInfo(
            host=host,
            port=port,
            not_valid_after=ts(22),
            issuer_common_name="Local Test CA",
        )

    findings = TLSCertificateCheck(fetch_certificate=fake_fetch).run(
        CheckContext(services=services, now=ts(20))
    )

    assert len(findings) == 2
    assert findings[0].service_id == "svc-expired"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].title == "Expired Service certificate has expired"
    assert findings[1].service_id == "svc-warning"
    assert findings[1].severity == Severity.HIGH
    assert findings[1].title == "Warning Service certificate expires soon"


def test_tls_cert_check_skips_long_lived_certificates() -> None:
    """Certificates beyond the warning threshold should not emit findings."""
    services = [
        _service(
            service_id="svc-stable",
            name="Stable Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTPS,
                host="stable-service",
                port=443,
            ),
        )
    ]

    def fake_fetch(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
        del host, port, timeout_seconds
        return TLSCertificateInfo(
            host="stable-service",
            port=443,
            not_valid_after=ts(20) + timedelta(days=14),
        )

    findings = TLSCertificateCheck(fetch_certificate=fake_fetch).run(
        CheckContext(services=services, now=ts(20))
    )

    assert findings == []


def test_tls_cert_check_uses_configured_warning_threshold() -> None:
    """Raising the warning threshold should surface findings earlier."""
    services = [
        _service(
            service_id="svc-warning-window",
            name="Warning Window Service",
            endpoint=_endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTPS,
                host="warning-window-service",
                port=443,
            ),
        )
    ]

    def fake_fetch(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
        del host, port, timeout_seconds
        return TLSCertificateInfo(
            host="warning-window-service",
            port=443,
            not_valid_after=ts(20) + timedelta(days=10),
        )

    findings = TLSCertificateCheck(
        warning_days=14,
        fetch_certificate=fake_fetch,
    ).run(CheckContext(services=services, now=ts(20)))

    assert len(findings) == 1
    assert findings[0].service_id == "svc-warning-window"
    assert findings[0].title == "Warning Window Service certificate expires soon"


def _service(*, service_id: str, name: str, endpoint: Endpoint) -> Service:
    """Build a minimal Service model for TLS check tests."""
    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.HEALTHY,
        descriptor_id="networking/test",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id=f"{service_id}-container",
        vm_id=None,
        image="example:latest",
        endpoints=[endpoint],
        dependencies=list[DependencyEdge](),
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _endpoint(
    *,
    name: str,
    protocol: EndpointProtocol,
    host: str,
    port: int,
) -> Endpoint:
    """Build a minimal Endpoint model for TLS check tests."""
    return Endpoint(
        name=name,
        protocol=protocol,
        host=host,
        port=port,
        path="/",
        url=None,
        auth_required=False,
        expected_status=200,
    )
