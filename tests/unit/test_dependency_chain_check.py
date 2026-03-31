"""Unit tests for the dependency-chain monitoring check."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.dependency_chain import DependencyChainCheck


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_dependency_chain_check_flags_configured_upstream_outages() -> None:
    """Downstream services should flag configured upstream dependencies that are down."""
    services = [
        build_service("svc-mariadb", "MariaDB", status=ServiceStatus.DOWN),
        build_service(
            "svc-nextcloud",
            "Nextcloud",
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-mariadb",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.DOCKER_NETWORK,
                    description="Shared Docker network confirms the dependency.",
                )
            ],
        ),
    ]

    findings = DependencyChainCheck().run(CheckContext(services=services, now=ts(21, 0)))

    assert len(findings) == 1
    assert findings[0].service_id == "svc-nextcloud"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == 0.98
    assert findings[0].evidence[0].data["edge_source"] == "docker_network"


def test_dependency_chain_check_uses_medium_severity_for_degraded_inferred_edges() -> None:
    """Degraded inferred upstream dependencies should emit medium findings."""
    services = [
        build_service("svc-delugevpn", "DelugeVPN", status=ServiceStatus.DEGRADED),
        build_service(
            "svc-radarr",
            "Radarr",
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-delugevpn",
                    confidence=DependencyConfidence.INFERRED,
                    source=DependencySource.DESCRIPTOR,
                    description="Descriptor dependency on DelugeVPN.",
                )
            ],
        ),
    ]

    findings = DependencyChainCheck().run(CheckContext(services=services, now=ts(21, 5)))

    assert len(findings) == 1
    assert findings[0].service_id == "svc-radarr"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == 0.9


def test_dependency_chain_check_ignores_healthy_and_unknown_upstreams() -> None:
    """Healthy or unknown dependency nodes should not produce findings."""
    services = [
        build_service("svc-delugevpn", "DelugeVPN", status=ServiceStatus.HEALTHY),
        build_service(
            "svc-share-media",
            "media",
            type_=ServiceType.SHARE,
            status=ServiceStatus.UNKNOWN,
        ),
        build_service(
            "svc-radarr",
            "Radarr",
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-delugevpn",
                    confidence=DependencyConfidence.INFERRED,
                    source=DependencySource.DESCRIPTOR,
                    description="Descriptor dependency on DelugeVPN.",
                ),
                DependencyEdge(
                    target_service_id="svc-share-media",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.SHARED_VOLUME,
                    description="Mounted media share.",
                ),
            ],
        ),
    ]

    findings = DependencyChainCheck().run(CheckContext(services=services, now=ts(21, 10)))

    assert findings == []


def build_service(
    service_id: str,
    name: str,
    *,
    type_: ServiceType = ServiceType.CONTAINER,
    status: ServiceStatus = ServiceStatus.HEALTHY,
    dependencies: list[DependencyEdge] | None = None,
) -> Service:
    """Build a minimal service model for dependency-chain tests."""
    return Service(
        id=service_id,
        name=name,
        type=type_,
        category="test",
        status=status,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=list(dependencies or []),
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
