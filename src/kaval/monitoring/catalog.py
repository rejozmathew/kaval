"""Catalog metadata for the currently implemented monitoring checks."""

from __future__ import annotations

from kaval.models import EndpointProtocol, KavalModel, Service, ServiceType


class MonitoringCheckCatalogEntry(KavalModel):
    """Operator-facing metadata for one supported monitoring check."""

    check_id: str
    label: str
    description: str


_CHECK_CATALOG: tuple[MonitoringCheckCatalogEntry, ...] = (
    MonitoringCheckCatalogEntry(
        check_id="container_health",
        label="Container health",
        description="Detect unhealthy, restarting, paused, or stopped containers.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="restart_storm",
        label="Restart storm",
        description="Detect rapid restart-count spikes between scheduler observations.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="endpoint_probe",
        label="Endpoint probe",
        description="Probe declared HTTP and HTTPS endpoints that do not require auth.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="vm_health",
        label="VM health",
        description="Track VM state and explicitly declared hosted-service probes.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="tls_cert",
        label="TLS certificate",
        description="Check HTTPS endpoint certificates for expiry and retrieval failures.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="dns_resolution",
        label="DNS resolution",
        description="Validate declared DNS targets against their expected answers.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="log_pattern",
        label="Log pattern",
        description=(
            "Match recent container logs against descriptor-defined warning "
            "and error patterns."
        ),
    ),
    MonitoringCheckCatalogEntry(
        check_id="unraid_system",
        label="Unraid system",
        description="Monitor array state, disk health, and share capacity.",
    ),
    MonitoringCheckCatalogEntry(
        check_id="dependency_chain",
        label="Dependency chain",
        description="Report services whose upstream dependencies are unhealthy.",
    ),
)


def monitoring_check_catalog() -> tuple[MonitoringCheckCatalogEntry, ...]:
    """Return metadata for the checks implemented in the current repo state."""
    return _CHECK_CATALOG


def monitoring_check_entry(check_id: str) -> MonitoringCheckCatalogEntry:
    """Return catalog metadata for one supported monitoring check."""
    for entry in _CHECK_CATALOG:
        if entry.check_id == check_id:
            return entry
    msg = f"unsupported monitoring check id: {check_id}"
    raise ValueError(msg)


def check_applies_to_service(check_id: str, service: Service) -> bool:
    """Return whether one implemented check is meaningful for one service."""
    if check_id in {"container_health", "restart_storm"}:
        return service.type == ServiceType.CONTAINER and service.container_id is not None
    if check_id == "endpoint_probe":
        return any(
            endpoint.protocol in {EndpointProtocol.HTTP, EndpointProtocol.HTTPS}
            and not endpoint.auth_required
            for endpoint in service.endpoints
        )
    if check_id == "vm_health":
        return service.type == ServiceType.VM and service.vm_id is not None
    if check_id == "tls_cert":
        return any(
            endpoint.protocol == EndpointProtocol.HTTPS for endpoint in service.endpoints
        )
    if check_id == "dns_resolution":
        return bool(service.dns_targets)
    if check_id == "log_pattern":
        return (
            service.type == ServiceType.CONTAINER
            and service.container_id is not None
            and service.descriptor_id is not None
        )
    if check_id == "unraid_system":
        return service.type in {ServiceType.SYSTEM, ServiceType.SHARE}
    if check_id == "dependency_chain":
        return bool(service.dependencies)
    msg = f"unsupported monitoring check id: {check_id}"
    raise ValueError(msg)
