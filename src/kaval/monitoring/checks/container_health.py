"""Deterministic container health monitoring check."""

from __future__ import annotations

from datetime import datetime

from kaval.discovery.docker import DockerContainerSnapshot
from kaval.models import Evidence, EvidenceKind, Finding, Service, ServiceType, Severity
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding


class ContainerHealthCheck(MonitoringCheck):
    """Emit findings for unhealthy, restarting, or stopped containers."""

    def __init__(self, interval_seconds: int = 60) -> None:
        """Store the check identity and schedule interval."""
        self.check_id = "container_health"
        self.interval_seconds = interval_seconds

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate the current Docker snapshot for unhealthy container states."""
        if context.docker_snapshot is None:
            return []

        containers_by_id = {
            container.id: container for container in context.docker_snapshot.containers
        }
        findings: list[Finding] = []
        for service in sorted(context.services, key=lambda service: service.id):
            if service.type != ServiceType.CONTAINER or service.container_id is None:
                continue
            container = containers_by_id.get(service.container_id)
            if container is None:
                continue
            finding = _finding_for_container(service, container, context.now, self.check_id)
            if finding is not None:
                findings.append(finding)
        return findings


def _finding_for_container(
    service: Service,
    container: DockerContainerSnapshot,
    now: datetime,
    check_id: str,
) -> Finding | None:
    """Return a finding for degraded container health, or None when healthy."""
    health_status = container.state.health.status if container.state.health is not None else None
    if health_status == "unhealthy":
        title = f"{service.name} container is unhealthy"
        summary = f"{service.name} reports an unhealthy Docker health status."
        impact = "Dependent services may fail until the container becomes healthy."
        severity = Severity.HIGH
    elif container.state.restarting or container.state.status == "restarting":
        title = f"{service.name} container is restarting"
        summary = f"{service.name} is currently restarting according to Docker state."
        impact = "Service availability is degraded while the container restarts."
        severity = Severity.HIGH
    elif container.state.status in {"dead", "exited"} or container.state.running is False:
        title = f"{service.name} container is not running"
        summary = f"{service.name} is in Docker state '{container.state.status}'."
        impact = "The service is down until the container starts successfully again."
        severity = Severity.HIGH
    elif container.state.status in {"created", "paused"}:
        title = f"{service.name} container is not serving traffic"
        summary = f"{service.name} is in Docker state '{container.state.status}'."
        impact = "The service may be unavailable while the container is not fully running."
        severity = Severity.MEDIUM
    else:
        return None

    return build_finding(
        check_id=check_id,
        service=service,
        title=title,
        severity=severity,
        summary=summary,
        impact=impact,
        evidence=[_docker_state_evidence(container, now)],
        now=now,
        confidence=0.95,
    )


def _docker_state_evidence(container: DockerContainerSnapshot, now: datetime) -> Evidence:
    """Build the Docker state evidence payload for a health finding."""
    health_status = container.state.health.status if container.state.health is not None else None
    return Evidence(
        kind=EvidenceKind.API,
        source="docker_api",
        summary=f"Docker state={container.state.status}, health={health_status or 'n/a'}",
        observed_at=now,
        data={
            "container_id": container.id,
            "state": container.state.status,
            "running": container.state.running,
            "restarting": container.state.restarting,
            "health": health_status,
            "restart_count": container.restart_count,
        },
    )
