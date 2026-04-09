"""Deterministic dependency-chain validation."""

from __future__ import annotations

from datetime import datetime

from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    Evidence,
    EvidenceKind,
    Finding,
    Service,
    ServiceStatus,
    Severity,
)
from kaval.monitoring.checks.base import (
    CheckContext,
    MonitoringCheck,
    build_finding,
    iter_target_services,
)


class DependencyChainCheck(MonitoringCheck):
    """Emit findings when an upstream dependency is unhealthy."""

    def __init__(self, interval_seconds: int = 120) -> None:
        """Store the check identity and schedule interval."""
        self.check_id = "dependency_chain"
        self.interval_seconds = interval_seconds

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate the current service graph for unhealthy upstream dependencies."""
        services_by_id = {service.id: service for service in context.services}
        findings: list[Finding] = []
        for service in sorted(iter_target_services(context), key=lambda service: service.id):
            for edge in sorted(service.dependencies, key=lambda edge: edge.target_service_id):
                dependency = services_by_id.get(edge.target_service_id)
                if dependency is None or dependency.status not in _UNHEALTHY_STATUSES:
                    continue
                findings.append(
                    _dependency_finding(
                        service=service,
                        dependency=dependency,
                        edge=edge,
                        now=context.now,
                        check_id=self.check_id,
                    )
                )
        return findings


_UNHEALTHY_STATUSES = {
    ServiceStatus.DEGRADED,
    ServiceStatus.DOWN,
    ServiceStatus.STOPPED,
}


def _dependency_finding(
    *,
    service: Service,
    dependency: Service,
    edge: DependencyEdge,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for one unhealthy upstream dependency."""
    severity = (
        Severity.HIGH
        if dependency.status in {ServiceStatus.DOWN, ServiceStatus.STOPPED}
        else Severity.MEDIUM
    )
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} depends on an unhealthy upstream service",
        severity=severity,
        summary=(
            f"{service.name} depends on {dependency.name}, which is currently "
            f"{dependency.status.value}."
        ),
        impact=(
            f"Requests that rely on {dependency.name} may fail until the upstream "
            "service recovers."
        ),
        evidence=[_dependency_evidence(dependency=dependency, edge=edge, now=now)],
        now=now,
        confidence=_finding_confidence(edge.confidence),
    )


def _dependency_evidence(
    *,
    dependency: Service,
    edge: DependencyEdge,
    now: datetime,
) -> Evidence:
    """Build the service-graph evidence payload for one unhealthy dependency."""
    return Evidence(
        kind=EvidenceKind.API,
        source="service_graph",
        summary=(
            f"Dependency edge targets {dependency.name} with status "
            f"{dependency.status.value}"
        ),
        observed_at=now,
        data={
            "dependency_service_id": dependency.id,
            "dependency_name": dependency.name,
            "dependency_status": dependency.status.value,
            "edge_confidence": edge.confidence.value,
            "edge_source": edge.source.value,
            "edge_description": edge.description,
        },
    )


def _finding_confidence(confidence: DependencyConfidence) -> float:
    """Map edge confidence into finding confidence."""
    if confidence == DependencyConfidence.CONFIGURED:
        return 0.98
    if confidence == DependencyConfidence.INFERRED:
        return 0.9
    return 0.75
