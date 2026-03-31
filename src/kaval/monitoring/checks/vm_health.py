"""Deterministic VM state and hosted-service health monitoring."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Callable

from kaval.discovery.unraid import UnraidVMSummary
from kaval.models import (
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding
from kaval.monitoring.checks.endpoint_probe import (
    EndpointProbeError,
    EndpointProbeResult,
    probe_endpoint_url,
)

type EndpointProber = Callable[[str, float], EndpointProbeResult]

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


class VMHealthCheck(MonitoringCheck):
    """Emit findings for unhealthy VM states and explicit hosted-service probes."""

    def __init__(
        self,
        interval_seconds: int = 120,
        *,
        timeout_seconds: float = 5.0,
        probe: EndpointProber | None = None,
    ) -> None:
        """Store the check identity, schedule interval, and probe transport."""
        self.check_id = "vm_health"
        self.interval_seconds = interval_seconds
        self._timeout_seconds = timeout_seconds
        self._probe = probe or probe_endpoint_url

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate discovered Unraid VMs and optional explicit hosted endpoints."""
        if context.unraid_snapshot is None:
            return []

        services_by_vm_id = {
            service.vm_id: service
            for service in context.services
            if service.type == ServiceType.VM and service.vm_id is not None
        }
        findings: list[Finding] = []
        for vm in sorted(context.unraid_snapshot.vms, key=lambda vm: (vm.name.lower(), vm.id)):
            service = services_by_vm_id.get(vm.id, _fallback_vm_service(vm))
            state_finding = _state_finding_for_vm(
                service=service,
                vm=vm,
                now=context.now,
                check_id=self.check_id,
            )
            if state_finding is not None:
                findings.append(state_finding)

            if _service_status_for_vm(vm) != ServiceStatus.HEALTHY:
                continue

            for endpoint in _probeable_vm_endpoints(service):
                url = _endpoint_url(endpoint)
                try:
                    result = self._probe(url, self._timeout_seconds)
                except EndpointProbeError as exc:
                    findings.append(
                        _endpoint_transport_failure_finding(
                            service=service,
                            vm=vm,
                            endpoint=endpoint,
                            url=url,
                            error_message=str(exc),
                            now=context.now,
                            check_id=self.check_id,
                        )
                    )
                    continue

                if _status_is_healthy(endpoint, result.status_code):
                    continue
                findings.append(
                    _endpoint_status_failure_finding(
                        service=service,
                        vm=vm,
                        endpoint=endpoint,
                        result=result,
                        now=context.now,
                        check_id=self.check_id,
                    )
                )
        return findings


def _state_finding_for_vm(
    *,
    service: Service,
    vm: UnraidVMSummary,
    now: datetime,
    check_id: str,
) -> Finding | None:
    """Return a deterministic finding for the current Unraid VM state."""
    state = (vm.state or "").strip().lower()
    if state in {"running", "started"}:
        return None
    if state in {"paused", "suspended"}:
        title = f"{service.name} VM is paused"
        summary = f"{service.name} reports VM state '{vm.state}'."
        impact = "Hosted workloads may be degraded until the VM resumes."
        severity = Severity.MEDIUM
    elif state in {"stopped", "shut off", "shutoff", "shutdown"}:
        title = f"{service.name} VM is not running"
        summary = f"{service.name} reports VM state '{vm.state}'."
        impact = "Workloads hosted inside the VM are unavailable until it starts again."
        severity = Severity.HIGH
    else:
        title = f"{service.name} VM is in an unknown state"
        summary = f"{service.name} reports VM state '{vm.state or 'unknown'}'."
        impact = "The VM health state could not be classified deterministically."
        severity = Severity.MEDIUM

    return build_finding(
        check_id=check_id,
        service=service,
        title=title,
        severity=severity,
        summary=summary,
        impact=impact,
        evidence=[_vm_state_evidence(vm, now)],
        now=now,
        confidence=0.95,
    )


def _vm_state_evidence(vm: UnraidVMSummary, now: datetime) -> Evidence:
    """Build the Unraid API evidence payload for a VM health finding."""
    return Evidence(
        kind=EvidenceKind.API,
        source="unraid_api",
        summary=f"Unraid reports VM state={vm.state or 'unknown'}",
        observed_at=now,
        data={
            "vm_id": vm.id,
            "name": vm.name,
            "state": vm.state,
            "os": vm.os,
            "auto_start": vm.auto_start,
        },
    )


def _probeable_vm_endpoints(service: Service) -> list[Endpoint]:
    """Return explicit HTTP/HTTPS VM endpoints that can be probed safely."""
    return [
        endpoint
        for endpoint in sorted(service.endpoints, key=lambda endpoint: endpoint.name)
        if endpoint.protocol in {EndpointProtocol.HTTP, EndpointProtocol.HTTPS}
        and not endpoint.auth_required
    ]


def _endpoint_url(endpoint: Endpoint) -> str:
    """Return the concrete URL to probe for one hosted VM endpoint."""
    if endpoint.url is not None:
        return endpoint.url
    if endpoint.host is None or endpoint.port is None:
        msg = f"endpoint {endpoint.name} is missing host/port details"
        raise EndpointProbeError(msg)

    scheme = endpoint.protocol.value
    path = endpoint.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{scheme}://{endpoint.host}:{endpoint.port}{path}"


def _status_is_healthy(endpoint: Endpoint, status_code: int) -> bool:
    """Return whether a hosted VM endpoint response counts as healthy."""
    if endpoint.expected_status is not None:
        return status_code == endpoint.expected_status
    return 200 <= status_code < 300


def _endpoint_transport_failure_finding(
    *,
    service: Service,
    vm: UnraidVMSummary,
    endpoint: Endpoint,
    url: str,
    error_message: str,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for an unreachable hosted VM endpoint."""
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} hosted service is unreachable",
        severity=Severity.HIGH,
        summary=f"Probe to {url} failed: {error_message}.",
        impact="A service hosted inside the VM is unreachable even though the VM is running.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="endpoint_probe",
                summary=f"{endpoint.name} probe failed to connect",
                observed_at=now,
                data={
                    "vm_id": vm.id,
                    "vm_name": vm.name,
                    "endpoint_name": endpoint.name,
                    "url": url,
                    "protocol": endpoint.protocol.value,
                    "expected_status": endpoint.expected_status,
                    "error": error_message,
                },
            )
        ],
        now=now,
        confidence=0.95,
    )


def _endpoint_status_failure_finding(
    *,
    service: Service,
    vm: UnraidVMSummary,
    endpoint: Endpoint,
    result: EndpointProbeResult,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for a hosted VM endpoint with an unhealthy response."""
    severity = Severity.HIGH if result.status_code >= 500 else Severity.MEDIUM
    expected_status = endpoint.expected_status
    expected_text = (
        str(expected_status)
        if expected_status is not None
        else "a 2xx success response"
    )
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} hosted service returned an unhealthy status",
        severity=severity,
        summary=(
            f"Probe to {result.url} returned HTTP {result.status_code}; "
            f"expected {expected_text}."
        ),
        impact="A service hosted inside the VM is responding unexpectedly.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="endpoint_probe",
                summary=f"{endpoint.name} probe returned HTTP {result.status_code}",
                observed_at=now,
                data={
                    "vm_id": vm.id,
                    "vm_name": vm.name,
                    "endpoint_name": endpoint.name,
                    "url": result.url,
                    "protocol": endpoint.protocol.value,
                    "status_code": result.status_code,
                    "expected_status": endpoint.expected_status,
                },
            )
        ],
        now=now,
        confidence=0.95,
    )


def _fallback_vm_service(vm: UnraidVMSummary) -> Service:
    """Build a minimal VM service when the dependency graph has not materialized one."""
    slug = _slugify(vm.id)
    if slug.startswith("vm-"):
        slug = slug.removeprefix("vm-")
    return Service(
        id=f"svc-vm-{slug}",
        name=vm.name,
        type=ServiceType.VM,
        category="virtualization",
        status=_service_status_for_vm(vm),
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=vm.id,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _service_status_for_vm(vm: UnraidVMSummary) -> ServiceStatus:
    """Map the Unraid VM state to the service status used by the check."""
    state = (vm.state or "").strip().lower()
    if state in {"running", "started"}:
        return ServiceStatus.HEALTHY
    if state in {"paused", "suspended"}:
        return ServiceStatus.DEGRADED
    if state in {"stopped", "shut off", "shutoff", "shutdown"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def _slugify(value: str) -> str:
    """Normalize a value for stable identifiers."""
    return _NON_ALNUM_RE.sub("-", value.lower()).strip("-")
