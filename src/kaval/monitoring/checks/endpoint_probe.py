"""Deterministic HTTP/HTTPS endpoint probe monitoring check."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable
from urllib import error, request

from kaval.models import (
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    Service,
    Severity,
)
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding

type EndpointProber = Callable[[str, float], "EndpointProbeResult"]


class EndpointProbeError(RuntimeError):
    """Raised when an endpoint probe cannot reach the target URL."""


@dataclass(frozen=True, slots=True)
class EndpointProbeResult:
    """The deterministic output of one HTTP/HTTPS endpoint probe."""

    url: str
    status_code: int


class EndpointProbeCheck(MonitoringCheck):
    """Probe declared HTTP/HTTPS service endpoints without modifying state."""

    def __init__(
        self,
        interval_seconds: int = 120,
        *,
        timeout_seconds: float = 5.0,
        probe: EndpointProber | None = None,
    ) -> None:
        """Store the check identity, schedule interval, and probe transport."""
        self.check_id = "endpoint_probe"
        self.interval_seconds = interval_seconds
        self._timeout_seconds = timeout_seconds
        self._probe = probe or probe_endpoint_url

    def run(self, context: CheckContext) -> list[Finding]:
        """Probe declared HTTP/HTTPS service endpoints and emit failure findings."""
        findings: list[Finding] = []
        for service in sorted(context.services, key=lambda service: service.id):
            for endpoint in _probeable_endpoints(service):
                url = _endpoint_url(endpoint)
                try:
                    result = self._probe(url, self._timeout_seconds)
                except EndpointProbeError as exc:
                    findings.append(
                        _transport_failure_finding(
                            service=service,
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
                    _status_failure_finding(
                        service=service,
                        endpoint=endpoint,
                        result=result,
                        now=context.now,
                        check_id=self.check_id,
                    )
                )
        return findings


def probe_endpoint_url(url: str, timeout_seconds: float) -> EndpointProbeResult:
    """Probe one HTTP/HTTPS URL with the standard library."""
    probe_request = request.Request(url, headers={"User-Agent": "kaval/0.1"})
    try:
        with request.urlopen(probe_request, timeout=timeout_seconds) as response:
            return EndpointProbeResult(
                url=response.geturl(),
                status_code=response.getcode(),
            )
    except error.HTTPError as exc:
        return EndpointProbeResult(
            url=exc.geturl(),
            status_code=exc.code,
        )
    except error.URLError as exc:
        raise EndpointProbeError(str(exc.reason)) from exc


def _probeable_endpoints(service: Service) -> list[Endpoint]:
    """Return deterministic probe targets for one service."""
    return [
        endpoint
        for endpoint in sorted(service.endpoints, key=lambda endpoint: endpoint.name)
        if endpoint.protocol in {EndpointProtocol.HTTP, EndpointProtocol.HTTPS}
        and not endpoint.auth_required
    ]


def _endpoint_url(endpoint: Endpoint) -> str:
    """Return the concrete URL to probe for one endpoint."""
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
    """Return whether an endpoint response counts as healthy."""
    if endpoint.expected_status is not None:
        return status_code == endpoint.expected_status
    return 200 <= status_code < 300


def _transport_failure_finding(
    *,
    service: Service,
    endpoint: Endpoint,
    url: str,
    error_message: str,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for an unreachable endpoint."""
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} endpoint is unreachable",
        severity=Severity.HIGH,
        summary=f"Probe to {url} failed: {error_message}.",
        impact="The service endpoint is unreachable and dependent access may fail.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="endpoint_probe",
                summary=f"{endpoint.name} probe failed to connect",
                observed_at=now,
                data={
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


def _status_failure_finding(
    *,
    service: Service,
    endpoint: Endpoint,
    result: EndpointProbeResult,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for an endpoint that responds with an unhealthy status."""
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
        title=f"{service.name} endpoint probe returned an unhealthy status",
        severity=severity,
        summary=(
            f"Probe to {result.url} returned HTTP {result.status_code}; "
            f"expected {expected_text}."
        ),
        impact="The service endpoint is responding unexpectedly and may be degraded.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="endpoint_probe",
                summary=f"{endpoint.name} probe returned HTTP {result.status_code}",
                observed_at=now,
                data={
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
