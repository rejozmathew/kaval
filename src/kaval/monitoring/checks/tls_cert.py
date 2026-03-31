"""Deterministic TLS certificate monitoring check."""

from __future__ import annotations

import os
import ssl
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable
from urllib import parse

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

type CertificateFetcher = Callable[[str, int, float], "TLSCertificateInfo"]


class TLSCertificateError(RuntimeError):
    """Raised when a TLS certificate cannot be retrieved or decoded."""


@dataclass(frozen=True, slots=True)
class TLSCertificateInfo:
    """Certificate metadata needed for deterministic expiry checks."""

    host: str
    port: int
    not_valid_after: datetime
    subject_common_name: str | None = None
    issuer_common_name: str | None = None


class TLSCertificateCheck(MonitoringCheck):
    """Inspect HTTPS endpoints for expired or near-expiry certificates."""

    def __init__(
        self,
        interval_seconds: int = 21600,
        *,
        timeout_seconds: float = 5.0,
        warning_days: int = 7,
        critical_days: int = 1,
        fetch_certificate: CertificateFetcher | None = None,
    ) -> None:
        """Store the check identity, thresholds, and certificate fetcher."""
        if warning_days <= 0:
            msg = "warning_days must be positive"
            raise ValueError(msg)
        if critical_days < 0:
            msg = "critical_days must be non-negative"
            raise ValueError(msg)
        if critical_days > warning_days:
            msg = "critical_days must be less than or equal to warning_days"
            raise ValueError(msg)

        self.check_id = "tls_cert"
        self.interval_seconds = interval_seconds
        self._timeout_seconds = timeout_seconds
        self._warning_days = warning_days
        self._critical_days = critical_days
        self._fetch_certificate = fetch_certificate or fetch_tls_certificate

    def run(self, context: CheckContext) -> list[Finding]:
        """Inspect HTTPS endpoints and emit expiry or retrieval findings."""
        findings: list[Finding] = []
        for service in sorted(context.services, key=lambda service: service.id):
            for endpoint in _https_endpoints(service):
                host, port = _endpoint_host_port(endpoint)
                try:
                    certificate = self._fetch_certificate(host, port, self._timeout_seconds)
                except TLSCertificateError as exc:
                    findings.append(
                        _certificate_fetch_failure(
                            service=service,
                            endpoint=endpoint,
                            host=host,
                            port=port,
                            error_message=str(exc),
                            now=context.now,
                            check_id=self.check_id,
                        )
                    )
                    continue

                finding = _certificate_expiry_finding(
                    service=service,
                    endpoint=endpoint,
                    certificate=certificate,
                    now=context.now,
                    check_id=self.check_id,
                    warning_days=self._warning_days,
                    critical_days=self._critical_days,
                )
                if finding is not None:
                    findings.append(finding)
        return findings


def fetch_tls_certificate(host: str, port: int, timeout_seconds: float) -> TLSCertificateInfo:
    """Fetch and decode one TLS certificate using the standard library."""
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout_seconds)
    except OSError as exc:
        raise TLSCertificateError(str(exc)) from exc

    decoded = _decode_pem_certificate(pem)
    not_after = _string_value(decoded.get("notAfter"))
    if not_after is None:
        msg = f"certificate for {host}:{port} did not include notAfter"
        raise TLSCertificateError(msg)

    return TLSCertificateInfo(
        host=host,
        port=port,
        not_valid_after=datetime.fromtimestamp(
            ssl.cert_time_to_seconds(not_after),
            tz=UTC,
        ),
        subject_common_name=_distinguished_name_value(decoded.get("subject"), "commonName"),
        issuer_common_name=_distinguished_name_value(decoded.get("issuer"), "commonName"),
    )


def _decode_pem_certificate(pem: str) -> dict[str, Any]:
    """Decode a PEM certificate into the ssl module's dictionary form."""
    ssl_private = getattr(ssl, "_ssl", None)
    if ssl_private is None or not hasattr(ssl_private, "_test_decode_cert"):
        msg = "TLS certificate decoding is unavailable in this Python runtime"
        raise TLSCertificateError(msg)

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".pem",
            delete=False,
        ) as handle:
            handle.write(pem)
            temp_path = handle.name
        decoded = ssl_private._test_decode_cert(temp_path)
    except OSError as exc:
        raise TLSCertificateError(str(exc)) from exc
    finally:
        if temp_path is not None:
            os.unlink(temp_path)

    if not isinstance(decoded, dict):
        msg = "decoded certificate payload was not a dictionary"
        raise TLSCertificateError(msg)
    return decoded


def _https_endpoints(service: Service) -> list[Endpoint]:
    """Return deterministic HTTPS endpoints for one service."""
    return [
        endpoint
        for endpoint in sorted(service.endpoints, key=lambda endpoint: endpoint.name)
        if endpoint.protocol == EndpointProtocol.HTTPS
    ]


def _endpoint_host_port(endpoint: Endpoint) -> tuple[str, int]:
    """Return the host and port for one HTTPS endpoint."""
    if endpoint.url is not None:
        parsed = parse.urlparse(endpoint.url)
        if parsed.hostname is None:
            msg = f"endpoint {endpoint.name} URL did not include a hostname"
            raise TLSCertificateError(msg)
        return parsed.hostname, parsed.port or 443

    if endpoint.host is None:
        msg = f"endpoint {endpoint.name} did not define a host"
        raise TLSCertificateError(msg)
    if endpoint.port is None:
        return endpoint.host, 443
    return endpoint.host, endpoint.port


def _certificate_expiry_finding(
    *,
    service: Service,
    endpoint: Endpoint,
    certificate: TLSCertificateInfo,
    now: datetime,
    check_id: str,
    warning_days: int,
    critical_days: int,
) -> Finding | None:
    """Return a finding for an expired or near-expiry certificate."""
    remaining_seconds = (certificate.not_valid_after - now).total_seconds()
    days_remaining = remaining_seconds / 86400
    if remaining_seconds < 0:
        title = f"{service.name} certificate has expired"
        summary = (
            f"TLS certificate for {certificate.host}:{certificate.port} expired on "
            f"{certificate.not_valid_after.isoformat()}."
        )
        impact = "Clients may reject the service until a valid certificate is installed."
        severity = Severity.CRITICAL
    elif days_remaining <= critical_days:
        title = f"{service.name} certificate is near expiry"
        summary = (
            f"TLS certificate for {certificate.host}:{certificate.port} expires in "
            f"{days_remaining:.1f} days."
        )
        impact = "Certificate expiry is imminent and service access may soon fail."
        severity = Severity.CRITICAL
    elif days_remaining <= warning_days:
        title = f"{service.name} certificate expires soon"
        summary = (
            f"TLS certificate for {certificate.host}:{certificate.port} expires in "
            f"{days_remaining:.1f} days."
        )
        impact = "Certificate renewal should be scheduled before clients begin rejecting it."
        severity = Severity.HIGH
    else:
        return None

    return build_finding(
        check_id=check_id,
        service=service,
        title=title,
        severity=severity,
        summary=summary,
        impact=impact,
        evidence=[
            _certificate_evidence(
                endpoint=endpoint,
                certificate=certificate,
                now=now,
                days_remaining=days_remaining,
                warning_days=warning_days,
                critical_days=critical_days,
            )
        ],
        now=now,
        confidence=0.97,
    )


def _certificate_fetch_failure(
    *,
    service: Service,
    endpoint: Endpoint,
    host: str,
    port: int,
    error_message: str,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding when certificate retrieval fails."""
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} certificate could not be inspected",
        severity=Severity.HIGH,
        summary=f"TLS certificate retrieval for {host}:{port} failed: {error_message}.",
        impact="TLS health could not be verified and secure clients may be affected.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="tls_cert",
                summary=f"{endpoint.name} certificate retrieval failed",
                observed_at=now,
                data={
                    "endpoint_name": endpoint.name,
                    "host": host,
                    "port": port,
                    "protocol": endpoint.protocol.value,
                    "error": error_message,
                },
            )
        ],
        now=now,
        confidence=0.9,
    )


def _certificate_evidence(
    *,
    endpoint: Endpoint,
    certificate: TLSCertificateInfo,
    now: datetime,
    days_remaining: float,
    warning_days: int,
    critical_days: int,
) -> Evidence:
    """Build the structured evidence payload for a certificate finding."""
    return Evidence(
        kind=EvidenceKind.PROBE,
        source="tls_cert",
        summary=(
            f"{endpoint.name} certificate expires at "
            f"{certificate.not_valid_after.isoformat()}"
        ),
        observed_at=now,
        data={
            "endpoint_name": endpoint.name,
            "host": certificate.host,
            "port": certificate.port,
            "subject_common_name": certificate.subject_common_name,
            "issuer_common_name": certificate.issuer_common_name,
            "not_valid_after": certificate.not_valid_after.isoformat(),
            "days_remaining": round(days_remaining, 3),
            "warning_days": warning_days,
            "critical_days": critical_days,
        },
    )


def _distinguished_name_value(raw_name: object, field: str) -> str | None:
    """Extract one field from the ssl module's distinguished-name structure."""
    if not isinstance(raw_name, tuple):
        return None
    for relative_distinguished_name in raw_name:
        if not isinstance(relative_distinguished_name, tuple):
            continue
        for attribute in relative_distinguished_name:
            if (
                isinstance(attribute, tuple)
                and len(attribute) == 2
                and attribute[0] == field
                and isinstance(attribute[1], str)
            ):
                return attribute[1]
    return None


def _string_value(value: object) -> str | None:
    """Return a string value from an untyped ssl decode payload."""
    if isinstance(value, str):
        return value
    return None
