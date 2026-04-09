"""Deterministic DNS resolution monitoring check."""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from socket import AF_INET, AF_INET6, SOCK_STREAM, gaierror, getaddrinfo
from typing import Callable, cast

from kaval.models import (
    DnsRecordType,
    DnsTarget,
    Evidence,
    EvidenceKind,
    Finding,
    JsonValue,
    Service,
    Severity,
)
from kaval.monitoring.checks.base import (
    CheckContext,
    MonitoringCheck,
    build_finding,
    iter_target_services,
)

type DnsResolver = Callable[[str, DnsRecordType], list[str]]


class DnsResolutionError(RuntimeError):
    """Raised when a DNS target cannot be resolved."""


class DNSResolutionCheck(MonitoringCheck):
    """Validate explicitly declared DNS targets for discovered services."""

    def __init__(
        self,
        interval_seconds: int = 300,
        *,
        resolver: DnsResolver | None = None,
    ) -> None:
        """Store the check identity, schedule interval, and resolver function."""
        self.check_id = "dns_resolution"
        self.interval_seconds = interval_seconds
        self._resolver = resolver or resolve_dns_target

    def run(self, context: CheckContext) -> list[Finding]:
        """Resolve declared DNS targets and emit deterministic findings."""
        findings: list[Finding] = []
        for service in sorted(iter_target_services(context), key=lambda service: service.id):
            for dns_target in sorted(
                service.dns_targets,
                key=lambda dns_target: (dns_target.host, dns_target.record_type.value),
            ):
                try:
                    answers = self._resolver(dns_target.host, dns_target.record_type)
                except DnsResolutionError as exc:
                    findings.append(
                        _resolution_failure_finding(
                            service=service,
                            dns_target=dns_target,
                            now=context.now,
                            check_id=self.check_id,
                            error_message=str(exc),
                        )
                    )
                    continue

                if not answers:
                    findings.append(
                        _resolution_failure_finding(
                            service=service,
                            dns_target=dns_target,
                            now=context.now,
                            check_id=self.check_id,
                            error_message="no DNS answers returned",
                        )
                    )
                    continue

                if _matches_expected_answers(dns_target, answers):
                    continue
                findings.append(
                    _answer_mismatch_finding(
                        service=service,
                        dns_target=dns_target,
                        now=context.now,
                        check_id=self.check_id,
                        answers=answers,
                    )
                )
        return findings


def resolve_dns_target(host: str, record_type: DnsRecordType) -> list[str]:
    """Resolve one DNS target with the standard library."""
    family = _address_family(record_type)
    try:
        records = getaddrinfo(host, 0, family=family, type=SOCK_STREAM)
    except gaierror as exc:
        raise DnsResolutionError(str(exc)) from exc

    answers = sorted(
        {
            _normalize_dns_value(record_type, str(record[4][0]))
            for record in records
            if record[4]
        }
    )
    return answers


def _address_family(record_type: DnsRecordType) -> int:
    """Return the socket address family for a DNS record type."""
    if record_type == DnsRecordType.AAAA:
        return AF_INET6
    return AF_INET


def _matches_expected_answers(dns_target: DnsTarget, answers: list[str]) -> bool:
    """Return whether resolved answers satisfy the declared DNS expectation."""
    if not dns_target.expected_values:
        return True
    expected = {
        _normalize_dns_value(dns_target.record_type, value)
        for value in dns_target.expected_values
    }
    actual = {_normalize_dns_value(dns_target.record_type, value) for value in answers}
    return actual == expected


def _normalize_dns_value(record_type: DnsRecordType, value: str) -> str:
    """Normalize a DNS answer for deterministic comparison."""
    if record_type in {DnsRecordType.A, DnsRecordType.AAAA}:
        return str(ip_address(value))
    return value.rstrip(".").lower()


def _resolution_failure_finding(
    *,
    service: Service,
    dns_target: DnsTarget,
    now: datetime,
    check_id: str,
    error_message: str,
) -> Finding:
    """Build a finding for a DNS target that failed to resolve."""
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} DNS target failed to resolve",
        severity=Severity.HIGH,
        summary=(
            f"{dns_target.record_type.value} lookup for {dns_target.host} failed: "
            f"{error_message}."
        ),
        impact="Clients that depend on this DNS name may not be able to reach the service.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="dns_resolution",
                summary=(
                    f"{dns_target.record_type.value} lookup for {dns_target.host} "
                    f"failed"
                ),
                observed_at=now,
                data={
                    "host": dns_target.host,
                    "record_type": dns_target.record_type.value,
                    "expected_values": cast(
                        JsonValue,
                        list(dns_target.expected_values),
                    ),
                    "error": error_message,
                },
            )
        ],
        now=now,
        confidence=0.95,
    )


def _answer_mismatch_finding(
    *,
    service: Service,
    dns_target: DnsTarget,
    now: datetime,
    check_id: str,
    answers: list[str],
) -> Finding:
    """Build a finding for a DNS target whose answers differ from expectations."""
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} DNS target returned unexpected answers",
        severity=Severity.HIGH,
        summary=(
            f"{dns_target.record_type.value} lookup for {dns_target.host} returned "
            f"{', '.join(answers)}; expected {', '.join(dns_target.expected_values)}."
        ),
        impact="Clients may be routed to the wrong destination for this service.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="dns_resolution",
                summary=(
                    f"{dns_target.record_type.value} lookup for {dns_target.host} "
                    "returned unexpected answers"
                ),
                observed_at=now,
                data={
                    "host": dns_target.host,
                    "record_type": dns_target.record_type.value,
                    "expected_values": cast(
                        JsonValue,
                        list(dns_target.expected_values),
                    ),
                    "answers": cast(JsonValue, list(answers)),
                },
            )
        ],
        now=now,
        confidence=0.95,
    )
