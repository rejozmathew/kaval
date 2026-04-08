"""Deterministic container log pattern monitoring."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable

from kaval.discovery.descriptors import (
    DescriptorLogSignals,
    LoadedServiceDescriptor,
    loaded_descriptor_identifier,
)
from kaval.discovery.docker import DockerTransportError
from kaval.models import Evidence, EvidenceKind, Finding, Service, ServiceType, Severity
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding

type LogReader = Callable[[str, int], str]


@dataclass(frozen=True, slots=True)
class MatchedLogPattern:
    """One descriptor-defined log pattern matched against recent log lines."""

    pattern: str
    line: str


class LogPatternCheck(MonitoringCheck):
    """Scan recent container logs for descriptor-defined error and warning patterns."""

    def __init__(
        self,
        descriptors: Iterable[LoadedServiceDescriptor],
        *,
        interval_seconds: int = 300,
        tail_lines: int = 200,
        log_reader: LogReader,
    ) -> None:
        """Store the check identity, descriptor catalog, and log reader."""
        if tail_lines <= 0:
            msg = "tail_lines must be positive"
            raise ValueError(msg)

        self.check_id = "log_pattern"
        self.interval_seconds = interval_seconds
        self._tail_lines = tail_lines
        self._log_reader = log_reader
        self._signals_by_descriptor_id = {
            _descriptor_id(item): item.descriptor.log_signals
            for item in descriptors
            if item.descriptor.log_signals.errors or item.descriptor.log_signals.warnings
        }

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate recent container logs against shipped descriptor patterns."""
        if context.docker_snapshot is None:
            return []

        active_container_ids = {
            container.id for container in context.docker_snapshot.containers
        }
        findings: list[Finding] = []
        for service in sorted(context.services, key=lambda service: service.id):
            if (
                service.type != ServiceType.CONTAINER
                or service.container_id is None
                or service.descriptor_id is None
                or service.container_id not in active_container_ids
            ):
                continue

            log_signals = self._signals_by_descriptor_id.get(service.descriptor_id)
            if log_signals is None:
                continue

            try:
                logs = self._log_reader(service.container_id, self._tail_lines)
            except DockerTransportError:
                continue

            findings.extend(
                _findings_for_service(
                    service=service,
                    log_signals=log_signals,
                    logs=logs,
                    tail_lines=self._tail_lines,
                    now=context.now,
                    check_id=self.check_id,
                )
            )
        return findings


def _findings_for_service(
    *,
    service: Service,
    log_signals: DescriptorLogSignals,
    logs: str,
    tail_lines: int,
    now: datetime,
    check_id: str,
) -> list[Finding]:
    """Build findings for any descriptor log patterns matched in recent logs."""
    findings: list[Finding] = []
    error_matches = _matched_patterns(log_signals.errors, logs)
    warning_matches = _matched_patterns(log_signals.warnings, logs)

    if error_matches:
        findings.append(
            build_finding(
                check_id=check_id,
                service=service,
                title=f"{service.name} logs match known error patterns",
                severity=Severity.HIGH,
                summary=_summary_text(service.name, "error", error_matches),
                impact="The service is emitting known error signals and may be degraded.",
                evidence=[
                    _log_evidence(
                        service=service,
                        matches=error_matches,
                        tail_lines=tail_lines,
                        now=now,
                        category="error",
                    )
                ],
                now=now,
                confidence=0.95,
            )
        )

    if warning_matches:
        findings.append(
            build_finding(
                check_id=check_id,
                service=service,
                title=f"{service.name} logs match warning patterns",
                severity=Severity.MEDIUM,
                summary=_summary_text(service.name, "warning", warning_matches),
                impact=(
                    "The service is emitting warning signals that may precede "
                    "user-visible failure."
                ),
                evidence=[
                    _log_evidence(
                        service=service,
                        matches=warning_matches,
                        tail_lines=tail_lines,
                        now=now,
                        category="warning",
                    )
                ],
                now=now,
                confidence=0.9,
            )
        )

    return findings


def _matched_patterns(patterns: list[str], logs: str) -> list[MatchedLogPattern]:
    """Return the first matched log line for each configured pattern."""
    lines = logs.splitlines()
    matches: list[MatchedLogPattern] = []
    for pattern in patterns:
        for line in lines:
            if _pattern_matches_line(pattern, line):
                matches.append(MatchedLogPattern(pattern=pattern, line=line))
                break
    return matches


def _pattern_matches_line(pattern: str, line: str) -> bool:
    """Return whether one log line matches the configured descriptor pattern."""
    try:
        return re.search(pattern, line, flags=re.IGNORECASE) is not None
    except re.error:
        return re.search(re.escape(pattern), line, flags=re.IGNORECASE) is not None


def _summary_text(
    service_name: str,
    category: str,
    matches: list[MatchedLogPattern],
) -> str:
    """Build a concise summary of matched descriptor patterns."""
    joined_patterns = ", ".join(match.pattern for match in matches)
    return (
        f"Recent logs for {service_name} matched descriptor {category} pattern(s): "
        f"{joined_patterns}."
    )


def _log_evidence(
    *,
    service: Service,
    matches: list[MatchedLogPattern],
    tail_lines: int,
    now: datetime,
    category: str,
) -> Evidence:
    """Build the structured log evidence payload for one matched category."""
    return Evidence(
        kind=EvidenceKind.LOG,
        source="docker_logs",
        summary=f"{service.name} produced {len(matches)} matched {category} log pattern(s)",
        observed_at=now,
        data={
            "container_id": service.container_id,
            "category": category,
            "tail_lines": tail_lines,
            "matched_patterns": [match.pattern for match in matches],
            "matched_lines": [match.line for match in matches],
        },
    )


def _descriptor_id(descriptor: LoadedServiceDescriptor) -> str:
    """Return the stable descriptor identifier used on Service records."""
    return loaded_descriptor_identifier(descriptor)
