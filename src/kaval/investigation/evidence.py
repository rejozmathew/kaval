"""Tier 1 evidence collection for incident investigations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable, Iterable, Sequence, cast

from kaval.discovery.descriptors import LoadedServiceDescriptor
from kaval.discovery.docker import (
    DockerContainerSnapshot,
    DockerDiscoverySnapshot,
    DockerTransportError,
)
from kaval.models import (
    Change,
    EvidenceStep,
    Finding,
    Incident,
    JournalEntry,
    JsonValue,
    OperationalMemoryResult,
    RedactionLevel,
    Service,
    SystemProfile,
    UserNote,
)

type LogReader = Callable[[str, int], str]

_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|token|secret)\b(\s*[:=]\s*)(\S+)"
)
_AUTH_HEADER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIAL_RE = re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<creds>[^/\s:@]+:[^/\s@]+)@")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
_SHARE_PATH_RE = re.compile(r"/mnt/(?:user|cache)/[^\s'\"`]+")
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class InvestigationEvidenceResult:
    """Collected Tier 1 evidence and operational-memory context for one incident."""

    evidence_steps: list[EvidenceStep]
    operational_memory: OperationalMemoryResult


def collect_incident_evidence(
    *,
    incident: Incident,
    findings: Sequence[Finding],
    services: Sequence[Service],
    changes: Sequence[Change],
    docker_snapshot: DockerDiscoverySnapshot | None = None,
    system_profile: SystemProfile | None = None,
    journal_entries: Sequence[JournalEntry] = (),
    user_notes: Sequence[UserNote] = (),
    descriptors: Iterable[LoadedServiceDescriptor] = (),
    log_reader: LogReader | None = None,
    log_tail_lines: int = 200,
    redaction_level: RedactionLevel = RedactionLevel.REDACT_FOR_LOCAL,
    now: datetime | None = None,
) -> InvestigationEvidenceResult:
    """Collect ordered, structured Tier 1 evidence for one incident."""
    if log_tail_lines <= 0:
        msg = "log_tail_lines must be positive"
        raise ValueError(msg)

    effective_now = now or datetime.now(tz=UTC)
    services_by_id = {service.id: service for service in services}
    relevant_findings = _incident_findings(incident, findings)
    relevant_services = _ordered_services(
        incident=incident,
        findings=relevant_findings,
        services=services_by_id,
    )
    relevant_changes = _relevant_changes(incident, changes)
    descriptor_map = _descriptor_map(descriptors)
    container_map = _container_map(docker_snapshot)
    operational_memory = query_operational_memory(
        incident=incident,
        journal_entries=journal_entries,
        user_notes=user_notes,
        system_profile=system_profile,
        redaction_level=redaction_level,
    )

    steps: list[EvidenceStep] = []
    steps.append(
        _build_step(
            order=len(steps) + 1,
            action="summarize_incident_findings",
            target=incident.id,
            result_summary=_finding_summary(incident, relevant_findings, relevant_services),
            result_data={
                "incident_id": incident.id,
                "finding_ids": [finding.id for finding in relevant_findings],
                "service_ids": [service.id for service in relevant_services],
                "findings": [
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "service_id": finding.service_id,
                        "summary": finding.summary,
                        "related_change_ids": [change.id for change in finding.related_changes],
                        "evidence": [
                            evidence.model_dump(mode="json")
                            for evidence in finding.evidence
                        ],
                    }
                    for finding in relevant_findings
                ],
            },
            timestamp=effective_now,
        )
    )

    for service in relevant_services:
        related_findings = [
            finding
            for finding in relevant_findings
            if finding.service_id == service.id
        ]
        steps.append(
            _service_state_step(
                order=len(steps) + 1,
                service=service,
                related_findings=related_findings,
                descriptor=descriptor_map.get(service.descriptor_id),
                container=container_map.get(service.container_id),
                timestamp=effective_now,
            )
        )

    for service in relevant_services:
        log_step = _service_log_step(
            order=len(steps) + 1,
            service=service,
            descriptor=descriptor_map.get(service.descriptor_id),
            log_reader=log_reader,
            log_tail_lines=log_tail_lines,
            redaction_level=redaction_level,
            timestamp=effective_now,
        )
        if log_step is not None:
            steps.append(log_step)

    steps.append(
        _dependency_context_step(
            order=len(steps) + 1,
            incident=incident,
            services=relevant_services,
            services_by_id=services_by_id,
            timestamp=effective_now,
        )
    )
    steps.append(
        _change_correlation_step(
            order=len(steps) + 1,
            incident=incident,
            changes=relevant_changes,
            services_by_id=services_by_id,
            timestamp=effective_now,
        )
    )
    steps.append(
        _operational_memory_step(
            order=len(steps) + 1,
            incident=incident,
            operational_memory=operational_memory,
            timestamp=effective_now,
        )
    )
    return InvestigationEvidenceResult(
        evidence_steps=steps,
        operational_memory=operational_memory,
    )


def query_operational_memory(
    *,
    incident: Incident,
    journal_entries: Sequence[JournalEntry],
    user_notes: Sequence[UserNote],
    system_profile: SystemProfile | None,
    redaction_level: RedactionLevel = RedactionLevel.REDACT_FOR_LOCAL,
) -> OperationalMemoryResult:
    """Filter and redact Operational Memory context relevant to an incident."""
    affected_service_ids = set(incident.affected_services)
    warnings: list[str] = []

    relevant_journal_entries: list[JournalEntry] = []
    skipped_superseded = 0
    for entry in sorted(journal_entries, key=lambda item: (item.date, item.id), reverse=True):
        if entry.superseded_by is not None:
            skipped_superseded += 1
            continue
        if not affected_service_ids.isdisjoint(entry.services) or entry.incident_id == incident.id:
            relevant_journal_entries.append(
                _redacted_journal_entry(entry, redaction_level=redaction_level)
            )

    if skipped_superseded:
        warnings.append(
            f"Excluded {skipped_superseded} superseded journal entr"
            f"{'y' if skipped_superseded == 1 else 'ies'} from model context."
        )

    relevant_user_notes: list[UserNote] = []
    skipped_unsafe_notes = 0
    for note in sorted(user_notes, key=lambda item: (item.updated_at, item.id), reverse=True):
        if note.service_id is not None and note.service_id not in affected_service_ids:
            continue
        if not note.safe_for_model:
            skipped_unsafe_notes += 1
            continue
        relevant_user_notes.append(_redacted_user_note(note, redaction_level=redaction_level))

    if skipped_unsafe_notes:
        warnings.append(
            f"Excluded {skipped_unsafe_notes} unsafe user note"
            f"{'' if skipped_unsafe_notes == 1 else 's'} from model context."
        )

    return OperationalMemoryResult(
        system_profile=system_profile,
        journal_entries=relevant_journal_entries,
        user_notes=relevant_user_notes,
        recurrence_count=_recurrence_count(incident, relevant_journal_entries),
        applied_redaction_level=redaction_level,
        warnings=warnings,
    )


def redact_sensitive_text(text: str, *, redaction_level: RedactionLevel) -> str:
    """Redact common secret-like patterns before prompt or notification use."""
    redacted = _KEY_VALUE_SECRET_RE.sub(r"\1\2[REDACTED]", text)
    redacted = _AUTH_HEADER_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", redacted)
    redacted = _URL_CREDENTIAL_RE.sub(r"\g<scheme>[REDACTED]@", redacted)

    if redaction_level == RedactionLevel.REDACT_FOR_CLOUD:
        redacted = _PRIVATE_IP_RE.sub("[REDACTED_IP]", redacted)
        redacted = _SHARE_PATH_RE.sub("[REDACTED_PATH]", redacted)

    return redacted


def _incident_findings(incident: Incident, findings: Sequence[Finding]) -> list[Finding]:
    """Return the findings directly attached to the incident."""
    incident_finding_ids = set(incident.all_findings) | set(incident.trigger_findings)
    relevant = [
        finding
        for finding in findings
        if finding.id in incident_finding_ids or finding.incident_id == incident.id
    ]
    relevant.sort(key=lambda finding: (finding.created_at, finding.id))
    return relevant


def _ordered_services(
    *,
    incident: Incident,
    findings: Sequence[Finding],
    services: dict[str, Service],
) -> list[Service]:
    """Return affected services in a stable, root-cause-aware order."""
    seen_ids: list[str] = []
    if incident.root_cause_service is not None and incident.root_cause_service in services:
        seen_ids.append(incident.root_cause_service)

    for service_id in incident.affected_services:
        if service_id in services and service_id not in seen_ids:
            seen_ids.append(service_id)

    for finding in findings:
        if finding.service_id in services and finding.service_id not in seen_ids:
            seen_ids.append(finding.service_id)

    return [services[service_id] for service_id in seen_ids if service_id in services]


def _relevant_changes(incident: Incident, changes: Sequence[Change]) -> list[Change]:
    """Return tracked changes correlated to the incident or its timing window."""
    correlated_change_ids = set(incident.changes_correlated)
    if correlated_change_ids:
        relevant = [change for change in changes if change.id in correlated_change_ids]
    else:
        lookback_start = incident.grouping_window_start - timedelta(hours=6)
        relevant = [
            change
            for change in changes
            if change.service_id in set(incident.affected_services)
            and lookback_start <= change.timestamp <= incident.grouping_window_end
        ]
    relevant.sort(key=lambda change: (change.timestamp, change.id))
    return relevant


def _descriptor_map(
    descriptors: Iterable[LoadedServiceDescriptor],
) -> dict[str | None, LoadedServiceDescriptor]:
    """Index descriptors by the stable identifier stored on Service records."""
    mapping: dict[str | None, LoadedServiceDescriptor] = {}
    for descriptor in descriptors:
        mapping[f"{descriptor.path.parent.name}/{descriptor.path.stem}"] = descriptor
    return mapping


def _container_map(
    docker_snapshot: DockerDiscoverySnapshot | None,
) -> dict[str | None, DockerContainerSnapshot]:
    """Index Docker container snapshots by identifier."""
    if docker_snapshot is None:
        return {}
    return {container.id: container for container in docker_snapshot.containers}


def _finding_summary(
    incident: Incident,
    findings: Sequence[Finding],
    services: Sequence[Service],
) -> str:
    """Build the headline summary for one incident evidence pass."""
    if not findings:
        return f"No findings were attached to incident {incident.id} at collection time."

    service_names = ", ".join(service.name for service in services) or "unknown services"
    return (
        f"Collected {len(findings)} finding(s) across {len(services)} affected service(s): "
        f"{service_names}."
    )


def _service_state_step(
    *,
    order: int,
    service: Service,
    related_findings: Sequence[Finding],
    descriptor: LoadedServiceDescriptor | None,
    container: DockerContainerSnapshot | None,
    timestamp: datetime,
) -> EvidenceStep:
    """Build the structured service-state evidence step for one affected service."""
    data: dict[str, object] = {
        "service_id": service.id,
        "service_name": service.name,
        "service_status": service.status.value,
        "service_type": service.type.value,
        "descriptor_id": service.descriptor_id,
        "image": service.image,
        "dependencies": [dependency.model_dump(mode="json") for dependency in service.dependencies],
        "dependents": list(service.dependents),
        "related_finding_ids": [finding.id for finding in related_findings],
    }

    summary_parts = [f"{service.name} is currently {service.status.value}"]
    if container is not None:
        data["container"] = {
            "container_id": container.id,
            "state": container.state.status,
            "running": container.state.running,
            "health_status": (
                container.state.health.status
                if container.state.health is not None
                else None
            ),
            "restart_count": container.restart_count,
            "env_names": list(container.env_names),
            "networks": [network.model_dump(mode="json") for network in container.networks],
            "mounts": [
                {
                    "type": mount.type,
                    "source": mount.source,
                    "destination": mount.destination,
                    "read_only": mount.read_only,
                }
                for mount in container.mounts
            ],
        }
        summary_parts.append(
            f"container state={container.state.status or 'unknown'}, "
            f"restarts={container.restart_count}"
        )
        if container.state.health is not None and container.state.health.status is not None:
            summary_parts.append(f"health={container.state.health.status}")

    if descriptor is not None:
        failure_modes = [
            failure_mode.model_dump(mode="json")
            for failure_mode in descriptor.descriptor.common_failure_modes
        ]
        if descriptor.descriptor.investigation_context is not None:
            data["investigation_context"] = _normalize_whitespace(
                descriptor.descriptor.investigation_context
            )
            summary_parts.append("descriptor context available")
        if failure_modes:
            data["common_failure_modes"] = failure_modes

    if related_findings:
        data["related_findings"] = [
            {
                "id": finding.id,
                "title": finding.title,
                "summary": finding.summary,
                "severity": finding.severity.value,
            }
            for finding in related_findings
        ]

    return _build_step(
        order=order,
        action="inspect_service_state",
        target=service.id,
        result_summary="; ".join(summary_parts) + ".",
        result_data=data,
        timestamp=timestamp,
    )


def _service_log_step(
    *,
    order: int,
    service: Service,
    descriptor: LoadedServiceDescriptor | None,
    log_reader: LogReader | None,
    log_tail_lines: int,
    redaction_level: RedactionLevel,
    timestamp: datetime,
) -> EvidenceStep | None:
    """Build a structured log-read evidence step when the service is container-backed."""
    if service.container_id is None:
        return None
    if log_reader is None:
        return _build_step(
            order=order,
            action="read_container_logs",
            target=service.id,
            result_summary=f"Skipped log collection for {service.name}: no log reader configured.",
            result_data={
                "service_id": service.id,
                "container_id": service.container_id,
                "skipped": True,
                "reason": "no_log_reader_configured",
            },
            timestamp=timestamp,
        )

    try:
        raw_logs = log_reader(service.container_id, log_tail_lines)
    except DockerTransportError as exc:
        return _build_step(
            order=order,
            action="read_container_logs",
            target=service.id,
            result_summary=f"Unable to read recent logs for {service.name}: {exc}.",
            result_data={
                "service_id": service.id,
                "container_id": service.container_id,
                "error": str(exc),
            },
            timestamp=timestamp,
        )

    redacted_lines = [
        redact_sensitive_text(line, redaction_level=redaction_level)
        for line in raw_logs.splitlines()
        if line.strip()
    ]
    excerpt_lines = redacted_lines[-min(20, len(redacted_lines)) :]
    matched_patterns = _matched_log_patterns(descriptor, "\n".join(redacted_lines))
    summary = (
        f"Captured {len(excerpt_lines)} recent log line(s) for {service.name}"
        if excerpt_lines
        else f"No recent log lines captured for {service.name}"
    )
    if matched_patterns:
        summary += f"; matched descriptor signal(s): {', '.join(matched_patterns)}"
    summary += "."

    return _build_step(
        order=order,
        action="read_container_logs",
        target=service.id,
        result_summary=summary,
        result_data={
            "service_id": service.id,
            "container_id": service.container_id,
            "tail_lines_requested": log_tail_lines,
            "captured_line_count": len(redacted_lines),
            "matched_patterns": matched_patterns,
            "excerpt_lines": excerpt_lines,
        },
        timestamp=timestamp,
    )


def _dependency_context_step(
    *,
    order: int,
    incident: Incident,
    services: Sequence[Service],
    services_by_id: dict[str, Service],
    timestamp: datetime,
) -> EvidenceStep:
    """Build the dependency-walk evidence step for the affected services."""
    affected_service_ids = {service.id for service in services}
    edges: list[dict[str, object]] = []
    impacted_by_root: list[str] = []
    for service in services:
        for dependency in service.dependencies:
            if dependency.target_service_id not in affected_service_ids:
                continue
            target_service = services_by_id[dependency.target_service_id]
            edge_record: dict[str, object] = {
                "source_service_id": service.id,
                "source_service_name": service.name,
                "target_service_id": target_service.id,
                "target_service_name": target_service.name,
                "confidence": dependency.confidence.value,
                "source": dependency.source.value,
                "description": dependency.description,
                "target_status": target_service.status.value,
            }
            edges.append(edge_record)
            if dependency.target_service_id == incident.root_cause_service:
                impacted_by_root.append(service.name)

    edges.sort(key=lambda edge: (str(edge["source_service_id"]), str(edge["target_service_id"])))
    if incident.root_cause_service is not None and impacted_by_root:
        root_name = services_by_id[incident.root_cause_service].name
        summary = (
            f"Dependency walk shows {root_name} upstream of {len(impacted_by_root)} "
            f"affected service(s): {', '.join(sorted(impacted_by_root))}."
        )
    elif edges:
        summary = f"Dependency walk found {len(edges)} affected-service edge(s) to review."
    else:
        summary = "Dependency walk found no direct dependency edges among the affected services."

    return _build_step(
        order=order,
        action="inspect_dependency_graph",
        target=incident.id,
        result_summary=summary,
        result_data={
            "incident_id": incident.id,
            "affected_service_ids": sorted(affected_service_ids),
            "edges": edges,
        },
        timestamp=timestamp,
    )


def _change_correlation_step(
    *,
    order: int,
    incident: Incident,
    changes: Sequence[Change],
    services_by_id: dict[str, Service],
    timestamp: datetime,
) -> EvidenceStep:
    """Build the change-timeline correlation evidence step."""
    change_records = [
        {
            "id": change.id,
            "type": change.type.value,
            "service_id": change.service_id,
            "service_name": (
                services_by_id[change.service_id].name
                if change.service_id is not None and change.service_id in services_by_id
                else None
            ),
            "description": change.description,
            "old_value": change.old_value,
            "new_value": change.new_value,
            "timestamp": change.timestamp.isoformat(),
        }
        for change in changes
    ]
    if change_records:
        summary = (
            f"Change correlation found {len(change_records)} tracked change(s) "
            f"touching the incident window."
        )
    else:
        summary = "No tracked change events correlated to this incident."

    return _build_step(
        order=order,
        action="correlate_change_timeline",
        target=incident.id,
        result_summary=summary,
        result_data={
            "incident_id": incident.id,
            "change_ids": [change["id"] for change in change_records],
            "changes": change_records,
        },
        timestamp=timestamp,
    )


def _operational_memory_step(
    *,
    order: int,
    incident: Incident,
    operational_memory: OperationalMemoryResult,
    timestamp: datetime,
) -> EvidenceStep:
    """Build the operational-memory evidence step."""
    summary_parts = []
    if operational_memory.system_profile is not None:
        summary_parts.append("system profile available")
    if operational_memory.journal_entries:
        summary_parts.append(
            f"{len(operational_memory.journal_entries)} journal entr"
            f"{'y' if len(operational_memory.journal_entries) == 1 else 'ies'} referenced"
        )
    if operational_memory.user_notes:
        summary_parts.append(
            f"{len(operational_memory.user_notes)} user note"
            f"{'' if len(operational_memory.user_notes) == 1 else 's'} referenced"
        )
    summary_parts.append(f"recurrence_count={operational_memory.recurrence_count}")
    if operational_memory.warnings:
        summary_parts.append(
            f"{len(operational_memory.warnings)} warning"
            f"{'' if len(operational_memory.warnings) == 1 else 's'}"
        )

    return _build_step(
        order=order,
        action="query_operational_memory",
        target=incident.id,
        result_summary="Operational Memory query: " + "; ".join(summary_parts) + ".",
        result_data=operational_memory.model_dump(mode="json"),
        timestamp=timestamp,
    )


def _build_step(
    *,
    order: int,
    action: str,
    target: str,
    result_summary: str,
    result_data: object,
    timestamp: datetime,
) -> EvidenceStep:
    """Build one ordered evidence step."""
    return EvidenceStep(
        order=order,
        action=action,
        target=target,
        result_summary=result_summary,
        result_data=cast(JsonValue, result_data),
        timestamp=timestamp,
    )


def _redacted_journal_entry(
    entry: JournalEntry,
    *,
    redaction_level: RedactionLevel,
) -> JournalEntry:
    """Return a redacted journal entry safe for prompt context."""
    return entry.model_copy(
        update={
            "summary": redact_sensitive_text(entry.summary, redaction_level=redaction_level),
            "root_cause": redact_sensitive_text(entry.root_cause, redaction_level=redaction_level),
            "resolution": redact_sensitive_text(entry.resolution, redaction_level=redaction_level),
            "lesson": redact_sensitive_text(entry.lesson, redaction_level=redaction_level),
        }
    )


def _redacted_user_note(
    note: UserNote,
    *,
    redaction_level: RedactionLevel,
) -> UserNote:
    """Return a redacted user note safe for prompt context."""
    return note.model_copy(
        update={"note": redact_sensitive_text(note.note, redaction_level=redaction_level)}
    )


def _recurrence_count(
    incident: Incident,
    journal_entries: Sequence[JournalEntry],
) -> int:
    """Estimate recurrence count from prior journal entries touching the same services."""
    if not journal_entries:
        return 0
    if incident.root_cause_service is not None:
        root_cause_matches = sum(
            1 for entry in journal_entries if incident.root_cause_service in entry.services
        )
        if root_cause_matches:
            return root_cause_matches
    affected_service_ids = set(incident.affected_services)
    return sum(
        1
        for entry in journal_entries
        if not affected_service_ids.isdisjoint(entry.services)
    )


def _matched_log_patterns(
    descriptor: LoadedServiceDescriptor | None,
    logs: str,
) -> list[str]:
    """Return descriptor log patterns that appear in the collected log text."""
    if descriptor is None:
        return []
    patterns = [
        *descriptor.descriptor.log_signals.errors,
        *descriptor.descriptor.log_signals.warnings,
    ]
    matched: list[str] = []
    for pattern in patterns:
        try:
            found = re.search(pattern, logs, flags=re.IGNORECASE) is not None
        except re.error:
            found = re.search(re.escape(pattern), logs, flags=re.IGNORECASE) is not None
        if found:
            matched.append(pattern)
    return matched


def _normalize_whitespace(value: str) -> str:
    """Collapse multiline descriptor context into one stable sentence."""
    return _WHITESPACE_RE.sub(" ", value).strip()
