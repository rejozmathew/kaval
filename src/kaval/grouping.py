"""Finding-to-incident grouping and lifecycle transition logic."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable, Mapping

from kaval.models import (
    INCIDENT_STATUS_TRANSITIONS,
    Finding,
    Incident,
    IncidentGroupingRule,
    IncidentStatus,
    Service,
)


@dataclass(frozen=True, slots=True)
class FindingGroup:
    """A group of findings that should map to the same incident."""

    findings: tuple[Finding, ...]

    @property
    def window_start(self) -> datetime:
        """Return the earliest finding timestamp in the group."""
        return min(finding.created_at for finding in self.findings)

    @property
    def window_end(self) -> datetime:
        """Return the latest finding timestamp in the group."""
        return max(finding.created_at for finding in self.findings)

    @property
    def affected_services(self) -> tuple[str, ...]:
        """Return unique service identifiers in stable order."""
        services = sorted({finding.service_id for finding in self.findings})
        return tuple(services)


def build_service_map(services: Iterable[Service]) -> dict[str, Service]:
    """Return a service lookup keyed by service identifier."""
    return {service.id: service for service in services}


def upstream_services(service_id: str, service_map: Mapping[str, Service]) -> set[str]:
    """Return all upstream dependencies for the given service."""
    visited: set[str] = set()
    stack = [service_id]
    while stack:
        current = stack.pop()
        service = service_map.get(current)
        if service is None:
            continue
        for dependency in service.dependencies:
            target_id = dependency.target_service_id
            if target_id in visited:
                continue
            visited.add(target_id)
            stack.append(target_id)
    return visited


def common_upstream_services(
    service_a: str,
    service_b: str,
    service_map: Mapping[str, Service],
) -> set[str]:
    """Return shared upstream dependencies for two services."""
    return upstream_services(service_a, service_map) & upstream_services(service_b, service_map)


def in_same_dependency_chain(
    service_a: str,
    service_b: str,
    service_map: Mapping[str, Service],
) -> bool:
    """Return whether two services appear in the same dependency chain."""
    if service_a == service_b:
        return True
    upstream_a = upstream_services(service_a, service_map)
    upstream_b = upstream_services(service_b, service_map)
    return service_b in upstream_a or service_a in upstream_b


def are_related_services(
    service_a: str,
    service_b: str,
    service_map: Mapping[str, Service],
    rule: IncidentGroupingRule,
) -> bool:
    """Return whether two services satisfy the grouping graph rules."""
    if service_a == service_b:
        return True
    if rule.group_by_dependency_chain and in_same_dependency_chain(
        service_a,
        service_b,
        service_map,
    ):
        return True
    if rule.group_by_common_upstream and common_upstream_services(
        service_a,
        service_b,
        service_map,
    ):
        return True
    return False


def within_grouping_window(
    left: datetime,
    right: datetime,
    window_minutes: int,
) -> bool:
    """Return whether two timestamps fall within the grouping window."""
    return abs(left - right) <= timedelta(minutes=window_minutes)


def should_group_findings(
    left: Finding,
    right: Finding,
    service_map: Mapping[str, Service],
    rule: IncidentGroupingRule,
) -> bool:
    """Return whether two findings should be assigned to the same incident."""
    if not within_grouping_window(left.created_at, right.created_at, rule.window_minutes):
        return False
    return are_related_services(left.service_id, right.service_id, service_map, rule)


def group_findings(
    findings: Iterable[Finding],
    services: Iterable[Service],
    rule: IncidentGroupingRule | None = None,
) -> list[FindingGroup]:
    """Group related findings into incident-sized clusters."""
    active_rule = rule or IncidentGroupingRule()
    ordered_findings = sorted(findings, key=lambda finding: (finding.created_at, finding.id))
    if not ordered_findings:
        return []

    service_map = build_service_map(services)
    adjacency: dict[int, set[int]] = defaultdict(set)
    for left_index, left in enumerate(ordered_findings):
        for right_index in range(left_index + 1, len(ordered_findings)):
            right = ordered_findings[right_index]
            if should_group_findings(left, right, service_map, active_rule):
                adjacency[left_index].add(right_index)
                adjacency[right_index].add(left_index)

    visited: set[int] = set()
    groups: list[FindingGroup] = []
    for index in range(len(ordered_findings)):
        if index in visited:
            continue
        stack = [index]
        component: list[Finding] = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(ordered_findings[current])
            stack.extend(sorted(adjacency[current] - visited))

        component.sort(key=lambda finding: (finding.created_at, finding.id))
        groups.extend(_split_component_by_window(component, active_rule.window_minutes))
    return groups


def can_transition_incident_status(
    current_status: IncidentStatus,
    next_status: IncidentStatus,
) -> bool:
    """Return whether an incident may transition to the next status."""
    return next_status in INCIDENT_STATUS_TRANSITIONS[current_status]


def transition_incident(
    incident: Incident,
    next_status: IncidentStatus,
    *,
    changed_at: datetime | None = None,
) -> Incident:
    """Return a copy of an incident transitioned to the requested state."""
    if not can_transition_incident_status(incident.status, next_status):
        msg = f"invalid incident transition: {incident.status} -> {next_status}"
        raise ValueError(msg)

    effective_changed_at = changed_at or datetime.now(tz=UTC)
    updates: dict[str, object] = {
        "status": next_status,
        "updated_at": effective_changed_at,
    }
    if next_status == IncidentStatus.RESOLVED:
        updates["resolved_at"] = effective_changed_at
        updates["mttr_seconds"] = (effective_changed_at - incident.created_at).total_seconds()
    return incident.model_copy(update=updates)


def _split_component_by_window(
    findings: list[Finding],
    window_minutes: int,
) -> list[FindingGroup]:
    """Split a connected component into window-bounded groups."""
    if not findings:
        return []

    groups: list[FindingGroup] = []
    current_group: list[Finding] = [findings[0]]
    current_start = findings[0].created_at
    for finding in findings[1:]:
        if within_grouping_window(current_start, finding.created_at, window_minutes):
            current_group.append(finding)
            continue
        groups.append(FindingGroup(findings=tuple(current_group)))
        current_group = [finding]
        current_start = finding.created_at
    groups.append(FindingGroup(findings=tuple(current_group)))
    return groups
