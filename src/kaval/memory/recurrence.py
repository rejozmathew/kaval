"""Conservative recurrence detection for Operational Memory journal history."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from kaval.models import Incident, JournalConfidence, JournalEntry

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_GENERIC_TOKENS = {
    "the",
    "and",
    "for",
    "from",
    "with",
    "this",
    "that",
    "after",
    "before",
    "again",
    "issue",
    "service",
    "container",
    "resolved",
    "restart",
    "restarted",
    "restarting",
    "degraded",
    "failure",
    "failing",
    "failed",
    "error",
    "errors",
    "incident",
    "investigation",
    "download",
    "client",
    "unavailable",
}
_SHORT_TOKEN_ALLOWLIST = {"ip", "vm", "tls", "ssl", "dns", "sso", "vpn"}


@dataclass(frozen=True, slots=True)
class RecurrenceAnalysis:
    """Structured recurrence result derived from trusted Operational Memory history."""

    recurrence_count: int
    matched_entry_ids: tuple[str, ...]
    excluded_speculative_matches: int = 0


def detect_recurrences(
    *,
    incident: Incident,
    journal_entries: Sequence[JournalEntry],
) -> RecurrenceAnalysis:
    """Return conservative recurrence matches for the current incident."""
    service_exclusions = _service_tokens(incident)
    incident_tokens = _incident_signal_tokens(incident, service_exclusions=service_exclusions)
    matched_entry_ids: list[str] = []
    excluded_speculative_matches = 0

    for entry in journal_entries:
        if not _shares_service_scope(incident, entry):
            continue
        if not _entry_matches_incident(
            incident=incident,
            incident_tokens=incident_tokens,
            entry=entry,
            service_exclusions=service_exclusions,
        ):
            continue
        if entry.confidence is JournalConfidence.SPECULATIVE:
            excluded_speculative_matches += 1
            continue
        matched_entry_ids.append(entry.id)

    return RecurrenceAnalysis(
        recurrence_count=len(matched_entry_ids),
        matched_entry_ids=tuple(matched_entry_ids),
        excluded_speculative_matches=excluded_speculative_matches,
    )


def _entry_matches_incident(
    *,
    incident: Incident,
    incident_tokens: set[str],
    entry: JournalEntry,
    service_exclusions: set[str],
) -> bool:
    """Return whether one journal entry conservatively matches the incident pattern."""
    entry_tokens = _entry_signal_tokens(entry, service_exclusions=service_exclusions)
    overlap = incident_tokens & entry_tokens
    if incident.root_cause_service is not None and incident.root_cause_service in entry.services:
        return bool(overlap)
    if len(overlap) >= 2:
        return True
    return not incident_tokens


def _shares_service_scope(incident: Incident, entry: JournalEntry) -> bool:
    """Return whether a journal entry overlaps the incident's service scope."""
    if incident.root_cause_service is not None and incident.root_cause_service in entry.services:
        return True
    affected_services = set(incident.affected_services)
    return not affected_services.isdisjoint(entry.services)


def _incident_signal_tokens(
    incident: Incident,
    *,
    service_exclusions: set[str],
) -> set[str]:
    """Return normalized current-incident tokens used for recurrence matching."""
    return _meaningful_tokens(
        [
            incident.title,
            incident.triggering_symptom,
            incident.suspected_cause,
            incident.confirmed_cause,
        ],
        service_exclusions=service_exclusions,
    )


def _entry_signal_tokens(
    entry: JournalEntry,
    *,
    service_exclusions: set[str],
) -> set[str]:
    """Return normalized journal-entry tokens used for recurrence matching."""
    return _meaningful_tokens(
        [
            entry.summary,
            entry.root_cause,
            *entry.tags,
        ],
        service_exclusions=service_exclusions,
    )


def _meaningful_tokens(
    values: Sequence[str | None],
    *,
    service_exclusions: set[str],
) -> set[str]:
    """Extract normalized, non-generic tokens from free text."""
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in _TOKEN_RE.findall(value.casefold()):
            if token in _GENERIC_TOKENS or token in service_exclusions:
                continue
            if len(token) < 3 and token not in _SHORT_TOKEN_ALLOWLIST:
                continue
            tokens.add(token)
    return tokens


def _service_tokens(incident: Incident) -> set[str]:
    """Return normalized service-name tokens that should not drive recurrence matching."""
    tokens: set[str] = set()
    for service_id in incident.affected_services:
        for token in _TOKEN_RE.findall(service_id.casefold().removeprefix("svc-")):
            tokens.add(token)
    return tokens
