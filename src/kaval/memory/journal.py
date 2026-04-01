"""Operational Memory journal writing and incident-resolution helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence
from uuid import uuid4

from kaval.database import KavalDatabase
from kaval.grouping import transition_incident
from kaval.memory.recurrence import detect_recurrences
from kaval.models import (
    CauseConfirmationSource,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    JournalConfidence,
    JournalEntry,
)

DEFAULT_JOURNAL_STALE_AFTER_DAYS = 180
_TAG_SANITIZE_RE = re.compile(r"[^a-z0-9]+")
_INACTIVE_FINDING_STATUSES = {
    FindingStatus.RESOLVED,
    FindingStatus.DISMISSED,
    FindingStatus.STALE,
}


class IncidentResolutionError(RuntimeError):
    """Base error for incident-resolution journal handling."""


class IncidentResolutionNotFoundError(IncidentResolutionError):
    """Raised when a required incident or investigation is missing."""


class IncidentResolutionConflictError(IncidentResolutionError):
    """Raised when a resolution request cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class IncidentResolutionResult:
    """Persisted outcome of resolving an incident and writing its journal entry."""

    incident: Incident
    investigation: Investigation
    journal_entry: JournalEntry
    findings: list[Finding]


@dataclass(slots=True)
class OperationalJournalService:
    """Resolve incidents and persist journal entries with trust metadata."""

    database: KavalDatabase
    default_stale_after_days: int = DEFAULT_JOURNAL_STALE_AFTER_DAYS

    def __post_init__(self) -> None:
        """Validate the configured stale-entry horizon."""
        if self.default_stale_after_days <= 0:
            msg = "default_stale_after_days must be positive"
            raise ValueError(msg)

    def resolve_incident(
        self,
        *,
        incident_id: str,
        resolution: str | None = None,
        lesson: str | None = None,
        cause_confirmation_source: CauseConfirmationSource = (
            CauseConfirmationSource.RESOLUTION_INFERRED
        ),
        confirmed_cause: str | None = None,
        applies_to_version: str | None = None,
        tags: Sequence[str] = (),
        now: datetime | None = None,
    ) -> IncidentResolutionResult:
        """Resolve one incident and auto-write its Operational Memory journal entry."""
        incident = self.database.get_incident(incident_id)
        if incident is None:
            msg = f"incident not found: {incident_id}"
            raise IncidentResolutionNotFoundError(msg)
        if incident.status == IncidentStatus.DISMISSED:
            msg = "dismissed incidents cannot be written to the operational journal"
            raise IncidentResolutionConflictError(msg)
        if incident.journal_entry_id is not None:
            msg = f"incident already has journal entry: {incident.journal_entry_id}"
            raise IncidentResolutionConflictError(msg)
        if incident.investigation_id is None:
            msg = "incident cannot be journaled without a completed investigation"
            raise IncidentResolutionConflictError(msg)

        investigation = self.database.get_investigation(incident.investigation_id)
        if investigation is None:
            msg = f"investigation not found: {incident.investigation_id}"
            raise IncidentResolutionNotFoundError(msg)
        if investigation.completed_at is None:
            msg = "investigation must be completed before incident resolution is journaled"
            raise IncidentResolutionConflictError(msg)

        effective_now = now or datetime.now(tz=UTC)
        resolved_at = incident.resolved_at or effective_now
        resolved_incident = _transition_to_resolved(incident, resolved_at=resolved_at)
        root_cause = _resolved_root_cause(
            incident=resolved_incident,
            investigation=investigation,
            confirmed_cause=confirmed_cause,
            cause_confirmation_source=cause_confirmation_source,
        )
        resolution_summary = resolution or _resolution_summary(
            incident=resolved_incident,
            investigation=investigation,
        )
        confidence = _journal_confidence(cause_confirmation_source)
        recurrence_count = _next_recurrence_count(
            incident=resolved_incident,
            journal_entries=self._list_journal_entries(),
        )
        journal_entry = JournalEntry(
            id=f"jrnl-{uuid4()}",
            incident_id=resolved_incident.id,
            date=resolved_at.date(),
            services=list(resolved_incident.affected_services),
            summary=_journal_summary(
                incident=resolved_incident,
                investigation=investigation,
                resolution_summary=resolution_summary,
            ),
            root_cause=root_cause,
            resolution=resolution_summary,
            time_to_resolution_minutes=max(
                0.0,
                (resolved_at - resolved_incident.created_at).total_seconds() / 60.0,
            ),
            model_used=investigation.model_used.value,
            tags=_journal_tags(resolved_incident, tags),
            lesson=lesson or _default_lesson(recurrence_count),
            recurrence_count=recurrence_count,
            confidence=confidence,
            user_confirmed=cause_confirmation_source is CauseConfirmationSource.USER_CONFIRMED,
            last_verified_at=(
                resolved_at
                if cause_confirmation_source is CauseConfirmationSource.USER_CONFIRMED
                else None
            ),
            applies_to_version=applies_to_version,
            superseded_by=None,
            stale_after_days=self.default_stale_after_days,
        )
        resolved_incident = resolved_incident.model_copy(
            update={
                "resolved_at": resolved_at,
                "mttr_seconds": max(
                    0.0,
                    (resolved_at - resolved_incident.created_at).total_seconds(),
                ),
                "resolution_mechanism": resolution_summary,
                "cause_confirmation_source": cause_confirmation_source,
                "confirmed_cause": (
                    root_cause
                    if cause_confirmation_source is CauseConfirmationSource.USER_CONFIRMED
                    else None
                ),
                "confidence": max(resolved_incident.confidence, investigation.confidence),
                "journal_entry_id": journal_entry.id,
                "updated_at": resolved_at,
            }
        )
        resolved_findings = _resolved_findings(
            self.database.list_findings(),
            incident_id=resolved_incident.id,
            resolved_at=resolved_at,
        )

        self.database.upsert_journal_entry(journal_entry)
        self.database.upsert_incident(resolved_incident)
        for finding in resolved_findings:
            self.database.upsert_finding(finding)

        return IncidentResolutionResult(
            incident=resolved_incident,
            investigation=investigation,
            journal_entry=journal_entry,
            findings=resolved_findings,
        )

    def _list_journal_entries(self) -> list[JournalEntry]:
        """Load existing journal entries from persistence for recurrence tracking."""
        rows = self.database.connection().execute(
            "SELECT payload FROM journal_entries ORDER BY entry_date, id"
        ).fetchall()
        return [JournalEntry.model_validate_json(str(row["payload"])) for row in rows]


def _resolved_root_cause(
    *,
    incident: Incident,
    investigation: Investigation,
    confirmed_cause: str | None,
    cause_confirmation_source: CauseConfirmationSource,
) -> str:
    """Return the resolved root-cause text to persist in the journal."""
    if (
        cause_confirmation_source is CauseConfirmationSource.USER_CONFIRMED
        and confirmed_cause is not None
    ):
        return confirmed_cause
    return (
        investigation.root_cause
        or incident.suspected_cause
        or incident.confirmed_cause
        or incident.triggering_symptom
        or incident.title
    )


def _resolution_summary(
    *,
    incident: Incident,
    investigation: Investigation,
) -> str:
    """Return a deterministic resolution summary when the caller does not supply one."""
    if incident.resolution_mechanism is not None:
        return incident.resolution_mechanism
    remediation = investigation.remediation
    if remediation is not None and remediation.action_type.value == "restart_container":
        return f"Restarted {remediation.target} container."
    if remediation is not None:
        return remediation.rationale
    return "Incident resolved after investigation follow-up."


def _journal_summary(
    *,
    incident: Incident,
    investigation: Investigation,
    resolution_summary: str,
) -> str:
    """Build the journal entry summary from the resolved incident context."""
    root_cause = investigation.root_cause or incident.suspected_cause or incident.title
    return f"{incident.title}: {root_cause}. {resolution_summary}"


def _journal_confidence(
    cause_confirmation_source: CauseConfirmationSource,
) -> JournalConfidence:
    """Map incident confirmation semantics into journal trust levels."""
    if cause_confirmation_source is CauseConfirmationSource.USER_CONFIRMED:
        return JournalConfidence.CONFIRMED
    if cause_confirmation_source in {
        CauseConfirmationSource.RESOLUTION_INFERRED,
        CauseConfirmationSource.RECURRENCE_PATTERN,
    }:
        return JournalConfidence.LIKELY
    return JournalConfidence.SPECULATIVE


def _journal_tags(incident: Incident, extra_tags: Sequence[str]) -> list[str]:
    """Build stable, lowercase journal tags from incident services and caller input."""
    tags: list[str] = []
    for service_id in incident.affected_services:
        tags.append(_sanitize_tag(service_id.removeprefix("svc-")))
    for raw_tag in extra_tags:
        tag = _sanitize_tag(raw_tag)
        if tag:
            tags.append(tag)
    if incident.root_cause_service is not None:
        tags.append(_sanitize_tag(incident.root_cause_service.removeprefix("svc-")))
    if incident.changes_correlated:
        tags.append("change-correlated")
    deduped: list[str] = []
    for tag in tags:
        if not tag or tag in deduped:
            continue
        deduped.append(tag)
    return deduped


def _sanitize_tag(value: str) -> str:
    """Normalize one tag value to the journal's lowercase slug format."""
    return _TAG_SANITIZE_RE.sub("-", value.casefold()).strip("-")


def _default_lesson(recurrence_count: int) -> str:
    """Return a conservative default lesson when the caller does not provide one."""
    if recurrence_count > 1:
        return "Recurring issue detected; consider a permanent preventative fix."
    return "Capture any server-specific prerequisites if this incident repeats."


def _next_recurrence_count(
    *,
    incident: Incident,
    journal_entries: Sequence[JournalEntry],
) -> int:
    """Return the next recurrence count for the incident's service scope."""
    prior_matches = detect_recurrences(
        incident=incident,
        journal_entries=[
            entry
            for entry in journal_entries
            if entry.superseded_by is None
        ],
    )
    return prior_matches.recurrence_count + 1


def _resolved_findings(
    findings: Sequence[Finding],
    *,
    incident_id: str,
    resolved_at: datetime,
) -> list[Finding]:
    """Return findings updated to resolved state for the target incident."""
    resolved: list[Finding] = []
    for finding in findings:
        if finding.incident_id != incident_id:
            continue
        if finding.status in _INACTIVE_FINDING_STATUSES:
            resolved.append(finding)
            continue
        resolved.append(
            finding.model_copy(
                update={
                    "status": FindingStatus.RESOLVED,
                    "resolved_at": resolved_at,
                }
            )
        )
    return resolved


def _transition_to_resolved(incident: Incident, *, resolved_at: datetime) -> Incident:
    """Move an incident through the allowed lifecycle until it is resolved."""
    if incident.status is IncidentStatus.RESOLVED:
        return incident.model_copy(update={"updated_at": resolved_at})
    working_incident = incident
    if working_incident.status is IncidentStatus.AWAITING_APPROVAL:
        working_incident = transition_incident(
            working_incident,
            IncidentStatus.REMEDIATING,
            changed_at=resolved_at,
        )
    if working_incident.status is IncidentStatus.OPEN:
        working_incident = transition_incident(
            working_incident,
            IncidentStatus.INVESTIGATING,
            changed_at=resolved_at,
        )
    return transition_incident(
        working_incident,
        IncidentStatus.RESOLVED,
        changed_at=resolved_at,
    )
