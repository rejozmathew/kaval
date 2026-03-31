"""Incident-centered notification formatting for Phase 2A."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import Incident, Investigation, NotificationPayload, NotificationSourceType

_MAX_EVIDENCE_LINES = 4


def format_incident_notification(
    *,
    incident: Incident,
    investigation: Investigation,
    now: datetime | None = None,
) -> NotificationPayload:
    """Format one incident investigation into the frozen notification payload contract."""
    effective_now = now or datetime.now(tz=UTC)
    evidence_lines = [
        step.result_summary for step in investigation.evidence_steps[:_MAX_EVIDENCE_LINES]
    ]
    root_cause = investigation.root_cause or incident.suspected_cause or incident.triggering_symptom
    confidence_text = _confidence_label(investigation.confidence)
    recommended_action = _recommended_action_text(investigation)
    summary = incident.triggering_symptom or root_cause or incident.title

    body_lines = [
        "Evidence:",
        *[f"- {line}" for line in evidence_lines],
        "",
        "Inference:",
        f"- Root cause: {root_cause or 'No confirmed root cause yet.'}",
        f"- Confidence: {confidence_text} ({investigation.confidence:.2f})",
        "",
        "Recommendation:",
        f"- {recommended_action}",
    ]
    if investigation.recurrence_count > 0:
        body_lines.extend(
            [
                "",
                "Past history:",
                f"- Seen {investigation.recurrence_count} time(s) in Operational Memory.",
            ]
        )

    return NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id=incident.id,
        incident_id=incident.id,
        severity=incident.severity,
        title=incident.title,
        summary=summary,
        body="\n".join(body_lines),
        evidence_lines=evidence_lines,
        recommended_action=(
            recommended_action
            if investigation.remediation is not None
            else None
        ),
        action_buttons=[],
        dedup_key=f"incident:{incident.id}",
        created_at=effective_now,
    )


def _confidence_label(confidence: float) -> str:
    """Map a numeric confidence score to a compact user-facing label."""
    if confidence >= 0.85:
        return "High"
    if confidence >= 0.6:
        return "Medium"
    return "Low"


def _recommended_action_text(investigation: Investigation) -> str:
    """Render the restart-only recommendation text for Phase 2A notifications."""
    if investigation.remediation is None:
        return "No restart recommended from the current evidence."
    return (
        f"Restart {investigation.remediation.target}."
        f" Risk: {investigation.remediation.risk_assessment.overall_risk.value}."
    )
