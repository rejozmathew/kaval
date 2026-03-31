"""Unit tests for Phase 2A incident notification formatting."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.models import (
    ActionType,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    NotificationSourceType,
    RemediationProposal,
    RemediationStatus,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Severity,
)
from kaval.notifications.formatter import format_incident_notification


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for formatter tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_formatter_renders_structured_incident_payload_for_restart_recommendation() -> None:
    """Evidence, inference, and restart-only recommendation should appear in one payload."""
    payload = format_incident_notification(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 40),
    )

    assert payload.source_type == NotificationSourceType.INCIDENT
    assert payload.source_id == "inc-delugevpn"
    assert payload.dedup_key == "incident:inc-delugevpn"
    assert payload.evidence_lines == [
        "DelugeVPN reports the VPN tunnel is inactive.",
        "Dependency walk shows DelugeVPN upstream of 1 affected service(s): Radarr.",
    ]
    assert payload.recommended_action == "Restart delugevpn. Risk: low."
    assert "Evidence:" in payload.body
    assert "Inference:" in payload.body
    assert "Recommendation:" in payload.body
    assert "Past history:" in payload.body


def test_formatter_renders_no_action_state_without_recommendation_buttons() -> None:
    """No-action investigations should stay incident-centered without restart language."""
    payload = format_incident_notification(
        incident=build_incident(),
        investigation=build_investigation(remediation=None),
        now=ts(14, 45),
    )

    assert payload.recommended_action is None
    assert "No restart recommended from the current evidence." in payload.body


def build_incident() -> Incident:
    """Build a representative incident for formatter tests."""
    return Incident(
        id="inc-delugevpn",
        title="Radarr and DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.AWAITING_APPROVAL,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn", "find-radarr"],
        affected_services=["svc-delugevpn", "svc-radarr"],
        triggering_symptom="Radarr download client unavailable",
        suspected_cause="DelugeVPN VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.95,
        investigation_id="inv-delugevpn",
        approved_actions=[],
        changes_correlated=["chg-delugevpn-restart"],
        grouping_window_start=ts(14, 20),
        grouping_window_end=ts(14, 25),
        created_at=ts(14, 20),
        updated_at=ts(14, 40),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation(
    *,
    remediation: RemediationProposal | None = RemediationProposal(
        action_type=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        rationale="Restart is the only bounded remediation in Phase 2A.",
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            checks=[
                RiskCheck(
                    check="bounded_action_scope",
                    result=RiskCheckResult.PASS,
                    detail="The proposed restart stays within the affected container scope.",
                )
            ],
            reversible=True,
            warnings=[],
        ),
        status=RemediationStatus.PROPOSED,
    ),
) -> Investigation:
    """Build a representative investigation for formatter tests."""
    return Investigation.model_validate(
        {
            "id": "inv-delugevpn",
            "incident_id": "inc-delugevpn",
            "trigger": InvestigationTrigger.AUTO,
            "status": InvestigationStatus.COMPLETED,
            "evidence_steps": [
                {
                    "order": 1,
                    "action": "summarize_incident_findings",
                    "target": "inc-delugevpn",
                    "result_summary": "DelugeVPN reports the VPN tunnel is inactive.",
                    "result_data": {"finding_ids": ["find-delugevpn"]},
                    "timestamp": ts(14, 30),
                },
                {
                    "order": 2,
                    "action": "inspect_dependency_graph",
                    "target": "inc-delugevpn",
                    "result_summary": (
                        "Dependency walk shows DelugeVPN upstream of 1 affected service(s): Radarr."
                    ),
                    "result_data": {"service_ids": ["svc-radarr"]},
                    "timestamp": ts(14, 31),
                },
            ],
            "research_steps": [],
            "root_cause": "DelugeVPN VPN tunnel dropped",
            "confidence": 0.94,
            "model_used": "local",
            "cloud_model_calls": 0,
            "journal_entries_referenced": ["jrnl-delugevpn-1", "jrnl-delugevpn-2"],
            "user_notes_referenced": ["note-delugevpn"],
            "recurrence_count": 2,
            "remediation": remediation.model_dump(mode="json") if remediation else None,
            "started_at": ts(14, 30),
            "completed_at": ts(14, 32),
        }
    )
