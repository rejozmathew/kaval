"""Unit tests for incident-grouped notification dispatch."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kaval.models import (
    ActionType,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    NotificationPayload,
    RemediationProposal,
    RemediationStatus,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Severity,
)
from kaval.notifications.bus import NotificationDeliveryResult, NotificationDeliveryStatus
from kaval.notifications.grouped import (
    IncidentNotificationDispatcher,
    IncidentNotificationDispatchStatus,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for grouped notification tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_dispatcher_sends_first_incident_notification() -> None:
    """The first incident notification should be formatted and sent immediately."""
    sender = FakeNotificationSender()
    dispatcher = IncidentNotificationDispatcher(sender=sender)

    result = dispatcher.dispatch(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 40),
    )

    assert result.status == IncidentNotificationDispatchStatus.SENT
    assert result.payload.dedup_key == "incident:inc-delugevpn"
    assert len(sender.payloads) == 1


def test_dispatcher_suppresses_duplicates_inside_dedup_window() -> None:
    """A second send for the same incident should be skipped inside the dedup window."""
    sender = FakeNotificationSender()
    dispatcher = IncidentNotificationDispatcher(sender=sender)

    first_result = dispatcher.dispatch(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 40),
    )
    second_result = dispatcher.dispatch(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 45),
    )

    assert first_result.status == IncidentNotificationDispatchStatus.SENT
    assert second_result.status == IncidentNotificationDispatchStatus.SKIPPED
    assert len(sender.payloads) == 1


def test_dispatcher_resends_after_dedup_window_expires() -> None:
    """The dispatcher should resend once the per-incident dedup window has elapsed."""
    sender = FakeNotificationSender()
    dispatcher = IncidentNotificationDispatcher(
        sender=sender,
        dedup_window=timedelta(minutes=15),
    )

    dispatcher.dispatch(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 40),
    )
    resend_result = dispatcher.dispatch(
        incident=build_incident(),
        investigation=build_investigation(),
        now=ts(14, 56),
    )

    assert resend_result.status == IncidentNotificationDispatchStatus.SENT
    assert len(sender.payloads) == 2


class FakeNotificationSender:
    """Deterministic notification sender for grouped-dispatch tests."""

    def __init__(self) -> None:
        """Initialize the captured payload list."""
        self.payloads: list[NotificationPayload] = []

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Capture the payload and report successful delivery."""
        self.payloads.append(payload)
        return NotificationDeliveryResult(
            status=NotificationDeliveryStatus.SENT,
            attempted_channels=1,
            delivered_channels=1,
            failed_channels=[],
            detail="sent",
        )


def build_incident() -> Incident:
    """Build a representative incident for grouped notification tests."""
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


def build_investigation() -> Investigation:
    """Build a representative investigation for grouped notification tests."""
    remediation = RemediationProposal(
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
    )
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
                }
            ],
            "research_steps": [],
            "root_cause": "DelugeVPN VPN tunnel dropped",
            "confidence": 0.94,
            "model_used": "local",
            "cloud_model_calls": 0,
            "journal_entries_referenced": ["jrnl-delugevpn-1"],
            "user_notes_referenced": ["note-delugevpn"],
            "recurrence_count": 2,
            "remediation": remediation.model_dump(mode="json"),
            "started_at": ts(14, 30),
            "completed_at": ts(14, 32),
        }
    )
