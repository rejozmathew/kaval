"""Integration tests for multi-issue summary notification delivery."""

from __future__ import annotations

from datetime import UTC, datetime

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
from kaval.notifications.routing import (
    IncidentAlertRoute,
    IncidentAlertRouter,
    IncidentAlertRoutingContext,
    IncidentAlertRoutingStatus,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for summary-notification tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_due_digest_bucket_with_multiple_incidents_sends_one_summary_notification() -> None:
    """A due digest bucket should collapse unrelated incidents into one summary payload."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    router.route(
        incident=build_incident(
            incident_id="inc-cert",
            title="Certificate expires soon",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-cert"),
        now=ts(12, 5),
    )
    router.route(
        incident=build_incident(
            incident_id="inc-container",
            title="Unknown container discovered",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-container"),
        now=ts(12, 35),
    )

    results = router.flush_due_notifications(now=ts(13, 0))

    assert len(results) == 1
    assert results[0].route == IncidentAlertRoute.SUMMARY
    assert results[0].status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 1
    assert sender.payloads[0].title == "2 active incidents"
    assert "Certificate expires soon (Medium)" in sender.payloads[0].body
    assert "Unknown container discovered (Medium)" in sender.payloads[0].body
    assert router.list_pending_digests() == []


def test_due_digest_bucket_with_one_incident_releases_original_payload() -> None:
    """A single queued digest incident should keep its original incident payload."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    router.route(
        incident=build_incident(
            incident_id="inc-cert",
            title="Certificate expires soon",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-cert"),
        now=ts(12, 5),
    )

    results = router.flush_due_notifications(now=ts(13, 0))

    assert len(results) == 1
    assert results[0].route == IncidentAlertRoute.HOURLY_DIGEST
    assert results[0].status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 1
    assert sender.payloads[0].incident_id == "inc-cert"
    assert sender.payloads[0].title == "Certificate expires soon"


def test_quiet_hours_release_sends_summary_when_multiple_incidents_were_held() -> None:
    """Held incidents should release as one summary when quiet hours end."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)
    context = IncidentAlertRoutingContext(quiet_hours_until=ts(7, 0))

    router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(6, 5),
        context=context,
    )
    router.route(
        incident=build_incident(
            incident_id="inc-cert",
            title="Certificate expires soon",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-cert"),
        now=ts(6, 20),
        context=context,
    )

    results = router.flush_due_notifications(now=ts(7, 0))

    assert len(results) == 1
    assert results[0].route == IncidentAlertRoute.SUMMARY
    assert results[0].status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 1
    assert sender.payloads[0].title == "2 incidents after quiet hours"
    assert "DelugeVPN tunnel dropped (High)" in sender.payloads[0].body
    assert "Certificate expires soon (Medium)" in sender.payloads[0].body
    assert router.list_quiet_hours_holds() == []


class FakeNotificationSender:
    """Deterministic sender that captures summary payloads."""

    def __init__(self) -> None:
        """Initialize the captured payload list."""
        self.payloads: list[NotificationPayload] = []

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Capture one payload and report a successful delivery."""
        self.payloads.append(payload)
        return NotificationDeliveryResult(
            status=NotificationDeliveryStatus.SENT,
            attempted_channels=1,
            delivered_channels=1,
            failed_channels=[],
            detail="sent",
        )


def build_incident(*, incident_id: str, title: str, severity: Severity) -> Incident:
    """Build a representative incident for summary tests."""
    return Incident(
        id=incident_id,
        title=title,
        severity=severity,
        status=IncidentStatus.AWAITING_APPROVAL,
        trigger_findings=[f"find-{incident_id}"],
        all_findings=[f"find-{incident_id}"],
        affected_services=["svc-core"],
        triggering_symptom=title,
        suspected_cause=f"{title} root cause",
        confirmed_cause=None,
        root_cause_service="svc-core",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.92,
        investigation_id=f"inv-{incident_id}",
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(11, 55),
        grouping_window_end=ts(12, 0),
        created_at=ts(12, 0),
        updated_at=ts(12, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation(incident_id: str) -> Investigation:
    """Build a representative investigation for summary tests."""
    remediation = RemediationProposal(
        action_type=ActionType.RESTART_CONTAINER,
        target="svc-core",
        rationale="Restart remains the only bounded remediation surface.",
        risk_assessment=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            checks=[
                RiskCheck(
                    check="bounded_action_scope",
                    result=RiskCheckResult.PASS,
                    detail="The proposed action stays inside the affected service scope.",
                )
            ],
            reversible=True,
            warnings=[],
        ),
        status=RemediationStatus.PROPOSED,
    )
    return Investigation.model_validate(
        {
            "id": f"inv-{incident_id}",
            "incident_id": incident_id,
            "trigger": InvestigationTrigger.AUTO,
            "status": InvestigationStatus.COMPLETED,
            "evidence_steps": [
                {
                    "order": 1,
                    "action": "summarize_incident_findings",
                    "target": incident_id,
                    "result_summary": "Kaval summarized the grouped incident findings.",
                    "result_data": {"incident_id": incident_id},
                    "timestamp": ts(12, 2),
                }
            ],
            "research_steps": [],
            "root_cause": "Root cause captured in investigation.",
            "confidence": 0.88,
            "model_used": "local",
            "cloud_model_calls": 0,
            "journal_entries_referenced": [],
            "user_notes_referenced": [],
            "recurrence_count": 0,
            "remediation": remediation.model_dump(mode="json"),
            "started_at": ts(12, 1),
            "completed_at": ts(12, 3),
        }
    )
