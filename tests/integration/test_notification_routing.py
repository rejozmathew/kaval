"""Integration tests for Phase 3B alert-routing behavior."""

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
    IncidentAlertRoutingStatus,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for routing tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_critical_incidents_send_immediately_without_dedup() -> None:
    """Critical incidents should push immediately on every routing attempt."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    first = router.route(
        incident=build_incident(
            incident_id="inc-array",
            title="Array degraded",
            severity=Severity.CRITICAL,
        ),
        investigation=build_investigation("inc-array"),
        now=ts(10, 5),
    )
    second = router.route(
        incident=build_incident(
            incident_id="inc-array",
            title="Array degraded",
            severity=Severity.CRITICAL,
        ),
        investigation=build_investigation("inc-array"),
        now=ts(10, 10),
    )

    assert first.route == IncidentAlertRoute.IMMEDIATE
    assert first.status == IncidentAlertRoutingStatus.SENT
    assert second.status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 2


def test_high_incidents_follow_the_existing_dedup_window() -> None:
    """High incidents should reuse the grouped-dispatch dedup behavior."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    first = router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(11, 0),
    )
    second = router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(11, 10),
    )

    assert first.route == IncidentAlertRoute.IMMEDIATE_WITH_DEDUP
    assert first.status == IncidentAlertRoutingStatus.SENT
    assert second.status == IncidentAlertRoutingStatus.SKIPPED
    assert len(sender.payloads) == 1


def test_medium_incidents_queue_into_one_hourly_digest_bucket() -> None:
    """Medium incidents should queue without sending and share one hourly bucket."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    first = router.route(
        incident=build_incident(
            incident_id="inc-cert",
            title="Certificate expires soon",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-cert"),
        now=ts(12, 5),
    )
    second = router.route(
        incident=build_incident(
            incident_id="inc-container",
            title="Unknown container discovered",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-container"),
        now=ts(12, 40),
    )
    repeated = router.route(
        incident=build_incident(
            incident_id="inc-cert",
            title="Certificate expires soon",
            severity=Severity.MEDIUM,
        ),
        investigation=build_investigation("inc-cert"),
        now=ts(12, 55),
    )

    pending = router.list_pending_digests()

    assert first.route == IncidentAlertRoute.HOURLY_DIGEST
    assert first.status == IncidentAlertRoutingStatus.QUEUED
    assert first.digest_bucket_start == ts(12, 0)
    assert first.digest_deliver_after == ts(13, 0)
    assert second.status == IncidentAlertRoutingStatus.QUEUED
    assert repeated.status == IncidentAlertRoutingStatus.QUEUED
    assert len(sender.payloads) == 0
    assert len(pending) == 1
    assert pending[0].bucket_start == ts(12, 0)
    assert pending[0].deliver_after == ts(13, 0)
    assert [incident.incident_id for incident in pending[0].incidents] == [
        "inc-cert",
        "inc-container",
    ]
    assert pending[0].incidents[0].last_updated_at == ts(12, 55)


def test_low_incidents_stay_dashboard_only() -> None:
    """Low incidents should never send or enter the digest backlog."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    result = router.route(
        incident=build_incident(
            incident_id="inc-update",
            title="Image update available",
            severity=Severity.LOW,
        ),
        investigation=build_investigation("inc-update"),
        now=ts(13, 15),
    )

    assert result.route == IncidentAlertRoute.DASHBOARD_ONLY
    assert result.status == IncidentAlertRoutingStatus.DASHBOARD_ONLY
    assert len(sender.payloads) == 0
    assert router.list_pending_digests() == []


class FakeNotificationSender:
    """Deterministic sender that captures formatted payloads."""

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
    """Build a representative incident for alert-routing tests."""
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
        grouping_window_start=ts(9, 55),
        grouping_window_end=ts(10, 0),
        created_at=ts(10, 0),
        updated_at=ts(10, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation(incident_id: str) -> Investigation:
    """Build a representative investigation for alert-routing tests."""
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
                    "timestamp": ts(10, 2),
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
            "started_at": ts(10, 1),
            "completed_at": ts(10, 3),
        }
    )
