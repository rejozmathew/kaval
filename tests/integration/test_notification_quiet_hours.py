"""Integration tests for quiet-hours and maintenance alert routing."""

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
    AlertMaintenanceWindow,
    IncidentAlertRouter,
    IncidentAlertRoutingContext,
    IncidentAlertRoutingStatus,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for routing-context tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_high_incidents_are_held_during_quiet_hours_without_duplication() -> None:
    """High incidents should be held once until quiet hours end."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)
    context = IncidentAlertRoutingContext(quiet_hours_until=ts(7, 0))

    first = router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(6, 15),
        context=context,
    )
    second = router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(6, 40),
        context=context,
    )

    held = router.list_quiet_hours_holds()

    assert first.status == IncidentAlertRoutingStatus.HELD
    assert second.status == IncidentAlertRoutingStatus.HELD
    assert len(sender.payloads) == 0
    assert len(held) == 1
    assert held[0].incident_id == "inc-delugevpn"
    assert held[0].deliver_after == ts(7, 0)
    assert held[0].last_updated_at == ts(6, 40)


def test_low_incidents_remain_dashboard_only_during_quiet_hours() -> None:
    """Dashboard-only incidents should not be promoted into quiet-hours holds."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)

    result = router.route(
        incident=build_incident(
            incident_id="inc-update",
            title="Image update available",
            severity=Severity.LOW,
        ),
        investigation=build_investigation("inc-update"),
        now=ts(6, 20),
        context=IncidentAlertRoutingContext(quiet_hours_until=ts(7, 0)),
    )

    assert result.status == IncidentAlertRoutingStatus.DASHBOARD_ONLY
    assert len(sender.payloads) == 0
    assert router.list_quiet_hours_holds() == []


def test_service_maintenance_suppresses_incidents_only_when_all_services_are_covered() -> None:
    """Maintenance should suppress only incidents fully scoped to maintained services."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)
    context = IncidentAlertRoutingContext(
        maintenance_windows=[
            AlertMaintenanceWindow(service_id="svc-delugevpn", expires_at=ts(8, 0))
        ]
    )

    suppressed = router.route(
        incident=build_incident(
            incident_id="inc-delugevpn",
            title="DelugeVPN tunnel dropped",
            severity=Severity.HIGH,
            affected_services=["svc-delugevpn"],
        ),
        investigation=build_investigation("inc-delugevpn"),
        now=ts(6, 10),
        context=context,
    )
    still_sent = router.route(
        incident=build_incident(
            incident_id="inc-media",
            title="Shared media path degraded",
            severity=Severity.CRITICAL,
            affected_services=["svc-delugevpn", "svc-radarr"],
        ),
        investigation=build_investigation("inc-media"),
        now=ts(6, 15),
        context=context,
    )

    assert suppressed.status == IncidentAlertRoutingStatus.SUPPRESSED
    assert still_sent.status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 1
    assert sender.payloads[0].incident_id == "inc-media"


def test_global_maintenance_still_allows_critical_self_health_through() -> None:
    """Critical Kaval self-health should not be suppressed by maintenance."""
    sender = FakeNotificationSender()
    router = IncidentAlertRouter(sender=sender)
    context = IncidentAlertRoutingContext(
        maintenance_windows=[AlertMaintenanceWindow(expires_at=ts(8, 0))],
        is_kaval_self_health=True,
    )

    result = router.route(
        incident=build_incident(
            incident_id="inc-kaval-notify",
            title="Notification delivery failing",
            severity=Severity.CRITICAL,
            affected_services=[],
        ),
        investigation=build_investigation("inc-kaval-notify"),
        now=ts(6, 5),
        context=context,
    )

    assert result.status == IncidentAlertRoutingStatus.SENT
    assert len(sender.payloads) == 1


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


def build_incident(
    *,
    incident_id: str,
    title: str,
    severity: Severity,
    affected_services: list[str] | None = None,
) -> Incident:
    """Build a representative incident for routing-context tests."""
    return Incident(
        id=incident_id,
        title=title,
        severity=severity,
        status=IncidentStatus.AWAITING_APPROVAL,
        trigger_findings=[f"find-{incident_id}"],
        all_findings=[f"find-{incident_id}"],
        affected_services=affected_services or ["svc-core"],
        triggering_symptom=title,
        suspected_cause=f"{title} root cause",
        confirmed_cause=None,
        root_cause_service=(
            (affected_services or ["svc-core"])[0]
            if affected_services != []
            else None
        ),
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.92,
        investigation_id=f"inv-{incident_id}",
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(5, 55),
        grouping_window_end=ts(6, 0),
        created_at=ts(6, 0),
        updated_at=ts(6, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation(incident_id: str) -> Investigation:
    """Build a representative investigation for routing-context tests."""
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
                    "timestamp": ts(6, 2),
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
            "started_at": ts(6, 1),
            "completed_at": ts(6, 3),
        }
    )
