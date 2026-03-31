"""Unit tests for the Phase 0 core data models."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from pydantic import ValidationError

from kaval.models import (
    ActionType,
    ApprovalToken,
    ArrayProfile,
    CauseConfirmationSource,
    Change,
    ChangeType,
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    EvidenceStep,
    ExecutorActionRequest,
    ExecutorActionResult,
    ExecutorActionStatus,
    Finding,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentGroupingRule,
    IncidentLifecycleTransition,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
    NetworkingProfile,
    NotificationAction,
    NotificationActionStyle,
    NotificationActionType,
    NotificationPayload,
    NotificationSourceType,
    OperationalMemoryQuery,
    OperationalMemoryResult,
    RedactionLevel,
    RemediationProposal,
    RemediationStatus,
    ResearchStep,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    UserNote,
    VMProfile,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 3, 30, hour, minute, tzinfo=UTC)


def build_change() -> Change:
    """Create a reusable change record."""
    return Change(
        id="chg-1",
        type=ChangeType.IMAGE_UPDATE,
        service_id="svc-delugevpn",
        description="Updated DelugeVPN image",
        old_value="2.1.0",
        new_value="2.1.1",
        timestamp=ts(13, 45),
        correlated_incidents=["inc-1"],
    )


def build_risk_assessment() -> RiskAssessment:
    """Create a reusable remediation risk assessment."""
    return RiskAssessment(
        overall_risk=RiskLevel.LOW,
        checks=[
            RiskCheck(
                check="container_exists",
                result=RiskCheckResult.PASS,
                detail="Container exists and is restartable.",
            )
        ],
        reversible=True,
        warnings=["Restart may briefly interrupt downloads."],
    )


def build_system_profile() -> SystemProfile:
    """Create a reusable operational memory system profile."""
    return SystemProfile(
        hostname="zactower",
        unraid_version="7.2.1",
        hardware=HardwareProfile(
            cpu="Intel i3-12100T",
            memory_gb=32.0,
            gpu="NVIDIA",
            ups="APC Back-UPS",
        ),
        storage=StorageProfile(
            array=ArrayProfile(
                parity_drives=1,
                data_drives=4,
                cache="2x NVMe RAID 1",
                total_tb=12.0,
                used_tb=4.2,
            )
        ),
        networking=NetworkingProfile(
            domain="zactower.com",
            dns_provider="cloudflare",
            reverse_proxy="nginx_proxy_manager",
            tunnel="cloudflare_zero_trust",
            vpn="wireguard",
            dns_resolver="pihole",
            ssl_strategy="cloudflare_origin_certs",
        ),
        services_summary=ServicesSummary(
            total_containers=25,
            total_vms=3,
            matched_descriptors=22,
        ),
        vms=[
            VMProfile(
                name="Ubuntu Server",
                purpose="Hosts Moodle LMS + MariaDB",
                os="Ubuntu 22.04 LTS",
                quirks="LVM default partition is only ~10GB regardless of vdisk size",
            )
        ],
        last_updated=ts(14),
    )


def build_approval_token() -> ApprovalToken:
    """Create a reusable approval token."""
    return ApprovalToken(
        token_id="tok-1",
        incident_id="inc-1",
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approved_by="user_via_telegram",
        issued_at=ts(14, 30),
        expires_at=ts(14, 35),
        nonce="nonce-1",
        hmac_signature="deadbeef",
        used_at=None,
        result=None,
    )


def test_incident_round_trip_and_transition_contract() -> None:
    """Incident models should round-trip and enforce lifecycle transitions."""
    incident = Incident(
        id="inc-1",
        title="Radarr and Sonarr failing",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-1"],
        all_findings=["find-1", "find-2"],
        affected_services=["svc-radarr", "svc-sonarr", "svc-delugevpn"],
        triggering_symptom="Radarr health check failing",
        suspected_cause="DelugeVPN VPN tunnel inactive",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.92,
        investigation_id="inv-1",
        approved_actions=[],
        changes_correlated=["chg-1"],
        grouping_window_start=ts(14, 23),
        grouping_window_end=ts(14, 28),
        created_at=ts(14, 23),
        updated_at=ts(14, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )

    assert incident.can_transition_to(IncidentStatus.AWAITING_APPROVAL) is True
    assert incident.can_transition_to(IncidentStatus.REMEDIATING) is False

    round_tripped = Incident.model_validate_json(incident.model_dump_json())
    assert round_tripped == incident

    grouping_rule = IncidentGroupingRule()
    assert grouping_rule.window_minutes == 5

    valid_transition = IncidentLifecycleTransition(
        from_status=IncidentStatus.INVESTIGATING,
        to_status=IncidentStatus.AWAITING_APPROVAL,
        reason="Approval required for restart.",
    )
    assert valid_transition.to_status == IncidentStatus.AWAITING_APPROVAL

    with pytest.raises(ValidationError):
        IncidentLifecycleTransition(
            from_status=IncidentStatus.OPEN,
            to_status=IncidentStatus.RESOLVED,
        )


def test_finding_and_investigation_round_trip() -> None:
    """Findings and investigations should serialize and validate cleanly."""
    change = build_change()
    finding = Finding(
        id="find-1",
        title="Radarr cannot reach download client",
        severity=Severity.HIGH,
        domain="arr",
        service_id="svc-radarr",
        summary="Radarr reports the download client is unavailable.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="radarr",
                summary="Download client not available",
                observed_at=ts(14, 24),
                data={"line_count": 1, "message": "Download client not available"},
            )
        ],
        impact="Download pipeline blocked.",
        confidence=0.88,
        status=FindingStatus.GROUPED,
        incident_id="inc-1",
        related_changes=[change],
        created_at=ts(14, 24),
        resolved_at=None,
    )
    assert Finding.model_validate_json(finding.model_dump_json()) == finding

    remediation = RemediationProposal(
        action_type=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        rationale="Restarting the VPN container restores the dependency chain.",
        risk_assessment=build_risk_assessment(),
        status=RemediationStatus.PROPOSED,
    )
    investigation = Investigation(
        id="inv-1",
        incident_id="inc-1",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="read_container_logs",
                target="delugevpn",
                result_summary="VPN tunnel inactive appears in recent logs.",
                result_data={"sample": "VPN tunnel inactive"},
                timestamp=ts(14, 25),
            )
        ],
        research_steps=[
            ResearchStep(
                order=1,
                action="query_operational_memory",
                source="sqlite://operational-memory",
                result_summary="Three matching recurrence entries found.",
                timestamp=ts(14, 26),
            )
        ],
        root_cause="DelugeVPN lost its VPN tunnel.",
        confidence=0.95,
        model_used=ModelUsed.LOCAL,
        cloud_model_calls=0,
        journal_entries_referenced=["jrnl-1"],
        user_notes_referenced=["note-1"],
        recurrence_count=3,
        remediation=remediation,
        started_at=ts(14, 24),
        completed_at=ts(14, 27),
    )
    assert Investigation.model_validate_json(investigation.model_dump_json()) == investigation

    with pytest.raises(ValidationError):
        Investigation(
            id="inv-invalid",
            incident_id="inc-1",
            trigger=InvestigationTrigger.AUTO,
            status=InvestigationStatus.RUNNING,
            evidence_steps=[],
            research_steps=[],
            root_cause=None,
            confidence=0.4,
            model_used=ModelUsed.CLOUD,
            cloud_model_calls=0,
            journal_entries_referenced=[],
            user_notes_referenced=[],
            recurrence_count=0,
            remediation=None,
            started_at=ts(14, 24),
            completed_at=None,
        )


def test_service_and_operational_memory_contracts_round_trip() -> None:
    """Service and operational memory models should preserve nested data."""
    service = Service(
        id="svc-delugevpn",
        name="DelugeVPN",
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.DEGRADED,
        descriptor_id="downloads/delugevpn",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-123",
        vm_id=None,
        image="binhex/arch-delugevpn:2.1.1",
        endpoints=[
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTP,
                host="delugevpn",
                port=8112,
                path="/",
                url=None,
                auth_required=False,
                expected_status=200,
            )
        ],
        dependencies=[
            DependencyEdge(
                target_service_id="svc-prowlarr",
                confidence=DependencyConfidence.CONFIGURED,
                source=DependencySource.DESCRIPTOR,
                description="Configured in the ARR stack descriptor.",
            )
        ],
        dependents=["svc-radarr", "svc-sonarr"],
        last_check=ts(14, 24),
        active_findings=2,
        active_incidents=1,
    )
    assert Service.model_validate_json(service.model_dump_json()) == service

    system_profile = build_system_profile()
    journal_entry = JournalEntry(
        id="jrnl-1",
        incident_id="inc-1",
        date=date(2026, 3, 1),
        services=["svc-delugevpn", "svc-radarr", "svc-sonarr"],
        summary="VPN tunnel dropped after ISP IP change.",
        root_cause="ISP rotated public IP and the VPN tunnel did not reconnect.",
        resolution="Restarted DelugeVPN.",
        time_to_resolution_minutes=3.0,
        model_used="local",
        tags=["delugevpn", "vpn", "recurring"],
        lesson="Restart has consistently resolved this issue.",
        recurrence_count=3,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(15),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=90,
    )
    user_note = UserNote(
        id="note-1",
        service_id="svc-delugevpn",
        note="Restart has historically been safe for this container.",
        safe_for_model=True,
        last_verified_at=ts(15),
        stale=False,
        added_at=ts(12),
        updated_at=ts(15),
    )

    query = OperationalMemoryQuery(
        incident_id="inc-1",
        service_ids=["svc-delugevpn"],
        tags=["vpn"],
        include_system_profile=True,
        include_journal=True,
        include_user_notes=True,
        max_journal_entries=5,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    )
    assert OperationalMemoryQuery.model_validate_json(query.model_dump_json()) == query

    result = OperationalMemoryResult(
        system_profile=system_profile,
        journal_entries=[journal_entry],
        user_notes=[user_note],
        recurrence_count=3,
        applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        warnings=[],
    )
    assert OperationalMemoryResult.model_validate_json(result.model_dump_json()) == result

    with pytest.raises(ValidationError):
        OperationalMemoryQuery(
            include_system_profile=False,
            include_journal=False,
            include_user_notes=False,
        )


def test_approval_and_executor_contract_validation() -> None:
    """Approval tokens and executor API contracts should stay bound together."""
    token = build_approval_token()
    request = ExecutorActionRequest(
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approval_token=token,
    )
    assert ExecutorActionRequest.model_validate_json(request.model_dump_json()) == request

    result = ExecutorActionResult(
        token_id=token.token_id,
        incident_id=token.incident_id,
        action=token.action,
        target=token.target,
        status=ExecutorActionStatus.SUCCESS,
        detail="Container restarted successfully.",
        executed_at=ts(14, 31),
    )
    assert ExecutorActionResult.model_validate_json(result.model_dump_json()) == result

    with pytest.raises(ValidationError):
        ExecutorActionRequest(
            action=ActionType.START_VM,
            target="delugevpn",
            approval_token=token,
        )


def test_notification_payload_round_trip() -> None:
    """Notification payloads should preserve interactive controls."""
    payload = NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id="inc-1",
        incident_id="inc-1",
        severity=Severity.HIGH,
        title="Radarr and Sonarr failing",
        summary="Root cause points to DelugeVPN.",
        body="Restarting DelugeVPN is recommended based on repeated history.",
        evidence_lines=[
            'DelugeVPN logs: "VPN tunnel inactive"',
            'Radarr logs: "Download client not available"',
        ],
        recommended_action="Restart DelugeVPN",
        action_buttons=[
            NotificationAction(
                label="Approve restart",
                action=NotificationActionType.APPROVE,
                style=NotificationActionStyle.PRIMARY,
                callback_id="approve-inc-1",
                url=None,
                expires_at=ts(14, 35),
            ),
            NotificationAction(
                label="Full details",
                action=NotificationActionType.VIEW_DETAILS,
                style=NotificationActionStyle.SECONDARY,
                callback_id=None,
                url="https://example.invalid/incidents/inc-1",
                expires_at=None,
            ),
        ],
        dedup_key="incident-inc-1",
        created_at=ts(14, 29),
    )

    assert NotificationPayload.model_validate_json(payload.model_dump_json()) == payload

    with pytest.raises(ValidationError):
        NotificationAction(
            label="Dismiss",
            action=NotificationActionType.DISMISS,
            style=NotificationActionStyle.DANGER,
            expires_at=ts(14, 35),
        )


def test_approval_token_rejects_invalid_expiry() -> None:
    """Approval tokens should reject invalid lifetimes."""
    with pytest.raises(ValidationError):
        ApprovalToken(
            token_id="tok-invalid",
            incident_id="inc-1",
            action=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            approved_by="user_via_web",
            issued_at=ts(14, 30),
            expires_at=ts(14, 30) - timedelta(seconds=1),
            nonce="nonce-invalid",
            hmac_signature="deadbeef",
            used_at=None,
            result=None,
        )


def test_incident_requires_confirmation_source_for_confirmed_cause() -> None:
    """Confirmed causes should always carry their confirmation source."""
    with pytest.raises(ValidationError):
        Incident(
            id="inc-invalid",
            title="Invalid incident",
            severity=Severity.LOW,
            status=IncidentStatus.RESOLVED,
            trigger_findings=["find-1"],
            all_findings=["find-1"],
            affected_services=["svc-one"],
            triggering_symptom="symptom",
            suspected_cause="suspected",
            confirmed_cause="confirmed",
            root_cause_service="svc-one",
            resolution_mechanism="restart",
            cause_confirmation_source=None,
            confidence=0.8,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=[],
            grouping_window_start=ts(12),
            grouping_window_end=ts(12, 5),
            created_at=ts(12),
            updated_at=ts(12, 5),
            resolved_at=ts(12, 10),
            mttr_seconds=600.0,
            journal_entry_id="jrnl-1",
        )

    valid = Incident(
        id="inc-2",
        title="Valid incident",
        severity=Severity.MEDIUM,
        status=IncidentStatus.RESOLVED,
        trigger_findings=["find-2"],
        all_findings=["find-2"],
        affected_services=["svc-two"],
        triggering_symptom="symptom",
        suspected_cause="suspected",
        confirmed_cause="confirmed",
        root_cause_service="svc-two",
        resolution_mechanism="restart",
        cause_confirmation_source=CauseConfirmationSource.USER_CONFIRMED,
        confidence=0.85,
        investigation_id="inv-2",
        approved_actions=["act-1"],
        changes_correlated=[],
        grouping_window_start=ts(13),
        grouping_window_end=ts(13, 5),
        created_at=ts(13),
        updated_at=ts(13, 5),
        resolved_at=ts(13, 9),
        mttr_seconds=540.0,
        journal_entry_id="jrnl-2",
    )
    assert Incident.model_validate_json(valid.model_dump_json()) == valid
