"""Contract tests for repository JSON schemas."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

from jsonschema.validators import validator_for

from kaval.discovery.descriptors import ServiceDescriptor
from kaval.models import (
    ActionType,
    ApprovalToken,
    ArrayProfile,
    Change,
    ChangeType,
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
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
from kaval.schema_export import SCHEMA_MODELS, export_schemas

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for schema samples."""
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
    """Create a reusable risk assessment record."""
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


def build_finding() -> Finding:
    """Create a reusable finding sample."""
    return Finding(
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
                data={"message": "Download client not available"},
            )
        ],
        impact="Download pipeline blocked.",
        confidence=0.88,
        status=FindingStatus.GROUPED,
        incident_id="inc-1",
        related_changes=[build_change()],
        created_at=ts(14, 24),
        resolved_at=None,
    )


def build_incident() -> Incident:
    """Create a reusable incident sample."""
    return Incident(
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


def build_investigation() -> Investigation:
    """Create a reusable investigation sample."""
    return Investigation(
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
        remediation=RemediationProposal(
            action_type=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            rationale="Restarting the VPN container restores the dependency chain.",
            risk_assessment=build_risk_assessment(),
            status=RemediationStatus.PROPOSED,
        ),
        started_at=ts(14, 24),
        completed_at=ts(14, 27),
    )


def build_service() -> Service:
    """Create a reusable service sample."""
    return Service(
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
        dns_targets=[
            DnsTarget(
                host="downloads.example.test",
                record_type=DnsRecordType.A,
                expected_values=["192.0.2.10"],
            )
        ],
        dependencies=[],
        dependents=["svc-radarr", "svc-sonarr"],
        last_check=ts(14, 24),
        active_findings=2,
        active_incidents=1,
    )


def build_system_profile() -> SystemProfile:
    """Create a reusable system profile sample."""
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


def build_journal_entry() -> JournalEntry:
    """Create a reusable journal entry sample."""
    return JournalEntry(
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


def build_user_note() -> UserNote:
    """Create a reusable user note sample."""
    return UserNote(
        id="note-1",
        service_id="svc-delugevpn",
        note="Restart has historically been safe for this container.",
        safe_for_model=True,
        last_verified_at=ts(15),
        stale=False,
        added_at=ts(12),
        updated_at=ts(15),
    )


def build_approval_token() -> ApprovalToken:
    """Create a reusable approval token sample."""
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


def build_service_descriptor() -> ServiceDescriptor:
    """Create a reusable service descriptor sample."""
    return ServiceDescriptor(
        id="radarr",
        name="Radarr",
        category="arr",
        project_url="https://radarr.video",
        icon="radarr.svg",
        match={
            "image_patterns": [
                "lscr.io/linuxserver/radarr*",
                "hotio/radarr*",
                "*radarr*",
            ],
            "container_name_patterns": ["radarr*"],
        },
        endpoints={
            "web_ui": {"port": 7878, "path": "/"},
            "health_api": {
                "port": 7878,
                "path": "/api/v3/health",
                "auth": "api_key",
                "auth_header": "X-Api-Key",
                "healthy_when": "json_array_empty",
            },
        },
        dns_targets=[
            {
                "host": "radarr.example.test",
                "record_type": "A",
                "expected_values": ["192.0.2.20"],
            }
        ],
        log_signals={
            "errors": [
                "Unable to connect to indexer",
                "Download client .* not available",
            ],
            "warnings": ["No indexers available"],
        },
        typical_dependencies={
            "containers": [
                "prowlarr",
                {"name": "delugevpn", "alternatives": ["qbittorrent", "transmission"]},
            ],
            "shares": ["media", "downloads"],
        },
        common_failure_modes=[
            {
                "trigger": "Download client .* not available",
                "likely_cause": "Download client container is down or has lost VPN tunnel",
                "check_first": ["delugevpn", "qbittorrent"],
            }
        ],
        investigation_context="Radarr health returns an empty array when healthy.",
        credential_hints={
            "api_key": {
                "description": "Radarr API Key",
                "location": "Radarr Web UI → Settings → General → API Key",
            }
        },
    )


def load_schema(schema_name: str) -> dict[str, object]:
    """Load a checked-in schema file from the repository."""
    schema_path = SCHEMAS_DIR / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_with_schema(schema_name: str, instance: object) -> None:
    """Validate a model payload against the checked-in schema."""
    schema = load_schema(schema_name)
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    validator.validate(instance)


def test_checked_in_schemas_match_exported_models(tmp_path: Path) -> None:
    """Checked-in schema artifacts should stay synchronized with the exporter."""
    exported_paths = export_schemas(tmp_path)
    expected_names = {filename for filename, _ in SCHEMA_MODELS}
    actual_names = {path.name for path in exported_paths}

    assert actual_names == expected_names

    for exported_path in exported_paths:
        checked_in = json.loads((SCHEMAS_DIR / exported_path.name).read_text(encoding="utf-8"))
        generated = json.loads(exported_path.read_text(encoding="utf-8"))
        assert generated == checked_in


def test_sample_payloads_validate_against_schemas() -> None:
    """Representative payloads should validate against checked-in schemas."""
    incident = build_incident()
    finding = build_finding()
    investigation = build_investigation()
    service = build_service()
    system_profile = build_system_profile()
    journal_entry = build_journal_entry()
    user_note = build_user_note()
    approval_token = build_approval_token()
    service_descriptor = build_service_descriptor()

    validate_with_schema("incident.json", incident.model_dump(mode="json"))
    validate_with_schema("finding.json", finding.model_dump(mode="json"))
    validate_with_schema("investigation.json", investigation.model_dump(mode="json"))
    validate_with_schema("service.json", service.model_dump(mode="json"))
    validate_with_schema(
        "service_descriptor.json",
        service_descriptor.model_dump(mode="json"),
    )
    validate_with_schema("system_profile.json", system_profile.model_dump(mode="json"))
    validate_with_schema("journal_entry.json", journal_entry.model_dump(mode="json"))
    validate_with_schema("user_note.json", user_note.model_dump(mode="json"))
    validate_with_schema("approval_token.json", approval_token.model_dump(mode="json"))
    validate_with_schema(
        "executor_action_request.json",
        ExecutorActionRequest(
            action=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            approval_token=approval_token,
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "executor_action_result.json",
        ExecutorActionResult(
            token_id=approval_token.token_id,
            incident_id=approval_token.incident_id,
            action=approval_token.action,
            target=approval_token.target,
            status=ExecutorActionStatus.SUCCESS,
            detail="Container restarted successfully.",
            executed_at=ts(14, 31),
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "incident_lifecycle_transition.json",
        IncidentLifecycleTransition(
            from_status=IncidentStatus.INVESTIGATING,
            to_status=IncidentStatus.AWAITING_APPROVAL,
            reason="Approval required for restart.",
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_payload.json",
        NotificationPayload(
            source_type=NotificationSourceType.INCIDENT,
            source_id=incident.id,
            incident_id=incident.id,
            severity=incident.severity,
            title=incident.title,
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
                )
            ],
            dedup_key="incident-inc-1",
            created_at=ts(14, 29),
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "operational_memory_query.json",
        OperationalMemoryQuery(
            incident_id=incident.id,
            service_ids=["svc-delugevpn"],
            tags=["vpn"],
            include_system_profile=True,
            include_journal=True,
            include_user_notes=True,
            max_journal_entries=5,
            redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "operational_memory_result.json",
        OperationalMemoryResult(
            system_profile=system_profile,
            journal_entries=[journal_entry],
            user_notes=[user_note],
            recurrence_count=3,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ).model_dump(mode="json"),
    )
