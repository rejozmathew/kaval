"""Unit tests for the Phase 0 SQLite persistence layer."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

from kaval.credentials.models import (
    CredentialRequest,
    CredentialRequestMode,
    CredentialRequestStatus,
    VaultConfigRecord,
    VaultCredentialRecord,
)
from kaval.database import KavalDatabase
from kaval.memory.note_models import UserNoteVersion
from kaval.models import (
    ActionType,
    ApprovalToken,
    ArrayProfile,
    Change,
    ChangeType,
    DependencyConfidence,
    DependencyEdge,
    DependencyOverride,
    DependencyOverrideState,
    DependencySource,
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    FindingFeedbackReason,
    FindingFeedbackRecord,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    MaintenanceScope,
    MaintenanceWindowRecord,
    ModelUsed,
    NetworkingProfile,
    Service,
    ServiceCheckOverride,
    ServiceCheckOverrideScope,
    ServiceInsightLevel,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    UserNote,
    VMProfile,
)
from kaval.runtime import (
    CapabilityRuntimeSignalSource,
    DiscoveryPipelineRuntimeSignal,
    ExecutorProcessRuntimeSignal,
    build_discovery_pipeline_runtime_signal,
    build_executor_process_runtime_signal,
    build_scheduler_runtime_signal,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 3, 30, hour, minute, tzinfo=UTC)


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_finding() -> Finding:
    """Create a reusable finding payload."""
    change = Change(
        id="chg-1",
        type=ChangeType.CONTAINER_RESTART,
        service_id="svc-delugevpn",
        description="Container restarted by Watchtower.",
        old_value="restart_count=1",
        new_value="restart_count=2",
        timestamp=ts(14, 20),
        correlated_incidents=["inc-1"],
    )
    return Finding(
        id="find-1",
        title="Download client unavailable",
        severity=Severity.HIGH,
        domain="arr",
        service_id="svc-radarr",
        summary="Radarr cannot reach DelugeVPN.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="radarr",
                summary="Download client not available",
                observed_at=ts(14, 23),
                data={"message": "Download client not available"},
            )
        ],
        impact="Download pipeline blocked.",
        confidence=0.87,
        status=FindingStatus.NEW,
        incident_id=None,
        related_changes=[change],
        created_at=ts(14, 23),
        resolved_at=None,
    )


def build_incident() -> Incident:
    """Create a reusable incident payload."""
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
        confidence=0.91,
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


def build_finding_feedback_record() -> FindingFeedbackRecord:
    """Create a reusable finding-feedback record payload."""
    return FindingFeedbackRecord(
        id="ffb-1",
        finding_id="find-1",
        service_id="svc-radarr",
        finding_domain="endpoint_probe",
        reason=FindingFeedbackReason.FALSE_POSITIVE,
        recorded_at=ts(14, 30),
    )


def build_maintenance_window_record() -> MaintenanceWindowRecord:
    """Create a reusable maintenance window payload."""
    return MaintenanceWindowRecord(
        scope=MaintenanceScope.SERVICE,
        service_id="svc-radarr",
        started_at=ts(15, 0),
        expires_at=ts(16, 0),
    )


def build_investigation() -> Investigation:
    """Create a reusable investigation payload."""
    return Investigation(
        id="inv-1",
        incident_id="inc-1",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[],
        research_steps=[],
        root_cause="DelugeVPN lost its VPN tunnel.",
        confidence=0.9,
        model_used=ModelUsed.LOCAL,
        cloud_model_calls=0,
        local_input_tokens=220,
        local_output_tokens=61,
        cloud_input_tokens=0,
        cloud_output_tokens=0,
        estimated_cloud_cost_usd=0.0,
        estimated_total_cost_usd=0.0,
        cloud_escalation_reason=None,
        journal_entries_referenced=[],
        user_notes_referenced=[],
        recurrence_count=3,
        remediation=None,
        started_at=ts(14, 24),
        completed_at=ts(14, 27),
    )


def build_service() -> Service:
    """Create a reusable service payload."""
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
        dependents=["svc-radarr"],
        last_check=ts(14, 24),
        active_findings=1,
        active_incidents=1,
    )


def build_system_profile() -> SystemProfile:
    """Create a reusable system profile payload."""
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
    """Create a reusable approval token payload."""
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


def build_credential_request() -> CredentialRequest:
    """Create a reusable credential-request payload."""
    return CredentialRequest(
        id="credreq-1",
        incident_id="inc-1",
        investigation_id="inv-1",
        service_id="svc-radarr",
        service_name="Radarr",
        credential_key="api_key",
        credential_description="Radarr API Key",
        credential_location="Radarr Web UI -> Settings -> General -> API Key",
        reason="Need diagnostics API access.",
        status=CredentialRequestStatus.AWAITING_INPUT,
        selected_mode=CredentialRequestMode.VOLATILE,
        decided_by="user_via_telegram",
        requested_at=ts(14, 10),
        expires_at=ts(14, 40),
        decided_at=ts(14, 12),
        satisfied_at=None,
        credential_reference=None,
    )


def build_journal_entry() -> JournalEntry:
    """Create a reusable journal entry payload."""
    return JournalEntry(
        id="jrnl-1",
        incident_id="inc-1",
        date=date(2026, 3, 1),
        services=["svc-delugevpn", "svc-radarr"],
        summary="VPN tunnel dropped after ISP IP change.",
        root_cause="ISP rotated public IP and the tunnel did not reconnect.",
        resolution="Restarted DelugeVPN.",
        time_to_resolution_minutes=3.0,
        model_used="local",
        tags=["vpn", "recurring"],
        lesson="Restart has consistently resolved this issue.",
        recurrence_count=3,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(15),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=90,
    )


def build_vault_config() -> VaultConfigRecord:
    """Create a reusable vault-config payload."""
    return VaultConfigRecord(
        salt_b64="c2FsdC1ieXRlcy0xMjM0NQ==",
        verifier_token="gAAAAABvaultverifier",
        created_at=ts(14, 5),
        updated_at=ts(14, 5),
    )


def build_vault_credential() -> VaultCredentialRecord:
    """Create a reusable encrypted vault-credential payload."""
    return VaultCredentialRecord(
        reference_id="vault:cred-1",
        request_id="credreq-1",
        incident_id="inc-1",
        service_id="svc-radarr",
        credential_key="api_key",
        ciphertext="gAAAAABvaultciphertext",
        submitted_by="user_via_telegram",
        created_at=ts(14, 15),
        updated_at=ts(14, 15),
    )


def build_user_note() -> UserNote:
    """Create a reusable user note payload."""
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


def build_user_note_version() -> UserNoteVersion:
    """Create a reusable retained user-note version payload."""
    return UserNoteVersion(
        id="notever-1",
        note_id="note-1",
        version_number=1,
        recorded_at=ts(15, 5),
        archived=False,
        current=False,
        note=build_user_note(),
    )


def test_bootstrap_applies_baseline_migration(tmp_path: Path) -> None:
    """Bootstrapping should create the expected baseline tables."""
    database = build_database(tmp_path)
    try:
        tables = {
            row["name"]
            for row in database.connection().execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "schema_migrations" in tables
        assert "findings" in tables
        assert "incidents" in tables
        assert "system_profiles" in tables
        assert "credential_requests" in tables
        assert "webhook_payloads" in tables
        assert "webhook_event_states" in tables
        assert "user_note_versions" in tables
        assert "finding_feedback_records" in tables
        assert "maintenance_windows" in tables
        assert database.applied_migrations() == [
            "0001_phase0_baseline",
            "0002_phase2b_credential_requests",
            "0003_phase2b_vault",
            "0004_phase3a_capability_runtime_signals",
            "0005_phase3b_webhook_payloads",
            "0006_phase3b_webhook_event_states",
            "0007_phase3b_user_note_versions",
            "0008_phase3c_dependency_overrides",
            "0009_phase3c_service_check_overrides",
            "0010_phase3c_finding_feedback_records",
            "0011_phase3c_maintenance_windows",
        ]
        assert database.migrations_current() is True
    finally:
        database.close()


def test_findings_and_incidents_support_crud(tmp_path: Path) -> None:
    """Findings and incidents should support create, read, update, and delete."""
    database = build_database(tmp_path)
    finding = build_finding()
    incident = build_incident()
    try:
        database.upsert_finding(finding)
        assert database.get_finding("find-1") == finding

        updated_finding = finding.model_copy(
            update={"status": FindingStatus.GROUPED, "incident_id": incident.id}
        )
        database.upsert_finding(updated_finding)
        assert database.get_finding("find-1") == updated_finding

        database.upsert_incident(incident)
        assert database.get_incident("inc-1") == incident
        assert [stored.id for stored in database.list_findings()] == ["find-1"]
        assert [stored.id for stored in database.list_incidents()] == ["inc-1"]

        database.delete_finding("find-1")
        database.delete_incident("inc-1")
        assert database.get_finding("find-1") is None
        assert database.get_incident("inc-1") is None
    finally:
        database.close()


def test_database_persists_finding_feedback_records(tmp_path: Path) -> None:
    """Finding feedback should persist as ordered append-only records."""
    database = build_database(tmp_path)
    finding_feedback_record = build_finding_feedback_record()
    try:
        database.upsert_finding_feedback_record(finding_feedback_record)
        updated_record = finding_feedback_record.model_copy(
            update={
                "reason": FindingFeedbackReason.ALREADY_AWARE,
                "recorded_at": ts(14, 31),
            }
        )
        database.upsert_finding_feedback_record(updated_record)

        assert database.list_finding_feedback_records() == [updated_record]
    finally:
        database.close()


def test_database_persists_maintenance_windows(tmp_path: Path) -> None:
    """Maintenance windows should persist by scope identity."""
    database = build_database(tmp_path)
    maintenance_window = build_maintenance_window_record()
    try:
        database.upsert_maintenance_window(maintenance_window)
        database.upsert_maintenance_window(
            MaintenanceWindowRecord(
                scope=MaintenanceScope.GLOBAL,
                started_at=ts(15, 5),
                expires_at=ts(15, 35),
            )
        )

        assert database.list_maintenance_windows() == [
            MaintenanceWindowRecord(
                scope=MaintenanceScope.GLOBAL,
                started_at=ts(15, 5),
                expires_at=ts(15, 35),
            ),
            maintenance_window,
        ]

        database.delete_maintenance_window(
            scope=MaintenanceScope.SERVICE,
            service_id="svc-radarr",
        )
        assert database.list_maintenance_windows() == [
            MaintenanceWindowRecord(
                scope=MaintenanceScope.GLOBAL,
                started_at=ts(15, 5),
                expires_at=ts(15, 35),
            )
        ]
    finally:
        database.close()


def test_database_persists_supporting_phase0_records(tmp_path: Path) -> None:
    """Phase 0 supporting entities should round-trip through SQLite."""
    database = build_database(tmp_path)
    investigation = build_investigation()
    service = build_service()
    system_profile = build_system_profile()
    approval_token = build_approval_token()
    credential_request = build_credential_request()
    vault_config = build_vault_config()
    vault_credential = build_vault_credential()
    journal_entry = build_journal_entry()
    user_note = build_user_note()
    try:
        database.upsert_investigation(investigation)
        database.upsert_service(service)
        database.upsert_system_profile(system_profile)
        database.upsert_approval_token(approval_token)
        database.upsert_credential_request(credential_request)
        database.upsert_vault_config(vault_config)
        database.upsert_vault_credential(vault_credential)
        database.upsert_journal_entry(journal_entry)
        database.upsert_user_note(user_note)

        stored_service = database.get_service(service.id)

        assert database.get_investigation(investigation.id) == investigation
        assert stored_service == service
        assert stored_service is not None
        assert stored_service.insight is not None
        assert stored_service.insight.level == ServiceInsightLevel.MONITORED
        assert database.get_system_profile() == system_profile
        assert database.get_approval_token(approval_token.token_id) == approval_token
        assert database.get_credential_request(credential_request.id) == credential_request
        assert database.get_vault_config() == vault_config
        assert database.get_vault_credential(vault_credential.reference_id) == vault_credential
        assert database.get_journal_entry(journal_entry.id) == journal_entry
        assert database.get_user_note(user_note.id) == user_note
        assert [stored.id for stored in database.list_investigations()] == [investigation.id]
        assert [stored.id for stored in database.list_credential_requests()] == [
            credential_request.id
        ]
        assert [stored.reference_id for stored in database.list_vault_credentials()] == [
            vault_credential.reference_id
        ]
        assert [stored.id for stored in database.list_services()] == [service.id]

        database.delete_investigation(investigation.id)
        database.delete_service(service.id)
        database.clear_system_profile()
        database.delete_approval_token(approval_token.token_id)
        database.delete_credential_request(credential_request.id)
        database.clear_vault_config()
        database.delete_vault_credential(vault_credential.reference_id)
        database.delete_journal_entry(journal_entry.id)
        database.delete_user_note(user_note.id)

        assert database.get_investigation(investigation.id) is None
        assert database.get_service(service.id) is None
        assert database.get_system_profile() is None
        assert database.get_approval_token(approval_token.token_id) is None
        assert database.get_credential_request(credential_request.id) is None
        assert database.get_vault_config() is None
        assert database.get_vault_credential(vault_credential.reference_id) is None
        assert database.get_journal_entry(journal_entry.id) is None
        assert database.get_user_note(user_note.id) is None
    finally:
        database.close()


def test_database_backfills_service_insight_for_pre_phase3_payloads(tmp_path: Path) -> None:
    """Legacy service rows without an insight field should still load with derived insight."""
    database = build_database(tmp_path)
    service = build_service()
    legacy_payload = service.model_dump(mode="json")
    legacy_payload.pop("insight")

    try:
        with database.connection():
            database.connection().execute(
                """
                INSERT INTO services (id, type, status, last_check, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    service.id,
                    service.type.value,
                    service.status.value,
                    service.last_check.isoformat() if service.last_check else None,
                    json.dumps(legacy_payload),
                ),
            )

        stored = database.get_service(service.id)
        assert stored is not None
        assert stored.insight is not None
        assert stored.insight.level == ServiceInsightLevel.MONITORED
    finally:
        database.close()


def test_database_persists_user_note_versions(tmp_path: Path) -> None:
    """User-note history snapshots should round-trip through SQLite."""
    database = build_database(tmp_path)
    first_version = build_user_note_version()
    second_version = first_version.model_copy(
        update={
            "id": "notever-2",
            "version_number": 2,
            "recorded_at": ts(16),
            "archived": True,
            "current": True,
            "note": first_version.note.model_copy(
                update={
                    "note": "Archive after validating the VPN path.",
                    "updated_at": ts(16),
                }
            ),
        }
    )
    try:
        database.upsert_user_note_version(first_version)
        database.upsert_user_note_version(second_version)

        assert database.list_user_note_versions("note-1") == [first_version, second_version]

        database.delete_user_note_versions("note-1")

        assert database.list_user_note_versions("note-1") == []
    finally:
        database.close()


def test_database_lists_changes_in_timestamp_order(tmp_path: Path) -> None:
    """Change records should be listed in deterministic timestamp order."""
    database = build_database(tmp_path)
    earlier = Change(
        id="chg-1",
        type=ChangeType.CONTAINER_RESTART,
        service_id="svc-delugevpn",
        description="Container restarted.",
        old_value="1",
        new_value="2",
        timestamp=ts(10, 0),
        correlated_incidents=[],
    )
    later = Change(
        id="chg-2",
        type=ChangeType.IMAGE_UPDATE,
        service_id="svc-delugevpn",
        description="Image updated.",
        old_value="old",
        new_value="new",
        timestamp=ts(10, 5),
        correlated_incidents=[],
    )
    try:
        database.upsert_change(later)
        database.upsert_change(earlier)
        assert [stored.id for stored in database.list_changes()] == ["chg-1", "chg-2"]
    finally:
        database.close()


def test_database_applies_present_dependency_overrides_to_effective_services(
    tmp_path: Path,
) -> None:
    """Present overrides should surface as user-confirmed edges on effective reads."""
    database = build_database(tmp_path)
    source_service = build_service()
    target_service = build_service().model_copy(
        update={
            "id": "svc-radarr",
            "name": "Radarr",
            "category": "arr",
            "descriptor_id": "arr/radarr",
            "container_id": "container-radarr",
            "image": "lscr.io/linuxserver/radarr:latest",
            "dependencies": [],
            "dependents": [],
            "active_findings": 0,
            "active_incidents": 0,
        }
    )
    try:
        database.upsert_service(source_service)
        database.upsert_service(target_service)
        database.upsert_dependency_override(
            DependencyOverride(
                source_service_id=source_service.id,
                target_service_id=target_service.id,
                state=DependencyOverrideState.PRESENT,
                description="Confirmed by the local admin after reviewing the service path.",
                updated_at=ts(18, 0),
            )
        )

        stored_source = database.get_service(source_service.id)
        stored_target = database.get_service(target_service.id)

        assert stored_source is not None
        assert stored_source.dependencies[-1] == DependencyEdge(
            target_service_id=target_service.id,
            confidence=DependencyConfidence.USER_CONFIRMED,
            source=DependencySource.USER,
            description="Confirmed by the local admin after reviewing the service path.",
        )
        assert stored_target is not None
        assert stored_target.dependents == [source_service.id]
    finally:
        database.close()


def test_database_applies_absent_dependency_overrides_after_service_refresh(
    tmp_path: Path,
) -> None:
    """Absent overrides should continue hiding discovered edges after later upserts."""
    database = build_database(tmp_path)
    source_service = build_service().model_copy(
        update={
            "dependencies": [
                DependencyEdge(
                    target_service_id="svc-radarr",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.DESCRIPTOR,
                    description="Descriptor declares the dependency.",
                )
            ],
            "dependents": [],
        }
    )
    target_service = build_service().model_copy(
        update={
            "id": "svc-radarr",
            "name": "Radarr",
            "category": "arr",
            "descriptor_id": "arr/radarr",
            "container_id": "container-radarr",
            "image": "lscr.io/linuxserver/radarr:latest",
            "dependencies": [],
            "dependents": [source_service.id],
            "active_findings": 0,
            "active_incidents": 0,
        }
    )
    try:
        database.upsert_service(source_service)
        database.upsert_service(target_service)
        database.upsert_dependency_override(
            DependencyOverride(
                source_service_id=source_service.id,
                target_service_id=target_service.id,
                state=DependencyOverrideState.ABSENT,
                description=None,
                updated_at=ts(18, 5),
            )
        )

        database.upsert_service(source_service)

        stored_source = database.get_service(source_service.id)
        stored_target = database.get_service(target_service.id)

        assert stored_source is not None
        assert stored_source.dependencies == []
        assert stored_target is not None
        assert stored_target.dependents == []
    finally:
        database.close()


def test_database_replaces_service_check_overrides_by_scope(tmp_path: Path) -> None:
    """Service-scoped monitoring overrides should round-trip separately per scope."""
    database = build_database(tmp_path)
    active_override = ServiceCheckOverride(
        scope=ServiceCheckOverrideScope.ACTIVE,
        service_id="svc-delugevpn",
        check_id="endpoint_probe",
        enabled=True,
        interval_seconds=120,
        updated_at=ts(18, 10),
    )
    staged_override = ServiceCheckOverride(
        scope=ServiceCheckOverrideScope.STAGED,
        service_id="svc-delugevpn",
        check_id="endpoint_probe",
        enabled=False,
        interval_seconds=45,
        updated_at=ts(18, 11),
    )

    try:
        database.replace_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE,
            overrides=[active_override],
        )
        database.replace_service_check_overrides(
            scope=ServiceCheckOverrideScope.STAGED,
            overrides=[staged_override],
        )

        assert database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE
        ) == [active_override]
        assert database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.STAGED
        ) == [staged_override]

        database.replace_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE,
            overrides=[],
        )

        assert database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE
        ) == []
        assert database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.STAGED
        ) == [staged_override]
    finally:
        database.close()


def test_database_persists_capability_runtime_signals(tmp_path: Path) -> None:
    """Capability runtime signals should round-trip through the keyed singleton table."""
    database = build_database(tmp_path)
    discovery_signal = build_discovery_pipeline_runtime_signal(
        recorded_at=ts(12, 0),
        last_succeeded_at=ts(12, 0),
        unraid_api_reachable=True,
        docker_api_reachable=True,
        trigger="integration_test",
    )
    scheduler_signal = build_scheduler_runtime_signal(
        recorded_at=ts(12, 5),
        last_completed_at=ts(12, 5),
        executed_check_ids=["dns_resolution", "endpoint_probe"],
    )
    executor_signal = build_executor_process_runtime_signal(
        recorded_at=ts(12, 10),
        listener_started_at=ts(12, 10),
        socket_path=tmp_path / "executor.sock",
        docker_socket_path=tmp_path / "docker.sock",
        socket_reachable=True,
        docker_accessible=True,
    )

    try:
        database.upsert_capability_runtime_signal(discovery_signal)
        database.upsert_capability_runtime_signal(scheduler_signal)
        database.upsert_capability_runtime_signal(executor_signal)

        stored_discovery = database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.DISCOVERY_PIPELINE
        )
        stored_executor = database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.EXECUTOR_PROCESS
        )

        assert isinstance(stored_discovery, DiscoveryPipelineRuntimeSignal)
        assert stored_discovery == discovery_signal
        assert isinstance(stored_executor, ExecutorProcessRuntimeSignal)
        assert stored_executor == executor_signal
        assert [
            signal.source.value for signal in database.list_capability_runtime_signals()
        ] == [
            "check_scheduler",
            "discovery_pipeline",
            "executor_process",
        ]

        database.delete_capability_runtime_signal(
            CapabilityRuntimeSignalSource.CHECK_SCHEDULER
        )

        assert database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.CHECK_SCHEDULER
        ) is None
    finally:
        database.close()
