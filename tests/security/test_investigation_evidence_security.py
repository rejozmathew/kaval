"""Security tests for investigation evidence collection."""

from __future__ import annotations

from datetime import UTC, date, datetime

from kaval.investigation.evidence import collect_incident_evidence, query_operational_memory
from kaval.models import (
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    RedactionLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
    UserNote,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_query_operational_memory_redacts_secret_like_note_content() -> None:
    """Safe notes should still be redacted before model context use."""
    incident = build_incident()
    result = query_operational_memory(
        incident=incident,
        journal_entries=[
            JournalEntry(
                id="jrnl-1",
                incident_id="inc-old-1",
                date=date(2026, 3, 20),
                services=["svc-delugevpn"],
                summary="Investigated https://user:pass@example.internal/path",
                root_cause="VPN token=abcd1234",
                resolution="Authorization: Bearer really-secret",
                time_to_resolution_minutes=4.0,
                model_used="local",
                tags=["vpn"],
                lesson="password=hunter2",
                recurrence_count=1,
                confidence=JournalConfidence.CONFIRMED,
                user_confirmed=True,
                last_verified_at=ts(9, 0),
                applies_to_version=None,
                superseded_by=None,
                stale_after_days=None,
            )
        ],
        user_notes=[
            UserNote(
                id="note-safe",
                service_id="svc-delugevpn",
                note="Provider token=unsafe-value",
                safe_for_model=True,
                last_verified_at=ts(9, 0),
                stale=False,
                added_at=ts(9, 0),
                updated_at=ts(9, 5),
            )
        ],
        system_profile=None,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    )

    assert result.journal_entries[0].summary == "Investigated https://[REDACTED]@example.internal/path"
    assert result.journal_entries[0].root_cause == "VPN token=[REDACTED]"
    assert result.journal_entries[0].resolution == "Authorization: Bearer [REDACTED]"
    assert result.journal_entries[0].lesson == "password=[REDACTED]"
    assert result.user_notes[0].note == "Provider token=[REDACTED]"


def test_collect_incident_evidence_redacts_container_log_excerpts() -> None:
    """Collected log excerpts should redact secret-like content before persistence."""
    incident = build_incident()
    findings = [
        Finding(
            id="find-1",
            title="DelugeVPN tunnel inactive",
            severity=Severity.HIGH,
            domain="downloads",
            service_id="svc-delugevpn",
            summary="Tunnel inactive.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="docker_logs",
                    summary="VPN tunnel inactive",
                    observed_at=ts(14, 0),
                    data={"message": "VPN tunnel inactive"},
                )
            ],
            impact="Downloads cannot proceed.",
            confidence=0.95,
            status=FindingStatus.GROUPED,
            incident_id="inc-1",
            related_changes=[],
            created_at=ts(14, 0),
            resolved_at=None,
        )
    ]

    result = collect_incident_evidence(
        incident=incident,
        findings=findings,
        services=[
            build_service(
                service_id="svc-delugevpn",
                name="DelugeVPN",
                container_id="def456",
            )
        ],
        changes=[],
        journal_entries=[],
        user_notes=[],
        log_reader=lambda _container_id, _tail_lines: (
            "Authorization: Bearer top-secret-token\n"
            "url=https://user:pass@example.internal/path\n"
        ),
        now=ts(14, 5),
    )

    log_step = result.evidence_steps[2]
    assert log_step.result_data["excerpt_lines"] == [
        "Authorization: Bearer [REDACTED]",
        "url=https://[REDACTED]@example.internal/path",
    ]


def test_query_operational_memory_excludes_unknown_version_scope_from_prompt_context() -> None:
    """Version-scoped entries should be withheld if the current service version is unknown."""
    incident = build_incident()
    result = query_operational_memory(
        incident=incident,
        services=[
            Service(
                id="svc-delugevpn",
                name="DelugeVPN",
                type=ServiceType.CONTAINER,
                category="downloads",
                status=ServiceStatus.HEALTHY,
                descriptor_id="downloads/delugevpn",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="def456",
                vm_id=None,
                image="binhex/arch-delugevpn",
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
                dependents=[],
                last_check=None,
                active_findings=1,
                active_incidents=1,
            )
        ],
        journal_entries=[
            JournalEntry(
                id="jrnl-versioned",
                incident_id="inc-old-1",
                date=date(2026, 3, 20),
                services=["svc-delugevpn"],
                summary="Version-specific tunnel issue.",
                root_cause="VPN library regression.",
                resolution="Restarted DelugeVPN.",
                time_to_resolution_minutes=4.0,
                model_used="local",
                tags=["vpn"],
                lesson="Applies only to newer builds.",
                recurrence_count=1,
                confidence=JournalConfidence.CONFIRMED,
                user_confirmed=True,
                last_verified_at=ts(9, 0),
                applies_to_version="svc-delugevpn >= 2.0.0",
                superseded_by=None,
                stale_after_days=180,
            )
        ],
        user_notes=[],
        system_profile=None,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        now=ts(14, 5),
    )

    assert result.journal_entries == []
    assert result.warnings == [
        (
            "Excluded 1 version-scoped journal entry because the current service version "
            "could not be verified."
        )
    ]


def test_query_operational_memory_cloud_redaction_applies_service_placeholders() -> None:
    """Cloud-level memory queries should redact service identifiers before prompt assembly."""
    incident = build_incident()
    service = build_service(
        service_id="svc-delugevpn",
        name="DelugeVPN",
        container_id="def456",
    )
    result = query_operational_memory(
        incident=incident,
        services=[service],
        journal_entries=[
            JournalEntry(
                id="jrnl-cloud",
                incident_id="inc-old-cloud",
                date=date(2026, 3, 20),
                services=["svc-delugevpn"],
                summary="svc-delugevpn DelugeVPN check http://delugevpn:8112/?token=abc123",
                root_cause="Service DelugeVPN reported a secret=shhh",
                resolution="Cookie: sessionid=abcdef",
                time_to_resolution_minutes=4.0,
                model_used="local",
                tags=["vpn"],
                lesson="Inspect /mnt/user/appdata/delugevpn for this service.",
                recurrence_count=1,
                confidence=JournalConfidence.CONFIRMED,
                user_confirmed=True,
                last_verified_at=ts(9, 0),
                applies_to_version=None,
                superseded_by=None,
                stale_after_days=180,
            )
        ],
        user_notes=[
            UserNote(
                id="note-cloud",
                service_id="svc-delugevpn",
                note="DelugeVPN svc-delugevpn URL=http://delugevpn:8112/?api_key=xyz789",
                safe_for_model=True,
                last_verified_at=ts(9, 0),
                stale=False,
                added_at=ts(9, 0),
                updated_at=ts(9, 5),
            )
        ],
        system_profile=None,
        redaction_level=RedactionLevel.REDACT_FOR_CLOUD,
        now=ts(14, 5),
    )

    entry = result.journal_entries[0]
    note = result.user_notes[0]
    assert "svc-delugevpn" not in entry.summary
    assert "DelugeVPN" not in entry.summary
    assert "abc123" not in entry.summary
    assert "shhh" not in entry.root_cause
    assert "abcdef" not in entry.resolution
    assert "/mnt/user/appdata/delugevpn" not in entry.lesson
    assert "xyz789" not in note.note
    assert "[SERVICE_ID_1]" in entry.summary
    assert "[SERVICE_1]" in entry.summary
    assert "http://[REDACTED_URL]" in entry.summary
    assert "Cookie: [REDACTED]" in entry.resolution


def build_incident() -> Incident:
    """Build a minimal DelugeVPN incident for security tests."""
    return Incident(
        id="inc-1",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-1"],
        all_findings=["find-1"],
        affected_services=["svc-delugevpn"],
        triggering_symptom="VPN tunnel inactive",
        suspected_cause="VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.95,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(14, 0),
        grouping_window_end=ts(14, 5),
        created_at=ts(14, 0),
        updated_at=ts(14, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_service(*, service_id: str, name: str, container_id: str) -> object:
    """Build the minimal service payload needed by the evidence collector."""
    from kaval.models import Service, ServiceStatus, ServiceType

    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=None,
        container_id=container_id,
        vm_id=None,
        image="binhex/arch-delugevpn:latest",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=1,
        active_incidents=1,
    )
