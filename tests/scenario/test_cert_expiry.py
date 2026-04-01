"""Scenario test for the certificate-expiry investigation workflow."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.discovery.descriptors import load_service_descriptors
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.models import (
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
    UserNote,
)

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for scenario assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_cert_expiry_workflow_persists_structured_no_restart_investigation(
    tmp_path: Path,
) -> None:
    """The cert-expiry path should produce structured evidence and no restart recommendation."""
    database = seed_database(tmp_path / "cert-expiry.db")

    try:
        workflow = InvestigationWorkflow(
            database=database,
            descriptors=tuple(load_service_descriptors([SERVICES_DIR])),
        )

        result = workflow.run(
            incident_id="inc-cert-expiry",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.status.value == "completed"
        assert result.synthesis.evidence_summary
        assert "TLS certificate for proxy.zactower.com expires in 1.0 days." in (
            result.prompt_bundle.user_prompt
        )
        assert (
            result.synthesis.inference.root_cause
            == "TLS certificate for proxy.zactower.com is near expiry and needs renewal."
        )
        assert result.synthesis.recommendation.action_type == "none"
        assert result.investigation.remediation is None
        assert result.investigation.recurrence_count == 1
        assert result.synthesis.degraded_mode_note is not None

        persisted_incident = database.get_incident("inc-cert-expiry")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.INVESTIGATING
        assert persisted_incident.investigation_id == result.investigation.id
    finally:
        database.close()


def seed_database(database_path: Path) -> KavalDatabase:
    """Seed the SQLite store with the certificate-expiry scenario."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    service = Service(
        id="svc-nginx_proxy_manager",
        name="Nginx Proxy Manager",
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.DEGRADED,
        descriptor_id="networking/nginx_proxy_manager",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-npm",
        vm_id=None,
        image="jc21/nginx-proxy-manager:latest",
        endpoints=[
            Endpoint(
                name="proxy_https",
                protocol=EndpointProtocol.HTTPS,
                host="proxy.zactower.com",
                port=443,
                path="/",
                url=None,
                auth_required=False,
                expected_status=200,
            )
        ],
        dependencies=[],
        dependents=[],
        last_check=ts(14, 24),
        active_findings=1,
        active_incidents=1,
    )
    finding = Finding(
        id="find-cert-expiry",
        title="Nginx Proxy Manager certificate expires soon",
        severity=Severity.HIGH,
        domain="tls",
        service_id=service.id,
        summary="TLS certificate for proxy.zactower.com expires in 1.0 days.",
        evidence=[
            Evidence(
                kind=EvidenceKind.PROBE,
                source="tls_cert",
                summary="Certificate expires in 1.0 days.",
                observed_at=ts(14, 23),
                data={
                    "host": "proxy.zactower.com",
                    "port": 443,
                    "expires_at": "2026-04-01T14:23:00Z",
                },
            )
        ],
        impact=(
            "Clients may soon reject the reverse-proxy endpoint until the certificate "
            "is renewed."
        ),
        confidence=0.97,
        status=FindingStatus.GROUPED,
        incident_id="inc-cert-expiry",
        related_changes=[],
        created_at=ts(14, 23),
        resolved_at=None,
    )
    incident = Incident(
        id="inc-cert-expiry",
        title="Reverse-proxy certificate nearing expiry",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=[finding.id],
        all_findings=[finding.id],
        affected_services=[service.id],
        triggering_symptom=finding.summary,
        suspected_cause="TLS certificate for proxy.zactower.com is near expiry and needs renewal.",
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.93,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(14, 23),
        grouping_window_end=ts(14, 28),
        created_at=ts(14, 23),
        updated_at=ts(14, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    journal_entry = JournalEntry(
        id="jrnl-cert-expiry-1",
        incident_id="inc-cert-old",
        date=date(2026, 3, 12),
        services=[service.id],
        summary="The reverse-proxy certificate nearly expired last month.",
        root_cause="Certificate renewal was skipped during provider maintenance.",
        resolution="Renewed the certificate manually and reloaded the reverse proxy.",
        time_to_resolution_minutes=18.0,
        model_used="local",
        tags=["tls", "certificates", "nginx_proxy_manager"],
        lesson="Certificate renewal should happen before the warning window collapses.",
        recurrence_count=1,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(10, 0),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=None,
    )
    user_note = UserNote(
        id="note-cert-expiry",
        service_id=service.id,
        note=(
            "Certificates for proxy.zactower.com are renewed manually after DNS "
            "challenge validation."
        ),
        safe_for_model=True,
        last_verified_at=ts(12, 0),
        stale=False,
        added_at=ts(12, 0),
        updated_at=ts(12, 30),
    )

    database.upsert_service(service)
    database.upsert_finding(finding)
    database.upsert_incident(incident)
    database.upsert_journal_entry(journal_entry)
    database.upsert_user_note(user_note)
    return database
