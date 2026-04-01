"""Scenario test for an Authentik SSO failure investigation."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.discovery.descriptors import load_service_descriptors
from kaval.investigation.prompts import InvestigationSynthesis
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
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


def test_authentik_sso_failure_workflow_uses_memory_context_and_keeps_no_action(
    tmp_path: Path,
) -> None:
    """The Authentik SSO path should use memory context and stay within no-action bounds."""
    database = seed_database(tmp_path / "authentik-sso.db")

    try:
        workflow = InvestigationWorkflow(
            database=database,
            descriptors=tuple(load_service_descriptors([SERVICES_DIR])),
            log_reader=lambda container_id, _tail_lines: (
                (
                    "2026-03-31T17:24:01Z error: OAuth source request failed for provider "
                    "google-oauth\n"
                )
                if container_id == "container-authentik"
                else "2026-03-31T17:24:02Z warn: OIDC login callback rejected\n"
            ),
            synthesizer=AuthentikSsoSynthesizer(),
        )

        result = workflow.run(
            incident_id="inc-authentik-sso",
            trigger=InvestigationTrigger.AUTO,
            now=ts(17, 30),
        )

        assert result.investigation.status.value == "completed"
        assert result.investigation.remediation is None
        assert result.investigation.recurrence_count == 1
        assert "Google OAuth federated source configured" in result.prompt_bundle.user_prompt
        assert "unsafe client secret" not in result.prompt_bundle.user_prompt
        assert result.synthesis.inference.root_cause == (
            "Authentik OAuth source requests to Google are failing, so downstream SSO "
            "callbacks are breaking even though the protected app is still up."
        )
        assert result.synthesis.recommendation.action_type == "none"

        persisted_incident = database.get_incident("inc-authentik-sso")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.INVESTIGATING
        assert persisted_incident.investigation_id == result.investigation.id
    finally:
        database.close()


class AuthentikSsoSynthesizer:
    """Deterministic no-action synthesis for the Authentik SSO scenario."""

    def synthesize(self, **_: object) -> InvestigationSynthesis:
        """Return one fixed no-action synthesis for the representative SSO failure."""
        return InvestigationSynthesis.model_validate(
            {
                "evidence_summary": [
                    "Authentik logs show OAuth source request failures.",
                    "The downstream protected app is rejecting SSO callbacks.",
                    "Operational Memory notes Google OAuth federation on this server.",
                ],
                "inference": {
                    "root_cause": (
                        "Authentik OAuth source requests to Google are failing, so "
                        "downstream SSO callbacks are breaking even though the protected "
                        "app is still up."
                    ),
                    "confidence": 0.88,
                    "reasoning": (
                        "The failure is concentrated in the identity provider and likely "
                        "requires OAuth configuration review rather than a bounded restart."
                    ),
                },
                "recommendation": {
                    "summary": "No restart-only remediation is justified for this SSO failure.",
                    "action_type": "none",
                    "target": None,
                    "rationale": (
                        "The current evidence points to identity-provider configuration or "
                        "upstream OAuth drift, which is outside the restart-only scope."
                    ),
                    "risk": {
                        "overall_risk": "medium",
                        "checks": [
                            {
                                "check": "bounded_action_scope",
                                "result": "unknown",
                                "detail": (
                                    "The likely fix is OAuth source review, not a bounded "
                                    "restart."
                                ),
                            }
                        ],
                        "reversible": True,
                        "warnings": [
                            (
                                "Restarting Authentik is unlikely to fix an upstream OAuth "
                                "configuration mismatch."
                            )
                        ],
                    },
                },
                "degraded_mode_note": None,
                "model_used": ModelUsed.NONE.value,
                "cloud_model_calls": 0,
            }
        )


def seed_database(database_path: Path) -> KavalDatabase:
    """Seed the SQLite store with the representative Authentik SSO failure path."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    authentik = Service(
        id="svc-authentik",
        name="Authentik",
        type=ServiceType.CONTAINER,
        category="identity",
        status=ServiceStatus.DEGRADED,
        descriptor_id="identity/authentik",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-authentik",
        vm_id=None,
        image="ghcr.io/goauthentik/server:2026.3.1",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=["svc-nextcloud"],
        last_check=ts(17, 24),
        active_findings=1,
        active_incidents=1,
    )
    nextcloud = Service(
        id="svc-nextcloud",
        name="Nextcloud",
        type=ServiceType.CONTAINER,
        category="cloud",
        status=ServiceStatus.DEGRADED,
        descriptor_id="cloud/nextcloud",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-nextcloud",
        vm_id=None,
        image="linuxserver/nextcloud:31.0.0",
        endpoints=[],
        dns_targets=[],
        dependencies=[
            DependencyEdge(
                target_service_id="svc-authentik",
                confidence=DependencyConfidence.INFERRED,
                source=DependencySource.DESCRIPTOR,
                description="Nextcloud SSO depends on Authentik.",
            )
        ],
        dependents=[],
        last_check=ts(17, 24),
        active_findings=1,
        active_incidents=1,
    )
    authentik_finding = Finding(
        id="find-authentik-oauth",
        title="Authentik OAuth source request failed",
        severity=Severity.HIGH,
        domain="identity",
        service_id=authentik.id,
        summary="Authentik logs show repeated OAuth source request failures for Google SSO.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="docker_logs",
                summary="OAuth source request failed",
                observed_at=ts(17, 23),
                data={"matched_patterns": ["OAuth source request failed"]},
            )
        ],
        impact="Users cannot complete federated SSO logins.",
        confidence=0.95,
        status=FindingStatus.GROUPED,
        incident_id="inc-authentik-sso",
        related_changes=[],
        created_at=ts(17, 23),
        resolved_at=None,
    )
    nextcloud_finding = Finding(
        id="find-nextcloud-sso",
        title="Nextcloud SSO login failed",
        severity=Severity.HIGH,
        domain="identity",
        service_id=nextcloud.id,
        summary="Nextcloud OIDC callbacks are failing after Authentik redirects users.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="application_logs",
                summary="OIDC callback rejected",
                observed_at=ts(17, 24),
                data={"message": "OIDC callback rejected"},
            )
        ],
        impact="Protected applications cannot complete SSO logins.",
        confidence=0.93,
        status=FindingStatus.GROUPED,
        incident_id="inc-authentik-sso",
        related_changes=[],
        created_at=ts(17, 24),
        resolved_at=None,
    )
    incident = Incident(
        id="inc-authentik-sso",
        title="Authentik and Nextcloud SSO degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=[authentik_finding.id],
        all_findings=[authentik_finding.id, nextcloud_finding.id],
        affected_services=[authentik.id, nextcloud.id],
        triggering_symptom=nextcloud_finding.summary,
        suspected_cause="Authentik OAuth source requests to Google are failing.",
        confirmed_cause=None,
        root_cause_service=authentik.id,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(17, 23),
        grouping_window_end=ts(17, 28),
        created_at=ts(17, 23),
        updated_at=ts(17, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    journal_entry = JournalEntry(
        id="jrnl-authentik-oauth-1",
        incident_id="inc-old-authentik",
        date=date(2026, 3, 12),
        services=[authentik.id],
        summary="Authentik SSO failed after Google OAuth source drift.",
        root_cause="Google OAuth client settings no longer matched the Authentik source.",
        resolution="Reviewed the Authentik source and restored the Google OAuth client values.",
        time_to_resolution_minutes=9.0,
        model_used="local",
        tags=["authentik", "sso", "oauth", "google"],
        lesson="Review Google OAuth client configuration before restarting identity services.",
        recurrence_count=1,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(10, 0),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=180,
    )
    safe_note = UserNote(
        id="note-authentik-safe",
        service_id=authentik.id,
        note=(
            "Google OAuth federated source configured. If SSO breaks after Google Cloud "
            "changes, check the OAuth client ID in Authentik sources."
        ),
        safe_for_model=True,
        last_verified_at=ts(12, 0),
        stale=False,
        added_at=ts(12, 0),
        updated_at=ts(12, 5),
    )
    unsafe_note = UserNote(
        id="note-authentik-unsafe",
        service_id=authentik.id,
        note="unsafe client secret: super-secret-google-client",
        safe_for_model=False,
        last_verified_at=ts(12, 0),
        stale=False,
        added_at=ts(12, 0),
        updated_at=ts(12, 6),
    )

    database.upsert_service(authentik)
    database.upsert_service(nextcloud)
    database.upsert_finding(authentik_finding)
    database.upsert_finding(nextcloud_finding)
    database.upsert_incident(incident)
    database.upsert_journal_entry(journal_entry)
    database.upsert_user_note(safe_note)
    database.upsert_user_note(unsafe_note)
    return database
