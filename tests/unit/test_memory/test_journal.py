"""Unit tests for Operational Memory journal writing."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.memory.journal import OperationalJournalService
from kaval.models import (
    CauseConfirmationSource,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    ModelUsed,
    RemediationProposal,
    RemediationStatus,
    RiskAssessment,
    RiskLevel,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_operational_journal_service_resolves_incident_and_persists_likely_entry(
    tmp_path: Path,
) -> None:
    """A resolved incident should auto-write a journal entry with likely confidence."""
    database = build_database(tmp_path)
    try:
        incident = build_incident()
        investigation = build_investigation()
        findings = [
            build_finding("find-delugevpn", service_id="svc-delugevpn"),
            build_finding("find-radarr", service_id="svc-radarr"),
        ]
        database.upsert_incident(incident)
        database.upsert_investigation(investigation)
        for finding in findings:
            database.upsert_finding(finding)

        result = OperationalJournalService(database=database).resolve_incident(
            incident_id=incident.id,
            cause_confirmation_source=CauseConfirmationSource.RESOLUTION_INFERRED,
            now=ts(14, 40),
        )

        assert result.incident.status is IncidentStatus.RESOLVED
        assert result.incident.resolution_mechanism == "Restarted delugevpn container."
        assert result.incident.cause_confirmation_source is (
            CauseConfirmationSource.RESOLUTION_INFERRED
        )
        assert result.incident.confirmed_cause is None
        assert result.incident.journal_entry_id == result.journal_entry.id
        assert result.journal_entry.confidence is JournalConfidence.LIKELY
        assert result.journal_entry.user_confirmed is False
        assert result.journal_entry.recurrence_count == 1
        assert result.journal_entry.stale_after_days == 180
        assert all(finding.status is FindingStatus.RESOLVED for finding in result.findings)
        assert all(finding.resolved_at == ts(14, 40) for finding in result.findings)
    finally:
        database.close()


def test_operational_journal_service_records_user_confirmed_cause_and_recurrence(
    tmp_path: Path,
) -> None:
    """User-confirmed resolutions should produce confirmed journal trust metadata."""
    database = build_database(tmp_path)
    try:
        incident = build_incident()
        investigation = build_investigation()
        database.upsert_incident(incident)
        database.upsert_investigation(investigation)
        database.upsert_finding(build_finding("find-delugevpn", service_id="svc-delugevpn"))
        database.upsert_journal_entry(
            build_prior_journal_entry(
                incident_id="inc-prior",
                recurrence_count=1,
            )
        )

        result = OperationalJournalService(database=database).resolve_incident(
            incident_id=incident.id,
            cause_confirmation_source=CauseConfirmationSource.USER_CONFIRMED,
            confirmed_cause="DelugeVPN lost its VPN tunnel.",
            lesson="Restart restored the tunnel after provider instability.",
            now=ts(14, 45),
        )

        assert result.incident.confirmed_cause == "DelugeVPN lost its VPN tunnel."
        assert result.incident.cause_confirmation_source is (
            CauseConfirmationSource.USER_CONFIRMED
        )
        assert result.journal_entry.confidence is JournalConfidence.CONFIRMED
        assert result.journal_entry.user_confirmed is True
        assert result.journal_entry.last_verified_at == ts(14, 45)
        assert result.journal_entry.recurrence_count == 2
        assert result.journal_entry.lesson == (
            "Restart restored the tunnel after provider instability."
        )
    finally:
        database.close()


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_incident() -> Incident:
    """Build a reusable incident for journal tests."""
    return Incident(
        id="inc-delugevpn",
        title="Radarr and DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.AWAITING_APPROVAL,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn", "find-radarr"],
        affected_services=["svc-delugevpn", "svc-radarr"],
        triggering_symptom="Radarr download client unavailable",
        suspected_cause="DelugeVPN lost its VPN tunnel.",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.92,
        investigation_id="inv-delugevpn",
        approved_actions=[],
        changes_correlated=["chg-delugevpn-restart"],
        grouping_window_start=ts(14, 0),
        grouping_window_end=ts(14, 5),
        created_at=ts(14, 0),
        updated_at=ts(14, 30),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation() -> Investigation:
    """Build a reusable completed investigation for journal tests."""
    return Investigation(
        id="inv-delugevpn",
        incident_id="inc-delugevpn",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[],
        research_steps=[],
        root_cause="DelugeVPN lost its VPN tunnel.",
        confidence=0.94,
        model_used=ModelUsed.BOTH,
        cloud_model_calls=1,
        journal_entries_referenced=["jrnl-prior"],
        user_notes_referenced=[],
        recurrence_count=1,
        remediation=RemediationProposal(
            action_type="restart_container",
            target="delugevpn",
            rationale="Restart the affected VPN container.",
            risk_assessment=RiskAssessment(
                overall_risk=RiskLevel.LOW,
                checks=[],
                reversible=True,
                warnings=[],
            ),
            status=RemediationStatus.VERIFIED,
        ),
        started_at=ts(14, 5),
        completed_at=ts(14, 30),
    )


def build_finding(finding_id: str, *, service_id: str) -> Finding:
    """Build a reusable finding associated with the incident."""
    return Finding(
        id=finding_id,
        title="Service degraded",
        severity=Severity.HIGH,
        domain="downloads",
        service_id=service_id,
        summary="Service unavailable during investigation.",
        evidence=[],
        impact="Download path blocked.",
        confidence=0.9,
        status=FindingStatus.INVESTIGATING,
        incident_id="inc-delugevpn",
        related_changes=[],
        created_at=ts(14, 0),
        resolved_at=None,
    )


def build_prior_journal_entry(*, incident_id: str, recurrence_count: int):
    """Build one prior journal entry for recurrence testing."""
    from datetime import date

    from kaval.models import JournalEntry

    return JournalEntry(
        id="jrnl-prior",
        incident_id=incident_id,
        date=date(2026, 3, 15),
        services=["svc-delugevpn"],
        summary="Previous DelugeVPN tunnel drop.",
        root_cause="VPN session dropped upstream.",
        resolution="Restarted delugevpn container.",
        time_to_resolution_minutes=7.0,
        model_used="local",
        tags=["delugevpn"],
        lesson="Restart resolved the issue.",
        recurrence_count=recurrence_count,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(10, 0),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=180,
    )
