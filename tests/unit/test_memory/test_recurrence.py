"""Unit tests for Operational Memory recurrence detection."""

from __future__ import annotations

from datetime import UTC, date, datetime

from kaval.memory.recurrence import detect_recurrences
from kaval.models import (
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_detect_recurrences_counts_only_trusted_matching_history() -> None:
    """Recurrence counts should use trusted matching entries and exclude speculative matches."""
    incident = build_incident(
        suspected_cause="DelugeVPN VPN tunnel dropped after provider flap",
        triggering_symptom="VPN tunnel inactive",
    )
    analysis = detect_recurrences(
        incident=incident,
        journal_entries=[
            build_journal_entry(
                entry_id="jrnl-confirmed",
                summary="VPN tunnel dropped again.",
                root_cause="Provider VPN tunnel inactive.",
                confidence=JournalConfidence.CONFIRMED,
            ),
            build_journal_entry(
                entry_id="jrnl-likely",
                summary="Another VPN tunnel outage.",
                root_cause="Tunnel reconnect failed after ISP change.",
                confidence=JournalConfidence.LIKELY,
            ),
            build_journal_entry(
                entry_id="jrnl-speculative",
                summary="Potential VPN tunnel problem.",
                root_cause="Maybe tunnel inactivity.",
                confidence=JournalConfidence.SPECULATIVE,
                user_confirmed=False,
            ),
            build_journal_entry(
                entry_id="jrnl-unrelated",
                summary="Disk filled on DelugeVPN.",
                root_cause="Appdata volume out of space.",
                confidence=JournalConfidence.CONFIRMED,
            ),
        ],
    )

    assert analysis.recurrence_count == 2
    assert analysis.matched_entry_ids == ("jrnl-confirmed", "jrnl-likely")
    assert analysis.excluded_speculative_matches == 1


def test_detect_recurrences_requires_matching_failure_signals_not_only_service_overlap() -> None:
    """Same-service history should not count as a recurrence when the failure pattern differs."""
    incident = build_incident(
        suspected_cause="NPM TLS handshake failure after image update",
        triggering_symptom="TLS handshake failed",
    )
    analysis = detect_recurrences(
        incident=incident,
        journal_entries=[
            build_journal_entry(
                entry_id="jrnl-unrelated",
                services=["svc-delugevpn"],
                summary="DelugeVPN disk filled unexpectedly.",
                root_cause="Appdata share out of space.",
                confidence=JournalConfidence.CONFIRMED,
            )
        ],
    )

    assert analysis.recurrence_count == 0
    assert analysis.matched_entry_ids == ()
    assert analysis.excluded_speculative_matches == 0


def build_incident(*, suspected_cause: str, triggering_symptom: str) -> Incident:
    """Build a minimal incident for recurrence tests."""
    return Incident(
        id="inc-1",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-1"],
        all_findings=["find-1"],
        affected_services=["svc-delugevpn"],
        triggering_symptom=triggering_symptom,
        suspected_cause=suspected_cause,
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
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


def build_journal_entry(
    *,
    entry_id: str,
    summary: str,
    root_cause: str,
    confidence: JournalConfidence,
    services: list[str] | None = None,
    user_confirmed: bool = True,
) -> JournalEntry:
    """Build a minimal journal entry for recurrence tests."""
    return JournalEntry(
        id=entry_id,
        incident_id=f"inc-{entry_id}",
        date=date(2026, 3, 20),
        services=services or ["svc-delugevpn"],
        summary=summary,
        root_cause=root_cause,
        resolution="Restarted the affected service.",
        time_to_resolution_minutes=5.0,
        model_used="local",
        tags=["vpn", "tunnel"] if "tunnel" in summary.casefold() else ["storage"],
        lesson="Capture the recurring pattern.",
        recurrence_count=1,
        confidence=confidence,
        user_confirmed=user_confirmed,
        last_verified_at=ts(10, 0),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=180,
    )
