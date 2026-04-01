"""Unit tests for Phase 2A investigation prompt templates."""

from __future__ import annotations

from datetime import UTC, date, datetime

from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.prompts import (
    INVESTIGATION_RESPONSE_SCHEMA,
    build_investigation_prompt_bundle,
)
from kaval.investigation.research import (
    ServiceResearchResult,
    Tier2ResearchBundle,
    Tier2ResearchStatus,
    Tier2ResearchTarget,
)
from kaval.models import (
    EvidenceStep,
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    OperationalMemoryResult,
    RedactionLevel,
    ResearchStep,
    Severity,
    UserNote,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_prompt_bundle_renders_structured_incident_evidence_and_contract() -> None:
    """Prompt rendering should preserve the evidence/inference/recommendation contract."""
    bundle = build_investigation_prompt_bundle(
        incident=build_incident(),
        evidence=build_evidence_result(),
        now=ts(14, 30),
    )

    assert bundle.response_schema_name == "phase2a_investigation"
    assert bundle.response_schema == INVESTIGATION_RESPONSE_SCHEMA
    assert "evidence_summary" in bundle.user_prompt
    assert "restart_container" in bundle.system_prompt
    assert "Use provided Tier 2 research only when it is present." in bundle.system_prompt
    assert "Do not recommend rollback, VM actions, config mutation" in bundle.system_prompt
    assert "Evidence Steps:" in bundle.user_prompt
    assert "1. [inspect_service_state] svc-delugevpn" in bundle.user_prompt
    assert "Operational Memory:" in bundle.user_prompt
    assert "\"recurrence_count\": 2" in bundle.user_prompt


def test_prompt_bundle_includes_degraded_mode_notes() -> None:
    """Prompt rendering should carry degraded-mode context into the user prompt."""
    bundle = build_investigation_prompt_bundle(
        incident=build_incident(),
        evidence=build_evidence_result(),
        degraded_reasons=[
            (
                "Research steps skipped (no internet access). Root cause analysis "
                "based on local evidence only. Confidence may be lower than usual."
            )
        ],
        now=ts(14, 30),
    )

    assert "Degraded mode details:" in bundle.user_prompt
    assert "Research steps skipped (no internet access)." in bundle.user_prompt
    assert "Phase Constraints:" in bundle.user_prompt


def test_prompt_bundle_renders_tier2_research_context_when_present() -> None:
    """Prompt rendering should expose ordered Tier 2 research and structured results."""
    bundle = build_investigation_prompt_bundle(
        incident=build_incident(),
        evidence=build_evidence_result(),
        research=build_research_bundle(),
        now=ts(14, 30),
    )

    assert "Research Steps:" in bundle.user_prompt
    assert "1. [fetch_github_release]" in bundle.user_prompt
    assert "Research Results:" in bundle.user_prompt
    assert "\"github_status\": \"success\"" in bundle.user_prompt
    assert "\"dockerhub_status\": \"partial\"" in bundle.user_prompt


def build_incident() -> Incident:
    """Build one deterministic DelugeVPN incident."""
    return Incident(
        id="inc-delugevpn",
        title="Radarr and DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn", "find-radarr"],
        affected_services=["svc-radarr", "svc-delugevpn"],
        triggering_symptom="Radarr download client unavailable",
        suspected_cause="DelugeVPN VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.95,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=["chg-delugevpn-restart"],
        grouping_window_start=ts(14, 23),
        grouping_window_end=ts(14, 28),
        created_at=ts(14, 23),
        updated_at=ts(14, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_evidence_result() -> InvestigationEvidenceResult:
    """Build one deterministic evidence bundle for prompt tests."""
    return InvestigationEvidenceResult(
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="inspect_service_state",
                target="svc-delugevpn",
                result_summary=(
                    "DelugeVPN is currently degraded; container state=running, "
                    "restarts=4."
                ),
                result_data={
                    "service_id": "svc-delugevpn",
                    "service_status": "degraded",
                    "container": {"restart_count": 4},
                },
                timestamp=ts(14, 24),
            ),
            EvidenceStep(
                order=2,
                action="inspect_dependency_graph",
                target="inc-delugevpn",
                result_summary=(
                    "Dependency walk shows DelugeVPN upstream of 1 affected service(s): Radarr."
                ),
                result_data={
                    "edges": [
                        {
                            "source_service_id": "svc-radarr",
                            "target_service_id": "svc-delugevpn",
                            "confidence": "inferred",
                        }
                    ]
                },
                timestamp=ts(14, 25),
            ),
        ],
        operational_memory=OperationalMemoryResult(
            system_profile=None,
            journal_entries=[
                JournalEntry(
                    id="jrnl-delugevpn-1",
                    incident_id="inc-old-1",
                    date=date(2026, 3, 20),
                    services=["svc-delugevpn"],
                    summary="DelugeVPN tunnel dropped again.",
                    root_cause="VPN tunnel inactive.",
                    resolution="Restarted DelugeVPN container.",
                    time_to_resolution_minutes=6.0,
                    model_used="local",
                    tags=["delugevpn"],
                    lesson="Recurrence points to unstable provider sessions.",
                    recurrence_count=2,
                    confidence=JournalConfidence.CONFIRMED,
                    user_confirmed=True,
                    last_verified_at=ts(11, 0),
                    applies_to_version=None,
                    superseded_by=None,
                    stale_after_days=None,
                )
            ],
            user_notes=[
                UserNote(
                    id="note-delugevpn",
                    service_id="svc-delugevpn",
                    note="Provider endpoint rotates often.",
                    safe_for_model=True,
                    last_verified_at=ts(12, 0),
                    stale=False,
                    added_at=ts(12, 0),
                    updated_at=ts(12, 30),
                )
            ],
            recurrence_count=2,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ),
    )


def build_research_bundle() -> Tier2ResearchBundle:
    """Build one deterministic Tier 2 research bundle for prompt tests."""
    return Tier2ResearchBundle(
        research_steps=[
            ResearchStep(
                order=1,
                action="fetch_github_release",
                source="https://github.com/binhex/arch-delugevpn/releases",
                result_summary="Found GitHub release v5.0.1 for binhex/arch-delugevpn.",
                timestamp=ts(14, 26),
            )
        ],
        service_results=[
            ServiceResearchResult(
                target=Tier2ResearchTarget(
                    service_id="svc-delugevpn",
                    service_name="DelugeVPN",
                    change_id="chg-delugevpn-image",
                    current_image="binhex/arch-delugevpn:5.0.1",
                    previous_image="binhex/arch-delugevpn:5.0.0",
                    current_tag="5.0.1",
                    previous_tag="5.0.0",
                    github_repository=None,
                    dockerhub_reference=None,
                ),
                github_status=Tier2ResearchStatus.SUCCESS,
                dockerhub_status=Tier2ResearchStatus.PARTIAL,
                warnings=["Previous Docker Hub tag metadata was not found."],
            )
        ],
        skipped_offline=False,
        degraded_reasons=[],
        warnings=["Previous Docker Hub tag metadata was not found."],
    )
