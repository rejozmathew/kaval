"""Security-focused tests for investigation prompt templates."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.prompts import (
    INVESTIGATION_RESPONSE_SCHEMA,
    INVESTIGATION_SYSTEM_PROMPT,
    build_investigation_prompt_bundle,
)
from kaval.models import (
    EvidenceStep,
    Incident,
    IncidentStatus,
    OperationalMemoryResult,
    RedactionLevel,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_prompt_contract_is_restart_only() -> None:
    """The investigation prompt contract must not permit broader remediation actions."""
    schema_text = json.dumps(INVESTIGATION_RESPONSE_SCHEMA, sort_keys=True)

    assert '"enum": ["restart_container", "none"]' in schema_text
    assert "pull_specific_image_tag" not in schema_text
    assert "start_vm" not in schema_text
    assert "stop_vm" not in schema_text


def test_system_prompt_forbids_unapproved_actions_and_external_research() -> None:
    """The system prompt should keep research explicit and remediation bounded."""
    bundle = build_investigation_prompt_bundle(
        incident=build_incident(),
        evidence=build_evidence_result(),
        now=ts(14, 30),
    )

    assert "Do not invent missing evidence, external research" in INVESTIGATION_SYSTEM_PROMPT
    assert "Use provided Tier 2 research only when it is present." in INVESTIGATION_SYSTEM_PROMPT
    assert "If research was skipped, missing, or offline" in INVESTIGATION_SYSTEM_PROMPT
    assert "Do not recommend rollback, VM actions, config mutation" in bundle.system_prompt
    assert "Recommendation may be `restart_container` only, or `none`" in bundle.user_prompt


def build_incident() -> Incident:
    """Build a minimal incident for prompt-security tests."""
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


def build_evidence_result() -> InvestigationEvidenceResult:
    """Build a minimal evidence bundle for prompt-security tests."""
    return InvestigationEvidenceResult(
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="inspect_service_state",
                target="svc-delugevpn",
                result_summary="DelugeVPN is degraded.",
                result_data={"service_id": "svc-delugevpn", "service_status": "degraded"},
                timestamp=ts(14, 1),
            )
        ],
        operational_memory=OperationalMemoryResult(
            system_profile=None,
            journal_entries=[],
            user_notes=[],
            recurrence_count=0,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ),
    )
