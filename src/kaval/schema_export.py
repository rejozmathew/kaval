"""Schema export helpers for Phase 0 contracts."""

from __future__ import annotations

import json
from pathlib import Path

from kaval.models import (
    ApprovalToken,
    Change,
    EvidenceStep,
    ExecutorActionRequest,
    ExecutorActionResult,
    Finding,
    Incident,
    IncidentLifecycleTransition,
    Investigation,
    JournalEntry,
    KavalModel,
    NotificationPayload,
    OperationalMemoryQuery,
    OperationalMemoryResult,
    RemediationProposal,
    ResearchStep,
    RiskAssessment,
    Service,
    SystemProfile,
    UserNote,
)

PHASE0_SCHEMA_MODELS: tuple[tuple[str, type[KavalModel]], ...] = (
    ("approval_token.json", ApprovalToken),
    ("change.json", Change),
    ("evidence_step.json", EvidenceStep),
    ("executor_action_request.json", ExecutorActionRequest),
    ("executor_action_result.json", ExecutorActionResult),
    ("finding.json", Finding),
    ("incident.json", Incident),
    ("incident_lifecycle_transition.json", IncidentLifecycleTransition),
    ("investigation.json", Investigation),
    ("journal_entry.json", JournalEntry),
    ("notification_payload.json", NotificationPayload),
    ("operational_memory_query.json", OperationalMemoryQuery),
    ("operational_memory_result.json", OperationalMemoryResult),
    ("remediation_proposal.json", RemediationProposal),
    ("research_step.json", ResearchStep),
    ("risk_assessment.json", RiskAssessment),
    ("service.json", Service),
    ("system_profile.json", SystemProfile),
    ("user_note.json", UserNote),
)


def export_phase0_schemas(output_dir: Path) -> list[Path]:
    """Export the Phase 0 model schemas into the target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    exported_paths: list[Path] = []
    for filename, model_type in PHASE0_SCHEMA_MODELS:
        schema_path = output_dir / filename
        schema = model_type.model_json_schema()
        schema_path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        exported_paths.append(schema_path)
    return exported_paths
