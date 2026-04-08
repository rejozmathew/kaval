"""Schema export helpers for repository contracts."""

from __future__ import annotations

import json
from pathlib import Path

from kaval.api.schemas import (
    DescriptorCommunityExportResponse,
    QuarantinedDescriptorActionResponse,
    QuarantinedDescriptorQueueItemResponse,
    ServiceAdapterFactsResponse,
    ServiceDescriptorGenerateResponse,
    ServiceDescriptorSaveRequest,
    ServiceDescriptorSaveResponse,
    ServiceDescriptorValidationResponse,
    ServiceDescriptorViewResponse,
)
from kaval.discovery.descriptors import ServiceDescriptor
from kaval.integrations.service_adapters import AdapterResult
from kaval.integrations.webhooks import WebhookEvent
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
    ServiceInsight,
    ServiceLifecycle,
    ServiceLifecycleEvent,
    SystemProfile,
    UserNote,
)

SCHEMA_MODELS: tuple[tuple[str, type[KavalModel]], ...] = (
    ("approval_token.json", ApprovalToken),
    ("adapter_result.json", AdapterResult),
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
    ("service_adapter_facts_response.json", ServiceAdapterFactsResponse),
    ("descriptor_community_export_response.json", DescriptorCommunityExportResponse),
    ("quarantined_descriptor_action_response.json", QuarantinedDescriptorActionResponse),
    ("quarantined_descriptor_queue_item_response.json", QuarantinedDescriptorQueueItemResponse),
    ("service_descriptor_generate_response.json", ServiceDescriptorGenerateResponse),
    ("service_descriptor_save_request.json", ServiceDescriptorSaveRequest),
    ("service_descriptor_save_response.json", ServiceDescriptorSaveResponse),
    ("service_descriptor_validation_response.json", ServiceDescriptorValidationResponse),
    ("service_descriptor_view_response.json", ServiceDescriptorViewResponse),
    ("service_insight.json", ServiceInsight),
    ("service_lifecycle.json", ServiceLifecycle),
    ("service_lifecycle_event.json", ServiceLifecycleEvent),
    ("service_descriptor.json", ServiceDescriptor),
    ("system_profile.json", SystemProfile),
    ("user_note.json", UserNote),
    ("webhook_event.json", WebhookEvent),
)


def export_schemas(output_dir: Path) -> list[Path]:
    """Export repository model schemas into the target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    exported_paths: list[Path] = []
    for filename, model_type in SCHEMA_MODELS:
        schema_path = output_dir / filename
        schema = model_type.model_json_schema()
        schema_path.write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        exported_paths.append(schema_path)
    return exported_paths


def export_phase0_schemas(output_dir: Path) -> list[Path]:
    """Backwards-compatible wrapper for the existing export entrypoint."""
    return export_schemas(output_dir)
