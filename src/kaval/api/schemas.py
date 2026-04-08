"""Typed request and response contracts for the Kaval API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from kaval.credentials.models import CredentialRequestMode
from kaval.integrations.adapter_fallback import AdapterFactFreshness
from kaval.integrations.service_adapters import AdapterStatus
from kaval.memory.note_models import UserNoteCreate, UserNoteUpdate
from kaval.models import (
    Change,
    DependencyConfidence,
    DependencySource,
    DescriptorSource,
    DnsTarget,
    Incident,
    Investigation,
    JsonValue,
    KavalModel,
    PortNumber,
    RedactionLevel,
    Service,
)


class HealthResponse(KavalModel):
    """Readiness status for the FastAPI application."""

    status: Literal["ok"]
    database_ready: bool


class ServiceGraphEdge(KavalModel):
    """One directed edge in the service graph response."""

    source_service_id: str
    target_service_id: str
    confidence: DependencyConfidence
    source: DependencySource
    description: str | None


class ServiceGraphNodeMeta(KavalModel):
    """Additional graph-only insight metadata for one service node."""

    service_id: str
    target_insight_level: int = Field(ge=0, le=5)
    improve_available: bool = False


class ServiceGraphResponse(KavalModel):
    """Read-only graph view built from persisted services."""

    services: list[Service]
    edges: list[ServiceGraphEdge]
    node_meta: list[ServiceGraphNodeMeta] = Field(default_factory=list)


class GraphEdgeUpsertRequest(KavalModel):
    """Admin mutation payload for confirming or editing one graph edge."""

    source_service_id: str
    target_service_id: str
    previous_source_service_id: str | None = None
    previous_target_service_id: str | None = None
    description: str | None = None


class GraphEdgeMutationResponse(KavalModel):
    """Mutation result for one graph-edge admin operation."""

    edge: ServiceGraphEdge | None = None
    audit_change: Change


class WidgetOverallStatus(StrEnum):
    """Overall health states exposed through the widget summary."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"


class WidgetSummaryResponse(KavalModel):
    """Compact health summary for homepage-style consumers."""

    status: WidgetOverallStatus = WidgetOverallStatus.HEALTHY
    total_services: int
    active_findings: int
    active_incidents: int
    healthy_services: int
    degraded_services: int
    down_services: int
    stopped_services: int
    unknown_services: int
    last_updated: datetime | None
    services_total: int = 0
    services_healthy: int = 0
    services_degraded: int = 0
    services_down: int = 0
    last_investigation: datetime | None = None
    effectiveness_score: int = Field(default=0, ge=0, le=100)
    adapters_healthy: int = Field(default=0, ge=0)
    adapters_degraded: int = Field(default=0, ge=0)
    pending_approvals: int = Field(default=0, ge=0)
    url: str | None = None
    refresh_interval_seconds: int | None = Field(default=None, ge=1)


class RealtimeSnapshotResponse(KavalModel):
    """WebSocket payload carrying the latest Phase 1 UI state."""

    kind: Literal["snapshot"]
    graph: ServiceGraphResponse
    incidents: list[Incident]
    investigations: list[Investigation]
    widget: WidgetSummaryResponse


class ServiceDetailAdapterConfigurationState(StrEnum):
    """Configuration states shown in the minimum service-detail insight panel."""

    CONFIGURED = "configured"
    UNCONFIGURED = "unconfigured"
    LOCKED = "locked"


class ServiceDetailAdapterHealthState(StrEnum):
    """Current health states currently derivable for one adapter."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ServiceDetailImproveActionKind(StrEnum):
    """Actionable improvement affordances for the minimum service detail view."""

    CONFIGURE_LOCAL_MODEL = "configure_local_model"
    CONFIGURE_ADAPTER = "configure_adapter"
    UNLOCK_VAULT = "unlock_vault"


class ServiceDetailAdapterResponse(KavalModel):
    """One adapter summary shown in the service detail insight section."""

    adapter_id: str
    display_name: str
    configuration_state: ServiceDetailAdapterConfigurationState
    configuration_summary: str
    health_state: ServiceDetailAdapterHealthState
    health_summary: str
    missing_credentials: list[str] = Field(default_factory=list)
    supported_fact_names: list[str] = Field(default_factory=list)


class ServiceDetailImproveActionResponse(KavalModel):
    """One improvement action shown in the service detail insight section."""

    kind: ServiceDetailImproveActionKind
    title: str
    detail: str


class ServiceDetailInsightSectionResponse(KavalModel):
    """The minimum service-detail insight payload for Phase 3A."""

    current_level: int
    adapter_available: bool
    adapters: list[ServiceDetailAdapterResponse] = Field(default_factory=list)
    improve_actions: list[ServiceDetailImproveActionResponse] = Field(default_factory=list)
    fact_summary_available: bool = False


class ServiceDetailResponse(KavalModel):
    """A later-enrichable service-detail response contract."""

    service: Service
    insight_section: ServiceDetailInsightSectionResponse


class DescriptorViewMatchResponse(KavalModel):
    """Rendered match rules for one descriptor view."""

    image_patterns: list[str] = Field(default_factory=list)
    container_name_patterns: list[str] = Field(default_factory=list)


class DescriptorViewEndpointResponse(KavalModel):
    """One rendered descriptor endpoint."""

    name: str
    port: int
    path: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    healthy_when: str | None = None


class DescriptorViewLogSignalsResponse(KavalModel):
    """Rendered log-signal section for one descriptor."""

    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DescriptorViewContainerDependencyResponse(KavalModel):
    """One rendered container dependency entry."""

    name: str
    alternatives: list[str] = Field(default_factory=list)


class DescriptorViewFailureModeResponse(KavalModel):
    """One rendered failure-mode entry."""

    trigger: str
    likely_cause: str
    check_first: list[str] = Field(default_factory=list)


class DescriptorViewInspectionSurfaceResponse(KavalModel):
    """One rendered inspection-surface entry."""

    id: str
    type: str
    description: str
    endpoint: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    read_only: bool = True
    facts_provided: list[str] = Field(default_factory=list)
    confidence_effect: str | None = None
    version_range: str | None = None


class DescriptorViewCredentialHintResponse(KavalModel):
    """One rendered credential-hint entry."""

    key: str
    description: str
    location: str
    prompt: str | None = None


class ServiceDescriptorViewResponse(KavalModel):
    """Rendered descriptor view contract for the admin UI."""

    descriptor_id: str
    file_path: str
    write_target_path: str
    name: str
    category: str
    source: DescriptorSource
    verified: bool = True
    generated_at: datetime | None = None
    project_url: str | None = None
    icon: str | None = None
    match: DescriptorViewMatchResponse
    endpoints: list[DescriptorViewEndpointResponse] = Field(default_factory=list)
    dns_targets: list[DnsTarget] = Field(default_factory=list)
    log_signals: DescriptorViewLogSignalsResponse = Field(
        default_factory=DescriptorViewLogSignalsResponse
    )
    typical_dependency_containers: list[DescriptorViewContainerDependencyResponse] = Field(
        default_factory=list
    )
    typical_dependency_shares: list[str] = Field(default_factory=list)
    common_failure_modes: list[DescriptorViewFailureModeResponse] = Field(
        default_factory=list
    )
    investigation_context: str | None = None
    inspection_surfaces: list[DescriptorViewInspectionSurfaceResponse] = Field(
        default_factory=list
    )
    credential_hints: list[DescriptorViewCredentialHintResponse] = Field(
        default_factory=list
    )
    raw_yaml: str


class DescriptorEditMode(StrEnum):
    """Supported save modes for the descriptor editor."""

    FORM = "form"
    YAML = "yaml"


class DescriptorEditMatchRequest(KavalModel):
    """Editable match patterns for the descriptor form mode."""

    image_patterns: list[str] = Field(default_factory=list)
    container_name_patterns: list[str] = Field(default_factory=list)


class DescriptorEditEndpointRequest(KavalModel):
    """Editable endpoint fields supported by the descriptor form mode."""

    name: str
    port: int = PortNumber
    path: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    healthy_when: str | None = None


class DescriptorEditContainerDependencyRequest(KavalModel):
    """Editable container dependency entry for descriptor form mode."""

    name: str
    alternatives: list[str] = Field(default_factory=list)


class ServiceDescriptorSaveRequest(KavalModel):
    """Mutation payload for the bounded Phase 3C descriptor editor."""

    mode: DescriptorEditMode
    match: DescriptorEditMatchRequest | None = None
    endpoints: list[DescriptorEditEndpointRequest] | None = None
    typical_dependency_containers: list[DescriptorEditContainerDependencyRequest] | None = None
    typical_dependency_shares: list[str] | None = None
    raw_yaml: str | None = None

    @model_validator(mode="after")
    def validate_edit_payload(self) -> ServiceDescriptorSaveRequest:
        """Require exactly the fields supported by the selected edit mode."""
        if self.mode == DescriptorEditMode.FORM:
            if (
                self.match is None
                or self.endpoints is None
                or self.typical_dependency_containers is None
                or self.typical_dependency_shares is None
            ):
                msg = "form mode requires match, endpoints, and dependency fields"
                raise ValueError(msg)
            if self.raw_yaml is not None:
                msg = "form mode does not accept raw_yaml"
                raise ValueError(msg)
            return self

        if self.raw_yaml is None or not self.raw_yaml.strip():
            msg = "yaml mode requires raw_yaml"
            raise ValueError(msg)
        if (
            self.match is not None
            or self.endpoints is not None
            or self.typical_dependency_containers is not None
            or self.typical_dependency_shares is not None
        ):
            msg = "yaml mode only accepts raw_yaml"
            raise ValueError(msg)
        return self


class ServiceDescriptorSaveResponse(KavalModel):
    """Mutation response for one descriptor editor save action."""

    descriptor: ServiceDescriptorViewResponse
    audit_change: Change


class ServiceDescriptorGenerateResponse(KavalModel):
    """Mutation response for one quarantined auto-generated descriptor trigger."""

    service_id: str
    service_name: str
    descriptor: ServiceDescriptorViewResponse
    audit_change: Change
    warnings: list[str] = Field(default_factory=list)


class QuarantinedDescriptorQueueItemResponse(KavalModel):
    """One quarantined descriptor candidate shown in the review queue."""

    descriptor: ServiceDescriptorViewResponse
    review_state: str
    review_updated_at: datetime
    matching_services: list[Service] = Field(default_factory=list)


class QuarantinedDescriptorActionResponse(KavalModel):
    """Mutation result for one quarantined descriptor review action."""

    descriptor_id: str
    action: str
    review_state: str | None = None
    descriptor: ServiceDescriptorViewResponse | None = None
    audit_change: Change


class DescriptorCommunityExportResponse(KavalModel):
    """Read-only export payload for a reviewed community descriptor candidate."""

    descriptor_id: str
    target_path: str
    yaml_text: str
    omitted_fields: list[str] = Field(default_factory=list)


class DescriptorValidationAffectedServiceResponse(KavalModel):
    """One currently bound service and its likely post-edit match status."""

    service_id: str
    service_name: str
    likely_matches: bool


class DescriptorValidationMatchPreviewResponse(KavalModel):
    """Likely descriptor-match impact preview for the current environment."""

    current_service_likely_matches: bool
    affected_services: list[DescriptorValidationAffectedServiceResponse] = Field(
        default_factory=list
    )


class DescriptorValidationDependencyImpactResponse(KavalModel):
    """Declared dependency changes inferred from the edited descriptor."""

    added_container_dependencies: list[str] = Field(default_factory=list)
    removed_container_dependencies: list[str] = Field(default_factory=list)
    added_share_dependencies: list[str] = Field(default_factory=list)
    removed_share_dependencies: list[str] = Field(default_factory=list)


class ServiceDescriptorValidationPreviewResponse(KavalModel):
    """Bounded descriptor preview assembled before a reviewed save."""

    descriptor_id: str
    write_target_path: str
    match: DescriptorValidationMatchPreviewResponse
    dependency_impact: DescriptorValidationDependencyImpactResponse


class ServiceDescriptorValidationResponse(KavalModel):
    """Validation and preview result for one pending descriptor edit."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    preview: ServiceDescriptorValidationPreviewResponse | None = None


class AdapterFactSourceType(StrEnum):
    """Provenance source labels for adapter-imported facts."""

    DEEP_INSPECTION_ADAPTER = "deep_inspection_adapter"


class ServiceAdapterFactsItemResponse(KavalModel):
    """One adapter-backed facts payload for a single service."""

    adapter_id: str
    display_name: str
    service_id: str
    service_name: str
    source: AdapterFactSourceType = AdapterFactSourceType.DEEP_INSPECTION_ADAPTER
    read_only: bool = True
    configuration_state: ServiceDetailAdapterConfigurationState
    configuration_summary: str
    health_state: ServiceDetailAdapterHealthState
    health_summary: str
    missing_credentials: list[str] = Field(default_factory=list)
    supported_fact_names: list[str] = Field(default_factory=list)
    execution_status: AdapterStatus | None = None
    facts_available: bool = False
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    excluded_paths: list[str] = Field(default_factory=list)
    applied_redaction_level: RedactionLevel | None = None
    facts_observed_at: datetime | None = None
    stale_at: datetime | None = None
    next_refresh_at: datetime | None = None
    refresh_interval_minutes: int = Field(ge=1)
    freshness: AdapterFactFreshness
    reason: str | None = None


class ServiceAdapterFactsResponse(KavalModel):
    """Read-only adapter-imported facts contract for one service."""

    service_id: str
    service_name: str
    checked_at: datetime
    facts_available: bool = False
    adapters: list[ServiceAdapterFactsItemResponse] = Field(default_factory=list)


class CreateCredentialRequestRequest(KavalModel):
    """API payload for creating one credential request."""

    incident_id: str
    investigation_id: str | None = None
    service_id: str
    credential_key: str
    reason: str


class CredentialRequestChoiceRequest(KavalModel):
    """API payload for recording one user choice on a credential request."""

    mode: CredentialRequestMode
    decided_by: str


class TelegramCredentialCallbackRequest(KavalModel):
    """API payload for replaying one Telegram callback identifier."""

    callback_id: str
    decided_by: str


class TelegramUpdateProcessingStatus(StrEnum):
    """Processing outcomes for inbound Telegram updates."""

    PROCESSED = "processed"
    IGNORED = "ignored"


class TelegramInboundChat(KavalModel):
    """Subset of Telegram chat metadata needed for Phase 3B ingress."""

    model_config = ConfigDict(extra="ignore")

    id: int


class TelegramInboundMessage(KavalModel):
    """Subset of Telegram message metadata needed for command routing."""

    model_config = ConfigDict(extra="ignore")

    message_id: int
    chat: TelegramInboundChat
    text: str | None = None


class TelegramInboundUpdateRequest(KavalModel):
    """Subset of one Telegram update used for inbound memory commands."""

    model_config = ConfigDict(extra="ignore")

    update_id: int
    message: TelegramInboundMessage | None = None


class TelegramInboundUpdateResponse(KavalModel):
    """API response describing how one inbound Telegram update was handled."""

    status: TelegramUpdateProcessingStatus
    detail: str
    reply_delivery_status: Literal["sent", "skipped", "failed"] | None = None


class CredentialSecretSubmissionRequest(KavalModel):
    """API payload for submitting one secret value after mode selection."""

    secret_value: str
    submitted_by: str


class VaultUnlockRequest(KavalModel):
    """API payload for initializing or unlocking the credential vault."""

    master_passphrase: str


class CreateUserNoteRequest(UserNoteCreate):
    """API payload for creating one active user note."""


class UpdateUserNoteRequest(UserNoteUpdate):
    """API payload for updating one active user note."""
