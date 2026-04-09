"""Core data contracts for Kaval Phase 0."""

from __future__ import annotations

from datetime import date, datetime
from enum import IntEnum, StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kaval.monitoring_thresholds import (
    monitoring_threshold_fields_present,
    validate_monitoring_threshold_fields,
)

type JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

ConfidenceScore = Field(ge=0.0, le=1.0)
NonNegativeInt = Field(ge=0)
NonNegativeFloat = Field(ge=0.0)
PortNumber = Field(ge=1, le=65535)
HttpStatusCode = Field(ge=100, le=599)
PositiveOrder = Field(ge=1)


class KavalModel(BaseModel):
    """Base model with strict contract validation."""

    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    """Supported severity values."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(StrEnum):
    """Lifecycle states for incidents."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class FindingStatus(StrEnum):
    """Lifecycle states for findings."""

    NEW = "new"
    GROUPED = "grouped"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    STALE = "stale"


class FindingFeedbackReason(StrEnum):
    """Explicit operator reasons for dismissing one finding as noise."""

    FALSE_POSITIVE = "false_positive"
    EXPECTED_BEHAVIOR = "expected_behavior"
    NOT_IMPORTANT = "not_important"
    ALREADY_AWARE = "already_aware"


class CauseConfirmationSource(StrEnum):
    """How a cause was confirmed or inferred."""

    USER_CONFIRMED = "user_confirmed"
    RESOLUTION_INFERRED = "resolution_inferred"
    RECURRENCE_PATTERN = "recurrence_pattern"
    UNCONFIRMED = "unconfirmed"


class InvestigationTrigger(StrEnum):
    """Supported investigation triggers."""

    AUTO = "auto"
    WEBHOOK = "webhook"
    USER_REQUEST = "user_request"


class InvestigationStatus(StrEnum):
    """Lifecycle states for investigations."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ModelUsed(StrEnum):
    """Models used during an investigation."""

    LOCAL = "local"
    CLOUD = "cloud"
    BOTH = "both"
    NONE = "none"


class RemediationStatus(StrEnum):
    """Lifecycle states for remediation proposals."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    VERIFIED = "verified"


class RiskLevel(StrEnum):
    """Risk levels for remediation proposals."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskCheckResult(StrEnum):
    """Outcomes for individual risk checks."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class ServiceType(StrEnum):
    """Supported service types."""

    CONTAINER = "container"
    VM = "vm"
    PLUGIN = "plugin"
    SHARE = "share"
    SYSTEM = "system"
    EXTERNAL = "external"
    NETWORK = "network"


class ServiceStatus(StrEnum):
    """Supported service health states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"
    STOPPED = "stopped"


class ServiceInsightLevel(IntEnum):
    """Supported per-service insight levels."""

    DISCOVERED = 0
    MATCHED = 1
    MONITORED = 2
    INVESTIGATION_READY = 3
    DEEP_INSPECTED = 4
    OPERATOR_ENRICHED = 5


class DescriptorSource(StrEnum):
    """Origins for service descriptors."""

    SHIPPED = "shipped"
    AUTO_GENERATED = "auto_generated"
    USER = "user"


class DependencyConfidence(StrEnum):
    """Confidence levels for dependency edges."""

    CONFIGURED = "configured"
    RUNTIME_OBSERVED = "runtime_observed"
    USER_CONFIRMED = "user_confirmed"
    INFERRED = "inferred"
    AUTO_GENERATED = "auto_generated"


class DependencySource(StrEnum):
    """Sources used to infer a dependency edge."""

    DOCKER_NETWORK = "docker_network"
    SHARED_VOLUME = "shared_volume"
    DESCRIPTOR = "descriptor"
    USER = "user"
    LLM = "llm"


class ChangeType(StrEnum):
    """Supported change event types."""

    SERVICE_ADDED = "service_added"
    SERVICE_REMOVED = "service_removed"
    SERVICE_MISSING = "service_missing"
    SERVICE_RENAMED_OR_REMATCHED = "service_renamed_or_rematched"
    IMAGE_UPDATE = "image_update"
    CONTAINER_RESTART = "container_restart"
    CONFIG_CHANGE = "config_change"
    UNRAID_EVENT = "unraid_event"
    PLUGIN_UPDATE = "plugin_update"
    EXTERNAL_CHANGE = "external_change"


class ServiceLifecycleState(StrEnum):
    """Persistent lifecycle states for a discovered service."""

    ACTIVE = "active"
    MISSING = "missing"
    REMOVED_INTENTIONAL = "removed_intentional"
    REMOVED_DURING_MAINTENANCE = "removed_during_maintenance"


class ServiceLifecycleEventType(StrEnum):
    """Lifecycle events derived from discovery and trusted context."""

    SERVICE_ADDED = "service_added"
    SERVICE_UPDATED = "service_updated"
    SERVICE_RESTARTED = "service_restarted"
    SERVICE_REMOVED_INTENTIONAL = "service_removed_intentional"
    SERVICE_REMOVED_UNEXPECTEDLY = "service_removed_unexpectedly"
    SERVICE_REMOVED_DURING_MAINTENANCE = "service_removed_during_maintenance"
    SERVICE_RENAMED_OR_REMATCHED = "service_renamed_or_rematched"


class JournalConfidence(StrEnum):
    """Confidence levels for journal entries."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SPECULATIVE = "speculative"


class ActionType(StrEnum):
    """Executor action types frozen in Phase 0."""

    RESTART_CONTAINER = "restart_container"
    PULL_SPECIFIC_IMAGE_TAG = "pull_specific_image_tag"
    START_VM = "start_vm"
    STOP_VM = "stop_vm"
    MODIFY_CONFIG_WITH_BACKUP = "modify_config_with_backup"


class NotificationSourceType(StrEnum):
    """Source entity types for notification payloads."""

    FINDING = "finding"
    INCIDENT = "incident"


class NotificationActionType(StrEnum):
    """Supported interactive notification actions."""

    APPROVE = "approve"
    VIEW_DETAILS = "view_details"
    DISMISS = "dismiss"


class NotificationActionStyle(StrEnum):
    """Display styles for interactive notification actions."""

    PRIMARY = "primary"
    SECONDARY = "secondary"
    DANGER = "danger"


class RedactionLevel(StrEnum):
    """Operational memory redaction levels."""

    REDACT_FOR_LOCAL = "redact_for_local"
    REDACT_FOR_CLOUD = "redact_for_cloud"


class EndpointProtocol(StrEnum):
    """Supported endpoint protocols."""

    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"


class DnsRecordType(StrEnum):
    """Supported deterministic DNS record types for Phase 1."""

    A = "A"
    AAAA = "AAAA"


class EvidenceKind(StrEnum):
    """Supported evidence categories."""

    LOG = "log"
    PROBE = "probe"
    CONFIG = "config"
    API = "api"
    EVENT = "event"
    MEMORY = "memory"
    METRIC = "metric"


class ExecutorActionStatus(StrEnum):
    """Execution outcomes returned by the executor."""

    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"


INCIDENT_STATUS_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.DISMISSED,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.AWAITING_APPROVAL,
            IncidentStatus.RESOLVED,
            IncidentStatus.DISMISSED,
        }
    ),
    IncidentStatus.AWAITING_APPROVAL: frozenset(
        {
            IncidentStatus.REMEDIATING,
            IncidentStatus.DISMISSED,
        }
    ),
    IncidentStatus.REMEDIATING: frozenset(
        {
            IncidentStatus.RESOLVED,
            IncidentStatus.DISMISSED,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.DISMISSED: frozenset(),
}


class Evidence(KavalModel):
    """A single piece of evidence attached to a finding."""

    kind: EvidenceKind
    source: str
    summary: str
    observed_at: datetime
    data: JsonValue | None = None


class Endpoint(KavalModel):
    """A network or application endpoint exposed by a service."""

    name: str
    protocol: EndpointProtocol
    host: str | None = None
    port: int | None = PortNumber
    path: str | None = None
    url: str | None = None
    auth_required: bool = False
    expected_status: int | None = HttpStatusCode

    @model_validator(mode="after")
    def validate_location(self) -> Self:
        """Require either a full URL or host/port-style endpoint details."""
        if self.url is None and self.host is None and self.port is None:
            msg = "endpoint must define url or host/port details"
            raise ValueError(msg)
        return self


class DnsTarget(KavalModel):
    """A DNS record target that should resolve for a service."""

    host: str
    record_type: DnsRecordType
    expected_values: list[str] = Field(default_factory=list)


class RiskCheck(KavalModel):
    """An individual remediation risk check."""

    check: str
    result: RiskCheckResult
    detail: str


class RiskAssessment(KavalModel):
    """Structured risk output for a remediation proposal."""

    overall_risk: RiskLevel
    checks: list[RiskCheck]
    reversible: bool
    warnings: list[str]


class RemediationProposal(KavalModel):
    """A proposed system-changing action and its risk assessment."""

    action_type: ActionType
    target: str
    rationale: str
    risk_assessment: RiskAssessment
    status: RemediationStatus


class Change(KavalModel):
    """A timeline event that may correlate with findings or incidents."""

    id: str
    type: ChangeType
    service_id: str | None
    description: str
    old_value: str | None
    new_value: str | None
    timestamp: datetime
    correlated_incidents: list[str]


class Finding(KavalModel):
    """An atomic monitoring observation."""

    id: str
    title: str
    severity: Severity
    domain: str
    service_id: str
    summary: str
    evidence: list[Evidence]
    impact: str
    confidence: float = ConfidenceScore
    status: FindingStatus
    incident_id: str | None
    related_changes: list[Change]
    created_at: datetime
    resolved_at: datetime | None

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        """Keep resolution timestamps aligned with terminal finding states."""
        if self.status == FindingStatus.RESOLVED and self.resolved_at is None:
            msg = "resolved findings must include resolved_at"
            raise ValueError(msg)
        if self.resolved_at is not None and self.status not in {
            FindingStatus.RESOLVED,
            FindingStatus.DISMISSED,
        }:
            msg = "resolved_at is only valid for resolved or dismissed findings"
            raise ValueError(msg)
        return self


class FindingFeedbackRecord(KavalModel):
    """One append-only operator feedback event for a dismissed finding."""

    id: str
    finding_id: str
    service_id: str
    finding_domain: str
    reason: FindingFeedbackReason
    recorded_at: datetime


class EvidenceStep(KavalModel):
    """One step in the evidence gathering chain."""

    order: int = PositiveOrder
    action: str
    target: str
    result_summary: str
    result_data: JsonValue
    timestamp: datetime


class ResearchStep(KavalModel):
    """One step in the investigation research chain."""

    order: int = PositiveOrder
    action: str
    source: str
    result_summary: str
    timestamp: datetime


class Investigation(KavalModel):
    """An investigation tied to a single incident."""

    id: str
    incident_id: str
    trigger: InvestigationTrigger
    status: InvestigationStatus
    evidence_steps: list[EvidenceStep]
    research_steps: list[ResearchStep]
    root_cause: str | None
    confidence: float = ConfidenceScore
    model_used: ModelUsed
    cloud_model_calls: int = NonNegativeInt
    local_input_tokens: int = Field(default=0, ge=0)
    local_output_tokens: int = Field(default=0, ge=0)
    cloud_input_tokens: int = Field(default=0, ge=0)
    cloud_output_tokens: int = Field(default=0, ge=0)
    estimated_cloud_cost_usd: float = Field(default=0.0, ge=0.0)
    estimated_total_cost_usd: float = Field(default=0.0, ge=0.0)
    cloud_escalation_reason: str | None = None
    journal_entries_referenced: list[str]
    user_notes_referenced: list[str]
    recurrence_count: int = NonNegativeInt
    remediation: RemediationProposal | None
    started_at: datetime
    completed_at: datetime | None

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        """Enforce investigation completion metadata consistency."""
        completed_states = {
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
            InvestigationStatus.CANCELLED,
        }
        if self.status in completed_states and self.completed_at is None:
            msg = "completed investigations must include completed_at"
            raise ValueError(msg)
        if self.status == InvestigationStatus.RUNNING and self.completed_at is not None:
            msg = "running investigations cannot include completed_at"
            raise ValueError(msg)
        if self.model_used in {ModelUsed.CLOUD, ModelUsed.BOTH} and self.cloud_model_calls == 0:
            msg = "cloud-backed investigations must record cloud_model_calls"
            raise ValueError(msg)
        if self.model_used == ModelUsed.NONE and self.cloud_model_calls != 0:
            msg = "model_used=none cannot report cloud_model_calls"
            raise ValueError(msg)
        if self.cloud_model_calls == 0 and (
            self.cloud_input_tokens != 0
            or self.cloud_output_tokens != 0
            or self.estimated_cloud_cost_usd != 0.0
        ):
            msg = "investigations without cloud calls cannot report cloud token or cost usage"
            raise ValueError(msg)
        if self.model_used == ModelUsed.NONE and (
            self.local_input_tokens != 0
            or self.local_output_tokens != 0
            or self.estimated_total_cost_usd != 0.0
        ):
            msg = "model_used=none cannot report local token or total cost usage"
            raise ValueError(msg)
        if self.estimated_total_cost_usd < self.estimated_cloud_cost_usd:
            msg = "estimated_total_cost_usd cannot be less than estimated_cloud_cost_usd"
            raise ValueError(msg)
        return self


class DependencyEdge(KavalModel):
    """A directed dependency from one service to another."""

    target_service_id: str
    confidence: DependencyConfidence
    source: DependencySource
    description: str | None


class DependencyOverrideState(StrEnum):
    """Persisted admin intent for one dependency edge."""

    PRESENT = "present"
    ABSENT = "absent"


class DependencyOverride(KavalModel):
    """One persisted admin override for a discovered dependency edge."""

    source_service_id: str
    target_service_id: str
    state: DependencyOverrideState
    description: str | None
    updated_at: datetime


class ServiceCheckOverrideScope(StrEnum):
    """Persisted monitoring-settings scope for one service-level override."""

    ACTIVE = "active"
    STAGED = "staged"


class ServiceCheckOverride(KavalModel):
    """One persisted service-scoped monitoring override."""

    scope: ServiceCheckOverrideScope
    service_id: str
    check_id: str
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)
    updated_at: datetime

    @model_validator(mode="after")
    def validate_override(self) -> Self:
        """Require at least one explicit override field."""
        validate_monitoring_threshold_fields(
            self.check_id,
            tls_warning_days=self.tls_warning_days,
            restart_delta_threshold=self.restart_delta_threshold,
            probe_timeout_seconds=self.probe_timeout_seconds,
        )
        if (
            self.enabled is None
            and self.interval_seconds is None
            and not monitoring_threshold_fields_present(
                tls_warning_days=self.tls_warning_days,
                restart_delta_threshold=self.restart_delta_threshold,
                probe_timeout_seconds=self.probe_timeout_seconds,
            )
        ):
            msg = (
                "service check override requires enabled, interval_seconds, "
                "or threshold settings"
            )
            raise ValueError(msg)
        return self


class MaintenanceScope(StrEnum):
    """Supported maintenance window scopes."""

    GLOBAL = "global"
    SERVICE = "service"


class MaintenanceWindowRecord(KavalModel):
    """One persisted time-bound maintenance window."""

    scope: MaintenanceScope
    service_id: str | None = None
    started_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        """Require valid scope shape and a positive maintenance duration."""
        if self.scope is MaintenanceScope.GLOBAL and self.service_id is not None:
            msg = "global maintenance windows must not set service_id"
            raise ValueError(msg)
        if self.scope is MaintenanceScope.SERVICE and not self.service_id:
            msg = "service maintenance windows require service_id"
            raise ValueError(msg)
        if self.expires_at <= self.started_at:
            msg = "maintenance expires_at must be after started_at"
            raise ValueError(msg)
        return self


class ServiceInsight(KavalModel):
    """The current insight depth available for one service."""

    level: ServiceInsightLevel


class ServiceLifecycle(KavalModel):
    """Lifecycle metadata retained for one service across discovery cycles."""

    state: ServiceLifecycleState = ServiceLifecycleState.ACTIVE
    last_event: ServiceLifecycleEventType | None = None
    changed_at: datetime | None = None
    previous_names: list[str] = Field(default_factory=list)
    previous_descriptor_ids: list[str] = Field(default_factory=list)


class ServiceLifecycleEvent(KavalModel):
    """One lifecycle event emitted for a service."""

    service_id: str
    event_type: ServiceLifecycleEventType
    timestamp: datetime
    summary: str
    change_id: str | None = None
    related_service_ids: list[str] = Field(default_factory=list)


class Service(KavalModel):
    """A discovered service in the monitored environment."""

    id: str
    name: str
    type: ServiceType
    category: str
    status: ServiceStatus
    descriptor_id: str | None
    descriptor_source: DescriptorSource | None
    container_id: str | None
    vm_id: str | None
    image: str | None
    endpoints: list[Endpoint]
    dns_targets: list[DnsTarget] = Field(default_factory=list)
    dependencies: list[DependencyEdge]
    dependents: list[str]
    insight: ServiceInsight | None = None
    lifecycle: ServiceLifecycle = Field(default_factory=ServiceLifecycle)
    last_check: datetime | None
    active_findings: int = NonNegativeInt
    active_incidents: int = NonNegativeInt

    @model_validator(mode="after")
    def populate_insight(self) -> Self:
        """Populate the base insight level when callers do not provide one."""
        if self.insight is None:
            self.insight = derive_service_insight(self)
        return self


def derive_service_insight(
    service: Service,
    *,
    local_model_configured: bool = False,
    deep_inspection_configured: bool = False,
    operator_enriched: bool = False,
) -> ServiceInsight:
    """Derive the current service insight level from the available capability chain."""
    level = ServiceInsightLevel.DISCOVERED

    if service.descriptor_id is not None:
        level = ServiceInsightLevel.MATCHED
        if service.last_check is not None:
            level = ServiceInsightLevel.MONITORED
            if local_model_configured:
                level = ServiceInsightLevel.INVESTIGATION_READY
                if deep_inspection_configured:
                    level = ServiceInsightLevel.DEEP_INSPECTED
                    if operator_enriched:
                        level = ServiceInsightLevel.OPERATOR_ENRICHED

    return ServiceInsight(level=level)


class Incident(KavalModel):
    """A grouped root-cause-centric unit of investigation."""

    id: str
    title: str
    severity: Severity
    status: IncidentStatus
    trigger_findings: list[str]
    all_findings: list[str]
    affected_services: list[str]
    triggering_symptom: str | None
    suspected_cause: str | None
    confirmed_cause: str | None
    root_cause_service: str | None
    resolution_mechanism: str | None
    cause_confirmation_source: CauseConfirmationSource | None
    confidence: float = ConfidenceScore
    investigation_id: str | None
    approved_actions: list[str]
    changes_correlated: list[str]
    grouping_window_start: datetime
    grouping_window_end: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    mttr_seconds: float | None = NonNegativeFloat
    journal_entry_id: str | None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        """Enforce incident temporal consistency and confirmation metadata."""
        if self.grouping_window_end < self.grouping_window_start:
            msg = "grouping_window_end cannot precede grouping_window_start"
            raise ValueError(msg)
        if self.updated_at < self.created_at:
            msg = "updated_at cannot precede created_at"
            raise ValueError(msg)
        if self.status == IncidentStatus.RESOLVED and self.resolved_at is None:
            msg = "resolved incidents must include resolved_at"
            raise ValueError(msg)
        if self.resolved_at is not None and self.status not in {
            IncidentStatus.RESOLVED,
            IncidentStatus.DISMISSED,
        }:
            msg = "resolved_at is only valid for resolved or dismissed incidents"
            raise ValueError(msg)
        if self.mttr_seconds is not None and self.resolved_at is None:
            msg = "mttr_seconds requires resolved_at"
            raise ValueError(msg)
        if self.confirmed_cause is not None and self.cause_confirmation_source is None:
            msg = "confirmed_cause requires cause_confirmation_source"
            raise ValueError(msg)
        return self

    def can_transition_to(self, next_status: IncidentStatus) -> bool:
        """Return whether the incident may move to the requested state."""
        return next_status in INCIDENT_STATUS_TRANSITIONS[self.status]


class IncidentGroupingRule(KavalModel):
    """Rules that govern finding-to-incident grouping."""

    window_minutes: int = Field(default=5, ge=1)
    group_by_dependency_chain: bool = True
    group_by_common_upstream: bool = True


class IncidentLifecycleTransition(KavalModel):
    """A frozen transition contract for the incident state machine."""

    from_status: IncidentStatus
    to_status: IncidentStatus
    reason: str | None = None

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        """Ensure the transition follows the Phase 0 lifecycle contract."""
        if self.to_status not in INCIDENT_STATUS_TRANSITIONS[self.from_status]:
            msg = f"invalid incident transition: {self.from_status} -> {self.to_status}"
            raise ValueError(msg)
        return self


class HardwareProfile(KavalModel):
    """System hardware facts stored in operational memory."""

    cpu: str
    memory_gb: float = NonNegativeFloat
    gpu: str | None
    ups: str | None


class ArrayProfile(KavalModel):
    """Array and cache summary for storage-related investigations."""

    parity_drives: int = NonNegativeInt
    data_drives: int = NonNegativeInt
    cache: str | None
    total_tb: float = NonNegativeFloat
    used_tb: float = NonNegativeFloat

    @model_validator(mode="after")
    def validate_capacity(self) -> Self:
        """Prevent impossible used-capacity values."""
        if self.used_tb > self.total_tb:
            msg = "used_tb cannot exceed total_tb"
            raise ValueError(msg)
        return self


class StorageProfile(KavalModel):
    """Storage facts stored in operational memory."""

    array: ArrayProfile


class NetworkingProfile(KavalModel):
    """Network configuration facts stored in operational memory."""

    domain: str | None
    dns_provider: str | None
    reverse_proxy: str | None
    tunnel: str | None
    vpn: str | None
    dns_resolver: str | None
    ssl_strategy: str | None


class ServicesSummary(KavalModel):
    """Counts describing discovered services."""

    total_containers: int = NonNegativeInt
    total_vms: int = NonNegativeInt
    matched_descriptors: int = NonNegativeInt


class PluginImpactService(KavalModel):
    """One service explicitly impacted by a persisted plugin facet."""

    service_id: str
    service_name: str
    descriptor_id: str


class PluginProfile(KavalModel):
    """A read-only Unraid plugin facet stored in the system profile."""

    name: str
    version: str | None = None
    enabled: bool | None = None
    update_available: bool | None = None
    impacted_services: list[PluginImpactService] = Field(default_factory=list)


class VMProfile(KavalModel):
    """A VM entry in the operational memory system profile."""

    name: str
    purpose: str
    os: str | None = None
    type: str | None = None
    quirks: str | None = None
    gpu_passthrough: bool = False


class SystemProfile(KavalModel):
    """Auto-generated system profile captured in operational memory."""

    hostname: str
    unraid_version: str
    hardware: HardwareProfile
    storage: StorageProfile
    networking: NetworkingProfile
    services_summary: ServicesSummary
    vms: list[VMProfile]
    plugins: list[PluginProfile] = Field(default_factory=list)
    last_updated: datetime


class JournalEntry(KavalModel):
    """An operational memory journal entry written after incident resolution."""

    id: str
    incident_id: str
    date: date
    services: list[str]
    summary: str
    root_cause: str
    resolution: str
    time_to_resolution_minutes: float = NonNegativeFloat
    model_used: str
    tags: list[str]
    lesson: str
    recurrence_count: int = NonNegativeInt
    confidence: JournalConfidence
    user_confirmed: bool
    last_verified_at: datetime | None
    applies_to_version: str | None
    superseded_by: str | None
    stale_after_days: int | None = NonNegativeInt


class UserNote(KavalModel):
    """A user-managed operational note."""

    id: str
    service_id: str | None
    note: str
    safe_for_model: bool = True
    last_verified_at: datetime | None
    stale: bool = False
    added_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_timestamps(self) -> Self:
        """Keep note timestamps ordered."""
        if self.updated_at < self.added_at:
            msg = "updated_at cannot precede added_at"
            raise ValueError(msg)
        return self


class ApprovalToken(KavalModel):
    """The signed approval token passed from Core to Executor."""

    token_id: str
    incident_id: str
    action: ActionType
    target: str
    approved_by: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    hmac_signature: str
    used_at: datetime | None
    result: str | None

    @model_validator(mode="after")
    def validate_expiry(self) -> Self:
        """Ensure the token lifetime and usage timestamps are coherent."""
        if self.expires_at <= self.issued_at:
            msg = "expires_at must be later than issued_at"
            raise ValueError(msg)
        if self.used_at is not None and self.used_at < self.issued_at:
            msg = "used_at cannot precede issued_at"
            raise ValueError(msg)
        return self


class ExecutorActionRequest(KavalModel):
    """The frozen Core↔Executor action request contract."""

    action: ActionType
    target: str
    approval_token: ApprovalToken

    @model_validator(mode="after")
    def validate_token_binding(self) -> Self:
        """Bind the request exactly to the approved token."""
        if self.action != self.approval_token.action:
            msg = "request action must match approval token action"
            raise ValueError(msg)
        if self.target != self.approval_token.target:
            msg = "request target must match approval token target"
            raise ValueError(msg)
        return self


class ExecutorActionResult(KavalModel):
    """The frozen Core↔Executor action response contract."""

    token_id: str
    incident_id: str
    action: ActionType
    target: str
    status: ExecutorActionStatus
    detail: str
    executed_at: datetime | None

    @model_validator(mode="after")
    def validate_execution_timestamp(self) -> Self:
        """Require execution timestamps for non-rejected outcomes."""
        if self.status != ExecutorActionStatus.REJECTED and self.executed_at is None:
            msg = "executed_at is required for executed actions"
            raise ValueError(msg)
        if self.status == ExecutorActionStatus.REJECTED and self.executed_at is not None:
            msg = "rejected actions cannot include executed_at"
            raise ValueError(msg)
        return self


class NotificationAction(KavalModel):
    """An interactive control attached to a notification."""

    label: str
    action: NotificationActionType
    style: NotificationActionStyle
    callback_id: str | None = None
    url: str | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        """Require either a callback identifier or a URL target."""
        if self.callback_id is None and self.url is None:
            msg = "notification actions require callback_id or url"
            raise ValueError(msg)
        return self


class NotificationPayload(KavalModel):
    """The frozen formatter-to-channel notification contract."""

    source_type: NotificationSourceType
    source_id: str
    incident_id: str | None = None
    severity: Severity
    title: str
    summary: str
    body: str
    evidence_lines: list[str] = Field(default_factory=list)
    recommended_action: str | None = None
    action_buttons: list[NotificationAction] = Field(default_factory=list)
    dedup_key: str
    created_at: datetime


class OperationalMemoryQuery(KavalModel):
    """The frozen query contract for operational memory lookups."""

    incident_id: str | None = None
    service_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    include_system_profile: bool = True
    include_journal: bool = True
    include_user_notes: bool = True
    max_journal_entries: int = Field(default=10, ge=0)
    redaction_level: RedactionLevel = RedactionLevel.REDACT_FOR_LOCAL

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """Reject empty queries that request no data categories."""
        if not any(
            (
                self.include_system_profile,
                self.include_journal,
                self.include_user_notes,
            )
        ):
            msg = "operational memory queries must request at least one data category"
            raise ValueError(msg)
        return self


class OperationalMemoryResult(KavalModel):
    """The frozen result contract for operational memory lookups."""

    system_profile: SystemProfile | None
    journal_entries: list[JournalEntry]
    user_notes: list[UserNote]
    recurrence_count: int = NonNegativeInt
    applied_redaction_level: RedactionLevel
    warnings: list[str] = Field(default_factory=list)


__all__ = [
    "ActionType",
    "ApprovalToken",
    "ArrayProfile",
    "CauseConfirmationSource",
    "Change",
    "ChangeType",
    "DependencyConfidence",
    "DependencyEdge",
    "DependencySource",
    "DescriptorSource",
    "Endpoint",
    "EndpointProtocol",
    "Evidence",
    "EvidenceKind",
    "EvidenceStep",
    "ExecutorActionRequest",
    "ExecutorActionResult",
    "ExecutorActionStatus",
    "Finding",
    "FindingFeedbackReason",
    "FindingFeedbackRecord",
    "FindingStatus",
    "HardwareProfile",
    "INCIDENT_STATUS_TRANSITIONS",
    "Incident",
    "IncidentGroupingRule",
    "IncidentLifecycleTransition",
    "IncidentStatus",
    "Investigation",
    "InvestigationStatus",
    "InvestigationTrigger",
    "JournalConfidence",
    "JournalEntry",
    "JsonValue",
    "KavalModel",
    "MaintenanceScope",
    "MaintenanceWindowRecord",
    "ModelUsed",
    "NetworkingProfile",
    "NotificationAction",
    "NotificationActionStyle",
    "NotificationActionType",
    "NotificationPayload",
    "NotificationSourceType",
    "OperationalMemoryQuery",
    "OperationalMemoryResult",
    "PluginImpactService",
    "PluginProfile",
    "RedactionLevel",
    "RemediationProposal",
    "RemediationStatus",
    "ResearchStep",
    "RiskAssessment",
    "RiskCheck",
    "RiskCheckResult",
    "RiskLevel",
    "Service",
    "ServiceStatus",
    "ServiceType",
    "ServicesSummary",
    "Severity",
    "StorageProfile",
    "SystemProfile",
    "UserNote",
    "VMProfile",
]
