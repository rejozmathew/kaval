"""Typed request and response contracts for the Kaval API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from kaval.credentials.models import CredentialRequestMode, VaultStatus
from kaval.integrations.adapter_fallback import AdapterFactFreshness
from kaval.integrations.service_adapters import AdapterStatus
from kaval.memory.note_models import UserNoteCreate, UserNoteUpdate
from kaval.models import (
    Change,
    DependencyConfidence,
    DependencySource,
    DescriptorSource,
    DnsTarget,
    Finding,
    FindingFeedbackReason,
    Incident,
    Investigation,
    JsonValue,
    KavalModel,
    MaintenanceScope,
    PortNumber,
    RedactionLevel,
    Service,
    ServiceStatus,
)
from kaval.monitoring_thresholds import (
    monitoring_threshold_fields_present,
    validate_monitoring_threshold_fields,
)
from kaval.recommendations import RecommendationActionTarget, RecommendationKind


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


class RecommendationActionResponse(KavalModel):
    """One deterministic follow-up path for a proactive recommendation."""

    label: str
    target: RecommendationActionTarget
    service_id: str | None = None


class RecommendationItemResponse(KavalModel):
    """One ranked proactive recommendation shown in the admin UI."""

    id: str
    kind: RecommendationKind
    title: str
    detail: str
    action: RecommendationActionResponse


class RecommendationsResponse(KavalModel):
    """Ordered proactive recommendations derived from current repo state."""

    items: list[RecommendationItemResponse] = Field(default_factory=list)


class RealtimeSnapshotResponse(KavalModel):
    """WebSocket payload carrying the latest Phase 1 UI state."""

    kind: Literal["snapshot"]
    graph: ServiceGraphResponse
    incidents: list[Incident]
    investigations: list[Investigation]
    widget: WidgetSummaryResponse


class FindingFeedbackSuggestionAction(StrEnum):
    """Operator-controlled next steps suggested from repeated dismissals."""

    SUPPRESS_CHECK = "suppress_check"
    ADJUST_THRESHOLD_OR_SUPPRESS = "adjust_threshold_or_suppress"


class FindingFeedbackSuggestionResponse(KavalModel):
    """One advisory recommendation derived from repeated finding dismissals."""

    service_id: str
    service_name: str
    check_id: str
    check_label: str
    dismissal_count: int = Field(ge=1)
    action: FindingFeedbackSuggestionAction
    message: str


class FindingReviewItemResponse(KavalModel):
    """One active or recently dismissed finding shown in the review panel."""

    finding: Finding
    service_name: str
    domain_label: str
    dismissal_reason: FindingFeedbackReason | None = None
    dismissal_count_for_pattern: int = Field(default=0, ge=0)
    suggestion: FindingFeedbackSuggestionResponse | None = None


class FindingReviewResponse(KavalModel):
    """Finding review payload with active, dismissed, and recommended noise controls."""

    active_findings: list[FindingReviewItemResponse] = Field(default_factory=list)
    recently_dismissed: list[FindingReviewItemResponse] = Field(default_factory=list)
    suggestions: list[FindingFeedbackSuggestionResponse] = Field(default_factory=list)


class FindingDismissRequest(KavalModel):
    """Explicit operator dismissal reason for one finding."""

    reason: FindingFeedbackReason


class FindingDismissResponse(KavalModel):
    """Dismissal result for one finding plus refreshed review state."""

    finding: Finding
    review: FindingReviewResponse
    audit_change: Change


class MaintenanceWindowResponse(KavalModel):
    """One active maintenance window visible to the operator."""

    scope: MaintenanceScope
    service_id: str | None = None
    service_name: str | None = None
    started_at: datetime
    expires_at: datetime
    minutes_remaining: int = Field(ge=0)


class MaintenanceModeResponse(KavalModel):
    """Current active global and per-service maintenance windows."""

    global_window: MaintenanceWindowResponse | None = None
    service_windows: list[MaintenanceWindowResponse] = Field(default_factory=list)
    self_health_guardrail: str


class MaintenanceWindowUpdateRequest(KavalModel):
    """Requested duration for one new or updated maintenance window."""

    duration_minutes: int = Field(ge=1, le=1440)


class MaintenanceModeMutationResponse(KavalModel):
    """Mutation result for one maintenance mode create or clear action."""

    maintenance: MaintenanceModeResponse
    audit_change: Change


class ModelSettingsSecretSource(StrEnum):
    """How one model API key is currently sourced."""

    VAULT = "vault"
    ENV = "env"
    UNSET = "unset"


class ModelSettingsTestTarget(StrEnum):
    """Supported model-settings connectivity test targets."""

    LOCAL = "local"
    CLOUD = "cloud"


class ModelSettingsTestScope(StrEnum):
    """Supported staged/active scopes for explicit model settings tests."""

    ACTIVE = "active"
    STAGED = "staged"


class ModelSettingsLocalScopeResponse(KavalModel):
    """One staged or active local-model settings view."""

    enabled: bool
    provider: Literal["openai_compatible"]
    model: str | None = None
    base_url: str
    timeout_seconds: float = Field(gt=0)
    api_key_ref: str | None = None
    api_key_source: ModelSettingsSecretSource
    api_key_configured: bool
    configured: bool


class ModelSettingsCloudScopeResponse(KavalModel):
    """One staged or active cloud-model settings view."""

    enabled: bool
    provider: Literal["anthropic", "openai", "openai_compatible"]
    model: str | None = None
    base_url: str
    timeout_seconds: float = Field(gt=0)
    max_output_tokens: int = Field(ge=1)
    api_key_ref: str | None = None
    api_key_source: ModelSettingsSecretSource
    api_key_configured: bool
    configured: bool


class ModelSettingsEscalationResponse(KavalModel):
    """Staged or active escalation thresholds and bounded cost controls."""

    finding_count_gt: int = Field(ge=0)
    local_confidence_lt: float = Field(ge=0.0, le=1.0)
    escalate_on_multiple_domains: bool
    escalate_on_changelog_research: bool
    escalate_on_user_request: bool
    max_cloud_calls_per_day: int = Field(ge=1)
    max_cloud_calls_per_incident: int = Field(ge=1)


class ModelSettingsScopeResponse(KavalModel):
    """One complete staged or active model-settings snapshot."""

    local: ModelSettingsLocalScopeResponse
    cloud: ModelSettingsCloudScopeResponse
    escalation: ModelSettingsEscalationResponse


class ModelSettingsResponse(KavalModel):
    """Model-settings payload with explicit staged and active snapshots."""

    config_path: str
    load_error: str | None = None
    apply_required: bool
    last_applied_at: datetime | None
    active: ModelSettingsScopeResponse
    staged: ModelSettingsScopeResponse


class ModelSettingsLocalUpdateRequest(KavalModel):
    """Writable local-model settings payload."""

    enabled: bool
    model: str | None = None
    base_url: str
    timeout_seconds: float = Field(gt=0)
    api_key: str | None = None
    clear_stored_api_key: bool = False

    @model_validator(mode="after")
    def validate_settings(self) -> ModelSettingsLocalUpdateRequest:
        """Keep writable local-model settings coherent."""
        if self.enabled and (self.model is None or not self.model.strip()):
            msg = "local model name is required when enabled"
            raise ValueError(msg)
        if not self.base_url.strip():
            msg = "local model base_url must not be empty"
            raise ValueError(msg)
        if (
            self.clear_stored_api_key
            and self.api_key is not None
            and self.api_key.strip()
        ):
            msg = "cannot clear and replace the local model API key in one request"
            raise ValueError(msg)
        return self


class ModelSettingsCloudUpdateRequest(KavalModel):
    """Writable cloud-model settings payload."""

    enabled: bool
    provider: Literal["anthropic", "openai", "openai_compatible"] = "anthropic"
    model: str | None = None
    base_url: str
    timeout_seconds: float = Field(gt=0)
    max_output_tokens: int = Field(ge=1)
    api_key: str | None = None
    clear_stored_api_key: bool = False

    @model_validator(mode="after")
    def validate_settings(self) -> ModelSettingsCloudUpdateRequest:
        """Keep writable cloud-model settings coherent."""
        if self.enabled and (self.model is None or not self.model.strip()):
            msg = "cloud model name is required when enabled"
            raise ValueError(msg)
        if not self.base_url.strip():
            msg = "cloud model base_url must not be empty"
            raise ValueError(msg)
        if (
            self.clear_stored_api_key
            and self.api_key is not None
            and self.api_key.strip()
        ):
            msg = "cannot clear and replace the cloud model API key in one request"
            raise ValueError(msg)
        return self


class ModelSettingsEscalationUpdateRequest(KavalModel):
    """Writable escalation thresholds and bounded cost controls."""

    finding_count_gt: int = Field(ge=0)
    local_confidence_lt: float = Field(ge=0.0, le=1.0)
    escalate_on_multiple_domains: bool
    escalate_on_changelog_research: bool
    escalate_on_user_request: bool
    max_cloud_calls_per_day: int = Field(ge=1)
    max_cloud_calls_per_incident: int = Field(ge=1)


class ModelSettingsUpdateRequest(KavalModel):
    """Full staged model-settings update payload."""

    local: ModelSettingsLocalUpdateRequest
    cloud: ModelSettingsCloudUpdateRequest
    escalation: ModelSettingsEscalationUpdateRequest


class ModelSettingsMutationResponse(KavalModel):
    """Mutation response for staged-save or explicit-apply model settings actions."""

    settings: ModelSettingsResponse
    audit_change: Change


class ModelSettingsTestRequest(KavalModel):
    """Explicit staged or active model-settings connectivity test request."""

    target: ModelSettingsTestTarget
    scope: ModelSettingsTestScope = ModelSettingsTestScope.STAGED


class ModelSettingsTestResponse(KavalModel):
    """Result of one explicit model-settings connectivity test."""

    target: ModelSettingsTestTarget
    scope: ModelSettingsTestScope
    ok: bool
    checked_at: datetime
    message: str


class NotificationSettingsSecretSource(StrEnum):
    """How one notification destination is currently sourced."""

    VAULT = "vault"
    ENV = "env"
    UNSET = "unset"


class NotificationSettingsTestScope(StrEnum):
    """Supported staged/active scopes for explicit notification settings tests."""

    ACTIVE = "active"
    STAGED = "staged"


class NotificationSettingsChannelScopeResponse(KavalModel):
    """One staged or active notification channel view."""

    id: str
    name: str
    kind: str
    enabled: bool
    destination_ref: str | None = None
    destination_source: NotificationSettingsSecretSource
    destination_configured: bool


class NotificationSettingsRoutingResponse(KavalModel):
    """Staged or active severity routing and dedup policy."""

    critical: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    high: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    medium: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    low: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    dedup_window_minutes: int = Field(ge=1)
    digest_window_minutes: int = Field(ge=1)


class NotificationSettingsQuietHoursResponse(KavalModel):
    """Staged or active quiet-hours schedule metadata."""

    enabled: bool
    start_time_local: str
    end_time_local: str
    timezone: str
    active_now: bool
    quiet_until: datetime | None = None


class NotificationSettingsScopeResponse(KavalModel):
    """One complete staged or active notification-settings snapshot."""

    channels: list[NotificationSettingsChannelScopeResponse] = Field(default_factory=list)
    routing: NotificationSettingsRoutingResponse
    quiet_hours: NotificationSettingsQuietHoursResponse
    configured_channel_count: int = Field(ge=0)


class NotificationSettingsResponse(KavalModel):
    """Notification-settings payload with explicit staged and active snapshots."""

    config_path: str
    load_error: str | None = None
    apply_required: bool
    last_applied_at: datetime | None
    active: NotificationSettingsScopeResponse
    staged: NotificationSettingsScopeResponse


class NotificationSettingsChannelUpdateRequest(KavalModel):
    """Writable notification channel payload with a write-only destination URL."""

    id: str | None = None
    name: str = Field(min_length=1)
    enabled: bool = True
    destination: str | None = None

    @model_validator(mode="after")
    def validate_settings(self) -> NotificationSettingsChannelUpdateRequest:
        """Reject empty names after trimming surrounding whitespace."""
        if not self.name.strip():
            msg = "notification channel name must not be empty"
            raise ValueError(msg)
        return self


class NotificationSettingsRoutingUpdateRequest(KavalModel):
    """Writable severity routing and dedup policy payload."""

    critical: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    high: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    medium: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    low: Literal[
        "immediate",
        "immediate_with_dedup",
        "hourly_digest",
        "dashboard_only",
    ]
    dedup_window_minutes: int = Field(ge=1)
    digest_window_minutes: int = Field(ge=1)


class NotificationSettingsQuietHoursUpdateRequest(KavalModel):
    """Writable daily quiet-hours schedule payload."""

    enabled: bool
    start_time_local: str
    end_time_local: str
    timezone: str


class NotificationSettingsUpdateRequest(KavalModel):
    """Full staged notification-settings update payload."""

    channels: list[NotificationSettingsChannelUpdateRequest] = Field(default_factory=list)
    routing: NotificationSettingsRoutingUpdateRequest
    quiet_hours: NotificationSettingsQuietHoursUpdateRequest


class NotificationSettingsMutationResponse(KavalModel):
    """Mutation response for staged-save or explicit-apply notification settings actions."""

    settings: NotificationSettingsResponse
    audit_change: Change


class NotificationSettingsTestRequest(KavalModel):
    """Explicit staged or active notification channel test request."""

    channel_id: str
    scope: NotificationSettingsTestScope = NotificationSettingsTestScope.STAGED


class NotificationSettingsTestResponse(KavalModel):
    """Result of one explicit notification channel test."""

    channel_id: str
    scope: NotificationSettingsTestScope
    ok: bool
    checked_at: datetime
    message: str


class MonitoringSettingsResolutionSource(StrEnum):
    """Where one effective monitoring setting currently comes from."""

    GLOBAL_DEFAULT = "global_default"
    SERVICE_OVERRIDE = "service_override"


class MonitoringSettingsCheckResponse(KavalModel):
    """One global monitoring-check settings row."""

    check_id: str
    label: str
    description: str
    enabled: bool
    interval_seconds: int = Field(ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)
    default_enabled: bool
    default_interval_seconds: int = Field(ge=1)
    default_tls_warning_days: int | None = Field(default=None, ge=1)
    default_restart_delta_threshold: int | None = Field(default=None, ge=1)
    default_probe_timeout_seconds: float | None = Field(default=None, gt=0)


class MonitoringSettingsServiceOverrideResponse(KavalModel):
    """One persisted service-scoped monitoring override row."""

    service_id: str
    service_name: str
    service_status: ServiceStatus
    check_id: str
    check_label: str
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)
    updated_at: datetime


class MonitoringSettingsEffectiveCheckResponse(KavalModel):
    """The effective cadence state for one service/check pair."""

    check_id: str
    label: str
    enabled: bool
    base_interval_seconds: int = Field(ge=1)
    effective_interval_seconds: int = Field(ge=1)
    source: MonitoringSettingsResolutionSource
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)
    threshold_source: MonitoringSettingsResolutionSource | None = None
    accelerated_now: bool
    incident_ids: list[str] = Field(default_factory=list)


class MonitoringSettingsEffectiveServiceResponse(KavalModel):
    """The effective cadence rows for one service."""

    service_id: str
    service_name: str
    service_status: ServiceStatus
    checks: list[MonitoringSettingsEffectiveCheckResponse] = Field(default_factory=list)


class MonitoringSettingsScopeResponse(KavalModel):
    """One complete staged or active monitoring-settings snapshot."""

    checks: list[MonitoringSettingsCheckResponse] = Field(default_factory=list)
    service_overrides: list[MonitoringSettingsServiceOverrideResponse] = Field(
        default_factory=list
    )
    effective_services: list[MonitoringSettingsEffectiveServiceResponse] = Field(
        default_factory=list
    )


class MonitoringSettingsResponse(KavalModel):
    """Monitoring-settings payload with explicit staged and active snapshots."""

    config_path: str
    load_error: str | None = None
    apply_required: bool
    last_applied_at: datetime | None
    active: MonitoringSettingsScopeResponse
    staged: MonitoringSettingsScopeResponse


class MonitoringSettingsCheckUpdateRequest(KavalModel):
    """Writable global monitoring-check settings payload."""

    check_id: str
    enabled: bool
    interval_seconds: int = Field(ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_thresholds(self) -> MonitoringSettingsCheckUpdateRequest:
        """Require only supported bounded threshold fields for the selected check."""
        validate_monitoring_threshold_fields(
            self.check_id,
            tls_warning_days=self.tls_warning_days,
            restart_delta_threshold=self.restart_delta_threshold,
            probe_timeout_seconds=self.probe_timeout_seconds,
        )
        if self.check_id == "tls_cert" and self.tls_warning_days is None:
            raise ValueError("tls_cert settings require tls_warning_days")
        if (
            self.check_id == "restart_storm"
            and self.restart_delta_threshold is None
        ):
            raise ValueError(
                "restart_storm settings require restart_delta_threshold"
            )
        if self.check_id == "endpoint_probe" and self.probe_timeout_seconds is None:
            raise ValueError(
                "endpoint_probe settings require probe_timeout_seconds"
            )
        return self


class MonitoringSettingsServiceOverrideUpdateRequest(KavalModel):
    """Writable staged service-scoped monitoring override payload."""

    service_id: str
    check_id: str
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    tls_warning_days: int | None = Field(default=None, ge=1)
    restart_delta_threshold: int | None = Field(default=None, ge=1)
    probe_timeout_seconds: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_override(self) -> MonitoringSettingsServiceOverrideUpdateRequest:
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
                "service override requires enabled, interval_seconds, "
                "or threshold settings"
            )
            raise ValueError(msg)
        return self


class MonitoringSettingsUpdateRequest(KavalModel):
    """Full staged monitoring-settings update payload."""

    checks: list[MonitoringSettingsCheckUpdateRequest] = Field(default_factory=list)
    service_overrides: list[MonitoringSettingsServiceOverrideUpdateRequest] = Field(
        default_factory=list
    )


class MonitoringSettingsMutationResponse(KavalModel):
    """Mutation response for staged-save or explicit-apply monitoring settings actions."""

    settings: MonitoringSettingsResponse
    audit_change: Change


class CredentialVaultEntrySource(StrEnum):
    """Source types for stored vault credentials shown in the admin UI."""

    CREDENTIAL_REQUEST = "credential_request"
    MANAGED_SETTING = "managed_setting"


class CredentialVaultCredentialResponse(KavalModel):
    """One stored credential summary with no secret material."""

    reference_id: str
    source: CredentialVaultEntrySource
    service_id: str
    service_name: str
    credential_key: str
    credential_description: str
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None = None
    last_tested_at: datetime | None = None
    expires_at: datetime | None = None


class CredentialVaultResponse(KavalModel):
    """Full operator-facing vault state and stored-credential list."""

    status: VaultStatus
    auto_lock_minutes: int = Field(ge=1)
    credentials: list[CredentialVaultCredentialResponse] = Field(default_factory=list)


class CredentialVaultMutationResponse(KavalModel):
    """Mutation response for explicit vault lock, unlock, or password change flows."""

    vault: CredentialVaultResponse
    audit_change: Change


class CredentialVaultTestItemResponse(KavalModel):
    """Result for one explicit vault readability test item."""

    reference_id: str
    service_name: str
    credential_description: str
    ok: bool
    message: str
    checked_at: datetime


class CredentialVaultTestResponse(KavalModel):
    """Result for one explicit test of all stored vault credentials."""

    vault: CredentialVaultResponse
    ok: bool
    checked_at: datetime
    tested_credentials: int = Field(ge=0)
    readable_credentials: int = Field(ge=0)
    results: list[CredentialVaultTestItemResponse] = Field(default_factory=list)
    message: str
    audit_change: Change | None = None


class CredentialVaultChangePasswordRequest(KavalModel):
    """API payload for changing the vault master passphrase."""

    current_master_passphrase: str
    new_master_passphrase: str


class SystemSettingsLogLevel(StrEnum):
    """Supported runtime log levels for admin-editable system settings."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"
    TRACE = "trace"


class SystemSettingsExportTarget(StrEnum):
    """Bounded export targets exposed by the Phase 3C system settings panel."""

    OPERATIONAL_MEMORY = "operational_memory"
    SETTINGS = "settings"
    DESCRIPTORS = "descriptors"


class SystemSettingsImportTarget(StrEnum):
    """Bounded import targets exposed by the Phase 3C system settings panel."""

    DESCRIPTORS = "descriptors"
    NOTES = "notes"
    CONFIGURATION_BACKUP = "configuration_backup"


class SystemSettingsSensitivity(StrEnum):
    """Sensitivity classifications shown for backup/export guidance."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SystemSettingsScopeResponse(KavalModel):
    """One staged or active system-settings snapshot."""

    log_level: SystemSettingsLogLevel
    audit_detail_retention_days: int = Field(ge=1, le=3650)
    audit_summary_retention_days: int = Field(ge=1, le=3650)

    @model_validator(mode="after")
    def validate_audit_retention_windows(self) -> SystemSettingsScopeResponse:
        """Keep the surfaced audit retention windows coherent."""
        if self.audit_summary_retention_days < self.audit_detail_retention_days:
            msg = (
                "audit_summary_retention_days must be greater than or equal to "
                "audit_detail_retention_days"
            )
            raise ValueError(msg)
        return self


class SystemSettingsDatabaseStatusResponse(KavalModel):
    """Read-only database status surfaced through the system settings panel."""

    path: str
    exists: bool
    size_bytes: int = Field(ge=0)
    migrations_current: bool
    quick_check_ok: bool
    quick_check_result: str
    journal_mode: str


class SystemSettingsExportGuidanceResponse(KavalModel):
    """One bounded export warning surfaced in the system settings panel."""

    target: SystemSettingsExportTarget
    label: str
    available: bool = False
    sensitivity: SystemSettingsSensitivity
    warning: str


class SystemSettingsImportGuidanceResponse(KavalModel):
    """One bounded import warning surfaced in the system settings panel."""

    target: SystemSettingsImportTarget
    label: str
    available: bool = False
    warning: str


class SystemSettingsTransferGuidanceResponse(KavalModel):
    """Import/export guidance shown without enabling Phase 4 transfer flows."""

    phase_guardrail: str
    exports: list[SystemSettingsExportGuidanceResponse] = Field(default_factory=list)
    imports: list[SystemSettingsImportGuidanceResponse] = Field(default_factory=list)


class SystemSettingsAboutModelStatusResponse(KavalModel):
    """Current runtime model status surfaced on the system about card."""

    local_model_enabled: bool
    local_model_configured: bool
    local_model_summary: str
    cloud_model_enabled: bool
    cloud_model_configured: bool
    cloud_model_summary: str
    escalation_summary: str


class SystemSettingsAboutResponse(KavalModel):
    """Current runtime/build metadata surfaced on the system about card."""

    api_title: str
    api_version: str
    api_summary: str | None = None
    checked_at: datetime
    started_at: datetime
    uptime_seconds: float = Field(ge=0)
    runtime_log_level: SystemSettingsLogLevel
    settings_path: str
    database_path: str
    services_dir: str
    web_dist_dir: str
    web_bundle_present: bool
    model_status: SystemSettingsAboutModelStatusResponse


class SystemSettingsResponse(KavalModel):
    """System-settings payload with explicit staged and active snapshots."""

    config_path: str
    load_error: str | None = None
    apply_required: bool
    last_applied_at: datetime | None
    active: SystemSettingsScopeResponse
    staged: SystemSettingsScopeResponse
    database: SystemSettingsDatabaseStatusResponse
    transfer_guidance: SystemSettingsTransferGuidanceResponse
    about: SystemSettingsAboutResponse


class SystemSettingsUpdateRequest(KavalModel):
    """Writable staged system-settings payload."""

    log_level: SystemSettingsLogLevel
    audit_detail_retention_days: int = Field(ge=1, le=3650)
    audit_summary_retention_days: int = Field(ge=1, le=3650)

    @model_validator(mode="after")
    def validate_audit_retention_windows(self) -> SystemSettingsUpdateRequest:
        """Keep requested audit retention windows coherent."""
        if self.audit_summary_retention_days < self.audit_detail_retention_days:
            msg = (
                "audit_summary_retention_days must be greater than or equal to "
                "audit_detail_retention_days"
            )
            raise ValueError(msg)
        return self


class SystemSettingsMutationResponse(KavalModel):
    """Mutation response for staged-save or explicit-apply system settings actions."""

    settings: SystemSettingsResponse
    audit_change: Change


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


class ServiceDetailMonitoringCheckResponse(KavalModel):
    """One service-scoped monitoring row shown in service detail."""

    check_id: str
    label: str
    description: str
    inherited_enabled: bool
    inherited_interval_seconds: int = Field(ge=1)
    effective_enabled: bool
    effective_interval_seconds: int = Field(ge=1)
    source: MonitoringSettingsResolutionSource
    suppressed: bool
    override_enabled: bool | None = None
    override_interval_seconds: int | None = Field(default=None, ge=1)
    override_updated_at: datetime | None = None


class ServiceDetailMonitoringSectionResponse(KavalModel):
    """Per-service monitoring and suppression state shown in service detail."""

    checks: list[ServiceDetailMonitoringCheckResponse] = Field(default_factory=list)


class ServiceDetailResponse(KavalModel):
    """A later-enrichable service-detail response contract."""

    service: Service
    insight_section: ServiceDetailInsightSectionResponse
    monitoring_section: ServiceDetailMonitoringSectionResponse


class ServiceDetailCheckSuppressionUpdateRequest(KavalModel):
    """Writable request for one explicit per-service check suppression toggle."""

    suppressed: bool


class ServiceDetailCheckSuppressionMutationResponse(KavalModel):
    """Mutation result for one per-service check suppression action."""

    detail: ServiceDetailResponse
    audit_change: Change


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
