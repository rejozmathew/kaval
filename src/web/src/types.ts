export type ServiceStatus =
  | "healthy"
  | "degraded"
  | "down"
  | "unknown"
  | "stopped";

export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface DependencyEdge {
  target_service_id: string;
  confidence: string;
  source: string;
  description: string | null;
}

export interface Service {
  id: string;
  name: string;
  type: string;
  category: string;
  status: ServiceStatus;
  insight: {
    level: number;
  } | null;
  lifecycle: {
    state: string;
    last_event: string | null;
    changed_at: string | null;
    previous_names: string[];
    previous_descriptor_ids: string[];
  };
  descriptor_id: string | null;
  descriptor_source: string | null;
  container_id: string | null;
  vm_id: string | null;
  image: string | null;
  endpoints: Array<{
    name: string;
    protocol: string;
    host: string | null;
    port: number | null;
    path: string | null;
    url: string | null;
    auth_required: boolean;
    expected_status: number | null;
  }>;
  dns_targets: Array<{
    host: string;
    record_type: string;
    expected_values: string[];
  }>;
  dependencies: DependencyEdge[];
  dependents: string[];
  last_check: string | null;
  active_findings: number;
  active_incidents: number;
}

export interface GraphEdge {
  source_service_id: string;
  target_service_id: string;
  confidence: string;
  source: string;
  description: string | null;
}

export interface GraphResponse {
  services: Service[];
  edges: GraphEdge[];
  node_meta: Array<{
    service_id: string;
    target_insight_level: number;
    improve_available: boolean;
  }>;
}

export interface GraphEdgeMutationResponse {
  edge: GraphEdge | null;
  audit_change: Change;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  affected_services: string[];
  changes_correlated: string[];
  triggering_symptom: string | null;
  suspected_cause: string | null;
  root_cause_service: string | null;
  investigation_id: string | null;
  approved_actions: string[];
  confidence: number;
  updated_at: string;
}

export interface Change {
  id: string;
  type: string;
  service_id: string | null;
  description: string;
  old_value: string | null;
  new_value: string | null;
  timestamp: string;
  correlated_incidents: string[];
}

export type FindingFeedbackReason =
  | "false_positive"
  | "expected_behavior"
  | "not_important"
  | "already_aware";

export interface Finding {
  id: string;
  title: string;
  severity: string;
  domain: string;
  service_id: string;
  summary: string;
  evidence: Array<{
    kind: string;
    source: string;
    summary: string;
    observed_at: string;
    data: JsonValue;
  }>;
  impact: string;
  confidence: number;
  status: string;
  incident_id: string | null;
  related_changes: Change[];
  created_at: string;
  resolved_at: string | null;
}

export interface EvidenceStep {
  order: number;
  action: string;
  target: string;
  result_summary: string;
  result_data: unknown;
  timestamp: string;
}

export interface RiskCheck {
  check: string;
  result: string;
  detail: string;
}

export interface RemediationProposal {
  action_type: string;
  target: string;
  rationale: string;
  status: string;
  risk_assessment: {
    overall_risk: string;
    checks: RiskCheck[];
    reversible: boolean;
    warnings: string[];
  };
}

export interface Investigation {
  id: string;
  incident_id: string;
  status: string;
  evidence_steps: EvidenceStep[];
  root_cause: string | null;
  confidence: number;
  model_used: string;
  cloud_model_calls: number;
  local_input_tokens: number;
  local_output_tokens: number;
  cloud_input_tokens: number;
  cloud_output_tokens: number;
  estimated_cloud_cost_usd: number;
  estimated_total_cost_usd: number;
  cloud_escalation_reason: string | null;
  recurrence_count: number;
  remediation: RemediationProposal | null;
  started_at: string;
  completed_at: string | null;
}

export interface CredentialRequest {
  id: string;
  incident_id: string;
  investigation_id: string | null;
  service_id: string;
  service_name: string;
  credential_key: string;
  credential_description: string;
  credential_location: string;
  reason: string;
  status: string;
  selected_mode: string | null;
  decided_by: string | null;
  decided_at: string | null;
  requested_at: string;
  expires_at: string;
  satisfied_at: string | null;
  credential_reference: string | null;
}

export interface JournalEntry {
  id: string;
  incident_id: string;
  date: string;
  services: string[];
  summary: string;
  root_cause: string;
  resolution: string;
  time_to_resolution_minutes: number;
  model_used: string;
  tags: string[];
  lesson: string;
  recurrence_count: number;
  confidence: string;
  user_confirmed: boolean;
  last_verified_at: string | null;
  applies_to_version: string | null;
  superseded_by: string | null;
  stale_after_days: number | null;
}

export interface UserNote {
  id: string;
  service_id: string | null;
  note: string;
  safe_for_model: boolean;
  last_verified_at: string | null;
  stale: boolean;
  added_at: string;
  updated_at: string;
}

export interface SystemProfile {
  hostname: string;
  unraid_version: string;
  hardware: {
    cpu: string;
    memory_gb: number;
    gpu: string | null;
    ups: string | null;
  };
  storage: {
    array: {
      parity_drives: number;
      data_drives: number;
      cache: string | null;
      total_tb: number;
      used_tb: number;
    };
  };
  networking: {
    domain: string | null;
    dns_provider: string | null;
    reverse_proxy: string | null;
    tunnel: string | null;
    vpn: string | null;
    dns_resolver: string | null;
    ssl_strategy: string | null;
  };
  services_summary: {
    total_containers: number;
    total_vms: number;
    matched_descriptors: number;
  };
  vms: Array<{
    name: string;
    purpose: string;
    os: string | null;
    type: string | null;
    quirks: string | null;
    gpu_passthrough: boolean;
  }>;
  plugins: Array<{
    name: string;
    version: string | null;
    enabled: boolean | null;
    update_available: boolean | null;
    impacted_services: Array<{
      service_id: string;
      service_name: string;
      descriptor_id: string;
    }>;
  }>;
  last_updated: string;
}

export interface WidgetSummary {
  total_services: number;
  active_findings: number;
  active_incidents: number;
  healthy_services: number;
  degraded_services: number;
  down_services: number;
  stopped_services: number;
  unknown_services: number;
  last_updated: string | null;
}

export interface CapabilityHealthLayer {
  layer: string;
  status: string;
  display_state: "healthy" | "degraded" | "unavailable" | "stale" | "disabled";
  summary: string;
  detail: string;
  user_impact: string;
  guidance: string;
  metadata: Record<string, unknown>;
}

export interface CapabilityHealthReport {
  checked_at: string;
  overall_status: string;
  layers: CapabilityHealthLayer[];
}

export type ModelSettingsSecretSource = "vault" | "env" | "unset";

export interface ModelSettingsScope {
  local: {
    enabled: boolean;
    provider: "openai_compatible";
    model: string | null;
    base_url: string;
    timeout_seconds: number;
    api_key_ref: string | null;
    api_key_source: ModelSettingsSecretSource;
    api_key_configured: boolean;
    configured: boolean;
  };
  cloud: {
    enabled: boolean;
    provider: "anthropic" | "openai" | "openai_compatible";
    model: string | null;
    base_url: string;
    timeout_seconds: number;
    max_output_tokens: number;
    api_key_ref: string | null;
    api_key_source: ModelSettingsSecretSource;
    api_key_configured: boolean;
    configured: boolean;
  };
  escalation: {
    finding_count_gt: number;
    local_confidence_lt: number;
    escalate_on_multiple_domains: boolean;
    escalate_on_changelog_research: boolean;
    escalate_on_user_request: boolean;
    max_cloud_calls_per_day: number;
    max_cloud_calls_per_incident: number;
  };
}

export interface ModelSettingsResponse {
  config_path: string;
  load_error: string | null;
  apply_required: boolean;
  last_applied_at: string | null;
  active: ModelSettingsScope;
  staged: ModelSettingsScope;
}

export interface ModelSettingsMutationResponse {
  settings: ModelSettingsResponse;
  audit_change: Change;
}

export interface ModelSettingsTestResponse {
  target: "local" | "cloud";
  scope: "active" | "staged";
  ok: boolean;
  checked_at: string;
  message: string;
}

export type NotificationSettingsSecretSource = "vault" | "env" | "unset";

export type NotificationSettingsRoute =
  | "immediate"
  | "immediate_with_dedup"
  | "hourly_digest"
  | "dashboard_only";

export interface NotificationSettingsScope {
  channels: Array<{
    id: string;
    name: string;
    kind: string;
    enabled: boolean;
    destination_ref: string | null;
    destination_source: NotificationSettingsSecretSource;
    destination_configured: boolean;
  }>;
  routing: {
    critical: NotificationSettingsRoute;
    high: NotificationSettingsRoute;
    medium: NotificationSettingsRoute;
    low: NotificationSettingsRoute;
    dedup_window_minutes: number;
    digest_window_minutes: number;
  };
  quiet_hours: {
    enabled: boolean;
    start_time_local: string;
    end_time_local: string;
    timezone: string;
    active_now: boolean;
    quiet_until: string | null;
  };
  configured_channel_count: number;
}

export interface NotificationSettingsResponse {
  config_path: string;
  load_error: string | null;
  apply_required: boolean;
  last_applied_at: string | null;
  active: NotificationSettingsScope;
  staged: NotificationSettingsScope;
}

export interface NotificationSettingsMutationResponse {
  settings: NotificationSettingsResponse;
  audit_change: Change;
}

export interface NotificationSettingsTestResponse {
  channel_id: string;
  scope: "active" | "staged";
  ok: boolean;
  checked_at: string;
  message: string;
}

export type MonitoringSettingsResolutionSource =
  | "global_default"
  | "service_override";

export interface MonitoringSettingsCheckResponse {
  check_id: string;
  label: string;
  description: string;
  enabled: boolean;
  interval_seconds: number;
  tls_warning_days: number | null;
  restart_delta_threshold: number | null;
  probe_timeout_seconds: number | null;
  default_enabled: boolean;
  default_interval_seconds: number;
  default_tls_warning_days: number | null;
  default_restart_delta_threshold: number | null;
  default_probe_timeout_seconds: number | null;
}

export interface MonitoringSettingsServiceOverrideResponse {
  service_id: string;
  service_name: string;
  service_status: ServiceStatus;
  check_id: string;
  check_label: string;
  enabled: boolean | null;
  interval_seconds: number | null;
  tls_warning_days: number | null;
  restart_delta_threshold: number | null;
  probe_timeout_seconds: number | null;
  updated_at: string;
}

export interface MonitoringSettingsEffectiveCheckResponse {
  check_id: string;
  label: string;
  enabled: boolean;
  base_interval_seconds: number;
  effective_interval_seconds: number;
  source: MonitoringSettingsResolutionSource;
  tls_warning_days: number | null;
  restart_delta_threshold: number | null;
  probe_timeout_seconds: number | null;
  threshold_source: MonitoringSettingsResolutionSource | null;
  accelerated_now: boolean;
  incident_ids: string[];
}

export interface MonitoringSettingsEffectiveServiceResponse {
  service_id: string;
  service_name: string;
  service_status: ServiceStatus;
  checks: MonitoringSettingsEffectiveCheckResponse[];
}

export interface MonitoringSettingsScope {
  checks: MonitoringSettingsCheckResponse[];
  service_overrides: MonitoringSettingsServiceOverrideResponse[];
  effective_services: MonitoringSettingsEffectiveServiceResponse[];
}

export interface MonitoringSettingsResponse {
  config_path: string;
  load_error: string | null;
  apply_required: boolean;
  last_applied_at: string | null;
  active: MonitoringSettingsScope;
  staged: MonitoringSettingsScope;
}

export interface MonitoringSettingsMutationResponse {
  settings: MonitoringSettingsResponse;
  audit_change: Change;
}

export type CredentialVaultEntrySource = "credential_request" | "managed_setting";

export interface CredentialVaultCredential {
  reference_id: string;
  source: CredentialVaultEntrySource;
  service_id: string;
  service_name: string;
  credential_key: string;
  credential_description: string;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  last_tested_at: string | null;
  expires_at: string | null;
}

export interface CredentialVaultResponse {
  status: {
    initialized: boolean;
    unlocked: boolean;
    unlock_expires_at: string | null;
    stored_credentials: number;
  };
  auto_lock_minutes: number;
  credentials: CredentialVaultCredential[];
}

export interface CredentialVaultMutationResponse {
  vault: CredentialVaultResponse;
  audit_change: Change;
}

export interface CredentialVaultTestItemResponse {
  reference_id: string;
  service_name: string;
  credential_description: string;
  ok: boolean;
  message: string;
  checked_at: string;
}

export interface CredentialVaultTestResponse {
  vault: CredentialVaultResponse;
  ok: boolean;
  checked_at: string;
  tested_credentials: number;
  readable_credentials: number;
  results: CredentialVaultTestItemResponse[];
  message: string;
  audit_change: Change | null;
}

export type SystemSettingsLogLevel =
  | "critical"
  | "error"
  | "warning"
  | "info"
  | "debug"
  | "trace";

export interface SystemSettingsScope {
  log_level: SystemSettingsLogLevel;
  audit_detail_retention_days: number;
  audit_summary_retention_days: number;
}

export interface SystemSettingsResponse {
  config_path: string;
  load_error: string | null;
  apply_required: boolean;
  last_applied_at: string | null;
  active: SystemSettingsScope;
  staged: SystemSettingsScope;
  database: {
    path: string;
    exists: boolean;
    size_bytes: number;
    migrations_current: boolean;
    quick_check_ok: boolean;
    quick_check_result: string;
    journal_mode: string;
  };
  transfer_guidance: {
    phase_guardrail: string;
    exports: Array<{
      target: "operational_memory" | "settings" | "descriptors";
      label: string;
      available: boolean;
      sensitivity: "low" | "medium" | "high";
      warning: string;
    }>;
    imports: Array<{
      target: "descriptors" | "notes" | "configuration_backup";
      label: string;
      available: boolean;
      warning: string;
    }>;
  };
  about: {
    api_title: string;
    api_version: string;
    api_summary: string | null;
    checked_at: string;
    started_at: string;
    uptime_seconds: number;
    runtime_log_level: SystemSettingsLogLevel;
    settings_path: string;
    database_path: string;
    services_dir: string;
    web_dist_dir: string;
    web_bundle_present: boolean;
    model_status: {
      local_model_enabled: boolean;
      local_model_configured: boolean;
      local_model_summary: string;
      cloud_model_enabled: boolean;
      cloud_model_configured: boolean;
      cloud_model_summary: string;
      escalation_summary: string;
    };
  };
}

export interface SystemSettingsMutationResponse {
  settings: SystemSettingsResponse;
  audit_change: Change;
}

export interface EffectivenessBreakdownItem {
  bucket: string;
  label: string;
  target_level: number;
  service_count: number;
  services_at_target: number;
  services_below_target: number;
}

export interface EffectivenessReport {
  score_percent: number;
  services_at_target: number;
  total_services: number;
  improvable_services: number;
  formula: string;
  breakdown: EffectivenessBreakdownItem[];
}

export interface RecommendationAction {
  label: string;
  target: "service_detail" | "finding_review" | "credential_vault" | "model_settings";
  service_id: string | null;
}

export interface RecommendationItem {
  id: string;
  kind: "missing_descriptor" | "stale_credential" | "noisy_check" | "cloud_model";
  title: string;
  detail: string;
  action: RecommendationAction;
}

export interface RecommendationsResponse {
  items: RecommendationItem[];
}

export interface RealtimeSnapshot {
  kind: "snapshot";
  graph: GraphResponse;
  incidents: Incident[];
  investigations: Investigation[];
  widget: WidgetSummary;
}

export interface FindingFeedbackSuggestion {
  service_id: string;
  service_name: string;
  check_id: string;
  check_label: string;
  dismissal_count: number;
  action: "suppress_check" | "adjust_threshold_or_suppress";
  message: string;
}

export interface FindingReviewItem {
  finding: Finding;
  service_name: string;
  domain_label: string;
  dismissal_reason: FindingFeedbackReason | null;
  dismissal_count_for_pattern: number;
  suggestion: FindingFeedbackSuggestion | null;
}

export interface FindingReviewResponse {
  active_findings: FindingReviewItem[];
  recently_dismissed: FindingReviewItem[];
  suggestions: FindingFeedbackSuggestion[];
}

export interface FindingDismissResponse {
  finding: Finding;
  review: FindingReviewResponse;
  audit_change: Change;
}

export interface MaintenanceWindow {
  scope: "global" | "service";
  service_id: string | null;
  service_name: string | null;
  started_at: string;
  expires_at: string;
  minutes_remaining: number;
}

export interface MaintenanceModeResponse {
  global_window: MaintenanceWindow | null;
  service_windows: MaintenanceWindow[];
  self_health_guardrail: string;
}

export interface MaintenanceModeMutationResponse {
  maintenance: MaintenanceModeResponse;
  audit_change: Change;
}

export interface ServiceDetailAdapter {
  adapter_id: string;
  display_name: string;
  configuration_state: "configured" | "unconfigured" | "locked";
  configuration_summary: string;
  health_state: "healthy" | "degraded" | "unknown";
  health_summary: string;
  missing_credentials: string[];
  supported_fact_names: string[];
}

export interface ServiceDetailImproveAction {
  kind: "configure_local_model" | "configure_adapter" | "unlock_vault";
  title: string;
  detail: string;
}

export interface ServiceDetailMonitoringCheck {
  check_id: string;
  label: string;
  description: string;
  inherited_enabled: boolean;
  inherited_interval_seconds: number;
  effective_enabled: boolean;
  effective_interval_seconds: number;
  source: "global_default" | "service_override";
  suppressed: boolean;
  override_enabled: boolean | null;
  override_interval_seconds: number | null;
  override_updated_at: string | null;
}

export interface ServiceDetailResponse {
  service: Service;
  insight_section: {
    current_level: number;
    adapter_available: boolean;
    adapters: ServiceDetailAdapter[];
    improve_actions: ServiceDetailImproveAction[];
    fact_summary_available: boolean;
  };
  monitoring_section: {
    checks: ServiceDetailMonitoringCheck[];
  };
}

export interface ServiceDetailCheckSuppressionMutationResponse {
  detail: ServiceDetailResponse;
  audit_change: Change;
}

export interface ServiceDescriptorView {
  descriptor_id: string;
  file_path: string;
  write_target_path: string;
  name: string;
  category: string;
  source: "shipped" | "auto_generated" | "user";
  verified: boolean;
  generated_at: string | null;
  project_url: string | null;
  icon: string | null;
  match: {
    image_patterns: string[];
    container_name_patterns: string[];
  };
  endpoints: Array<{
    name: string;
    port: number;
    path: string | null;
    auth: string | null;
    auth_header: string | null;
    healthy_when: string | null;
  }>;
  dns_targets: Array<{
    host: string;
    record_type: string;
    expected_values: string[];
  }>;
  log_signals: {
    errors: string[];
    warnings: string[];
  };
  typical_dependency_containers: Array<{
    name: string;
    alternatives: string[];
  }>;
  typical_dependency_shares: string[];
  common_failure_modes: Array<{
    trigger: string;
    likely_cause: string;
    check_first: string[];
  }>;
  investigation_context: string | null;
  inspection_surfaces: Array<{
    id: string;
    type: string;
    description: string;
    endpoint: string | null;
    auth: string | null;
    auth_header: string | null;
    read_only: boolean;
    facts_provided: string[];
    confidence_effect: string | null;
    version_range: string | null;
  }>;
  credential_hints: Array<{
    key: string;
    description: string;
    location: string;
    prompt: string | null;
  }>;
  raw_yaml: string;
}

export interface ServiceDescriptorSaveResponse {
  descriptor: ServiceDescriptorView;
  audit_change: Change;
}

export interface ServiceDescriptorGenerateResponse {
  service_id: string;
  service_name: string;
  descriptor: ServiceDescriptorView;
  audit_change: Change;
  warnings: string[];
}

export interface QuarantinedDescriptorQueueItem {
  descriptor: ServiceDescriptorView;
  review_state: "pending" | "deferred";
  review_updated_at: string;
  matching_services: Service[];
}

export interface QuarantinedDescriptorActionResponse {
  descriptor_id: string;
  action: "edited" | "promoted" | "dismissed" | "deferred";
  review_state: "pending" | "deferred" | null;
  descriptor: ServiceDescriptorView | null;
  audit_change: Change;
}

export interface ServiceDescriptorValidationResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
  preview: {
    descriptor_id: string;
    write_target_path: string;
    match: {
      current_service_likely_matches: boolean;
      affected_services: Array<{
        service_id: string;
        service_name: string;
        likely_matches: boolean;
      }>;
    };
    dependency_impact: {
      added_container_dependencies: string[];
      removed_container_dependencies: string[];
      added_share_dependencies: string[];
      removed_share_dependencies: string[];
    };
  } | null;
}

export interface ServiceAdapterFactsItem {
  adapter_id: string;
  display_name: string;
  service_id: string;
  service_name: string;
  source: "deep_inspection_adapter";
  read_only: boolean;
  configuration_state: "configured" | "unconfigured" | "locked";
  configuration_summary: string;
  health_state: "healthy" | "degraded" | "unknown";
  health_summary: string;
  missing_credentials: string[];
  supported_fact_names: string[];
  execution_status:
    | "success"
    | "auth_failed"
    | "connection_failed"
    | "version_incompatible"
    | "parse_error"
    | "disabled"
    | null;
  facts_available: boolean;
  facts: Record<string, JsonValue>;
  excluded_paths: string[];
  applied_redaction_level:
    | "none"
    | "redact_for_model"
    | "redact_for_local"
    | "redact_for_export"
    | null;
  facts_observed_at: string | null;
  stale_at: string | null;
  next_refresh_at: string | null;
  refresh_interval_minutes: number;
  freshness: "current" | "stale" | "unavailable";
  reason: string | null;
}

export interface ServiceAdapterFactsResponse {
  service_id: string;
  service_name: string;
  checked_at: string;
  facts_available: boolean;
  adapters: ServiceAdapterFactsItem[];
}
