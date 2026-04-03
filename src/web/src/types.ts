export type ServiceStatus =
  | "healthy"
  | "degraded"
  | "down"
  | "unknown"
  | "stopped";

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

export interface RealtimeSnapshot {
  kind: "snapshot";
  graph: GraphResponse;
  incidents: Incident[];
  investigations: Investigation[];
  widget: WidgetSummary;
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

export interface ServiceDetailResponse {
  service: Service;
  insight_section: {
    current_level: number;
    adapter_available: boolean;
    adapters: ServiceDetailAdapter[];
    improve_actions: ServiceDetailImproveAction[];
    fact_summary_available: boolean;
  };
}
