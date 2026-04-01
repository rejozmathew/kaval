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
  triggering_symptom: string | null;
  suspected_cause: string | null;
  investigation_id: string | null;
  approved_actions: string[];
  confidence: number;
  updated_at: string;
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
