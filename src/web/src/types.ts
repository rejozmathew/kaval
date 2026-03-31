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
  suspected_cause: string | null;
  confidence: number;
  updated_at: string;
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
  widget: WidgetSummary;
}
