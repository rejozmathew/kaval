import { startTransition, useDeferredValue, useEffect, useState } from "react";

import type {
  Change,
  CapabilityHealthReport,
  CredentialVaultMutationResponse,
  CredentialVaultResponse,
  CredentialVaultTestResponse,
  CredentialRequest,
  EffectivenessReport,
  FindingDismissResponse,
  FindingFeedbackReason,
  FindingReviewResponse,
  GraphEdge,
  GraphEdgeMutationResponse,
  GraphResponse,
  Incident,
  Investigation,
  JournalEntry,
  JsonValue,
  MaintenanceModeMutationResponse,
  MaintenanceModeResponse,
  ModelSettingsMutationResponse,
  ModelSettingsResponse,
  ModelSettingsTestResponse,
  MonitoringSettingsMutationResponse,
  MonitoringSettingsResponse,
  NotificationSettingsMutationResponse,
  NotificationSettingsResponse,
  NotificationSettingsRoute,
  NotificationSettingsTestResponse,
  RecommendationAction,
  RecommendationItem,
  RecommendationsResponse,
  QuarantinedDescriptorActionResponse,
  QuarantinedDescriptorQueueItem,
  RealtimeSnapshot,
  ServiceAdapterFactsItem,
  ServiceAdapterFactsResponse,
  ServiceDetailCheckSuppressionMutationResponse,
  Service,
  ServiceDescriptorGenerateResponse,
  ServiceDescriptorSaveResponse,
  ServiceDescriptorValidationResponse,
  ServiceDescriptorView,
  ServiceStatus,
  ServiceDetailResponse,
  SystemSettingsLogLevel,
  SystemSettingsMutationResponse,
  SystemSettingsResponse,
  SystemProfile,
  UserNote,
  WidgetSummary,
} from "./types";

const CARD_WIDTH = 220;
const CARD_HEIGHT = 96;
const COLUMN_WIDTH = 280;
const HEADER_HEIGHT = 72;
const ROW_GAP = 128;
const VM_CHILD_BADGE_WIDTH = 86;
const VM_CHILD_BADGE_GAP = 8;
const MAX_VM_CHILD_BADGES = 2;

interface LoadState {
  graph: GraphResponse | null;
  capabilityHealth: CapabilityHealthReport | null;
  changes: Change[];
  credentialRequests: CredentialRequest[];
  effectiveness: EffectivenessReport | null;
  findingReview: FindingReviewResponse | null;
  incidents: Incident[];
  investigations: Investigation[];
  journalEntries: JournalEntry[];
  recommendations: RecommendationsResponse | null;
  systemProfile: SystemProfile | null;
  userNotes: UserNote[];
  widget: WidgetSummary | null;
  error: string | null;
  loading: boolean;
}

interface FindingFeedbackMutationState {
  dismissingFindingId: string | null;
  error: string | null;
  auditChangeId: string | null;
}

interface MaintenanceModeState {
  detail: MaintenanceModeResponse | null;
  error: string | null;
  loading: boolean;
}

interface MaintenanceModeEditorState {
  globalDurationMinutes: string;
  serviceId: string;
  serviceDurationMinutes: string;
}

interface MaintenanceModeMutationState {
  savingTarget: "global" | "service" | null;
  clearingServiceId: string | "global" | null;
  error: string | null;
  auditChangeId: string | null;
}

interface ServiceDetailState {
  detail: ServiceDetailResponse | null;
  error: string | null;
  loading: boolean;
}

interface ServiceDetailSuppressionMutationState {
  submitting: boolean;
  checkId: string | null;
  error: string | null;
  auditChangeId: string | null;
}

interface ServiceAdapterFactsState {
  detail: ServiceAdapterFactsResponse | null;
  error: string | null;
  loading: boolean;
}

interface ServiceDescriptorState {
  detail: ServiceDescriptorView | null;
  error: string | null;
  loading: boolean;
}

interface QuarantinedDescriptorQueueState {
  items: QuarantinedDescriptorQueueItem[];
  error: string | null;
  loading: boolean;
}

interface ModelSettingsState {
  detail: ModelSettingsResponse | null;
  error: string | null;
  loading: boolean;
}

interface ModelSettingsEditorState {
  localEnabled: boolean;
  localModel: string;
  localBaseUrl: string;
  localTimeoutSeconds: string;
  localApiKey: string;
  clearLocalStoredApiKey: boolean;
  cloudEnabled: boolean;
  cloudProvider: "anthropic" | "openai" | "openai_compatible";
  cloudModel: string;
  cloudBaseUrl: string;
  cloudTimeoutSeconds: string;
  cloudMaxOutputTokens: string;
  cloudApiKey: string;
  clearCloudStoredApiKey: boolean;
  escalationFindingCountGt: string;
  escalationLocalConfidenceLt: string;
  escalationOnMultipleDomains: boolean;
  escalationOnChangelogResearch: boolean;
  escalationOnUserRequest: boolean;
  escalationMaxCloudCallsPerDay: string;
  escalationMaxCloudCallsPerIncident: string;
}

interface ModelSettingsMutationState {
  saving: boolean;
  applying: boolean;
  testingTarget: "local" | "cloud" | null;
  error: string | null;
  auditChangeId: string | null;
  testResult: ModelSettingsTestResponse | null;
}

interface NotificationSettingsState {
  detail: NotificationSettingsResponse | null;
  error: string | null;
  loading: boolean;
}

interface NotificationChannelEditorState {
  clientId: string;
  channelId: string | null;
  name: string;
  enabled: boolean;
  kind: string;
  destination: string;
  destinationConfigured: boolean;
  destinationSource: "vault" | "env" | "unset";
}

interface NotificationSettingsEditorState {
  channels: NotificationChannelEditorState[];
  criticalRoute: NotificationSettingsRoute;
  highRoute: NotificationSettingsRoute;
  mediumRoute: NotificationSettingsRoute;
  lowRoute: NotificationSettingsRoute;
  dedupWindowMinutes: string;
  digestWindowMinutes: string;
  quietHoursEnabled: boolean;
  quietHoursStart: string;
  quietHoursEnd: string;
  quietHoursTimezone: string;
}

interface NotificationSettingsMutationState {
  saving: boolean;
  applying: boolean;
  testingChannelId: string | null;
  error: string | null;
  auditChangeId: string | null;
  testResult: NotificationSettingsTestResponse | null;
}

interface MonitoringSettingsState {
  detail: MonitoringSettingsResponse | null;
  error: string | null;
  loading: boolean;
}

interface MonitoringCheckEditorState {
  checkId: string;
  label: string;
  description: string;
  enabled: boolean;
  intervalSeconds: string;
  tlsWarningDays: string;
  restartDeltaThreshold: string;
  probeTimeoutSeconds: string;
  defaultEnabled: boolean;
  defaultIntervalSeconds: number;
  defaultTlsWarningDays: number | null;
  defaultRestartDeltaThreshold: number | null;
  defaultProbeTimeoutSeconds: number | null;
}

interface MonitoringServiceOverrideEditorState {
  clientId: string;
  serviceId: string;
  checkId: string;
  enabledMode: "inherit" | "enabled" | "disabled";
  intervalSeconds: string;
  tlsWarningDays: string;
  restartDeltaThreshold: string;
  probeTimeoutSeconds: string;
}

interface MonitoringSettingsEditorState {
  checks: MonitoringCheckEditorState[];
  serviceOverrides: MonitoringServiceOverrideEditorState[];
}

interface MonitoringSettingsMutationState {
  saving: boolean;
  applying: boolean;
  error: string | null;
  auditChangeId: string | null;
}

interface CredentialVaultState {
  detail: CredentialVaultResponse | null;
  error: string | null;
  loading: boolean;
}

interface CredentialVaultEditorState {
  unlockPassphrase: string;
  currentPassphrase: string;
  newPassphrase: string;
  confirmNewPassphrase: string;
}

interface CredentialVaultMutationState {
  unlocking: boolean;
  locking: boolean;
  testing: boolean;
  changingPassword: boolean;
  error: string | null;
  auditChangeId: string | null;
  testResult: CredentialVaultTestResponse | null;
}

interface SystemSettingsState {
  detail: SystemSettingsResponse | null;
  error: string | null;
  loading: boolean;
}

interface SystemSettingsEditorState {
  logLevel: SystemSettingsLogLevel;
  auditDetailRetentionDays: string;
  auditSummaryRetentionDays: string;
}

interface SystemSettingsMutationState {
  saving: boolean;
  applying: boolean;
  error: string | null;
  auditChangeId: string | null;
}

type AuditEventType =
  | "service_lifecycle"
  | "image_update"
  | "container_restart"
  | "plugin_update"
  | "system_event"
  | "external_change"
  | "graph_edit"
  | "descriptor"
  | "model_settings"
  | "notification_settings"
  | "monitoring_settings"
  | "system_settings"
  | "credential_vault"
  | "maintenance"
  | "finding_feedback"
  | "config_change";

interface AuditTrailFilterState {
  type: AuditEventType | "all";
  serviceId: string;
  dateFrom: string;
  dateTo: string;
}

interface AuditTrailEntry {
  change: Change;
  auditType: AuditEventType;
  targetLabel: string;
  detailAvailable: boolean;
  linkedInvestigationIds: string[];
}

interface AuditTrailExportRecord {
  id: string;
  timestamp: string;
  audit_type: string;
  change_type: string;
  target: string;
  description: string;
  trigger: string;
  result: string;
  prior_value: string;
  detail_state: string;
  correlated_incidents: string[];
  investigation_ids: string[];
}

interface ModelUsageWindowSummary {
  key: "today" | "week" | "month";
  label: string;
  investigationCount: number;
  localModelCalls: number;
  cloudModelCalls: number;
  localInputTokens: number;
  localOutputTokens: number;
  cloudInputTokens: number;
  cloudOutputTokens: number;
  estimatedCloudCostUsd: number;
  estimatedTotalCostUsd: number;
}

interface ModelUsageIncidentBreakdown {
  incidentId: string;
  incidentTitle: string;
  severity: string;
  status: string;
  investigationCount: number;
  localModelCalls: number;
  cloudModelCalls: number;
  localInputTokens: number;
  localOutputTokens: number;
  cloudInputTokens: number;
  cloudOutputTokens: number;
  estimatedCloudCostUsd: number;
  estimatedTotalCostUsd: number;
  cloudEscalationReasons: string[];
  latestInvestigationAt: string | null;
}

interface ModelUsageEscalationSummary {
  reason: string;
  label: string;
  matchedInvestigations: number;
  executedInvestigations: number;
  cloudCallCount: number;
}

interface ModelUsageDashboardData {
  telemetryBackedInvestigationCount: number;
  windows: ModelUsageWindowSummary[];
  incidents: ModelUsageIncidentBreakdown[];
  escalations: ModelUsageEscalationSummary[];
}

interface QuarantinedDescriptorEditorState {
  descriptorId: string | null;
  rawYaml: string;
  open: boolean;
}

interface QuarantinedDescriptorMutationState {
  submitting: boolean;
  descriptorId: string | null;
  action: "refresh" | "save" | "promote" | "dismiss" | "defer" | null;
  error: string | null;
  auditChangeId: string | null;
}

type DescriptorEditorMode = "form" | "yaml";

interface DescriptorEditorEndpointState {
  clientId: string;
  name: string;
  port: string;
  path: string;
  auth: string;
  authHeader: string;
  healthyWhen: string;
}

interface DescriptorEditorDependencyState {
  clientId: string;
  name: string;
  alternatives: string;
}

interface DescriptorEditorState {
  mode: DescriptorEditorMode;
  imagePatterns: string;
  containerNamePatterns: string;
  shareDependencies: string;
  endpoints: DescriptorEditorEndpointState[];
  containerDependencies: DescriptorEditorDependencyState[];
  rawYaml: string;
}

interface DescriptorMutationState {
  saving: boolean;
  error: string | null;
  auditChangeId: string | null;
}

interface DescriptorValidationState {
  validating: boolean;
  error: string | null;
  result: ServiceDescriptorValidationResponse | null;
}

interface GuidedSetupMutationState {
  identifyingServiceId: string | null;
  error: string | null;
  auditChangeId: string | null;
}

type MemoryTabId = "journal" | "notes" | "system" | "recurrence" | "facts";

interface NoteEditorState {
  serviceId: string;
  note: string;
  safeForModel: boolean;
  stale: boolean;
  lastVerifiedAt: string;
}

interface NoteMutationState {
  saving: boolean;
  targetNoteId: string | null;
  error: string | null;
}

interface EdgeMutationState {
  saving: boolean;
  error: string | null;
  auditChangeId: string | null;
}

interface EdgeEditorState {
  sourceServiceId: string;
  targetServiceId: string;
  previousSourceServiceId: string | null;
  previousTargetServiceId: string | null;
  description: string;
}

interface GraphFilterState {
  categories: string[];
  confidences: GraphEdge["confidence"][];
  insightLevels: number[];
  statuses: ServiceStatus[];
}

interface IncidentGraphFocus {
  rootServiceId: string | null;
  serviceIds: string[];
  edgeKeys: string[];
  evidenceServiceIds: string[];
}

interface UserNoteGroup {
  key: string;
  label: string;
  serviceId: string | null;
  notes: UserNote[];
}

interface RecurrencePatternView {
  activeEntry: JournalEntry;
  priorEntries: JournalEntry[];
}

const EMPTY_SUPPLEMENTAL_STATE: SupplementalPanelsState = {
  capabilityHealth: null,
  changes: [],
  credentialRequests: [],
  effectiveness: null,
  findingReview: null,
  journalEntries: [],
  recommendations: null,
  systemProfile: null,
  userNotes: [],
};

interface NodeLayout {
  service: Service;
  x: number;
  y: number;
}

interface VmHostedSurfaceBadge {
  label: string;
  empty: boolean;
}

type SupplementalPanelsState = Pick<
  LoadState,
  | "capabilityHealth"
  | "changes"
  | "credentialRequests"
  | "effectiveness"
  | "findingReview"
  | "journalEntries"
  | "recommendations"
  | "systemProfile"
  | "userNotes"
>;

const statusLabel = {
  healthy: "Healthy",
  degraded: "Degraded",
  down: "Down",
  stopped: "Stopped",
  unknown: "Unknown",
} as const;

const insightLabel = {
  0: "Discovered",
  1: "Matched",
  2: "Monitored",
  3: "Ready",
  4: "Deep",
  5: "Enriched",
} as const;

const notificationRouteOptions: NotificationSettingsRoute[] = [
  "immediate",
  "immediate_with_dedup",
  "hourly_digest",
  "dashboard_only",
];

const systemLogLevelOptions: SystemSettingsLogLevel[] = [
  "critical",
  "error",
  "warning",
  "info",
  "debug",
  "trace",
];

const DEFAULT_AUDIT_DETAIL_RETENTION_DAYS = 90;
const DEFAULT_AUDIT_SUMMARY_RETENTION_DAYS = 365;
const GLOBAL_AUDIT_SERVICE_FILTER = "__global__";

const graphConfidenceLegend: Array<{
  confidence: GraphEdge["confidence"];
  label: string;
  detail: string;
}> = [
  {
    confidence: "user_confirmed",
    label: "Confirmed edge",
    detail: "Explicitly confirmed in the admin graph.",
  },
  {
    confidence: "runtime_observed",
    label: "Runtime observed edge",
    detail: "Backed by live service facts or adapter output.",
  },
  {
    confidence: "configured",
    label: "Configured edge",
    detail: "Declared by known configuration or mounted resources.",
  },
  {
    confidence: "inferred",
    label: "Inferred edge",
    detail: "Derived from topology or descriptor matching only.",
  },
  {
    confidence: "auto_generated",
    label: "Auto-generated edge",
    detail: "Suggested automatically and still awaiting review.",
  },
];

export default function App() {
  const [state, setState] = useState<LoadState>({
    graph: null,
    ...EMPTY_SUPPLEMENTAL_STATE,
    incidents: [],
    investigations: [],
    widget: null,
    error: null,
    loading: true,
  });
  const [selectedServiceId, setSelectedServiceId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<"connecting" | "live" | "offline">("connecting");
  const [serviceDetailState, setServiceDetailState] = useState<ServiceDetailState>({
    detail: null,
    error: null,
    loading: false,
  });
  const [serviceDetailSuppressionMutationState, setServiceDetailSuppressionMutationState] =
    useState<ServiceDetailSuppressionMutationState>({
      submitting: false,
      checkId: null,
      error: null,
      auditChangeId: null,
    });
  const [findingFeedbackReasonById, setFindingFeedbackReasonById] = useState<
    Record<string, FindingFeedbackReason>
  >({});
  const [findingFeedbackMutationState, setFindingFeedbackMutationState] =
    useState<FindingFeedbackMutationState>({
      dismissingFindingId: null,
      error: null,
      auditChangeId: null,
    });
  const [maintenanceModeState, setMaintenanceModeState] = useState<MaintenanceModeState>({
    detail: null,
    error: null,
    loading: true,
  });
  const [maintenanceModeEditorState, setMaintenanceModeEditorState] =
    useState<MaintenanceModeEditorState>({
      globalDurationMinutes: "30",
      serviceId: "",
      serviceDurationMinutes: "120",
    });
  const [maintenanceModeMutationState, setMaintenanceModeMutationState] =
    useState<MaintenanceModeMutationState>({
      savingTarget: null,
      clearingServiceId: null,
      error: null,
      auditChangeId: null,
    });
  const [serviceAdapterFactsState, setServiceAdapterFactsState] =
    useState<ServiceAdapterFactsState>({
      detail: null,
      error: null,
      loading: false,
    });
  const [serviceDescriptorState, setServiceDescriptorState] = useState<ServiceDescriptorState>({
    detail: null,
    error: null,
    loading: false,
  });
  const [modelSettingsState, setModelSettingsState] = useState<ModelSettingsState>({
    detail: null,
    error: null,
    loading: true,
  });
  const [modelSettingsEditorState, setModelSettingsEditorState] =
    useState<ModelSettingsEditorState | null>(null);
  const [modelSettingsMutationState, setModelSettingsMutationState] =
    useState<ModelSettingsMutationState>({
      saving: false,
      applying: false,
      testingTarget: null,
      error: null,
      auditChangeId: null,
      testResult: null,
    });
  const [notificationSettingsState, setNotificationSettingsState] =
    useState<NotificationSettingsState>({
      detail: null,
      error: null,
      loading: true,
    });
  const [notificationSettingsEditorState, setNotificationSettingsEditorState] =
    useState<NotificationSettingsEditorState | null>(null);
  const [notificationSettingsMutationState, setNotificationSettingsMutationState] =
    useState<NotificationSettingsMutationState>({
      saving: false,
      applying: false,
      testingChannelId: null,
      error: null,
      auditChangeId: null,
      testResult: null,
    });
  const [monitoringSettingsState, setMonitoringSettingsState] =
    useState<MonitoringSettingsState>({
      detail: null,
      error: null,
      loading: true,
    });
  const [monitoringSettingsEditorState, setMonitoringSettingsEditorState] =
    useState<MonitoringSettingsEditorState | null>(null);
  const [monitoringSettingsMutationState, setMonitoringSettingsMutationState] =
    useState<MonitoringSettingsMutationState>({
      saving: false,
      applying: false,
      error: null,
      auditChangeId: null,
    });
  const [credentialVaultState, setCredentialVaultState] = useState<CredentialVaultState>({
    detail: null,
    error: null,
    loading: true,
  });
  const [credentialVaultEditorState, setCredentialVaultEditorState] =
    useState<CredentialVaultEditorState>({
      unlockPassphrase: "",
      currentPassphrase: "",
      newPassphrase: "",
      confirmNewPassphrase: "",
    });
  const [credentialVaultMutationState, setCredentialVaultMutationState] =
    useState<CredentialVaultMutationState>({
      unlocking: false,
      locking: false,
      testing: false,
      changingPassword: false,
      error: null,
      auditChangeId: null,
      testResult: null,
    });
  const [systemSettingsState, setSystemSettingsState] = useState<SystemSettingsState>({
    detail: null,
    error: null,
    loading: true,
  });
  const [systemSettingsEditorState, setSystemSettingsEditorState] =
    useState<SystemSettingsEditorState | null>(null);
  const [systemSettingsMutationState, setSystemSettingsMutationState] =
    useState<SystemSettingsMutationState>({
      saving: false,
      applying: false,
      error: null,
      auditChangeId: null,
    });
  const [auditTrailFilters, setAuditTrailFilters] = useState<AuditTrailFilterState>({
    type: "all",
    serviceId: "all",
    dateFrom: "",
    dateTo: "",
  });
  const [quarantinedDescriptorQueueState, setQuarantinedDescriptorQueueState] =
    useState<QuarantinedDescriptorQueueState>({
      items: [],
      error: null,
      loading: true,
    });
  const [selectedQuarantinedDescriptorId, setSelectedQuarantinedDescriptorId] =
    useState<string | null>(null);
  const [quarantinedDescriptorEditorState, setQuarantinedDescriptorEditorState] =
    useState<QuarantinedDescriptorEditorState>({
      descriptorId: null,
      rawYaml: "",
      open: false,
    });
  const [quarantinedDescriptorMutationState, setQuarantinedDescriptorMutationState] =
    useState<QuarantinedDescriptorMutationState>({
      submitting: false,
      descriptorId: null,
      action: null,
      error: null,
      auditChangeId: null,
    });
  const [descriptorEditorOpen, setDescriptorEditorOpen] = useState(false);
  const [descriptorEditorState, setDescriptorEditorState] =
    useState<DescriptorEditorState | null>(null);
  const [descriptorMutationState, setDescriptorMutationState] =
    useState<DescriptorMutationState>({
      saving: false,
      error: null,
      auditChangeId: null,
    });
  const [descriptorValidationState, setDescriptorValidationState] =
    useState<DescriptorValidationState>({
      validating: false,
      error: null,
      result: null,
    });
  const [guidedSetupSkippedServiceIds, setGuidedSetupSkippedServiceIds] = useState<string[]>([]);
  const [guidedSetupMutationState, setGuidedSetupMutationState] =
    useState<GuidedSetupMutationState>({
      identifyingServiceId: null,
      error: null,
      auditChangeId: null,
    });
  const [activeMemoryTab, setActiveMemoryTab] = useState<MemoryTabId>("journal");
  const [noteSearch, setNoteSearch] = useState("");
  const deferredNoteSearch = useDeferredValue(noteSearch);
  const [noteEditorState, setNoteEditorState] = useState<NoteEditorState>({
    serviceId: "",
    note: "",
    safeForModel: true,
    stale: false,
    lastVerifiedAt: "",
  });
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [noteMutationState, setNoteMutationState] = useState<NoteMutationState>({
    saving: false,
    targetNoteId: null,
    error: null,
  });
  const [selectedEdgeKey, setSelectedEdgeKey] = useState<string | null>(null);
  const [hoveredEdgeKey, setHoveredEdgeKey] = useState<string | null>(null);
  const [edgeEditorState, setEdgeEditorState] = useState<EdgeEditorState | null>(null);
  const [edgeMutationState, setEdgeMutationState] = useState<EdgeMutationState>({
    saving: false,
    error: null,
    auditChangeId: null,
  });
  const [graphFilters, setGraphFilters] = useState<GraphFilterState>({
    categories: [],
    confidences: [],
    insightLevels: [],
    statuses: [],
  });
  const [incidentModeEnabled, setIncidentModeEnabled] = useState(false);
  const selectedQuarantinedDescriptor =
    quarantinedDescriptorQueueState.items.find(
      (item) => item.descriptor.descriptor_id === selectedQuarantinedDescriptorId,
    ) ??
    quarantinedDescriptorQueueState.items[0] ??
    null;

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [
          graphResponse,
          incidentResponse,
          investigationResponse,
          widgetResponse,
          supplemental,
        ] = await Promise.all([
          fetch("/api/v1/graph"),
          fetch("/api/v1/incidents"),
          fetch("/api/v1/investigations"),
          fetch("/api/v1/widget"),
          loadSupplementalPanels(),
        ]);
        if (
          !graphResponse.ok ||
          !incidentResponse.ok ||
          !investigationResponse.ok ||
          !widgetResponse.ok
        ) {
          throw new Error("Kaval UI could not load monitoring data.");
        }

        const [graph, incidents, investigations, widget] = (await Promise.all([
          graphResponse.json(),
          incidentResponse.json(),
          investigationResponse.json(),
          widgetResponse.json(),
        ])) as [GraphResponse, Incident[], Investigation[], WidgetSummary];

        if (cancelled) {
          return;
        }

        startTransition(() => {
          setState({
            graph,
            ...supplemental,
            incidents,
            investigations,
            widget,
            error: null,
            loading: false,
          });
        });
      } catch (error) {
        if (cancelled) {
          return;
        }
        const message = error instanceof Error ? error.message : "Unknown UI load failure.";
        startTransition(() => {
          setState({
            graph: null,
            ...EMPTY_SUPPLEMENTAL_STATE,
            incidents: [],
            investigations: [],
            widget: null,
            error: message,
            loading: false,
          });
        });
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void loadModelSettings();
  }, []);

  useEffect(() => {
    void loadNotificationSettings();
  }, []);

  useEffect(() => {
    void loadMonitoringSettings();
  }, []);

  useEffect(() => {
    void loadCredentialVault();
  }, []);

  useEffect(() => {
    void loadSystemSettings();
  }, []);

  useEffect(() => {
    void loadMaintenanceMode();
  }, []);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;

    const connect = () => {
      if (cancelled) {
        return;
      }

      startTransition(() => {
        setLiveState("connecting");
      });

      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${protocol}://${window.location.host}/api/v1/ws`);
      socket.onopen = () => {
        startTransition(() => {
          setLiveState("live");
        });
      };
      socket.onmessage = (event) => {
        const snapshot = JSON.parse(event.data) as RealtimeSnapshot;
        if (snapshot.kind !== "snapshot") {
          return;
        }
        void loadSupplementalPanels()
          .then((supplemental) => {
            if (cancelled) {
              return;
            }
            startTransition(() => {
              setState((current) => ({
                ...current,
                ...supplemental,
              }));
            });
          })
          .catch(() => {
            if (cancelled) {
              return;
            }
            startTransition(() => {
              setState((current) => current);
            });
          });
        startTransition(() => {
          setState((current) => ({
            ...current,
            graph: snapshot.graph,
            incidents: snapshot.incidents,
            investigations: snapshot.investigations,
            widget: snapshot.widget,
            error: null,
            loading: false,
          }));
          setSelectedServiceId((currentSelection) => {
            if (
              currentSelection !== null &&
              snapshot.graph.services.some((service) => service.id === currentSelection)
            ) {
              return currentSelection;
            }
            return snapshot.graph.services[0]?.id ?? null;
          });
        });
      };
      socket.onerror = () => {
        socket?.close();
      };
      socket.onclose = () => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setLiveState("offline");
        });
        reconnectTimer = window.setTimeout(connect, 2000);
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      socket?.close();
    };
  }, []);

  useEffect(() => {
    const nextIncidentId = chooseIncidentId(state.incidents, selectedIncidentId);
    if (nextIncidentId !== selectedIncidentId) {
      setSelectedIncidentId(nextIncidentId);
    }

    const nextServiceId = chooseServiceId(
      state.graph?.services ?? [],
      state.incidents,
      selectedServiceId,
      nextIncidentId,
    );
    if (nextServiceId !== selectedServiceId) {
      setSelectedServiceId(nextServiceId);
    }
  }, [state.graph, state.incidents, selectedIncidentId, selectedServiceId]);

  useEffect(() => {
    const services = state.graph?.services ?? [];
    if (services.length === 0) {
      return;
    }
    setMaintenanceModeEditorState((current) => {
      if (current.serviceId !== "" && services.some((service) => service.id === current.serviceId)) {
        return current;
      }
      return {
        ...current,
        serviceId: selectedServiceId ?? services[0].id,
      };
    });
  }, [state.graph, selectedServiceId]);

  useEffect(() => {
    void loadQuarantinedDescriptorQueue();
  }, []);

  useEffect(() => {
    startTransition(() => {
      setSelectedQuarantinedDescriptorId((current) =>
        chooseQuarantinedDescriptorId(
          quarantinedDescriptorQueueState.items,
          current,
          selectedServiceId,
        ),
      );
    });
  }, [quarantinedDescriptorQueueState.items, selectedServiceId]);

  useEffect(() => {
    if (selectedQuarantinedDescriptor === null) {
      startTransition(() => {
        setQuarantinedDescriptorEditorState({
          descriptorId: null,
          rawYaml: "",
          open: false,
        });
        setQuarantinedDescriptorMutationState({
          submitting: false,
          descriptorId: null,
          action: null,
          error: null,
          auditChangeId: null,
        });
      });
      return;
    }
    startTransition(() => {
      setQuarantinedDescriptorEditorState({
        descriptorId: selectedQuarantinedDescriptor.descriptor.descriptor_id,
        rawYaml: selectedQuarantinedDescriptor.descriptor.raw_yaml,
        open: false,
      });
    });
  }, [
    selectedQuarantinedDescriptor?.descriptor.descriptor_id,
    selectedQuarantinedDescriptor?.descriptor.raw_yaml,
  ]);

  useEffect(() => {
    let cancelled = false;

    if (selectedServiceId === null || state.graph === null) {
      startTransition(() => {
        setServiceDetailState({
          detail: null,
          error: null,
          loading: false,
        });
      });
      return () => {
        cancelled = true;
      };
    }

    startTransition(() => {
      setServiceDetailState((current) => ({
        detail:
          current.detail?.service.id === selectedServiceId ? current.detail : null,
        error: null,
        loading: true,
      }));
    });

    void fetchJson<ServiceDetailResponse>(
      `/api/v1/services/${encodeURIComponent(selectedServiceId)}/detail`,
    )
      .then((detail) => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setServiceDetailState({
            detail,
            error: null,
            loading: false,
          });
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        const message =
          error instanceof Error ? error.message : "Unknown service detail load failure.";
        startTransition(() => {
          setServiceDetailState({
            detail: null,
            error: message,
            loading: false,
          });
        });
      });

    return () => {
      cancelled = true;
    };
  }, [selectedServiceId, state.graph, state.credentialRequests]);

  useEffect(() => {
    startTransition(() => {
      setServiceDetailSuppressionMutationState({
        submitting: false,
        checkId: null,
        error: null,
        auditChangeId: null,
      });
    });
  }, [selectedServiceId]);

  useEffect(() => {
    let cancelled = false;

    if (activeMemoryTab !== "facts") {
      return () => {
        cancelled = true;
      };
    }

    if (selectedServiceId === null) {
      startTransition(() => {
        setServiceAdapterFactsState({
          detail: null,
          error: null,
          loading: false,
        });
      });
      return () => {
        cancelled = true;
      };
    }

    startTransition(() => {
      setServiceAdapterFactsState((current) => ({
        detail:
          current.detail?.service_id === selectedServiceId ? current.detail : null,
        error: null,
        loading: true,
      }));
    });

    void fetchJson<ServiceAdapterFactsResponse>(
      `/api/v1/services/${encodeURIComponent(selectedServiceId)}/adapter-facts`,
    )
      .then((detail) => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setServiceAdapterFactsState({
            detail,
            error: null,
            loading: false,
          });
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        const message =
          error instanceof Error ? error.message : "Unknown adapter facts load failure.";
        startTransition(() => {
          setServiceAdapterFactsState({
            detail: null,
            error: message,
            loading: false,
          });
        });
      });

    return () => {
      cancelled = true;
    };
  }, [activeMemoryTab, selectedServiceId]);

  useEffect(() => {
    let cancelled = false;

    if (
      selectedServiceId === null ||
      serviceDetailState.detail?.service.id !== selectedServiceId ||
      serviceDetailState.detail.service.descriptor_id === null
    ) {
      startTransition(() => {
        setServiceDescriptorState({
          detail: null,
          error: null,
          loading: false,
        });
      });
      return () => {
        cancelled = true;
      };
    }

    startTransition(() => {
      setServiceDescriptorState((current) => ({
        detail:
          current.detail?.descriptor_id === serviceDetailState.detail?.service.descriptor_id
            ? current.detail
            : null,
        error: null,
        loading: true,
      }));
    });

    void fetchJson<ServiceDescriptorView>(
      `/api/v1/services/${encodeURIComponent(selectedServiceId)}/descriptor`,
    )
      .then((detail) => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setServiceDescriptorState({
            detail,
            error: null,
            loading: false,
          });
        });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        const message =
          error instanceof Error ? error.message : "Unknown descriptor view load failure.";
        startTransition(() => {
          setServiceDescriptorState({
            detail: null,
            error: message,
            loading: false,
          });
        });
      });

    return () => {
      cancelled = true;
    };
  }, [selectedServiceId, serviceDetailState.detail?.service.descriptor_id, serviceDetailState.detail?.service.id]);

  useEffect(() => {
    if (serviceDescriptorState.detail === null) {
      startTransition(() => {
        setDescriptorEditorOpen(false);
        setDescriptorEditorState(null);
        setDescriptorMutationState({
          saving: false,
          error: null,
          auditChangeId: null,
        });
        setDescriptorValidationState({
          validating: false,
          error: null,
          result: null,
        });
      });
      return;
    }
    const descriptorDetail = serviceDescriptorState.detail;

    startTransition(() => {
      setDescriptorEditorState((current) =>
        createDescriptorEditorState(
          descriptorDetail,
          current?.mode ?? "form",
        ),
      );
      setDescriptorValidationState({
        validating: false,
        error: null,
        result: null,
      });
    });
  }, [
    serviceDescriptorState.detail?.descriptor_id,
    serviceDescriptorState.detail?.file_path,
    serviceDescriptorState.detail?.raw_yaml,
  ]);

  const services = state.graph?.services ?? [];
  const edges = state.graph?.edges ?? [];
  const nodeMetaByServiceId = new Map(
    (state.graph?.node_meta ?? []).map((item) => [item.service_id, item]),
  );
  const serviceById = new Map(services.map((service) => [service.id, service]));
  const serviceNames = new Map(services.map((service) => [service.id, service.name]));
  const containerServices = services.filter((service) => service.type === "container");
  const vmServices = services.filter((service) => service.type === "vm");
  const shareServices = services.filter((service) => service.type === "share");
  const matchedContainerCount = containerServices.filter(
    (service) => service.descriptor_id !== null,
  ).length;
  const unknownContainerServices = containerServices.filter(
    (service) => service.descriptor_id === null,
  );
  const visibleUnknownContainerServices = unknownContainerServices.filter(
    (service) => !guidedSetupSkippedServiceIds.includes(service.id),
  );
  const skippedUnknownContainerCount =
    unknownContainerServices.length - visibleUnknownContainerServices.length;
  const lowConfidenceEdges = edges.filter((edge) => edgeNeedsConfirmation(edge));
  const setupImprovableServices = services
    .filter((service) => nodeMetaByServiceId.get(service.id)?.improve_available ?? false)
    .sort((left, right) => left.name.localeCompare(right.name));
  const selectedQuarantinedMatchingServices =
    selectedQuarantinedDescriptor?.matching_services.map(
      (service) => serviceById.get(service.id) ?? service,
    ) ?? [];
  const descriptorReviewQueueCount = quarantinedDescriptorQueueState.items.length;
  const pendingDescriptorReviewCount = quarantinedDescriptorQueueState.items.filter(
    (item) => item.review_state === "pending",
  ).length;
  const deferredDescriptorReviewCount = quarantinedDescriptorQueueState.items.filter(
    (item) => item.review_state === "deferred",
  ).length;
  const selectedQuarantinedDraftDirty =
    selectedQuarantinedDescriptor !== null &&
    quarantinedDescriptorEditorState.descriptorId ===
      selectedQuarantinedDescriptor.descriptor.descriptor_id &&
    quarantinedDescriptorEditorState.rawYaml !==
      selectedQuarantinedDescriptor.descriptor.raw_yaml;
  const serviceReferenceMap = buildServiceReferenceMap(services);
  const categories = groupServicesByCategory(services);
  const layouts = buildLayouts(categories);
  const layoutById = new Map(layouts.map((layout) => [layout.service.id, layout]));
  const matchingServiceIds = new Set(
    services
      .filter((service) => {
        const insightLevel = service.insight?.level ?? 0;
        return (
          (graphFilters.categories.length === 0 ||
            graphFilters.categories.includes(service.category)) &&
          (graphFilters.statuses.length === 0 || graphFilters.statuses.includes(service.status)) &&
          (graphFilters.insightLevels.length === 0 ||
            graphFilters.insightLevels.includes(insightLevel))
        );
      })
      .map((service) => service.id),
  );
  const matchingConfidenceEdges = edges.filter(
    (edge) =>
      graphFilters.confidences.length === 0 ||
      graphFilters.confidences.includes(edge.confidence),
  );
  const confidenceMatchedServiceIds = new Set(
    matchingConfidenceEdges.flatMap((edge) => [
      edge.source_service_id,
      edge.target_service_id,
    ]),
  );
  const filterHighlightedServiceIds = new Set(
    services
      .filter(
        (service) =>
          matchingServiceIds.has(service.id) &&
          (graphFilters.confidences.length === 0 ||
            confidenceMatchedServiceIds.has(service.id)),
      )
      .map((service) => service.id),
  );
  const filterHighlightedEdgeKeys = new Set(
    matchingConfidenceEdges
      .filter(
        (edge) =>
          filterHighlightedServiceIds.has(edge.source_service_id) &&
          filterHighlightedServiceIds.has(edge.target_service_id),
      )
      .map(edgeKey),
  );
  const selectedEdge =
    selectedEdgeKey === null ? null : edges.find((edge) => edgeKey(edge) === selectedEdgeKey) ?? null;
  const hoveredEdge =
    hoveredEdgeKey === null ? null : edges.find((edge) => edgeKey(edge) === hoveredEdgeKey) ?? null;
  const activeEdge = selectedEdge ?? hoveredEdge;
  const activeEdgeSourceName =
    activeEdge === null
      ? null
      : serviceNames.get(activeEdge.source_service_id) ?? activeEdge.source_service_id;
  const activeEdgeTargetName =
    activeEdge === null
      ? null
      : serviceNames.get(activeEdge.target_service_id) ?? activeEdge.target_service_id;
  const selectedService =
    services.find((service) => service.id === selectedServiceId) ?? layouts[0]?.service ?? null;
  const selectedServiceDetail =
    selectedService !== null && serviceDetailState.detail?.service.id === selectedService.id
      ? serviceDetailState.detail
      : null;
  const selectedVmProfile =
    selectedServiceDetail?.service.type === "vm"
      ? state.systemProfile?.vms.find(
          (vm) => vm.name.toLocaleLowerCase() === selectedServiceDetail.service.name.toLocaleLowerCase(),
        ) ?? null
      : null;
  const selectedVmHostedSurfaceLabels =
    selectedServiceDetail?.service.type === "vm"
      ? buildVmHostedSurfaceLabels(selectedServiceDetail.service)
      : [];
  const selectedServiceFacts =
    selectedService !== null && serviceAdapterFactsState.detail?.service_id === selectedService.id
      ? serviceAdapterFactsState.detail
      : null;
  const modelSettingsDetail = modelSettingsState.detail;
  const modelSettingsTestScope =
    modelSettingsDetail !== null && modelSettingsDetail.apply_required ? "staged" : "active";
  const notificationSettingsDetail = notificationSettingsState.detail;
  const testableNotificationChannelId =
    notificationSettingsEditorState?.channels.find(
      (channel) =>
        channel.channelId !== null &&
        channel.enabled &&
        channel.destinationConfigured,
    )?.channelId ?? null;
  const notificationSettingsTestScope =
    notificationSettingsDetail !== null && notificationSettingsDetail.apply_required
      ? "staged"
      : "active";
  const monitoringSettingsDetail = monitoringSettingsState.detail;
  const findingReview = state.findingReview;
  const credentialVaultDetail = credentialVaultState.detail;
  const maintenanceModeDetail = maintenanceModeState.detail;
  const systemSettingsDetail = systemSettingsState.detail;
  const activeReviewFindings = findingReview?.active_findings ?? [];
  const dismissedReviewFindings = findingReview?.recently_dismissed ?? [];
  const findingSuggestions = findingReview?.suggestions ?? [];
  const recommendations = state.recommendations?.items ?? [];
  const sortedIncidents = [...state.incidents].sort((left, right) =>
    right.updated_at.localeCompare(left.updated_at),
  );
  const selectedIncident =
    sortedIncidents.find((incident) => incident.id === selectedIncidentId) ??
    sortedIncidents[0] ??
    null;
  const selectedInvestigation =
    selectedIncident === null
      ? null
      : state.investigations.find((investigation) => {
          if (selectedIncident.investigation_id !== null) {
            return investigation.id === selectedIncident.investigation_id;
          }
          return investigation.incident_id === selectedIncident.id;
        }) ?? null;
  const modelUsageDashboard = buildModelUsageDashboard(
    state.investigations,
    sortedIncidents,
  );
  const todayModelUsageWindow =
    modelUsageDashboard.windows.find((window) => window.key === "today") ?? null;
  const maxIncidentCloudCallsUsed = modelUsageDashboard.incidents.reduce(
    (currentMax, incidentUsage) =>
      Math.max(currentMax, incidentUsage.cloudModelCalls),
    0,
  );
  const incidentsAtCloudCallBudget =
    modelSettingsDetail === null
      ? []
      : modelUsageDashboard.incidents.filter(
          (incidentUsage) =>
            incidentUsage.cloudModelCalls >=
            modelSettingsDetail.active.escalation.max_cloud_calls_per_incident,
        );
  const cloudCostEstimateGap =
    modelSettingsDetail?.active.cloud.provider === "openai_compatible" &&
    modelUsageDashboard.incidents.some(
      (incidentUsage) =>
        incidentUsage.cloudModelCalls > 0 && incidentUsage.estimatedCloudCostUsd === 0,
    );
  const incidentGraphFocus =
    selectedIncident === null
      ? null
      : buildIncidentGraphFocus(
          selectedIncident,
          selectedInvestigation,
          services,
          edges,
          serviceReferenceMap,
        );
  const incidentModeActive = incidentModeEnabled && incidentGraphFocus !== null;
  const incidentFocusServiceIds = new Set(incidentGraphFocus?.serviceIds ?? []);
  const incidentFocusEdgeKeys = new Set(incidentGraphFocus?.edgeKeys ?? []);
  const incidentEvidenceServiceIds = new Set(incidentGraphFocus?.evidenceServiceIds ?? []);
  const highlightedServiceIds = incidentModeActive
    ? new Set(
        [...filterHighlightedServiceIds].filter((serviceId) =>
          incidentFocusServiceIds.has(serviceId),
        ),
      )
    : filterHighlightedServiceIds;
  const highlightedEdgeKeys = incidentModeActive
    ? new Set(
        [...filterHighlightedEdgeKeys].filter((key) => incidentFocusEdgeKeys.has(key)),
      )
    : filterHighlightedEdgeKeys;
  const incidentRootServiceName =
    incidentGraphFocus?.rootServiceId === null || incidentGraphFocus?.rootServiceId === undefined
      ? null
      : serviceNames.get(incidentGraphFocus.rootServiceId) ?? incidentGraphFocus.rootServiceId;
  const investigationByIncidentId = new Map(
    state.investigations.map((investigation) => [investigation.incident_id, investigation]),
  );
  const sortedChanges = [...state.changes].sort((left, right) =>
    right.timestamp.localeCompare(left.timestamp),
  );
  const activeAuditDetailRetentionDays =
    systemSettingsDetail?.active.audit_detail_retention_days ??
    DEFAULT_AUDIT_DETAIL_RETENTION_DAYS;
  const activeAuditSummaryRetentionDays =
    systemSettingsDetail?.active.audit_summary_retention_days ??
    DEFAULT_AUDIT_SUMMARY_RETENTION_DAYS;
  const stagedAuditDetailRetentionDays =
    systemSettingsDetail?.staged.audit_detail_retention_days ??
    DEFAULT_AUDIT_DETAIL_RETENTION_DAYS;
  const stagedAuditSummaryRetentionDays =
    systemSettingsDetail?.staged.audit_summary_retention_days ??
    DEFAULT_AUDIT_SUMMARY_RETENTION_DAYS;
  const auditTrailEntries = sortedChanges
    .map((change) =>
      buildAuditTrailEntry(
        change,
        {
          activeDetailRetentionDays: activeAuditDetailRetentionDays,
          activeSummaryRetentionDays: activeAuditSummaryRetentionDays,
        },
        serviceNames,
        investigationByIncidentId,
      ),
    )
    .filter((entry): entry is AuditTrailEntry => entry !== null);
  const auditTypeOptions = Array.from(
    new Set(auditTrailEntries.map((entry) => entry.auditType)),
  ).sort((left, right) => left.localeCompare(right));
  const filteredAuditTrailEntries = auditTrailEntries.filter((entry) =>
    auditTrailEntryMatchesFilters(entry, auditTrailFilters),
  );
  const highlightedChangeIds = new Set(selectedIncident?.changes_correlated ?? []);
  const sortedCredentialRequests = [...state.credentialRequests].sort((left, right) =>
    right.requested_at.localeCompare(left.requested_at),
  );
  const pendingCredentialRequests = sortedCredentialRequests.filter((request) =>
    ["pending", "awaiting_input"].includes(request.status),
  );
  const approvalIncidents = sortedIncidents.filter(
    (incident) => incident.status === "awaiting_approval",
  );
  const sortedJournalEntries = [...state.journalEntries].sort((left, right) =>
    right.date.localeCompare(left.date),
  );
  const sortedUserNotes = [...state.userNotes].sort((left, right) =>
    right.updated_at.localeCompare(left.updated_at),
  );
  const excludedNotesCount = sortedUserNotes.filter((note) => !note.safe_for_model).length;
  const staleNotesCount = sortedUserNotes.filter((note) => note.stale).length;
  const globalNotesCount = sortedUserNotes.filter((note) => note.service_id === null).length;
  const confirmedJournalCount = sortedJournalEntries.filter(
    (entry) => entry.confidence === "confirmed",
  ).length;
  const userConfirmedJournalCount = sortedJournalEntries.filter(
    (entry) => entry.user_confirmed,
  ).length;
  const journalEntriesNeedingReviewCount = sortedJournalEntries.filter((entry) =>
    journalEntryNeedsReview(entry),
  ).length;
  const selectedServiceJournalCount =
    selectedService === null
      ? 0
      : sortedJournalEntries.filter((entry) => entry.services.includes(selectedService.id)).length;
  const selectedServiceNoteCount =
    selectedService === null
      ? 0
      : sortedUserNotes.filter((note) => note.service_id === selectedService.id).length;
  const recurrencePatterns = buildRecurrencePatterns(sortedJournalEntries);
  const impactedRecurrenceServicesCount = new Set(
    recurrencePatterns.flatMap((pattern) => pattern.activeEntry.services),
  ).size;
  const highestRecurrenceCount = recurrencePatterns.reduce(
    (currentHighest, pattern) =>
      Math.max(currentHighest, pattern.activeEntry.recurrence_count),
    0,
  );
  const selectedServiceRecurrenceCount =
    selectedService === null
      ? 0
      : recurrencePatterns.filter((pattern) =>
          pattern.activeEntry.services.includes(selectedService.id),
        ).length;
  const selectedServiceFactAdapters = selectedServiceFacts?.adapters ?? [];
  const selectedServiceIncidents =
    selectedService === null
      ? []
      : sortedIncidents.filter((incident) =>
          incident.affected_services.includes(selectedService.id),
        );
  const selectedServiceCredentialRequests =
    selectedService === null
      ? []
      : sortedCredentialRequests.filter((request) => request.service_id === selectedService.id);
  const selectedServiceJournalEntries =
    selectedService === null
      ? []
      : sortedJournalEntries.filter((entry) => entry.services.includes(selectedService.id));
  const selectedServiceNotes =
    selectedService === null
      ? []
      : sortedUserNotes.filter((note) => note.service_id === selectedService.id);
  const selectedServiceRecurrencePatterns =
    selectedService === null
      ? []
      : recurrencePatterns.filter((pattern) =>
          pattern.activeEntry.services.includes(selectedService.id),
        );
  const notificationHealthLayer =
    state.capabilityHealth?.layers.find((layer) => layer.layer === "notification_channels") ??
    null;
  const notificationChannelCount =
    typeof notificationHealthLayer?.metadata["configured_channels"] === "number"
      ? notificationHealthLayer.metadata["configured_channels"]
      : 0;
  const currentFactsCount = selectedServiceFactAdapters.filter(
    (adapter) => adapter.facts_available && adapter.freshness === "current",
  ).length;
  const staleFactsCount = selectedServiceFactAdapters.filter(
    (adapter) => adapter.facts_available && adapter.freshness === "stale",
  ).length;
  const attentionFactsCount = selectedServiceFactAdapters.filter(
    (adapter) => !adapter.facts_available || adapter.freshness !== "current",
  ).length;
  const redactedFactPathCount = selectedServiceFactAdapters.reduce(
    (count, adapter) => count + adapter.excluded_paths.length,
    0,
  );
  const filteredUserNotes = filterUserNotes(
    sortedUserNotes,
    deferredNoteSearch,
    serviceNames,
  );
  const userNoteGroups = groupUserNotes(
    filteredUserNotes,
    serviceNames,
    selectedService?.id ?? null,
  );
  const memoryBrowserHeading =
    activeMemoryTab === "journal"
      ? "Operational journal with provenance"
      : activeMemoryTab === "notes"
        ? "User notes and trust controls"
        : activeMemoryTab === "system"
          ? "System profile snapshot"
          : activeMemoryTab === "recurrence"
            ? "Recurring incident patterns"
            : "Adapter facts with freshness";
  const memoryBrowserMeta =
    activeMemoryTab === "journal"
      ? `${sortedJournalEntries.length} journal · ${journalEntriesNeedingReviewCount} review`
      : activeMemoryTab === "notes"
        ? `${sortedUserNotes.length} notes · ${excludedNotesCount} excluded`
        : activeMemoryTab === "system"
          ? state.systemProfile
            ? `${state.systemProfile.hostname} · updated ${formatTimestamp(state.systemProfile.last_updated)}`
            : "Snapshot unavailable"
          : activeMemoryTab === "recurrence"
            ? `${recurrencePatterns.length} patterns · ${impactedRecurrenceServicesCount} services`
            : selectedServiceFacts
              ? `${selectedServiceFacts.adapters.length} adapters · checked ${formatTimestamp(selectedServiceFacts.checked_at)}`
              : selectedService
                ? `Facts for ${selectedService.name}`
                : "Select a service";
  const systemProfileStorageUsage =
    state.systemProfile === null || state.systemProfile.storage.array.total_tb === 0
      ? "0%"
      : `${Math.round(
          (state.systemProfile.storage.array.used_tb / state.systemProfile.storage.array.total_tb) *
            100,
        )}%`;
  const surfaceWidth = Math.max(categories.length * COLUMN_WIDTH + 120, 720);
  const surfaceHeight =
    Math.max(...layouts.map((layout) => layout.y), 0) + CARD_HEIGHT + HEADER_HEIGHT + 96;

  async function submitNoteEditor(serviceIdOverride: string | null = null) {
    const trimmedNote = noteEditorState.note.trim();
    if (!trimmedNote) {
      setNoteMutationState({
        saving: false,
        targetNoteId: editingNoteId,
        error: "Note text must not be empty.",
      });
      return;
    }

    setNoteMutationState({
      saving: true,
      targetNoteId: editingNoteId,
      error: null,
    });

    const payload = {
      service_id: (serviceIdOverride ?? noteEditorState.serviceId) || null,
      note: trimmedNote,
      safe_for_model: noteEditorState.safeForModel,
      stale: noteEditorState.stale,
      last_verified_at: noteEditorState.lastVerifiedAt
        ? new Date(noteEditorState.lastVerifiedAt).toISOString()
        : null,
    };

    try {
      const response = await fetch(
        editingNoteId === null
          ? "/api/v1/memory/notes"
          : `/api/v1/memory/notes/${encodeURIComponent(editingNoteId)}`,
        {
          method: editingNoteId === null ? "POST" : "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
      );
      if (!response.ok) {
        throw new Error("Kaval UI could not save the note.");
      }
      const note = (await response.json()) as UserNote;
      startTransition(() => {
        setState((current) => ({
          ...current,
          userNotes:
            editingNoteId === null
              ? [note, ...current.userNotes]
              : current.userNotes.map((item) => (item.id === note.id ? note : item)),
        }));
        setEditingNoteId(null);
        setNoteEditorState(createEmptyNoteEditorState(selectedService?.id ?? null));
        setNoteMutationState({
          saving: false,
          targetNoteId: null,
          error: null,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown note save failure.";
      setNoteMutationState({
        saving: false,
        targetNoteId: editingNoteId,
        error: message,
      });
    }
  }

  async function archiveNote(noteId: string) {
    setNoteMutationState({
      saving: true,
      targetNoteId: noteId,
      error: null,
    });
    try {
      const response = await fetch(
        `/api/v1/memory/notes/${encodeURIComponent(noteId)}/archive`,
        {
          method: "POST",
        },
      );
      if (!response.ok) {
        throw new Error("Kaval UI could not archive the note.");
      }
      startTransition(() => {
        setState((current) => ({
          ...current,
          userNotes: current.userNotes.filter((note) => note.id !== noteId),
        }));
        if (editingNoteId === noteId) {
          setEditingNoteId(null);
          setNoteEditorState(createEmptyNoteEditorState(selectedService?.id ?? null));
        }
        setNoteMutationState({
          saving: false,
          targetNoteId: null,
          error: null,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown note archive failure.";
      setNoteMutationState({
        saving: false,
        targetNoteId: noteId,
        error: message,
      });
    }
  }

  async function deleteNote(noteId: string) {
    setNoteMutationState({
      saving: true,
      targetNoteId: noteId,
      error: null,
    });
    try {
      const response = await fetch(`/api/v1/memory/notes/${encodeURIComponent(noteId)}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        throw new Error("Kaval UI could not delete the note.");
      }
      startTransition(() => {
        setState((current) => ({
          ...current,
          userNotes: current.userNotes.filter((note) => note.id !== noteId),
        }));
        if (editingNoteId === noteId) {
          setEditingNoteId(null);
          setNoteEditorState(createEmptyNoteEditorState(selectedService?.id ?? null));
        }
        setNoteMutationState({
          saving: false,
          targetNoteId: null,
          error: null,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown note delete failure.";
      setNoteMutationState({
        saving: false,
        targetNoteId: noteId,
        error: message,
      });
    }
  }

  async function refreshGraphPanels() {
    const [graph, changes] = await Promise.all([
      fetchJson<GraphResponse>("/api/v1/graph"),
      fetchJson<Change[]>("/api/v1/changes"),
    ]);
    startTransition(() => {
      setState((current) => ({
        ...current,
        graph,
        changes,
      }));
    });
    return graph;
  }

  async function refreshCapabilityHealthPanel() {
    const capabilityHealth = await fetchJson<CapabilityHealthReport>("/api/v1/capability-health");
    startTransition(() => {
      setState((current) => ({
        ...current,
        capabilityHealth,
      }));
    });
  }

  function focusGuidedSetupService(serviceId: string) {
    setGuidedSetupSkippedServiceIds((current) =>
      current.filter((candidateId) => candidateId !== serviceId),
    );
    setSelectedServiceId(serviceId);
    scrollToPanel("investigation-detail-panel");
  }

  function focusGuidedSetupEdge(edge: GraphEdge) {
    setSelectedEdgeKey(edgeKey(edge));
    setEdgeEditorState(null);
    setEdgeMutationState({
      saving: false,
      error: null,
      auditChangeId: null,
    });
    scrollToPanel("service-map-panel");
  }

  async function generateAutoGeneratedDescriptorForService(service: Service) {
    if (service.descriptor_id !== null) {
      return;
    }

    startTransition(() => {
      setGuidedSetupMutationState({
        identifyingServiceId: service.id,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(service.id)}/descriptor/auto-generate`,
        {
          method: "POST",
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(
            response,
            "Kaval UI could not generate a quarantined descriptor draft.",
          ),
        );
      }
      const payload = (await response.json()) as ServiceDescriptorGenerateResponse;
      await Promise.all([refreshGraphPanels(), loadQuarantinedDescriptorQueue()]);
      startTransition(() => {
        setGuidedSetupMutationState({
          identifyingServiceId: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
        setGuidedSetupSkippedServiceIds((current) =>
          current.filter((candidateId) => candidateId !== service.id),
        );
        setSelectedServiceId(service.id);
        setSelectedQuarantinedDescriptorId(payload.descriptor.descriptor_id);
      });
      scrollToPanel("descriptor-review-queue-panel");
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown descriptor generation failure.";
      startTransition(() => {
        setGuidedSetupMutationState({
          identifyingServiceId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function updateServiceCheckSuppression(checkId: string, suppressed: boolean) {
    if (selectedServiceId === null) {
      return;
    }

    startTransition(() => {
      setServiceDetailSuppressionMutationState({
        submitting: true,
        checkId,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(
          selectedServiceId,
        )}/checks/${encodeURIComponent(checkId)}/suppression`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ suppressed }),
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(response, "Could not update per-service check suppression."),
        );
      }
      const payload = (await response.json()) as ServiceDetailCheckSuppressionMutationResponse;
      let refreshedChanges: Change[] | null = null;
      let refreshedMonitoringSettings: MonitoringSettingsResponse | null = null;
      let refreshError: string | null = null;

      try {
        [refreshedChanges, refreshedMonitoringSettings] = await Promise.all([
          fetchJson<Change[]>("/api/v1/changes"),
          fetchJson<MonitoringSettingsResponse>("/api/v1/settings/monitoring"),
        ]);
      } catch (error) {
        refreshError =
          error instanceof Error
            ? `Suppression saved, but dependent panels did not refresh: ${error.message}`
            : "Suppression saved, but dependent panels did not refresh.";
      }

      startTransition(() => {
        setServiceDetailState({
          detail: payload.detail,
          error: null,
          loading: false,
        });
        if (refreshedChanges !== null) {
          setState((current) => ({
            ...current,
            changes: refreshedChanges,
          }));
        }
        if (refreshedMonitoringSettings !== null) {
          setMonitoringSettingsState({
            detail: refreshedMonitoringSettings,
            error: null,
            loading: false,
          });
          setMonitoringSettingsEditorState(
            createMonitoringSettingsEditorState(refreshedMonitoringSettings),
          );
        }
        setServiceDetailSuppressionMutationState({
          submitting: false,
          checkId: null,
          error: refreshError,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown service suppression update failure.";
      startTransition(() => {
        setServiceDetailSuppressionMutationState({
          submitting: false,
          checkId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function dismissFindingAsNoise(findingId: string) {
    const reason = findingFeedbackReasonById[findingId] ?? "false_positive";
    startTransition(() => {
      setFindingFeedbackMutationState({
        dismissingFindingId: findingId,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const response = await fetch(`/api/v1/findings/${encodeURIComponent(findingId)}/dismiss`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not dismiss the finding as noise."));
      }
      const payload = (await response.json()) as FindingDismissResponse;
      let refreshedIncidents: Incident[] | null = null;
      let refreshedChanges: Change[] | null = null;
      let refreshedWidget: WidgetSummary | null = null;
      let refreshError: string | null = null;

      try {
        [refreshedIncidents, refreshedChanges, refreshedWidget] = await Promise.all([
          fetchJson<Incident[]>("/api/v1/incidents"),
          fetchJson<Change[]>("/api/v1/changes"),
          fetchJson<WidgetSummary>("/api/v1/widget"),
        ]);
      } catch (error) {
        refreshError =
          error instanceof Error
            ? `Feedback saved, but dependent panels did not refresh: ${error.message}`
            : "Feedback saved, but dependent panels did not refresh.";
      }

      startTransition(() => {
        setState((current) => ({
          ...current,
          findingReview: payload.review,
          incidents: refreshedIncidents ?? current.incidents,
          changes: refreshedChanges ?? current.changes,
          widget: refreshedWidget ?? current.widget,
        }));
        setFindingFeedbackMutationState({
          dismissingFindingId: null,
          error: refreshError,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown finding feedback update failure.";
      startTransition(() => {
        setFindingFeedbackMutationState({
          dismissingFindingId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function loadMaintenanceMode() {
    startTransition(() => {
      setMaintenanceModeState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<MaintenanceModeResponse>("/api/v1/maintenance");
      startTransition(() => {
        setMaintenanceModeState({
          detail,
          error: null,
          loading: false,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown maintenance mode load failure.";
      startTransition(() => {
        setMaintenanceModeState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  async function enableGlobalMaintenance() {
    startTransition(() => {
      setMaintenanceModeMutationState({
        savingTarget: "global",
        clearingServiceId: null,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const durationMinutes = parseIntegerInput(
        maintenanceModeEditorState.globalDurationMinutes,
        "Global maintenance duration",
      );
      if (durationMinutes < 1) {
        throw new Error("Global maintenance duration must be at least 1 minute.");
      }
      const response = await fetch("/api/v1/maintenance/global", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ duration_minutes: durationMinutes }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not enable global maintenance."));
      }
      const payload = (await response.json()) as MaintenanceModeMutationResponse;
      const refreshedChanges = await fetchJson<Change[]>("/api/v1/changes");
      startTransition(() => {
        setMaintenanceModeState({
          detail: payload.maintenance,
          error: null,
          loading: false,
        });
        setState((current) => ({
          ...current,
          changes: refreshedChanges,
        }));
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown global maintenance update failure.";
      startTransition(() => {
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function clearGlobalMaintenance() {
    startTransition(() => {
      setMaintenanceModeMutationState({
        savingTarget: null,
        clearingServiceId: "global",
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const response = await fetch("/api/v1/maintenance/global", {
        method: "DELETE",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not clear global maintenance."));
      }
      const payload = (await response.json()) as MaintenanceModeMutationResponse;
      const refreshedChanges = await fetchJson<Change[]>("/api/v1/changes");
      startTransition(() => {
        setMaintenanceModeState({
          detail: payload.maintenance,
          error: null,
          loading: false,
        });
        setState((current) => ({
          ...current,
          changes: refreshedChanges,
        }));
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown global maintenance clear failure.";
      startTransition(() => {
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function enableServiceMaintenance() {
    const serviceId = maintenanceModeEditorState.serviceId || selectedServiceId;
    if (serviceId === null || serviceId === "") {
      startTransition(() => {
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: "Select a service before enabling maintenance.",
          auditChangeId: null,
        });
      });
      return;
    }
    startTransition(() => {
      setMaintenanceModeMutationState({
        savingTarget: "service",
        clearingServiceId: null,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const durationMinutes = parseIntegerInput(
        maintenanceModeEditorState.serviceDurationMinutes,
        "Service maintenance duration",
      );
      if (durationMinutes < 1) {
        throw new Error("Service maintenance duration must be at least 1 minute.");
      }
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(serviceId)}/maintenance`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ duration_minutes: durationMinutes }),
        },
      );
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not enable service maintenance."));
      }
      const payload = (await response.json()) as MaintenanceModeMutationResponse;
      const refreshedChanges = await fetchJson<Change[]>("/api/v1/changes");
      startTransition(() => {
        setMaintenanceModeState({
          detail: payload.maintenance,
          error: null,
          loading: false,
        });
        setState((current) => ({
          ...current,
          changes: refreshedChanges,
        }));
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown service maintenance update failure.";
      startTransition(() => {
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function clearServiceMaintenance(serviceId: string) {
    startTransition(() => {
      setMaintenanceModeMutationState({
        savingTarget: null,
        clearingServiceId: serviceId,
        error: null,
        auditChangeId: null,
      });
    });

    try {
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(serviceId)}/maintenance`,
        {
          method: "DELETE",
        },
      );
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not clear service maintenance."));
      }
      const payload = (await response.json()) as MaintenanceModeMutationResponse;
      const refreshedChanges = await fetchJson<Change[]>("/api/v1/changes");
      startTransition(() => {
        setMaintenanceModeState({
          detail: payload.maintenance,
          error: null,
          loading: false,
        });
        setState((current) => ({
          ...current,
          changes: refreshedChanges,
        }));
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown service maintenance clear failure.";
      startTransition(() => {
        setMaintenanceModeMutationState({
          savingTarget: null,
          clearingServiceId: null,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  function applyRecommendationAction(action: RecommendationAction) {
    if (action.service_id) {
      setSelectedServiceId(action.service_id);
    }
    const panelId = {
      service_detail: "service-detail-panel",
      finding_review: "finding-review-panel",
      credential_vault: "credential-vault-panel",
      model_settings: "model-configuration-panel",
    }[action.target];
    scrollToPanel(panelId);
  }

  function openAuditIncident(incidentId: string, serviceId: string | null) {
    if (serviceId) {
      setSelectedServiceId(serviceId);
    }
    setSelectedIncidentId(incidentId);
    scrollToPanel("investigation-detail-panel");
  }

  async function loadModelSettings() {
    startTransition(() => {
      setModelSettingsState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<ModelSettingsResponse>("/api/v1/settings/models");
      startTransition(() => {
        setModelSettingsState({
          detail,
          error: null,
          loading: false,
        });
        setModelSettingsEditorState(createModelSettingsEditorState(detail));
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown model settings load failure.";
      startTransition(() => {
        setModelSettingsState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  function updateModelSettingsEditor(
    updater: (current: ModelSettingsEditorState) => ModelSettingsEditorState,
  ) {
    setModelSettingsEditorState((current) => {
      if (current === null) {
        return current;
      }
      return updater(current);
    });
  }

  async function saveModelSettings() {
    if (modelSettingsEditorState === null) {
      return;
    }

    startTransition(() => {
      setModelSettingsMutationState((current) => ({
        ...current,
        saving: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/models", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildModelSettingsUpdatePayload(modelSettingsEditorState)),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not save staged model settings."));
      }
      const payload = (await response.json()) as ModelSettingsMutationResponse;
      startTransition(() => {
        setModelSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setModelSettingsEditorState(createModelSettingsEditorState(payload.settings));
        setModelSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await refreshGraphPanels();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown model settings save failure.";
      startTransition(() => {
        setModelSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: message,
        }));
      });
    }
  }

  async function applyModelSettings() {
    if (modelSettingsState.detail === null) {
      return;
    }

    startTransition(() => {
      setModelSettingsMutationState((current) => ({
        ...current,
        applying: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/models/apply", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not apply model settings."));
      }
      const payload = (await response.json()) as ModelSettingsMutationResponse;
      startTransition(() => {
        setModelSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setModelSettingsEditorState(createModelSettingsEditorState(payload.settings));
        setModelSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown model settings apply failure.";
      startTransition(() => {
        setModelSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: message,
        }));
      });
    }
  }

  async function testModelSettings(target: "local" | "cloud") {
    const scope =
      modelSettingsState.detail !== null && modelSettingsState.detail.apply_required
        ? "staged"
        : "active";

    startTransition(() => {
      setModelSettingsMutationState((current) => ({
        ...current,
        testingTarget: target,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/models/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, scope }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not test model settings."));
      }
      const payload = (await response.json()) as ModelSettingsTestResponse;
      startTransition(() => {
        setModelSettingsMutationState((current) => ({
          ...current,
          testingTarget: null,
          error: null,
          testResult: payload,
        }));
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown model settings test failure.";
      startTransition(() => {
        setModelSettingsMutationState((current) => ({
          ...current,
          testingTarget: null,
          error: message,
        }));
      });
    }
  }

  async function loadNotificationSettings() {
    startTransition(() => {
      setNotificationSettingsState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<NotificationSettingsResponse>("/api/v1/settings/notifications");
      startTransition(() => {
        setNotificationSettingsState({
          detail,
          error: null,
          loading: false,
        });
        setNotificationSettingsEditorState(createNotificationSettingsEditorState(detail));
      });
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unknown notification settings load failure.";
      startTransition(() => {
        setNotificationSettingsState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  function updateNotificationSettingsEditor(
    updater: (current: NotificationSettingsEditorState) => NotificationSettingsEditorState,
  ) {
    setNotificationSettingsEditorState((current) => {
      if (current === null) {
        return current;
      }
      return updater(current);
    });
  }

  function addNotificationSettingsChannel() {
    updateNotificationSettingsEditor((current) => ({
      ...current,
      channels: [...current.channels, createDraftNotificationChannel()],
    }));
  }

  function removeNotificationSettingsChannel(clientId: string) {
    updateNotificationSettingsEditor((current) => ({
      ...current,
      channels: current.channels.filter((channel) => channel.clientId !== clientId),
    }));
  }

  async function saveNotificationSettings() {
    if (notificationSettingsEditorState === null) {
      return;
    }

    startTransition(() => {
      setNotificationSettingsMutationState((current) => ({
        ...current,
        saving: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/notifications", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          buildNotificationSettingsUpdatePayload(notificationSettingsEditorState),
        ),
      });
      if (!response.ok) {
        throw new Error(
          await readApiError(response, "Could not save staged notification settings."),
        );
      }
      const payload = (await response.json()) as NotificationSettingsMutationResponse;
      startTransition(() => {
        setNotificationSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setNotificationSettingsEditorState(createNotificationSettingsEditorState(payload.settings));
        setNotificationSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await refreshGraphPanels();
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unknown notification settings save failure.";
      startTransition(() => {
        setNotificationSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: message,
        }));
      });
    }
  }

  async function applyNotificationSettings() {
    if (notificationSettingsState.detail === null) {
      return;
    }

    startTransition(() => {
      setNotificationSettingsMutationState((current) => ({
        ...current,
        applying: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/notifications/apply", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not apply notification settings."));
      }
      const payload = (await response.json()) as NotificationSettingsMutationResponse;
      startTransition(() => {
        setNotificationSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setNotificationSettingsEditorState(createNotificationSettingsEditorState(payload.settings));
        setNotificationSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([
        refreshGraphPanels(),
        refreshCapabilityHealthPanel(),
        loadSystemSettings(),
      ]);
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unknown notification settings apply failure.";
      startTransition(() => {
        setNotificationSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: message,
        }));
      });
    }
  }

  async function testNotificationChannel(channelId: string) {
    startTransition(() => {
      setNotificationSettingsMutationState((current) => ({
        ...current,
        testingChannelId: channelId,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/notifications/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channel_id: channelId,
          scope: notificationSettingsTestScope,
        }),
      });
      if (!response.ok) {
        throw new Error(
          await readApiError(response, "Could not send the notification test."),
        );
      }
      const payload = (await response.json()) as NotificationSettingsTestResponse;
      startTransition(() => {
        setNotificationSettingsMutationState((current) => ({
          ...current,
          testingChannelId: null,
          error: null,
          testResult: payload,
        }));
      });
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Unknown notification settings test failure.";
      startTransition(() => {
        setNotificationSettingsMutationState((current) => ({
          ...current,
          testingChannelId: null,
          error: message,
        }));
      });
    }
  }

  async function loadMonitoringSettings() {
    startTransition(() => {
      setMonitoringSettingsState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<MonitoringSettingsResponse>("/api/v1/settings/monitoring");
      startTransition(() => {
        setMonitoringSettingsState({
          detail,
          error: null,
          loading: false,
        });
        setMonitoringSettingsEditorState(createMonitoringSettingsEditorState(detail));
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown monitoring settings load failure.";
      startTransition(() => {
        setMonitoringSettingsState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  function updateMonitoringSettingsEditor(
    updater: (current: MonitoringSettingsEditorState) => MonitoringSettingsEditorState,
  ) {
    setMonitoringSettingsEditorState((current) => {
      if (current === null) {
        return current;
      }
      return updater(current);
    });
  }

  function addMonitoringServiceOverride() {
    if (monitoringSettingsEditorState === null) {
      return;
    }
    const defaultService = services[0] ?? null;
    const defaultCheck =
      defaultService === null
        ? monitoringSettingsEditorState.checks[0] ?? null
        : monitoringSettingsEditorState.checks.find((check) =>
            monitoringCheckAppliesToService(check.checkId, defaultService),
          ) ??
          monitoringSettingsEditorState.checks[0] ??
          null;
    updateMonitoringSettingsEditor((current) => ({
      ...current,
      serviceOverrides: [
        ...current.serviceOverrides,
        {
          clientId: createClientId(),
          serviceId: defaultService?.id ?? "",
          checkId: defaultCheck?.checkId ?? "",
          enabledMode: "enabled",
          intervalSeconds: "",
          tlsWarningDays: "",
          restartDeltaThreshold: "",
          probeTimeoutSeconds: "",
        },
      ],
    }));
  }

  function removeMonitoringServiceOverride(clientId: string) {
    updateMonitoringSettingsEditor((current) => ({
      ...current,
      serviceOverrides: current.serviceOverrides.filter((item) => item.clientId !== clientId),
    }));
  }

  async function saveMonitoringSettings() {
    if (monitoringSettingsEditorState === null) {
      return;
    }

    startTransition(() => {
      setMonitoringSettingsMutationState((current) => ({
        ...current,
        saving: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/monitoring", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildMonitoringSettingsUpdatePayload(monitoringSettingsEditorState)),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not save staged monitoring settings."));
      }
      const payload = (await response.json()) as MonitoringSettingsMutationResponse;
      startTransition(() => {
        setMonitoringSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setMonitoringSettingsEditorState(createMonitoringSettingsEditorState(payload.settings));
        setMonitoringSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await refreshGraphPanels();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown monitoring settings save failure.";
      startTransition(() => {
        setMonitoringSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: message,
        }));
      });
    }
  }

  async function applyMonitoringSettings() {
    if (monitoringSettingsState.detail === null) {
      return;
    }

    startTransition(() => {
      setMonitoringSettingsMutationState((current) => ({
        ...current,
        applying: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/monitoring/apply", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not apply monitoring settings."));
      }
      const payload = (await response.json()) as MonitoringSettingsMutationResponse;
      startTransition(() => {
        setMonitoringSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setMonitoringSettingsEditorState(createMonitoringSettingsEditorState(payload.settings));
        setMonitoringSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown monitoring settings apply failure.";
      startTransition(() => {
        setMonitoringSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: message,
        }));
      });
    }
  }

  async function loadSystemSettings() {
    startTransition(() => {
      setSystemSettingsState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<SystemSettingsResponse>("/api/v1/settings/system");
      startTransition(() => {
        setSystemSettingsState({
          detail,
          error: null,
          loading: false,
        });
        setSystemSettingsEditorState(createSystemSettingsEditorState(detail));
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown system settings load failure.";
      startTransition(() => {
        setSystemSettingsState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  function updateSystemSettingsEditor(
    updater: (current: SystemSettingsEditorState) => SystemSettingsEditorState,
  ) {
    setSystemSettingsEditorState((current) => {
      if (current === null) {
        return current;
      }
      return updater(current);
    });
  }

  async function saveSystemSettings() {
    if (systemSettingsEditorState === null) {
      return;
    }

    startTransition(() => {
      setSystemSettingsMutationState((current) => ({
        ...current,
        saving: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/system", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildSystemSettingsUpdatePayload(systemSettingsEditorState)),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not save staged system settings."));
      }
      const payload = (await response.json()) as SystemSettingsMutationResponse;
      startTransition(() => {
        setSystemSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setSystemSettingsEditorState(createSystemSettingsEditorState(payload.settings));
        setSystemSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await refreshGraphPanels();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown system settings save failure.";
      startTransition(() => {
        setSystemSettingsMutationState((current) => ({
          ...current,
          saving: false,
          error: message,
        }));
      });
    }
  }

  async function applySystemSettings() {
    if (systemSettingsState.detail === null) {
      return;
    }

    startTransition(() => {
      setSystemSettingsMutationState((current) => ({
        ...current,
        applying: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/system/apply", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not apply system settings."));
      }
      const payload = (await response.json()) as SystemSettingsMutationResponse;
      startTransition(() => {
        setSystemSettingsState({
          detail: payload.settings,
          error: null,
          loading: false,
        });
        setSystemSettingsEditorState(createSystemSettingsEditorState(payload.settings));
        setSystemSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await refreshGraphPanels();
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown system settings apply failure.";
      startTransition(() => {
        setSystemSettingsMutationState((current) => ({
          ...current,
          applying: false,
          error: message,
        }));
      });
    }
  }

  function updateCredentialVaultEditor(
    updater: (current: CredentialVaultEditorState) => CredentialVaultEditorState,
  ) {
    setCredentialVaultEditorState((current) => updater(current));
  }

  async function loadCredentialVault() {
    startTransition(() => {
      setCredentialVaultState((current) => ({
        ...current,
        error: null,
        loading: true,
      }));
    });
    try {
      const detail = await fetchJson<CredentialVaultResponse>("/api/v1/settings/vault");
      startTransition(() => {
        setCredentialVaultState({
          detail,
          error: null,
          loading: false,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown credential vault load failure.";
      startTransition(() => {
        setCredentialVaultState({
          detail: null,
          error: message,
          loading: false,
        });
      });
    }
  }

  async function unlockCredentialVault() {
    if (!credentialVaultEditorState.unlockPassphrase.trim()) {
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          error: "Master passphrase is required to unlock the vault.",
        }));
      });
      return;
    }

    startTransition(() => {
      setCredentialVaultMutationState((current) => ({
        ...current,
        unlocking: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/vault/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          master_passphrase: credentialVaultEditorState.unlockPassphrase,
        }),
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not unlock the credential vault."));
      }
      const payload = (await response.json()) as CredentialVaultMutationResponse;
      startTransition(() => {
        setCredentialVaultState({
          detail: payload.vault,
          error: null,
          loading: false,
        });
        setCredentialVaultEditorState((current) => ({
          ...current,
          unlockPassphrase: "",
        }));
        setCredentialVaultMutationState((current) => ({
          ...current,
          unlocking: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown credential vault unlock failure.";
      startTransition(() => {
        setCredentialVaultEditorState((current) => ({
          ...current,
          unlockPassphrase: "",
        }));
        setCredentialVaultMutationState((current) => ({
          ...current,
          unlocking: false,
          error: message,
        }));
      });
    }
  }

  async function lockCredentialVault() {
    startTransition(() => {
      setCredentialVaultMutationState((current) => ({
        ...current,
        locking: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/vault/lock", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not lock the credential vault."));
      }
      const payload = (await response.json()) as CredentialVaultMutationResponse;
      startTransition(() => {
        setCredentialVaultState({
          detail: payload.vault,
          error: null,
          loading: false,
        });
        setCredentialVaultMutationState((current) => ({
          ...current,
          locking: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown credential vault lock failure.";
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          locking: false,
          error: message,
        }));
      });
    }
  }

  async function testCredentialVault() {
    startTransition(() => {
      setCredentialVaultMutationState((current) => ({
        ...current,
        testing: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/vault/test", {
        method: "POST",
      });
      if (!response.ok) {
        throw new Error(await readApiError(response, "Could not test stored vault credentials."));
      }
      const payload = (await response.json()) as CredentialVaultTestResponse;
      startTransition(() => {
        setCredentialVaultState({
          detail: payload.vault,
          error: null,
          loading: false,
        });
        setCredentialVaultMutationState((current) => ({
          ...current,
          testing: false,
          error: null,
          auditChangeId: payload.audit_change?.id ?? current.auditChangeId,
          testResult: payload,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown credential vault test failure.";
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          testing: false,
          error: message,
        }));
      });
    }
  }

  async function changeCredentialVaultPassword() {
    if (!credentialVaultEditorState.currentPassphrase.trim()) {
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          error: "Current master passphrase is required.",
        }));
      });
      return;
    }
    if (!credentialVaultEditorState.newPassphrase.trim()) {
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          error: "New master passphrase is required.",
        }));
      });
      return;
    }
    if (
      credentialVaultEditorState.newPassphrase !==
      credentialVaultEditorState.confirmNewPassphrase
    ) {
      startTransition(() => {
        setCredentialVaultMutationState((current) => ({
          ...current,
          error: "New master passphrase confirmation does not match.",
        }));
      });
      return;
    }

    startTransition(() => {
      setCredentialVaultMutationState((current) => ({
        ...current,
        changingPassword: true,
        error: null,
      }));
    });

    try {
      const response = await fetch("/api/v1/settings/vault/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_master_passphrase: credentialVaultEditorState.currentPassphrase,
          new_master_passphrase: credentialVaultEditorState.newPassphrase,
        }),
      });
      if (!response.ok) {
        throw new Error(
          await readApiError(response, "Could not change the vault master passphrase."),
        );
      }
      const payload = (await response.json()) as CredentialVaultMutationResponse;
      startTransition(() => {
        setCredentialVaultState({
          detail: payload.vault,
          error: null,
          loading: false,
        });
        setCredentialVaultEditorState({
          unlockPassphrase: "",
          currentPassphrase: "",
          newPassphrase: "",
          confirmNewPassphrase: "",
        });
        setCredentialVaultMutationState((current) => ({
          ...current,
          changingPassword: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        }));
      });
      await Promise.all([refreshGraphPanels(), refreshCapabilityHealthPanel()]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown vault password change failure.";
      startTransition(() => {
        setCredentialVaultEditorState((current) => ({
          ...current,
          currentPassphrase: "",
          newPassphrase: "",
          confirmNewPassphrase: "",
        }));
        setCredentialVaultMutationState((current) => ({
          ...current,
          changingPassword: false,
          error: message,
        }));
      });
    }
  }

  async function loadQuarantinedDescriptorQueue() {
    setQuarantinedDescriptorQueueState((current) => ({
      ...current,
      error: null,
      loading: true,
    }));
    try {
      const items = await fetchJson<QuarantinedDescriptorQueueItem[]>(
        "/api/v1/descriptors/auto-generated",
      );
      startTransition(() => {
        setQuarantinedDescriptorQueueState({
          items,
          error: null,
          loading: false,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown descriptor review queue failure.";
      startTransition(() => {
        setQuarantinedDescriptorQueueState((current) => ({
          ...current,
          error: message,
          loading: false,
        }));
      });
    }
  }

  function updateDescriptorEditor(
    updater: (current: DescriptorEditorState) => DescriptorEditorState,
  ) {
    setDescriptorEditorState((current) => {
      if (current === null) {
        return current;
      }
      return updater(current);
    });
    setDescriptorMutationState((current) => ({
      ...current,
      error: null,
      auditChangeId: null,
    }));
    setDescriptorValidationState({
      validating: false,
      error: null,
      result: null,
    });
  }

  function beginDescriptorEdit(mode: DescriptorEditorMode) {
    if (serviceDescriptorState.detail === null) {
      return;
    }
    const descriptorDetail = serviceDescriptorState.detail;
    setDescriptorEditorOpen(true);
    setDescriptorEditorState((current) =>
      current === null
        ? createDescriptorEditorState(descriptorDetail, mode)
        : {
            ...current,
            mode,
          },
    );
    setDescriptorMutationState({
      saving: false,
      error: null,
      auditChangeId: null,
    });
    setDescriptorValidationState({
      validating: false,
      error: null,
      result: null,
    });
  }

  function cancelDescriptorEdit() {
    if (serviceDescriptorState.detail === null) {
      return;
    }
    setDescriptorEditorOpen(false);
    setDescriptorEditorState(createDescriptorEditorState(serviceDescriptorState.detail));
    setDescriptorMutationState({
      saving: false,
      error: null,
      auditChangeId: null,
    });
    setDescriptorValidationState({
      validating: false,
      error: null,
      result: null,
    });
  }

  function updateDescriptorEndpoint(
    clientId: string,
    field: keyof Omit<DescriptorEditorEndpointState, "clientId">,
    value: string,
  ) {
    updateDescriptorEditor((current) => ({
      ...current,
      endpoints: current.endpoints.map((endpoint) =>
        endpoint.clientId === clientId
          ? {
              ...endpoint,
              [field]: value,
            }
          : endpoint,
      ),
    }));
  }

  function addDescriptorEndpoint() {
    updateDescriptorEditor((current) => ({
      ...current,
      endpoints: [...current.endpoints, createEmptyDescriptorEndpointState()],
    }));
  }

  function removeDescriptorEndpoint(clientId: string) {
    updateDescriptorEditor((current) => ({
      ...current,
      endpoints: current.endpoints.filter((endpoint) => endpoint.clientId !== clientId),
    }));
  }

  function updateDescriptorDependency(
    clientId: string,
    field: keyof Omit<DescriptorEditorDependencyState, "clientId">,
    value: string,
  ) {
    updateDescriptorEditor((current) => ({
      ...current,
      containerDependencies: current.containerDependencies.map((dependency) =>
        dependency.clientId === clientId
          ? {
              ...dependency,
              [field]: value,
            }
          : dependency,
      ),
    }));
  }

  function addDescriptorDependency() {
    updateDescriptorEditor((current) => ({
      ...current,
      containerDependencies: [
        ...current.containerDependencies,
        createEmptyDescriptorDependencyState(),
      ],
    }));
  }

  function removeDescriptorDependency(clientId: string) {
    updateDescriptorEditor((current) => ({
      ...current,
      containerDependencies: current.containerDependencies.filter(
        (dependency) => dependency.clientId !== clientId,
      ),
    }));
  }

  async function validateDescriptorEdit() {
    if (selectedServiceId === null || descriptorEditorState === null) {
      return;
    }
    setDescriptorValidationState({
      validating: true,
      error: null,
      result: null,
    });
    try {
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(selectedServiceId)}/descriptor/validate`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildDescriptorSavePayload(descriptorEditorState)),
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(
            response,
            "Kaval UI could not validate the descriptor.",
          ),
        );
      }
      const result = (await response.json()) as ServiceDescriptorValidationResponse;
      setDescriptorValidationState({
        validating: false,
        error: null,
        result,
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown descriptor validation failure.";
      setDescriptorValidationState({
        validating: false,
        error: message,
        result: null,
      });
    }
  }

  async function saveDescriptorEdit() {
    if (selectedServiceId === null || descriptorEditorState === null) {
      return;
    }
    if (!descriptorValidationState.result?.valid) {
      setDescriptorMutationState({
        saving: false,
        error: "Run validation and preview before saving the descriptor.",
        auditChangeId: null,
      });
      return;
    }
    setDescriptorMutationState({
      saving: true,
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch(
        `/api/v1/services/${encodeURIComponent(selectedServiceId)}/descriptor`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildDescriptorSavePayload(descriptorEditorState)),
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(
            response,
            "Kaval UI could not save the descriptor.",
          ),
        );
      }
      const payload = (await response.json()) as ServiceDescriptorSaveResponse;
      const [, refreshedDetail] = await Promise.all([
        refreshGraphPanels(),
        fetchJson<ServiceDetailResponse>(
          `/api/v1/services/${encodeURIComponent(selectedServiceId)}/detail`,
        ),
      ]);
      startTransition(() => {
        setServiceDetailState({
          detail: refreshedDetail,
          error: null,
          loading: false,
        });
        setServiceDescriptorState({
          detail: payload.descriptor,
          error: null,
          loading: false,
        });
        setDescriptorMutationState({
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
        setDescriptorValidationState({
          validating: false,
          error: null,
          result: null,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown descriptor save failure.";
      setDescriptorMutationState({
        saving: false,
        error: message,
        auditChangeId: null,
      });
    }
  }

  async function saveQuarantinedDescriptorDraft() {
    if (selectedQuarantinedDescriptor === null) {
      return;
    }
    const descriptor = selectedQuarantinedDescriptor.descriptor;
    const localDescriptorId = descriptorIdSegment(descriptor);
    setQuarantinedDescriptorMutationState({
      submitting: true,
      descriptorId: descriptor.descriptor_id,
      action: "save",
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch(
        `/api/v1/descriptors/auto-generated/${encodeURIComponent(
          descriptor.category,
        )}/${encodeURIComponent(localDescriptorId)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            mode: "yaml",
            raw_yaml: quarantinedDescriptorEditorState.rawYaml,
          }),
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(
            response,
            "Kaval UI could not save the quarantined descriptor draft.",
          ),
        );
      }
      const payload = (await response.json()) as QuarantinedDescriptorActionResponse;
      await Promise.all([refreshGraphPanels(), loadQuarantinedDescriptorQueue()]);
      startTransition(() => {
        setQuarantinedDescriptorMutationState({
          submitting: false,
          descriptorId: null,
          action: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
        setSelectedQuarantinedDescriptorId(payload.descriptor_id);
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown quarantined descriptor save failure.";
      startTransition(() => {
        setQuarantinedDescriptorMutationState({
          submitting: false,
          descriptorId: descriptor.descriptor_id,
          action: "save",
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function runQuarantinedDescriptorAction(
    action: "promote" | "dismiss" | "defer",
  ) {
    if (selectedQuarantinedDescriptor === null) {
      return;
    }
    const descriptor = selectedQuarantinedDescriptor.descriptor;
    const localDescriptorId = descriptorIdSegment(descriptor);
    setQuarantinedDescriptorMutationState({
      submitting: true,
      descriptorId: descriptor.descriptor_id,
      action,
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch(
        `/api/v1/descriptors/auto-generated/${encodeURIComponent(
          descriptor.category,
        )}/${encodeURIComponent(localDescriptorId)}/${action}`,
        {
          method: "POST",
        },
      );
      if (!response.ok) {
        throw new Error(
          await readApiError(
            response,
            `Kaval UI could not ${action} the quarantined descriptor.`,
          ),
        );
      }
      const payload = (await response.json()) as QuarantinedDescriptorActionResponse;
      await Promise.all([refreshGraphPanels(), loadQuarantinedDescriptorQueue()]);
      startTransition(() => {
        setQuarantinedDescriptorMutationState({
          submitting: false,
          descriptorId: null,
          action: null,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
        if (payload.action === "promoted" || payload.action === "dismissed") {
          setQuarantinedDescriptorEditorState({
            descriptorId: null,
            rawYaml: "",
            open: false,
          });
        }
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : `Unknown quarantined descriptor ${action} failure.`;
      startTransition(() => {
        setQuarantinedDescriptorMutationState({
          submitting: false,
          descriptorId: descriptor.descriptor_id,
          action,
          error: message,
          auditChangeId: null,
        });
      });
    }
  }

  async function confirmEdge(edge: GraphEdge) {
    setEdgeMutationState({
      saving: true,
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch("/api/v1/graph/edges", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_service_id: edge.source_service_id,
          target_service_id: edge.target_service_id,
        }),
      });
      if (!response.ok) {
        throw new Error("Kaval UI could not confirm the edge.");
      }
      const payload = (await response.json()) as GraphEdgeMutationResponse;
      await refreshGraphPanels();
      startTransition(() => {
        setSelectedEdgeKey(payload.edge ? edgeKey(payload.edge) : null);
        setEdgeEditorState(null);
        setEdgeMutationState({
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown edge confirmation failure.";
      setEdgeMutationState({
        saving: false,
        error: message,
        auditChangeId: null,
      });
    }
  }

  function beginEdgeEdit(edge: GraphEdge) {
    setSelectedEdgeKey(edgeKey(edge));
    setEdgeEditorState({
      sourceServiceId: edge.source_service_id,
      targetServiceId: edge.target_service_id,
      previousSourceServiceId: edge.source_service_id,
      previousTargetServiceId: edge.target_service_id,
      description: edge.description ?? "",
    });
    setEdgeMutationState({
      saving: false,
      error: null,
      auditChangeId: null,
    });
  }

  function beginEdgeAdd() {
    const sourceServiceId = selectedService?.id ?? services[0]?.id ?? "";
    const targetServiceId =
      services.find((service) => service.id !== sourceServiceId)?.id ?? "";
    setSelectedEdgeKey(null);
    setHoveredEdgeKey(null);
    setEdgeEditorState({
      sourceServiceId,
      targetServiceId,
      previousSourceServiceId: null,
      previousTargetServiceId: null,
      description: "",
    });
    setEdgeMutationState({
      saving: false,
      error: null,
      auditChangeId: null,
    });
  }

  async function saveEdgeEdit() {
    if (edgeEditorState === null) {
      return;
    }
    setEdgeMutationState({
      saving: true,
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch("/api/v1/graph/edges", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          previous_source_service_id: edgeEditorState.previousSourceServiceId,
          previous_target_service_id: edgeEditorState.previousTargetServiceId,
          source_service_id: edgeEditorState.sourceServiceId,
          target_service_id: edgeEditorState.targetServiceId,
          description: edgeEditorState.description.trim() || null,
        }),
      });
      if (!response.ok) {
        throw new Error("Kaval UI could not save the edge edit.");
      }
      const payload = (await response.json()) as GraphEdgeMutationResponse;
      await refreshGraphPanels();
      startTransition(() => {
        setSelectedEdgeKey(payload.edge ? edgeKey(payload.edge) : null);
        setEdgeEditorState(
          payload.edge
            ? {
                sourceServiceId: payload.edge.source_service_id,
                targetServiceId: payload.edge.target_service_id,
                previousSourceServiceId: payload.edge.source_service_id,
                previousTargetServiceId: payload.edge.target_service_id,
                description: payload.edge.description ?? "",
              }
            : null,
        );
        setEdgeMutationState({
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown edge edit failure.";
      setEdgeMutationState({
        saving: false,
        error: message,
        auditChangeId: null,
      });
    }
  }

  async function removeEdge(edge: GraphEdge) {
    setEdgeMutationState({
      saving: true,
      error: null,
      auditChangeId: null,
    });
    try {
      const response = await fetch(
        `/api/v1/graph/edges/${encodeURIComponent(edge.source_service_id)}/${encodeURIComponent(edge.target_service_id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        throw new Error("Kaval UI could not remove the edge.");
      }
      const payload = (await response.json()) as GraphEdgeMutationResponse;
      await refreshGraphPanels();
      startTransition(() => {
        setSelectedEdgeKey(null);
        setHoveredEdgeKey(null);
        setEdgeEditorState(null);
        setEdgeMutationState({
          saving: false,
          error: null,
          auditChangeId: payload.audit_change.id,
        });
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown edge removal failure.";
      setEdgeMutationState({
        saving: false,
        error: message,
        auditChangeId: null,
      });
    }
  }

  function toggleGraphFilter<K extends keyof GraphFilterState>(
    key: K,
    value: GraphFilterState[K][number],
  ) {
    setGraphFilters((current) => {
      const values = current[key] as Array<GraphFilterState[K][number]>;
      const nextValues = values.includes(value)
        ? values.filter((item) => item !== value)
        : [...values, value];
      return {
        ...current,
        [key]: nextValues,
      };
    });
  }

  function clearGraphFilters() {
    setGraphFilters({
      categories: [],
      confidences: [],
      insightLevels: [],
      statuses: [],
    });
  }

  function pinGraphEdge(sourceServiceId: string, targetServiceId: string) {
    setSelectedEdgeKey(`${sourceServiceId}::${targetServiceId}`);
    setEdgeEditorState(null);
    setEdgeMutationState((current) => ({
      ...current,
      error: null,
      auditChangeId: null,
    }));
  }

  return (
    <div className="shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <header className="hero">
        <div>
          <p className="eyebrow">Kaval Phase 2B</p>
          <h1>Investigations, queued decisions, and memory in one surface.</h1>
          <p className="hero-copy">
            Deterministic monitoring now sits beside Tier 2 research, approval-state context,
            and Operational Memory. The Phase 2B view keeps the earlier incident detail while
            exposing the current change timeline, waiting approvals, and learned history.
          </p>
        </div>
        <div className="summary-grid">
          <SummaryTile
            label="Services"
            value={state.widget?.total_services ?? 0}
            accent="warm"
          />
          <SummaryTile
            label="Active Findings"
            value={state.widget?.active_findings ?? 0}
            accent="alert"
          />
          <SummaryTile
            label="Active Incidents"
            value={state.widget?.active_incidents ?? 0}
            accent="ice"
          />
          <SummaryTile
            label="Effectiveness"
            value={
              state.effectiveness ? `${Math.round(state.effectiveness.score_percent)}%` : "0%"
            }
            accent="ice"
          />
        </div>
      </header>

      {state.loading ? (
        <section className="message-card">Loading Phase 2A investigation state…</section>
      ) : null}
      {state.error ? <section className="message-card error">{state.error}</section> : null}

      {!state.loading && !state.error && state.graph && state.widget ? (
        <>
        {state.effectiveness ? (
          <section className="panel effectiveness-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Effectiveness</p>
                <h2>Coverage at maximum insight</h2>
              </div>
              <div className="panel-status">
                <span className="status-pill effectiveness-score">
                  {state.effectiveness.score_percent.toFixed(1)}%
                </span>
                <p className="panel-meta">
                  {state.effectiveness.services_at_target}/
                  {state.effectiveness.total_services} at max
                </p>
              </div>
            </div>

            <p className="muted effectiveness-formula">{state.effectiveness.formula}.</p>

            <div className="effectiveness-breakdown">
              {state.effectiveness.breakdown.map((item) => (
                <article key={`${item.bucket}-${item.target_level}`} className="effectiveness-card">
                  <div className="timeline-topline">
                    <p className="timeline-service">{item.label}</p>
                    <span className="chip ghost">L{item.target_level}</span>
                  </div>
                  <p className="muted">
                    {item.services_at_target}/{item.service_count} services currently at max.
                  </p>
                  <p className="step-meta">
                    {item.services_below_target} can still be improved.
                  </p>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {state.recommendations ? (
          <section className="panel effectiveness-panel" id="recommendations-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Recommendations</p>
                <h2>Proactive next steps</h2>
              </div>
              <p className="panel-meta">{recommendations.length} active</p>
            </div>

            {recommendations.length > 0 ? (
              <div className="queue-list">
                {recommendations.map((item: RecommendationItem) => (
                  <article key={item.id} className="queue-item">
                    <div className="timeline-topline">
                      <p className="timeline-service">{item.title}</p>
                      <span className="chip ghost">{formatLabel(item.kind)}</span>
                    </div>
                    <p className="muted">{item.detail}</p>
                    <div className="note-action-row">
                      <button
                        className="note-button note-button-ghost"
                        onClick={() => applyRecommendationAction(item.action)}
                        type="button"
                      >
                        {item.action.label}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <p className="muted">
                No proactive recommendations are currently active from the existing admin state.
              </p>
            )}
          </section>
        ) : null}

        <section className="panel effectiveness-panel" id="guided-setup-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Guided Setup</p>
              <h2>Step 1: Discovery summary</h2>
            </div>
            <p className="panel-meta">
              {matchedContainerCount}/{containerServices.length} containers matched
            </p>
          </div>

          <div className="action-strip">
            <span className="action-pill">{containerServices.length} containers</span>
            <span className="action-pill">{vmServices.length} VMs</span>
            <span className="action-pill">{shareServices.length} shares</span>
            <span className="action-pill">{unknownContainerServices.length} unknown</span>
            <button
              className="note-button note-button-ghost"
              disabled={skippedUnknownContainerCount === 0}
              onClick={() => setGuidedSetupSkippedServiceIds([])}
              type="button"
            >
              Restore skipped
            </button>
          </div>

          <div className="detail-grid">
            <article className="system-profile-card">
              <p className="timeline-service">What Kaval found</p>
              <p className="muted service-inline-copy">
                Discovery is reusing the current persisted graph state. Matched services already
                participate in the main monitoring and admin surfaces, while unknown containers
                stay under generic monitoring until you identify them or skip them for now.
              </p>
              <ul className="system-profile-list compact">
                <li>
                  <span>Containers</span>
                  <strong>{containerServices.length}</strong>
                </li>
                <li>
                  <span>Matched containers</span>
                  <strong>{matchedContainerCount}</strong>
                </li>
                <li>
                  <span>Unknown containers</span>
                  <strong>{unknownContainerServices.length}</strong>
                </li>
                <li>
                  <span>VMs</span>
                  <strong>{vmServices.length}</strong>
                </li>
                <li>
                  <span>Shares</span>
                  <strong>{shareServices.length}</strong>
                </li>
              </ul>
            </article>
            <article className="system-profile-card">
              <p className="timeline-service">Step contract</p>
              <p className="muted service-inline-copy">
                Identify routes into the main service detail and quarantined descriptor workflow.
                Skip for now only hides a container from this setup step and does not change
                monitoring, matching, or incident behavior.
              </p>
              <ul className="system-profile-list compact">
                <li>
                  <span>Visible unknowns</span>
                  <strong>{visibleUnknownContainerServices.length}</strong>
                </li>
                <li>
                  <span>Skipped in setup</span>
                  <strong>{skippedUnknownContainerCount}</strong>
                </li>
              </ul>
            </article>
          </div>

          {guidedSetupMutationState.auditChangeId ? (
            <p className="message-inline">
              Guided setup generated a quarantined descriptor draft and logged it as{" "}
              {guidedSetupMutationState.auditChangeId}.
            </p>
          ) : null}
          {guidedSetupMutationState.error ? (
            <p className="message-inline error">{guidedSetupMutationState.error}</p>
          ) : null}

          <div className="queue-section">
            <div className="memory-section-header">
              <div>
                <p className="detail-label">Unknown containers</p>
                <p className="muted">
                  Use the existing identification flow for containers that still have no matched
                  descriptor.
                </p>
              </div>
            </div>

            {visibleUnknownContainerServices.length > 0 ? (
              <div className="queue-list">
                {visibleUnknownContainerServices.map((service) => (
                  <article className="queue-item" key={`guided-setup-${service.id}`}>
                    <div className="timeline-topline">
                      <p className="timeline-service">{service.name}</p>
                      <span className="chip warning">Unknown container</span>
                    </div>
                    <p className="muted">{formatOptionalValue(service.image)}</p>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Ports</span>
                        <strong>{formatServiceEndpointSummary(service)}</strong>
                      </li>
                      <li>
                        <span>Container ID</span>
                        <strong>{formatOptionalValue(service.container_id)}</strong>
                      </li>
                      <li>
                        <span>Active findings</span>
                        <strong>{service.active_findings}</strong>
                      </li>
                    </ul>
                    <div className="note-action-row">
                      <button
                        className="note-button note-button-primary"
                        onClick={() => focusGuidedSetupService(service.id)}
                        type="button"
                      >
                        Identify
                      </button>
                      <button
                        className="note-button note-button-ghost"
                        onClick={() =>
                          setGuidedSetupSkippedServiceIds((current) =>
                            current.includes(service.id) ? current : [...current, service.id],
                          )
                        }
                        type="button"
                      >
                        Skip for now
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            ) : unknownContainerServices.length > 0 ? (
              <p className="muted">
                All unknown containers are currently skipped in setup. Restore them to continue
                identification.
              </p>
            ) : (
              <p className="muted">
                No unknown containers are currently waiting for identification in guided setup.
              </p>
            )}
          </div>
        </section>

        <section className="panel effectiveness-panel" id="guided-setup-dependency-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Guided Setup</p>
              <h2>Step 2: Dependency review</h2>
            </div>
            <p className="panel-meta">{lowConfidenceEdges.length} edges need review</p>
          </div>

          <div className="detail-grid">
            <article className="system-profile-card">
              <p className="timeline-service">Review contract</p>
              <p className="muted service-inline-copy">
                This step reuses the existing graph confidence model. Confirm and correct actions
                go through the same edge mutation path used by the main dependency map.
              </p>
            </article>
            <article className="system-profile-card">
              <p className="timeline-service">Confidence guidance</p>
              <p className="muted service-inline-copy">
                Inferred edges come from topology or descriptor logic. Auto-generated edges stay
                lower trust until an explicit review promotes stronger evidence.
              </p>
            </article>
          </div>

          {edgeMutationState.auditChangeId ? (
            <p className="message-inline">
              Dependency review logged a graph change as {edgeMutationState.auditChangeId}.
            </p>
          ) : null}
          {edgeMutationState.error ? (
            <p className="message-inline error">{edgeMutationState.error}</p>
          ) : null}

          {lowConfidenceEdges.length > 0 ? (
            <div className="queue-list">
              {lowConfidenceEdges.map((edge) => {
                const sourceName = serviceNames.get(edge.source_service_id) ?? edge.source_service_id;
                const targetName = serviceNames.get(edge.target_service_id) ?? edge.target_service_id;
                return (
                  <article className="queue-item" key={`guided-edge-${edgeKey(edge)}`}>
                    <div className="timeline-topline">
                      <p className="timeline-service">
                        {sourceName} → {targetName}
                      </p>
                      <span className={`chip ghost confidence-${edge.confidence}`}>
                        {formatLabel(edge.confidence)}
                      </span>
                    </div>
                    <p className="muted">{buildGraphEdgeSourceSummary(edge)}</p>
                    <p className="step-meta">{graphEdgeConfidenceDetail(edge.confidence)}</p>
                    <div className="note-action-row">
                      <button
                        className="note-button note-button-ghost"
                        onClick={() => focusGuidedSetupEdge(edge)}
                        type="button"
                      >
                        Review on graph
                      </button>
                      <button
                        className="note-button note-button-primary"
                        disabled={edgeMutationState.saving}
                        onClick={() => {
                          void confirmEdge(edge);
                        }}
                        type="button"
                      >
                        {edgeMutationState.saving ? "Saving…" : "Confirm edge"}
                      </button>
                      <button
                        className="note-button note-button-ghost"
                        onClick={() => {
                          beginEdgeEdit(edge);
                          scrollToPanel("service-map-panel");
                        }}
                        type="button"
                      >
                        Correct edge
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <p className="muted">
              No inferred or auto-generated edges currently need guided review.
            </p>
          )}
        </section>

        <section className="panel effectiveness-panel" id="guided-setup-effectiveness-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Guided Setup</p>
              <h2>Step 3: Effectiveness assessment</h2>
            </div>
            <p className="panel-meta">
              {state.effectiveness ? `${Math.round(state.effectiveness.score_percent)}% coverage` : "No score"}
            </p>
          </div>

          {state.effectiveness ? (
            <>
              <div className="detail-grid">
                <article className="system-profile-card">
                  <p className="timeline-service">Coverage summary</p>
                  <p className="muted service-inline-copy">{state.effectiveness.formula}.</p>
                  <ul className="system-profile-list compact">
                    <li>
                      <span>At target</span>
                      <strong>{state.effectiveness.services_at_target}</strong>
                    </li>
                    <li>
                      <span>Total services</span>
                      <strong>{state.effectiveness.total_services}</strong>
                    </li>
                    <li>
                      <span>Improvable services</span>
                      <strong>{state.effectiveness.improvable_services}</strong>
                    </li>
                  </ul>
                </article>
                <article className="system-profile-card">
                  <p className="timeline-service">Why limits remain</p>
                  <p className="muted service-inline-copy">
                    Lower insight usually means a service is still unmatched, missing local
                    investigation capability, or lacks configured deep inspection. Review a
                    service below to see the exact improvement path already exposed elsewhere in
                    the UI.
                  </p>
                </article>
              </div>

              <div className="effectiveness-breakdown">
                {state.effectiveness.breakdown.map((item) => (
                  <article key={`guided-setup-${item.bucket}`} className="effectiveness-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">{item.label}</p>
                      <span className="chip ghost">L{item.target_level}</span>
                    </div>
                    <p className="muted">
                      {item.services_at_target}/{item.service_count} services currently at target.
                    </p>
                    <p className="step-meta">
                      {item.services_below_target} still need additional capability.
                    </p>
                  </article>
                ))}
              </div>

              {setupImprovableServices.length > 0 ? (
                <div className="queue-section">
                  <div className="memory-section-header">
                    <div>
                      <p className="detail-label">Services below target</p>
                      <p className="muted">
                        These services already expose a concrete improvement path through the main
                        service detail panel.
                      </p>
                    </div>
                  </div>
                  <div className="queue-list">
                    {setupImprovableServices.map((service) => {
                      const nodeMeta = nodeMetaByServiceId.get(service.id) ?? null;
                      const insightLevel = service.insight?.level ?? 0;
                      const selectedImproveActions =
                        selectedServiceDetail?.service.id === service.id
                          ? selectedServiceDetail.insight_section.improve_actions
                          : [];
                      return (
                        <article className="queue-item" key={`guided-improve-${service.id}`}>
                          <div className="timeline-topline">
                            <p className="timeline-service">{service.name}</p>
                            <span className="chip ghost">
                              L{insightLevel}
                              {nodeMeta ? ` → L${nodeMeta.target_insight_level}` : ""}
                            </span>
                          </div>
                          <p className="muted">
                            {buildGuidedSetupLimitationSummary(service, nodeMeta)}
                          </p>
                          {selectedImproveActions.length > 0 ? (
                            <div className="improve-list service-inline-stack">
                              {selectedImproveActions.map((action) => (
                                <article
                                  key={`${service.id}-${action.kind}-${action.title}`}
                                  className="improve-card"
                                >
                                  <p className="improve-title">{action.title}</p>
                                  <p className="muted">{action.detail}</p>
                                </article>
                              ))}
                            </div>
                          ) : null}
                          <div className="note-action-row">
                            <button
                              className="note-button note-button-primary"
                              onClick={() => {
                                setSelectedServiceId(service.id);
                                scrollToPanel("investigation-detail-panel");
                              }}
                              type="button"
                            >
                              Review service
                            </button>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                </div>
              ) : null}

              {recommendations.length > 0 ? (
                <div className="queue-section">
                  <div className="memory-section-header">
                    <div>
                      <p className="detail-label">Targeted next actions</p>
                      <p className="muted">
                        These are the currently ranked improvement recommendations from the same
                        admin state used elsewhere in the dashboard.
                      </p>
                    </div>
                  </div>
                  <div className="queue-list">
                    {recommendations.slice(0, 3).map((item) => (
                      <article className="queue-item" key={`guided-recommendation-${item.id}`}>
                        <div className="timeline-topline">
                          <p className="timeline-service">{item.title}</p>
                          <span className="chip ghost">{formatLabel(item.kind)}</span>
                        </div>
                        <p className="muted">{item.detail}</p>
                        <div className="note-action-row">
                          <button
                            className="note-button note-button-ghost"
                            onClick={() => applyRecommendationAction(item.action)}
                            type="button"
                          >
                            {item.action.label}
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <p className="muted">
              Effectiveness scoring is not available yet, so guided setup cannot summarize
              improvement coverage.
            </p>
          )}
        </section>

        <section className="panel effectiveness-panel" id="guided-setup-notification-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Guided Setup</p>
              <h2>Step 4: Notification setup</h2>
            </div>
            <p className="panel-meta">
              {notificationSettingsDetail
                ? `${notificationSettingsDetail.staged.configured_channel_count} staged channels`
                : "No settings"}
            </p>
          </div>

          {notificationSettingsDetail && notificationSettingsEditorState ? (
            <>
              <div className="detail-grid">
                <article className="system-profile-card">
                  <p className="timeline-service">Current routing posture</p>
                  <p className="muted service-inline-copy">
                    Channel selection, severity routing, and quiet hours all persist through the
                    main notification settings model. Setup only surfaces the same staged state.
                  </p>
                  <ul className="system-profile-list compact">
                    <li>
                      <span>Configured channels</span>
                      <strong>{notificationSettingsDetail.staged.configured_channel_count}</strong>
                    </li>
                    <li>
                      <span>Critical route</span>
                      <strong>{formatLabel(notificationSettingsDetail.staged.routing.critical)}</strong>
                    </li>
                    <li>
                      <span>High route</span>
                      <strong>{formatLabel(notificationSettingsDetail.staged.routing.high)}</strong>
                    </li>
                    <li>
                      <span>Quiet hours</span>
                      <strong>
                        {notificationSettingsDetail.staged.quiet_hours.enabled
                          ? `${notificationSettingsDetail.staged.quiet_hours.start_time_local}–${notificationSettingsDetail.staged.quiet_hours.end_time_local}`
                          : "Disabled"}
                      </strong>
                    </li>
                  </ul>
                </article>
                <article className="system-profile-card">
                  <p className="timeline-service">Safe test path</p>
                  <p className="muted service-inline-copy">
                    Test delivery remains explicit. Kaval only sends a notification test when you
                    click it, and only through the selected staged or active channel scope.
                  </p>
                  <ul className="system-profile-list compact">
                    <li>
                      <span>Test scope</span>
                      <strong>{formatLabel(notificationSettingsTestScope)}</strong>
                    </li>
                    <li>
                      <span>Apply required</span>
                      <strong>
                        {notificationSettingsDetail.apply_required ? "Yes" : "No"}
                      </strong>
                    </li>
                  </ul>
                </article>
              </div>

              <div className="queue-section">
                <div className="memory-section-header">
                  <div>
                    <p className="detail-label">Configured channels</p>
                    <p className="muted">
                      Open the main settings panel below to add, remove, or edit channel
                      destinations.
                    </p>
                  </div>
                </div>
                {notificationSettingsEditorState.channels.length > 0 ? (
                  <div className="queue-list">
                    {notificationSettingsEditorState.channels.map((channel) => (
                      <article className="queue-item" key={`guided-notify-${channel.clientId}`}>
                        <div className="timeline-topline">
                          <p className="timeline-service">{channel.name || "Unnamed channel"}</p>
                          <span className="chip ghost">
                            {channel.enabled ? "Enabled" : "Disabled"}
                          </span>
                        </div>
                        <p className="muted">
                          {channel.destinationConfigured
                            ? `${formatLabel(channel.kind)} via ${formatLabel(channel.destinationSource)}`
                            : "Destination still needs to be configured"}
                        </p>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p className="muted">No channels are configured yet.</p>
                )}
              </div>

              {notificationSettingsMutationState.testResult ? (
                <p
                  className={`message-inline ${
                    notificationSettingsMutationState.testResult.ok ? "" : "error"
                  }`}
                >
                  Channel {notificationSettingsMutationState.testResult.channel_id}{" "}
                  {formatLabel(notificationSettingsMutationState.testResult.scope)} test at{" "}
                  {formatTimestamp(notificationSettingsMutationState.testResult.checked_at)}:{" "}
                  {notificationSettingsMutationState.testResult.message}
                </p>
              ) : null}
              {notificationSettingsMutationState.error ? (
                <p className="message-inline error">{notificationSettingsMutationState.error}</p>
              ) : null}

              <div className="note-action-row">
                <button
                  className="note-button note-button-primary"
                  onClick={() => scrollToPanel("notification-settings-panel")}
                  type="button"
                >
                  Configure channels
                </button>
                <button
                  className="note-button note-button-ghost"
                  disabled={
                    notificationSettingsMutationState.testingChannelId !== null ||
                    testableNotificationChannelId === null
                  }
                  onClick={() => {
                    if (testableNotificationChannelId !== null) {
                      void testNotificationChannel(testableNotificationChannelId);
                    }
                  }}
                  type="button"
                >
                  {notificationSettingsMutationState.testingChannelId !== null
                    ? "Testing…"
                    : `Test ${notificationSettingsTestScope}`}
                </button>
                <button
                  className="note-button note-button-ghost"
                  disabled={
                    notificationSettingsMutationState.applying ||
                    notificationSettingsDetail.apply_required === false
                  }
                  onClick={() => {
                    void applyNotificationSettings();
                  }}
                  type="button"
                >
                  {notificationSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                </button>
              </div>
            </>
          ) : (
            <p className="muted">
              Notification settings are not available yet, so guided setup cannot configure or
              test alert delivery.
            </p>
          )}
        </section>

        <section className="panel effectiveness-panel" id="guided-setup-model-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Guided Setup</p>
              <h2>Step 5: Model configuration</h2>
            </div>
            <p className="panel-meta">
              {modelSettingsDetail
                ? `${modelSettingsDetail.staged.local.configured ? "Local ready" : "Local pending"}`
                : "No settings"}
            </p>
          </div>

          {modelSettingsDetail && modelSettingsEditorState ? (
            <>
              <div className="detail-grid">
                <article className="system-profile-card">
                  <p className="timeline-service">Current readiness</p>
                  <p className="muted service-inline-copy">
                    Local investigation is the primary path in Phase 3C. Cloud remains optional
                    and only participates through the bounded escalation policy already configured
                    in model settings.
                  </p>
                  <ul className="system-profile-list compact">
                    <li>
                      <span>Local model</span>
                      <strong>
                        {modelSettingsDetail.staged.local.configured
                          ? `${modelSettingsDetail.staged.local.model} · ${modelSettingsDetail.staged.local.base_url}`
                          : "Not configured"}
                      </strong>
                    </li>
                    <li>
                      <span>Cloud model</span>
                      <strong>
                        {modelSettingsDetail.staged.cloud.configured
                          ? `${formatLabel(modelSettingsDetail.staged.cloud.provider)} · ${modelSettingsDetail.staged.cloud.model}`
                          : "Optional / not configured"}
                      </strong>
                    </li>
                    <li>
                      <span>Test scope</span>
                      <strong>{formatLabel(modelSettingsTestScope)}</strong>
                    </li>
                  </ul>
                </article>
                <article className="system-profile-card">
                  <p className="timeline-service">Escalation and cost context</p>
                  <p className="muted service-inline-copy">
                    These caps stay deterministic. Setup does not add provider-specific behavior
                    beyond the generic model settings contract already accepted for this phase.
                  </p>
                  <ul className="system-profile-list compact">
                    <li>
                      <span>Cloud calls / day</span>
                      <strong>{modelSettingsDetail.staged.escalation.max_cloud_calls_per_day}</strong>
                    </li>
                    <li>
                      <span>Cloud calls / incident</span>
                      <strong>
                        {modelSettingsDetail.staged.escalation.max_cloud_calls_per_incident}
                      </strong>
                    </li>
                    <li>
                      <span>Escalate below confidence</span>
                      <strong>{modelSettingsDetail.staged.escalation.local_confidence_lt}</strong>
                    </li>
                  </ul>
                </article>
              </div>

              {modelSettingsMutationState.testResult ? (
                <p
                  className={`message-inline ${
                    modelSettingsMutationState.testResult.ok ? "" : "error"
                  }`}
                >
                  {formatLabel(modelSettingsMutationState.testResult.target)}{" "}
                  {formatLabel(modelSettingsMutationState.testResult.scope)} test at{" "}
                  {formatTimestamp(modelSettingsMutationState.testResult.checked_at)}:{" "}
                  {modelSettingsMutationState.testResult.message}
                </p>
              ) : null}
              {modelSettingsMutationState.error ? (
                <p className="message-inline error">{modelSettingsMutationState.error}</p>
              ) : null}

              <div className="note-action-row">
                <button
                  className="note-button note-button-primary"
                  onClick={() => scrollToPanel("model-configuration-panel")}
                  type="button"
                >
                  Configure models
                </button>
                <button
                  className="note-button note-button-ghost"
                  disabled={
                    modelSettingsMutationState.testingTarget !== null ||
                    !modelSettingsEditorState.localEnabled ||
                    !modelSettingsEditorState.localModel
                  }
                  onClick={() => {
                    void testModelSettings("local");
                  }}
                  type="button"
                >
                  {modelSettingsMutationState.testingTarget === "local"
                    ? "Testing local…"
                    : `Test ${modelSettingsTestScope} local`}
                </button>
                <button
                  className="note-button note-button-ghost"
                  disabled={
                    modelSettingsMutationState.testingTarget !== null ||
                    !modelSettingsEditorState.cloudEnabled ||
                    !modelSettingsEditorState.cloudModel
                  }
                  onClick={() => {
                    void testModelSettings("cloud");
                  }}
                  type="button"
                >
                  {modelSettingsMutationState.testingTarget === "cloud"
                    ? "Testing cloud…"
                    : `Test ${modelSettingsTestScope} cloud`}
                </button>
                <button
                  className="note-button note-button-ghost"
                  disabled={
                    modelSettingsMutationState.applying ||
                    modelSettingsDetail.apply_required === false
                  }
                  onClick={() => {
                    void applyModelSettings();
                  }}
                  type="button"
                >
                  {modelSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                </button>
              </div>
            </>
          ) : (
            <p className="muted">
              Model settings are not available yet, so guided setup cannot validate local or cloud
              model readiness.
            </p>
          )}
        </section>

        <main className="content">
          <section className="map-panel panel" id="service-map-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Service Map</p>
                <h2>Dependency view</h2>
              </div>
              <div className="panel-status">
                <span className={`live-pill ${liveState}`}>{liveState}</span>
                <p className="panel-meta">
                  {state.widget.healthy_services} healthy, {state.widget.degraded_services} degraded,
                  {" "}
                  {state.widget.down_services} down
                </p>
              </div>
            </div>

            <div className="graph-filter-panel">
              <div className="graph-filter-summary">
                <p className="detail-label">View filters</p>
                <p className="muted">
                  {incidentModeActive ? "Incident mode active. " : ""}
                  Highlighting {highlightedServiceIds.size} of {services.length} services and{" "}
                  {highlightedEdgeKeys.size} of {edges.length} edges.
                </p>
              </div>
              <div className="graph-filter-groups">
                <div className="graph-filter-group">
                  <span>Category</span>
                  <div className="filter-chip-row">
                    {categories.map(([category]) => (
                      <button
                        key={category}
                        className={`filter-chip ${graphFilters.categories.includes(category) ? "active" : ""}`}
                        onClick={() => toggleGraphFilter("categories", category)}
                        type="button"
                      >
                        {category}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="graph-filter-group">
                  <span>Health</span>
                  <div className="filter-chip-row">
                    {Object.entries(statusLabel).map(([status, label]) => (
                      <button
                        key={status}
                        className={`filter-chip ${graphFilters.statuses.includes(status as ServiceStatus) ? "active" : ""}`}
                        onClick={() => toggleGraphFilter("statuses", status as ServiceStatus)}
                        type="button"
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="graph-filter-group">
                  <span>Insight</span>
                  <div className="filter-chip-row">
                    {Object.entries(insightLabel).map(([level, label]) => (
                      <button
                        key={level}
                        className={`filter-chip ${graphFilters.insightLevels.includes(Number(level)) ? "active" : ""}`}
                        onClick={() => toggleGraphFilter("insightLevels", Number(level))}
                        type="button"
                      >
                        L{level} · {label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="graph-filter-group">
                  <span>Confidence</span>
                  <div className="filter-chip-row">
                    {graphConfidenceLegend.map((item) => (
                      <button
                        key={item.confidence}
                        className={`filter-chip ${graphFilters.confidences.includes(item.confidence) ? "active" : ""}`}
                        onClick={() => toggleGraphFilter("confidences", item.confidence)}
                        type="button"
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="graph-filter-group">
                  <span>Incident mode</span>
                  {selectedIncident && incidentGraphFocus ? (
                    <>
                      <p className="muted graph-incident-summary">
                        {incidentModeActive
                          ? `Focusing ${incidentGraphFocus.serviceIds.length} services and ${incidentGraphFocus.edgeKeys.length} path edges for ${selectedIncident.title}.`
                          : `Selected incident ${selectedIncident.title} is ready for graph focus.`}{" "}
                        {incidentRootServiceName
                          ? `Graph anchor: ${incidentRootServiceName}.`
                          : "No graph anchor is currently persisted for this incident."}
                      </p>
                      <div className="filter-chip-row">
                        <button
                          className={`filter-chip ${incidentModeActive ? "active" : ""}`}
                          onClick={() => setIncidentModeEnabled((current) => !current)}
                          type="button"
                        >
                          {incidentModeActive
                            ? "Disable incident mode"
                            : "Focus selected incident"}
                        </button>
                      </div>
                    </>
                  ) : (
                    <p className="muted graph-incident-summary">
                      Select an incident to highlight its likely failure path without removing the
                      rest of the graph.
                    </p>
                  )}
                </div>
              </div>
              <div className="action-strip">
                <button className="note-button" onClick={clearGraphFilters} type="button">
                  Clear filters
                </button>
              </div>
            </div>

            <div className="map-frame">
              <svg
                className="map-canvas"
                viewBox={`0 0 ${surfaceWidth} ${surfaceHeight}`}
                role="img"
                aria-label="Kaval service dependency map"
              >
                <defs>
                  <linearGradient id="warm-glow" x1="0%" x2="100%" y1="0%" y2="100%">
                    <stop offset="0%" stopColor="#ffb45e" />
                    <stop offset="100%" stopColor="#ff7348" />
                  </linearGradient>
                </defs>

                {categories.map(([category], index) => (
                  <text
                    key={category}
                    className="lane-label"
                    x={84 + index * COLUMN_WIDTH}
                    y={42}
                  >
                    {category}
                  </text>
                ))}

                {edges.map((edge) => {
                  const source = layoutById.get(edge.source_service_id);
                  const target = layoutById.get(edge.target_service_id);
                  if (!source || !target) {
                    return null;
                  }
                  const key = edgeKey(edge);
                  return (
                    <path
                      key={`${edge.source_service_id}-${edge.target_service_id}`}
                      className={`edge edge-${edge.confidence} ${selectedEdgeKey === key ? "selected" : ""} ${incidentModeActive && incidentFocusEdgeKeys.has(key) ? "incident-path" : ""} ${highlightedEdgeKeys.has(key) ? "" : "filtered-out"}`}
                      d={edgePath(source, target)}
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedEdgeKey(key);
                        setEdgeEditorState(null);
                        setEdgeMutationState((current) => ({
                          ...current,
                          error: null,
                          auditChangeId: null,
                        }));
                      }}
                      onMouseEnter={() => setHoveredEdgeKey(key)}
                      onMouseLeave={() =>
                        setHoveredEdgeKey((current) =>
                          current === key ? null : current,
                        )
                      }
                    >
                      <title>{buildEdgeTitle(edge, source.service.name, target.service.name)}</title>
                    </path>
                  );
                })}

                {edges.map((edge) => {
                  if (!edgeNeedsConfirmation(edge)) {
                    return null;
                  }
                  const source = layoutById.get(edge.source_service_id);
                  const target = layoutById.get(edge.target_service_id);
                  if (!source || !target) {
                    return null;
                  }
                  const marker = edgeMarkerPosition(source, target);
                  return (
                    <g
                      key={`${edgeKey(edge)}-review`}
                      className={`edge-review-marker ${highlightedEdgeKeys.has(edgeKey(edge)) ? "" : "filtered-out"}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        setSelectedEdgeKey(edgeKey(edge));
                        setEdgeEditorState(null);
                      }}
                      transform={`translate(${marker.x} ${marker.y})`}
                    >
                      <circle r={11} />
                      <text textAnchor="middle" y={4}>
                        ?
                      </text>
                      <title>Low-confidence edge. Click to review or confirm it.</title>
                    </g>
                  );
                })}

                {layouts.map((layout) => (
                  <ServiceNode
                    key={layout.service.id}
                    layout={layout}
                    nodeMeta={nodeMetaByServiceId.get(layout.service.id) ?? null}
                    filteredOut={!highlightedServiceIds.has(layout.service.id)}
                    incidentFocused={incidentModeActive && incidentFocusServiceIds.has(layout.service.id)}
                    incidentRoot={incidentModeActive && incidentGraphFocus?.rootServiceId === layout.service.id}
                    incidentEvidence={
                      incidentModeActive && incidentEvidenceServiceIds.has(layout.service.id)
                    }
                    selected={layout.service.id === selectedService?.id}
                    onSelect={setSelectedServiceId}
                  />
                ))}
              </svg>
            </div>

            <p className="legend-caption">
              Edge styling reflects dependency confidence. Stronger evidence reads brighter and
              more solid; weaker or quarantined relationships become more patterned or faint.
            </p>
            <div className="legend">
              {graphConfidenceLegend.map((item) => (
                <LegendSwatch
                  key={item.confidence}
                  tone={item.confidence}
                  label={item.label}
                  detail={item.detail}
                />
              ))}
            </div>
            <div className="edge-detail-card">
              {activeEdge && activeEdgeSourceName && activeEdgeTargetName ? (
                <>
                  <div className="timeline-topline">
                    <div>
                      <p className="timeline-service">
                        {activeEdgeSourceName} → {activeEdgeTargetName}
                      </p>
                      <p className="muted edge-detail-meta">
                        {selectedEdge ? "Pinned edge detail" : "Hover detail"}
                      </p>
                    </div>
                    <span
                      className={`status-pill edge-confidence-pill confidence-${activeEdge.confidence}`}
                    >
                      {formatLabel(activeEdge.confidence)}
                    </span>
                  </div>
                  <div className="detail-grid edge-detail-grid">
                    <div>
                      <p className="detail-label">Source of truth</p>
                      <p className="service-detail-lead">
                        {buildGraphEdgeSourceSummary(activeEdge)}
                      </p>
                    </div>
                    <div>
                      <p className="detail-label">Investigation impact</p>
                      <p className="service-detail-lead">
                        {graphEdgeConfidenceDetail(activeEdge.confidence)}
                      </p>
                    </div>
                  </div>
                  <p className="muted edge-description">
                    {activeEdge.description ?? "No additional dependency note is recorded yet."}
                  </p>
                  {selectedEdge ? (
                    <>
                      <div className="action-strip">
                        <button
                          className="note-button"
                          onClick={() => void confirmEdge(selectedEdge)}
                          type="button"
                        >
                          Confirm
                        </button>
                        <button
                          className="note-button"
                          onClick={() => beginEdgeEdit(selectedEdge)}
                          type="button"
                        >
                          Edit
                        </button>
                        <button
                          className="note-button"
                          onClick={() => void removeEdge(selectedEdge)}
                          type="button"
                        >
                          Remove
                        </button>
                        <button
                          className="note-button"
                          onClick={() => {
                            setSelectedEdgeKey(null);
                            setEdgeEditorState(null);
                          }}
                          type="button"
                        >
                          Close
                        </button>
                      </div>
                      {edgeEditorState ? (
                        <div className="edge-editor">
                          <label className="note-field">
                            <span>Source service</span>
                            <select
                              onChange={(event) =>
                                setEdgeEditorState((current) =>
                                  current === null
                                    ? null
                                    : {
                                        ...current,
                                        sourceServiceId: event.target.value,
                                      },
                                )
                              }
                              value={edgeEditorState.sourceServiceId}
                            >
                              {services.map((service) => (
                                <option key={service.id} value={service.id}>
                                  {service.name}
                                </option>
                              ))}
                            </select>
                          </label>
                          <label className="note-field">
                            <span>Target service</span>
                            <select
                              onChange={(event) =>
                                setEdgeEditorState((current) =>
                                  current === null
                                    ? null
                                    : {
                                        ...current,
                                        targetServiceId: event.target.value,
                                      },
                                )
                              }
                              value={edgeEditorState.targetServiceId}
                            >
                              {services
                                .filter(
                                  (service) =>
                                    service.id !== edgeEditorState.sourceServiceId,
                                )
                                .map((service) => (
                                  <option key={service.id} value={service.id}>
                                    {service.name}
                                  </option>
                                ))}
                            </select>
                          </label>
                          <label className="note-field note-field-wide">
                            <span>Admin note</span>
                            <textarea
                              onChange={(event) =>
                                setEdgeEditorState((current) =>
                                  current === null
                                    ? null
                                    : {
                                        ...current,
                                        description: event.target.value,
                                      },
                                )
                              }
                              rows={3}
                              value={edgeEditorState.description}
                            />
                          </label>
                          <div className="action-strip">
                            <button
                              className="note-button"
                              onClick={() => void saveEdgeEdit()}
                              type="button"
                            >
                              Save edge
                            </button>
                            <button
                              className="note-button"
                              onClick={() => setEdgeEditorState(null)}
                              type="button"
                            >
                              Cancel edit
                            </button>
                          </div>
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <p className="muted edge-detail-meta">
                      Click the edge to pin it and apply confirm, edit, or remove actions.
                    </p>
                  )}
                  {edgeMutationState.saving ? (
                    <p className="muted edge-detail-meta">Saving edge change…</p>
                  ) : null}
                  {edgeMutationState.auditChangeId ? (
                    <p className="muted edge-detail-meta">
                      Logged in the change timeline as {edgeMutationState.auditChangeId}.
                    </p>
                  ) : null}
                  {edgeMutationState.error ? (
                    <p className="message-inline error">{edgeMutationState.error}</p>
                  ) : null}
                </>
              ) : edgeEditorState ? (
                <>
                  <div className="timeline-topline">
                    <div>
                      <p className="timeline-service">Add dependency edge</p>
                      <p className="muted edge-detail-meta">
                        Review the source, target, and note before saving.
                      </p>
                    </div>
                    <span className="status-pill edge-confidence-pill confidence-user_confirmed">
                      User Confirmed
                    </span>
                  </div>
                  <div className="edge-editor">
                    <label className="note-field">
                      <span>Source service</span>
                      <select
                        onChange={(event) =>
                          setEdgeEditorState((current) =>
                            current === null
                              ? null
                              : {
                                  ...current,
                                  sourceServiceId: event.target.value,
                                  targetServiceId:
                                    current.targetServiceId === event.target.value
                                      ? services.find(
                                          (service) =>
                                            service.id !== event.target.value,
                                        )?.id ?? ""
                                      : current.targetServiceId,
                                },
                          )
                        }
                        value={edgeEditorState.sourceServiceId}
                      >
                        {services.map((service) => (
                          <option key={service.id} value={service.id}>
                            {service.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="note-field">
                      <span>Target service</span>
                      <select
                        onChange={(event) =>
                          setEdgeEditorState((current) =>
                            current === null
                              ? null
                              : {
                                  ...current,
                                  targetServiceId: event.target.value,
                                },
                          )
                        }
                        value={edgeEditorState.targetServiceId}
                      >
                        {services
                          .filter((service) => service.id !== edgeEditorState.sourceServiceId)
                          .map((service) => (
                            <option key={service.id} value={service.id}>
                              {service.name}
                            </option>
                          ))}
                      </select>
                    </label>
                    <label className="note-field note-field-wide">
                      <span>Admin note</span>
                      <textarea
                        onChange={(event) =>
                          setEdgeEditorState((current) =>
                            current === null
                              ? null
                              : {
                                  ...current,
                                  description: event.target.value,
                                },
                          )
                        }
                        rows={3}
                        value={edgeEditorState.description}
                      />
                    </label>
                    <div className="action-strip">
                      <button
                        className="note-button"
                        disabled={
                          edgeMutationState.saving ||
                          !edgeEditorState.sourceServiceId ||
                          !edgeEditorState.targetServiceId
                        }
                        onClick={() => void saveEdgeEdit()}
                        type="button"
                      >
                        Save edge
                      </button>
                      <button
                        className="note-button"
                        onClick={() => setEdgeEditorState(null)}
                        type="button"
                      >
                        Cancel add
                      </button>
                    </div>
                  </div>
                  {edgeMutationState.saving ? (
                    <p className="muted edge-detail-meta">Saving edge change…</p>
                  ) : null}
                  {edgeMutationState.auditChangeId ? (
                    <p className="muted edge-detail-meta">
                      Logged in the change timeline as {edgeMutationState.auditChangeId}.
                    </p>
                  ) : null}
                  {edgeMutationState.error ? (
                    <p className="message-inline error">{edgeMutationState.error}</p>
                  ) : null}
                </>
              ) : (
                <>
                  <p className="muted edge-detail-meta">
                    Hover or click an edge to inspect its provenance, confidence, and admin
                    controls.
                  </p>
                  <div className="action-strip">
                    <button
                      className="note-button"
                      disabled={services.length < 2}
                      onClick={beginEdgeAdd}
                      type="button"
                    >
                      Add dependency
                    </button>
                  </div>
                </>
              )}
            </div>
          </section>

          <aside className="side-column">
            <section className="panel detail-panel" id="service-detail-panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Kaval Health</p>
                  <h2>Capability layers</h2>
                </div>
                {state.capabilityHealth ? (
                  <div className="panel-status">
                    <span
                      className={`status-pill capability-state state-${state.capabilityHealth.overall_status}`}
                    >
                      {formatLabel(state.capabilityHealth.overall_status)}
                    </span>
                  </div>
                ) : null}
              </div>

              {state.capabilityHealth ? (
                <div className="investigation-grid">
                  <div className="detail-block">
                    <p className="detail-label">Scope</p>
                    <p className="muted">
                      These states describe Kaval's own runtime capabilities, not the selected
                      service.
                    </p>
                    <p className="muted">
                      Checked {formatTimestamp(state.capabilityHealth.checked_at)}
                    </p>
                  </div>

                  <div className="kaval-health-list">
                    {state.capabilityHealth.layers.map((layer) => (
                      <article key={layer.layer} className="kaval-health-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">{formatLabel(layer.layer)}</p>
                          <span
                            className={`status-pill capability-state state-${layer.display_state}`}
                          >
                            {formatLabel(layer.display_state)}
                          </span>
                        </div>
                        <p className="muted capability-summary">{layer.summary}</p>
                        <p className="muted">{layer.detail}</p>
                        <p className="step-meta">Impact: {layer.user_impact}</p>
                      </article>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="muted">Capability-health data has not been loaded yet.</p>
              )}
            </section>

            <section className="panel detail-panel" id="investigation-detail-panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Service Detail</p>
                  <h2>{selectedService?.name ?? "No service selected"}</h2>
                </div>
                {selectedService ? (
                  <div className="panel-status service-detail-status">
                    <span className={`status-pill status-${selectedService.status}`}>
                      {statusLabel[selectedService.status]}
                    </span>
                    {selectedServiceDetail ? (
                      <span
                        className={`status-pill insight-pill insight-${selectedServiceDetail.insight_section.current_level}`}
                      >
                        L{selectedServiceDetail.insight_section.current_level}{" "}
                        {labelForInsight(selectedServiceDetail.insight_section.current_level)}
                      </span>
                    ) : null}
                  </div>
                ) : null}
              </div>

              {selectedServiceDetail ? (
                <div className="investigation-grid">
                  <div className="action-strip">
                    <span className="action-pill">{formatLabel(selectedServiceDetail.service.type)}</span>
                    <span className="action-pill">
                      {selectedServiceDetail.service.category}
                    </span>
                    <span className="action-pill">
                      {formatLabel(selectedServiceDetail.service.lifecycle.state)}
                    </span>
                    {selectedServiceDetail.service.descriptor_id ? (
                      <span className="action-pill">Descriptor matched</span>
                    ) : null}
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Identity</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <p className="timeline-service">Matched identity</p>
                        <ul className="system-profile-list compact">
                          <li>
                            <span>Descriptor</span>
                            <strong>
                              {formatOptionalValue(selectedServiceDetail.service.descriptor_id)}
                            </strong>
                          </li>
                          <li>
                            <span>Descriptor source</span>
                            <strong>
                              {formatOptionalLabel(
                                selectedServiceDetail.service.descriptor_source,
                              )}
                            </strong>
                          </li>
                          <li>
                            <span>Docker image</span>
                            <strong>{formatOptionalValue(selectedServiceDetail.service.image)}</strong>
                          </li>
                          <li>
                            <span>Container ID</span>
                            <strong>
                              {formatOptionalValue(selectedServiceDetail.service.container_id)}
                            </strong>
                          </li>
                          <li>
                            <span>VM ID</span>
                            <strong>{formatOptionalValue(selectedServiceDetail.service.vm_id)}</strong>
                          </li>
                        </ul>
                      </article>
                      <article className="system-profile-card">
                        <p className="timeline-service">Observed runtime identity</p>
                        <ul className="system-profile-list compact">
                          <li>
                            <span>Lifecycle</span>
                            <strong>
                              {formatLabel(selectedServiceDetail.service.lifecycle.state)}
                            </strong>
                          </li>
                          <li>
                            <span>Last event</span>
                            <strong>
                              {formatOptionalValue(selectedServiceDetail.service.lifecycle.last_event)}
                            </strong>
                          </li>
                          <li>
                            <span>Changed at</span>
                            <strong>
                              {formatOptionalTimestamp(
                                selectedServiceDetail.service.lifecycle.changed_at,
                              )}
                            </strong>
                          </li>
                        </ul>
                        {selectedServiceDetail.service.lifecycle.previous_names.length > 0 ? (
                          <ul className="chip-list service-inline-chip-list">
                            {selectedServiceDetail.service.lifecycle.previous_names.map((name) => (
                              <li key={name}>
                                <span className="chip ghost">{name}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="muted service-inline-copy">
                            No prior service names have been recorded for this service.
                          </p>
                        )}
                        {selectedServiceDetail.service.endpoints.length > 0 ? (
                          <ul className="endpoint-list">
                            {selectedServiceDetail.service.endpoints.map((endpoint) => (
                              <li key={`${endpoint.name}-${endpoint.url ?? endpoint.port ?? endpoint.protocol}`}>
                                {endpoint.name}: {endpoint.url ?? endpoint.host ?? "local"}{" "}
                                {endpoint.port ? `:${endpoint.port}` : ""}{" "}
                                {endpoint.auth_required ? "· auth" : "· open"}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </article>
                    </div>
                  </div>

                  {selectedServiceDetail.service.type === "vm" ? (
                    <div className="detail-block">
                      <p className="detail-label">VM boundary</p>
                      <div className="detail-grid">
                        <article className="system-profile-card system-profile-card-wide">
                          <div className="timeline-topline">
                            <p className="timeline-service">Guided setup prompt</p>
                            <span className="chip ghost">State + explicit endpoints only</span>
                          </div>
                          <p className="muted service-inline-copy">
                            Kaval v1 models this VM as a host boundary. The graph can show VM
                            state plus any explicit hosted endpoints already attached to this
                            service, but it does not introspect guest processes, packages, or
                            nested workloads from inside the VM.
                          </p>
                          <ul className="system-profile-list compact">
                            <li>
                              <span>Purpose</span>
                              <strong>{formatOptionalValue(selectedVmProfile?.purpose ?? null)}</strong>
                            </li>
                            <li>
                              <span>OS</span>
                              <strong>{formatOptionalValue(selectedVmProfile?.os ?? null)}</strong>
                            </li>
                            <li>
                              <span>Type</span>
                              <strong>{formatOptionalValue(selectedVmProfile?.type ?? null)}</strong>
                            </li>
                            <li>
                              <span>Hosted surfaces</span>
                              <strong>{selectedVmHostedSurfaceLabels.length}</strong>
                            </li>
                          </ul>
                          {selectedVmHostedSurfaceLabels.length > 0 ? (
                            <>
                              <p className="step-meta">
                                Hosted children in the graph come only from the current explicit
                                endpoint list for this VM service.
                              </p>
                              <ul className="chip-list service-inline-chip-list">
                                {selectedVmHostedSurfaceLabels.map((label) => (
                                  <li key={label}>
                                    <span className="chip ghost">{label}</span>
                                  </li>
                                ))}
                              </ul>
                            </>
                          ) : (
                            <p className="muted service-inline-copy">
                              No explicit hosted endpoints are currently recorded for this VM, so
                              graph coverage remains limited to VM state health and incident
                              context tied to this service.
                            </p>
                          )}
                          <p className="step-meta">
                            No guest introspection or hidden VM-only configuration path is added in
                            this phase.
                          </p>
                        </article>
                      </div>
                    </div>
                  ) : null}

                  <div className="detail-block">
                    <p className="detail-label">Health</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <p className="timeline-service">Current service status</p>
                        <ul className="system-profile-list compact">
                          <li>
                            <span>Status</span>
                            <strong>{statusLabel[selectedServiceDetail.service.status]}</strong>
                          </li>
                          <li>
                            <span>Active findings</span>
                            <strong>{selectedServiceDetail.service.active_findings}</strong>
                          </li>
                          <li>
                            <span>Active incidents</span>
                            <strong>{selectedServiceDetail.service.active_incidents}</strong>
                          </li>
                          <li>
                            <span>Last check</span>
                            <strong>
                              {formatOptionalTimestamp(selectedServiceDetail.service.last_check)}
                            </strong>
                          </li>
                        </ul>
                      </article>
                      <article className="system-profile-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">Recent incidents</p>
                          {selectedServiceIncidents[0] ? (
                            <button
                              className="note-button"
                              onClick={() => setSelectedIncidentId(selectedServiceIncidents[0].id)}
                              type="button"
                            >
                              Open latest
                            </button>
                          ) : null}
                        </div>
                        {selectedServiceIncidents.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceIncidents.slice(0, 3).map((incident) => (
                              <article className="service-inline-item" key={incident.id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">{incident.title}</p>
                                  <div className="adapter-state-strip">
                                    <span className={`severity severity-${incident.severity}`}>
                                      {incident.severity}
                                    </span>
                                    <span className="chip ghost">
                                      {formatLabel(incident.status)}
                                    </span>
                                  </div>
                                </div>
                                <p className="muted service-inline-copy">
                                  {incident.triggering_symptom ??
                                    incident.suspected_cause ??
                                    "No persisted symptom summary."}
                                </p>
                                <p className="step-meta">
                                  Updated {formatTimestamp(incident.updated_at)}
                                </p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No persisted incidents currently affect this service.
                          </p>
                        )}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Noise Control</p>
                    <div className="detail-grid">
                      <article className="system-profile-card system-profile-card-wide">
                        <div className="timeline-topline">
                          <p className="timeline-service">Per-service check suppression</p>
                          <span className="chip ghost">
                            {selectedServiceDetail.monitoring_section.checks.length} applicable
                          </span>
                        </div>
                        <p className="muted service-inline-copy">
                          Suppression here is explicit and auditable. It only affects this service
                          and preserves check definitions and global monitoring defaults.
                        </p>
                        {selectedServiceDetail.monitoring_section.checks.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceDetail.monitoring_section.checks.map((check) => {
                              const suppressionLocked = check.override_enabled === true;
                              const rowBusy =
                                serviceDetailSuppressionMutationState.submitting &&
                                serviceDetailSuppressionMutationState.checkId === check.check_id;
                              return (
                                <article className="service-inline-item" key={check.check_id}>
                                  <div className="timeline-topline">
                                    <p className="timeline-service">{check.label}</p>
                                    <div className="adapter-state-strip">
                                      <span className="chip ghost">
                                        {check.suppressed
                                          ? "Suppressed"
                                          : check.effective_enabled
                                            ? "Enabled"
                                            : "Disabled globally"}
                                      </span>
                                      <span className="chip ghost">
                                        {formatLabel(check.source)}
                                      </span>
                                    </div>
                                  </div>
                                  <p className="muted service-inline-copy">{check.description}</p>
                                  <p className="step-meta">
                                    Inherited {check.inherited_enabled ? "on" : "off"} every{" "}
                                    {formatDurationSeconds(check.inherited_interval_seconds)}.{" "}
                                    Effective {check.effective_enabled ? "on" : "off"} every{" "}
                                    {formatDurationSeconds(check.effective_interval_seconds)}.
                                  </p>
                                  {check.override_interval_seconds !== null ? (
                                    <p className="step-meta">
                                      Local interval override:{" "}
                                      {formatDurationSeconds(check.override_interval_seconds)}.
                                    </p>
                                  ) : null}
                                  {check.override_updated_at ? (
                                    <p className="step-meta">
                                      Local override updated{" "}
                                      {formatTimestamp(check.override_updated_at)}.
                                    </p>
                                  ) : null}
                                  {suppressionLocked ? (
                                    <p className="muted service-inline-copy">
                                      This check is explicitly forced on for this service from the
                                      monitoring settings panel. Edit it there before changing
                                      suppression here.
                                    </p>
                                  ) : !check.effective_enabled && !check.suppressed ? (
                                    <p className="muted service-inline-copy">
                                      This check is currently off due to the global monitoring
                                      rule. Local suppression keeps it off if the global rule is
                                      re-enabled later.
                                    </p>
                                  ) : check.suppressed ? (
                                    <p className="muted service-inline-copy">
                                      The scheduler currently skips this check for this service.
                                    </p>
                                  ) : (
                                    <p className="muted service-inline-copy">
                                      This service currently inherits the active global monitoring
                                      rule for this check.
                                    </p>
                                  )}
                                  <div className="action-strip">
                                    <button
                                      className="note-button"
                                      disabled={
                                        suppressionLocked ||
                                        serviceDetailSuppressionMutationState.submitting
                                      }
                                      onClick={() =>
                                        void updateServiceCheckSuppression(
                                          check.check_id,
                                          !check.suppressed,
                                        )
                                      }
                                      type="button"
                                    >
                                      {rowBusy
                                        ? "Saving…"
                                        : check.suppressed
                                          ? "Unsuppress"
                                          : "Suppress"}
                                    </button>
                                  </div>
                                </article>
                              );
                            })}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No currently shipped monitoring checks apply to this service.
                          </p>
                        )}
                        {serviceDetailSuppressionMutationState.auditChangeId ? (
                          <p className="step-meta model-settings-audit">
                            Logged in the change timeline as{" "}
                            {serviceDetailSuppressionMutationState.auditChangeId}.
                          </p>
                        ) : null}
                        {serviceDetailSuppressionMutationState.error ? (
                          <p className="note-error">
                            {serviceDetailSuppressionMutationState.error}
                          </p>
                        ) : null}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Insight</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <p className="service-detail-lead">
                          Level {selectedServiceDetail.insight_section.current_level}:{" "}
                          {labelForInsight(selectedServiceDetail.insight_section.current_level)}
                        </p>
                        <p className="muted service-inline-copy">
                          Current insight reflects the existing descriptor, monitoring, model, and
                          deep-inspection chain already active for this service.
                        </p>
                        {selectedServiceDetail.insight_section.improve_actions.length > 0 ? (
                          <div className="improve-list service-inline-stack">
                            {selectedServiceDetail.insight_section.improve_actions.map((action) => (
                              <article
                                key={`${action.kind}-${action.title}`}
                                className="improve-card"
                              >
                                <p className="improve-title">{action.title}</p>
                                <p className="muted">{action.detail}</p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No immediate improvement action is available from the current Phase 3A
                            foundations.
                          </p>
                        )}
                      </article>
                      <article className="system-profile-card">
                        <p className="timeline-service">Deep inspection surfaces</p>
                        {selectedServiceDetail.insight_section.adapter_available ? (
                          <div className="adapter-list service-inline-stack">
                            {selectedServiceDetail.insight_section.adapters.map((adapter) => (
                              <article key={adapter.adapter_id} className="adapter-card">
                                <div className="timeline-topline">
                                  <p className="timeline-service">{adapter.display_name}</p>
                                  <div className="adapter-state-strip">
                                    <span className="chip ghost">
                                      {formatLabel(adapter.configuration_state)}
                                    </span>
                                    <span className="chip ghost">
                                      {formatLabel(adapter.health_state)}
                                    </span>
                                  </div>
                                </div>
                                <p className="muted">{adapter.configuration_summary}</p>
                                <p className="muted">{adapter.health_summary}</p>
                                {adapter.missing_credentials.length > 0 ? (
                                  <p className="muted">
                                    Missing:{" "}
                                    {adapter.missing_credentials
                                      .map((credential) => formatLabel(credential))
                                      .join(", ")}
                                  </p>
                                ) : null}
                                {adapter.supported_fact_names.length > 0 ? (
                                  <ul className="chip-list adapter-capability-list">
                                    {adapter.supported_fact_names.map((factName) => (
                                      <li key={factName}>
                                        <span className="chip">
                                          {formatLabel(factName)}
                                        </span>
                                      </li>
                                    ))}
                                  </ul>
                                ) : null}
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No shipped deep-inspection adapter is currently available for this
                            service.
                          </p>
                        )}
                      </article>
                      <article className="system-profile-card system-profile-card-wide">
                        <div className="timeline-topline">
                          <p className="timeline-service">Imported facts</p>
                          {selectedServiceFacts ? (
                            <span className="step-meta">
                              Checked {formatTimestamp(selectedServiceFacts.checked_at)}
                            </span>
                          ) : null}
                        </div>
                        {serviceAdapterFactsState.loading ? (
                          <p className="muted service-inline-copy">
                            Loading prompt-safe imported facts for this service…
                          </p>
                        ) : serviceAdapterFactsState.error ? (
                          <p className="muted service-inline-copy">
                            {serviceAdapterFactsState.error}
                          </p>
                        ) : selectedServiceFacts && selectedServiceFactAdapters.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceFactAdapters.map((adapter) => (
                              <article className="service-inline-item" key={adapter.adapter_id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">{adapter.display_name}</p>
                                  <div className="adapter-state-strip">
                                    <span
                                      className={`status-pill fact-freshness fact-freshness-${adapter.freshness}`}
                                    >
                                      {formatLabel(adapter.freshness)}
                                    </span>
                                    <span className="chip ghost">
                                      {formatLabel(adapter.health_state)}
                                    </span>
                                  </div>
                                </div>
                                <p className="muted">{adapter.configuration_summary}</p>
                                <p className="muted">{adapter.health_summary}</p>
                                <p className="step-meta">
                                  {adapter.facts_observed_at
                                    ? `Observed ${formatTimestamp(adapter.facts_observed_at)}`
                                    : `Checked ${formatTimestamp(selectedServiceFacts.checked_at)}`}
                                  {" · "}
                                  Next refresh {formatOptionalTimestamp(adapter.next_refresh_at)}
                                </p>
                                {adapter.facts_available ? (
                                  <div className="fact-value-grid">
                                    {Object.entries(adapter.facts).map(([factName, value]) => (
                                      <article
                                        className="fact-value-card"
                                        key={`${adapter.adapter_id}-${factName}`}
                                      >
                                        <p className="detail-label">
                                          {formatLabel(factName)}
                                        </p>
                                        <pre className="fact-json-block">
                                          {formatFactValue(value)}
                                        </pre>
                                      </article>
                                    ))}
                                  </div>
                                ) : (
                                  <p className="muted service-inline-copy">
                                    No prompt-safe fact values are currently available for this
                                    adapter.
                                  </p>
                                )}
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            Prompt-safe imported facts are not currently available for this
                            service.
                          </p>
                        )}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Dependencies</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">Upstream dependencies</p>
                          <button className="note-button" onClick={beginEdgeAdd} type="button">
                            Add dependency
                          </button>
                        </div>
                        {selectedServiceDetail.service.dependencies.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceDetail.service.dependencies.map((dependency) => (
                              <article
                                className="service-inline-item"
                                key={`${selectedServiceDetail.service.id}-${dependency.target_service_id}`}
                              >
                                <div className="timeline-topline">
                                  <p className="timeline-service">
                                    {serviceNames.get(dependency.target_service_id) ??
                                      dependency.target_service_id}
                                  </p>
                                  <span
                                    className={`status-pill edge-confidence-pill confidence-${dependency.confidence}`}
                                  >
                                    {formatLabel(dependency.confidence)}
                                  </span>
                                </div>
                                <p className="muted service-inline-copy">
                                  {formatLabel(dependency.source)}
                                  {dependency.description
                                    ? ` · ${dependency.description}`
                                    : " · No admin note recorded yet."}
                                </p>
                                <div className="action-strip">
                                  <button
                                    className="note-button"
                                    onClick={() =>
                                      pinGraphEdge(
                                        selectedServiceDetail.service.id,
                                        dependency.target_service_id,
                                      )
                                    }
                                    type="button"
                                  >
                                    Review edge
                                  </button>
                                  <button
                                    className="note-button"
                                    onClick={() => setSelectedServiceId(dependency.target_service_id)}
                                    type="button"
                                  >
                                    Open service
                                  </button>
                                </div>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No upstream dependencies are currently recorded for this service.
                          </p>
                        )}
                      </article>
                      <article className="system-profile-card">
                        <p className="timeline-service">Downstream impact</p>
                        {selectedServiceDetail.service.dependents.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceDetail.service.dependents.map((dependentId) => {
                              const dependentService = serviceById.get(dependentId) ?? null;
                              return (
                                <article className="service-inline-item" key={dependentId}>
                                  <div className="timeline-topline">
                                    <p className="timeline-service">
                                      {serviceNames.get(dependentId) ?? dependentId}
                                    </p>
                                    {dependentService ? (
                                      <span
                                        className={`status-pill status-${dependentService.status}`}
                                      >
                                        {statusLabel[dependentService.status]}
                                      </span>
                                    ) : null}
                                  </div>
                                  {dependentService ? (
                                    <p className="muted service-inline-copy">
                                      {dependentService.active_findings} findings ·{" "}
                                      {dependentService.active_incidents} incidents
                                    </p>
                                  ) : null}
                                  <div className="action-strip">
                                    <button
                                      className="note-button"
                                      onClick={() => pinGraphEdge(dependentId, selectedServiceDetail.service.id)}
                                      type="button"
                                    >
                                      Review edge
                                    </button>
                                    <button
                                      className="note-button"
                                      onClick={() => setSelectedServiceId(dependentId)}
                                      type="button"
                                    >
                                      Open service
                                    </button>
                                  </div>
                                </article>
                              );
                            })}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No downstream dependents are currently recorded for this service.
                          </p>
                        )}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Credentials</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <p className="timeline-service">Adapter credential state</p>
                        {selectedServiceDetail.insight_section.adapters.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceDetail.insight_section.adapters.map((adapter) => (
                              <article className="service-inline-item" key={adapter.adapter_id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">{adapter.display_name}</p>
                                  <span className="chip ghost">
                                    {formatLabel(adapter.configuration_state)}
                                  </span>
                                </div>
                                <p className="muted service-inline-copy">
                                  {adapter.configuration_summary}
                                </p>
                                {adapter.missing_credentials.length > 0 ? (
                                  <p className="step-meta">
                                    Missing credentials:{" "}
                                    {adapter.missing_credentials
                                      .map((credential) => formatLabel(credential))
                                      .join(", ")}
                                  </p>
                                ) : (
                                  <p className="step-meta">
                                    Credentials currently satisfy the descriptor-backed adapter
                                    requirements.
                                  </p>
                                )}
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No descriptor-backed credential requirements are currently defined for
                            this service.
                          </p>
                        )}
                      </article>
                      <article className="system-profile-card">
                        <p className="timeline-service">Credential request activity</p>
                        {selectedServiceCredentialRequests.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceCredentialRequests.slice(0, 3).map((request) => (
                              <article className="service-inline-item" key={request.id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">
                                    {formatLabel(request.credential_key)}
                                  </p>
                                  <span className="chip ghost">
                                    {formatLabel(request.status)}
                                  </span>
                                </div>
                                <p className="muted service-inline-copy">{request.reason}</p>
                                <p className="step-meta">
                                  Requested {formatTimestamp(request.requested_at)}
                                </p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No credential requests have been recorded for this service yet.
                          </p>
                        )}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Memory</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">User notes</p>
                          <button
                            className="note-button"
                            onClick={() => {
                              setActiveMemoryTab("notes");
                              setEditingNoteId(null);
                              setNoteEditorState(createEmptyNoteEditorState(selectedServiceDetail.service.id));
                            }}
                            type="button"
                          >
                            Open notes workspace
                          </button>
                        </div>
                        {selectedServiceNotes.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceNotes.slice(0, 3).map((note) => (
                              <article className="service-inline-item" key={note.id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">
                                    {note.safe_for_model ? "Model-safe note" : "Excluded note"}
                                  </p>
                                  <div className="adapter-state-strip">
                                    <span className="chip ghost">
                                      {note.stale ? "Needs review" : "Current"}
                                    </span>
                                    <span className="chip ghost">
                                      {formatOptionalTimestamp(note.last_verified_at)}
                                    </span>
                                  </div>
                                </div>
                                <p className="muted service-inline-copy">{note.note}</p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No user notes are currently attached to this service.
                          </p>
                        )}
                        <div className="note-editor service-inline-note-editor">
                          <div className="timeline-topline">
                            <p className="timeline-service">Quick note</p>
                            <span className="chip ghost">{selectedServiceDetail.service.name}</span>
                          </div>
                          <div className="note-field">
                            <span>Note</span>
                            <textarea
                              onChange={(event) =>
                                setNoteEditorState((current) => ({
                                  ...current,
                                  serviceId: selectedServiceDetail.service.id,
                                  note: event.target.value,
                                }))
                              }
                              rows={3}
                              value={
                                noteEditorState.serviceId === selectedServiceDetail.service.id ||
                                noteEditorState.serviceId === ""
                                  ? noteEditorState.note
                                  : ""
                              }
                            />
                          </div>
                          <div className="action-strip">
                            <button
                              className="note-button"
                              disabled={noteMutationState.saving}
                              onClick={() => void submitNoteEditor(selectedServiceDetail.service.id)}
                              type="button"
                            >
                              {noteMutationState.saving ? "Saving…" : "Save note"}
                            </button>
                          </div>
                          {noteMutationState.error ? (
                            <p className="message-inline error">{noteMutationState.error}</p>
                          ) : null}
                        </div>
                      </article>
                      <article className="system-profile-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">Journal and recurrence</p>
                          <div className="action-strip">
                            <button
                              className="note-button"
                              onClick={() => setActiveMemoryTab("journal")}
                              type="button"
                            >
                              Open journal
                            </button>
                            <button
                              className="note-button"
                              onClick={() => setActiveMemoryTab("recurrence")}
                              type="button"
                            >
                              Open recurrence
                            </button>
                          </div>
                        </div>
                        {selectedServiceJournalEntries.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceJournalEntries.slice(0, 3).map((entry) => (
                              <article className="service-inline-item" key={entry.id}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">{entry.summary}</p>
                                  <span className="chip ghost">
                                    {formatLabel(entry.confidence)}
                                  </span>
                                </div>
                                <p className="muted service-inline-copy">{entry.root_cause}</p>
                                <p className="step-meta">
                                  {entry.date} · recurrence {entry.recurrence_count}
                                </p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            No journal entries currently reference this service.
                          </p>
                        )}
                        {selectedServiceRecurrencePatterns.length > 0 ? (
                          <p className="step-meta">
                            {selectedServiceRecurrencePatterns.length} active recurrence pattern(s)
                            currently include this service.
                          </p>
                        ) : null}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Notifications</p>
                    <div className="detail-grid">
                      <article className="system-profile-card">
                        <div className="timeline-topline">
                          <p className="timeline-service">Notification channel health</p>
                          {notificationHealthLayer ? (
                            <span
                              className={`status-pill capability-state state-${notificationHealthLayer.display_state}`}
                            >
                              {formatLabel(notificationHealthLayer.display_state)}
                            </span>
                          ) : null}
                        </div>
                        {notificationHealthLayer ? (
                          <>
                            <p className="muted service-inline-copy">
                              {notificationHealthLayer.summary}
                            </p>
                            <p className="muted service-inline-copy">
                              {notificationHealthLayer.detail}
                            </p>
                            <p className="step-meta">
                              {notificationChannelCount} configured channel
                              {notificationChannelCount === 1 ? "" : "s"} ·{" "}
                              {notificationHealthLayer.user_impact}
                            </p>
                          </>
                        ) : (
                          <p className="muted service-inline-copy">
                            Notification channel health has not been loaded yet.
                          </p>
                        )}
                      </article>
                      <article className="system-profile-card">
                        <p className="timeline-service">Service alert context</p>
                        <p className="muted service-inline-copy">
                          Incident-centered routing currently applies to this service through the
                          shared Phase 3B notification policy. Per-service overrides land in later
                          Phase 3C settings and noise-control tasks.
                        </p>
                        {selectedServiceIncidents.length > 0 ? (
                          <div className="service-inline-list">
                            {selectedServiceIncidents.slice(0, 2).map((incident) => (
                              <article className="service-inline-item" key={`${incident.id}-notify`}>
                                <div className="timeline-topline">
                                  <p className="timeline-service">{incident.title}</p>
                                  <span className={`severity severity-${incident.severity}`}>
                                    {incident.severity}
                                  </span>
                                </div>
                                <p className="muted service-inline-copy">
                                  {formatLabel(incident.status)} · confidence{" "}
                                  {incident.confidence.toFixed(2)}
                                </p>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <p className="muted service-inline-copy">
                            This service is not part of any persisted incident notification context
                            right now.
                          </p>
                        )}
                      </article>
                    </div>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Descriptor</p>
                    {selectedServiceDetail.service.descriptor_id === null ? (
                      <>
                        <p className="muted service-inline-copy">
                          No matched descriptor is currently attached to this service, so rendered
                          descriptor view mode is unavailable until the service is identified.
                        </p>
                        <div className="note-action-row">
                          {selectedServiceDetail.service.type === "container" ? (
                            <button
                              className="note-button note-button-primary"
                              disabled={
                                guidedSetupMutationState.identifyingServiceId ===
                                selectedServiceDetail.service.id
                              }
                              onClick={() => {
                                void generateAutoGeneratedDescriptorForService(
                                  selectedServiceDetail.service,
                                );
                              }}
                              type="button"
                            >
                              {guidedSetupMutationState.identifyingServiceId ===
                              selectedServiceDetail.service.id
                                ? "Generating…"
                                : "Generate draft descriptor"}
                            </button>
                          ) : null}
                          <button
                            className="note-button note-button-ghost"
                            onClick={() => scrollToPanel("descriptor-review-queue-panel")}
                            type="button"
                          >
                            Open review queue
                          </button>
                          {selectedServiceDetail.service.type === "container" ? (
                            <button
                              className="note-button note-button-ghost"
                              onClick={() =>
                                setGuidedSetupSkippedServiceIds((current) =>
                                  current.includes(selectedServiceDetail.service.id)
                                    ? current
                                    : [...current, selectedServiceDetail.service.id],
                                )
                              }
                              type="button"
                            >
                              Skip in setup
                            </button>
                          ) : null}
                        </div>
                      </>
                    ) : serviceDescriptorState.loading ? (
                      <p className="muted service-inline-copy">
                        Loading rendered descriptor view…
                      </p>
                    ) : serviceDescriptorState.error ? (
                      <p className="muted service-inline-copy">
                        {serviceDescriptorState.error}
                      </p>
                    ) : serviceDescriptorState.detail ? (
                      <>
                        <div className="descriptor-editor-toolbar">
                          <div>
                            <p className="step-meta descriptor-editor-meta">
                              Active descriptor file: {serviceDescriptorState.detail.file_path}
                            </p>
                            <p className="step-meta descriptor-editor-meta">
                              Deterministic saves write to{" "}
                              {serviceDescriptorState.detail.write_target_path}. Shipped
                              descriptors stay immutable.
                            </p>
                          </div>
                          <div className="action-strip">
                            <button
                              className={`note-button ${
                                descriptorEditorOpen && descriptorEditorState?.mode === "form"
                                  ? "note-button-primary"
                                  : "note-button-ghost"
                              }`}
                              disabled={descriptorMutationState.saving}
                              onClick={() => beginDescriptorEdit("form")}
                              type="button"
                            >
                              Edit common fields
                            </button>
                            <button
                              className={`note-button ${
                                descriptorEditorOpen && descriptorEditorState?.mode === "yaml"
                                  ? "note-button-primary"
                                  : "note-button-ghost"
                              }`}
                              disabled={descriptorMutationState.saving}
                              onClick={() => beginDescriptorEdit("yaml")}
                              type="button"
                            >
                              Advanced YAML
                            </button>
                          </div>
                        </div>
                        {descriptorMutationState.auditChangeId ? (
                          <p className="message-inline">
                            Logged in the change timeline as{" "}
                            {descriptorMutationState.auditChangeId}.
                          </p>
                        ) : null}
                        {descriptorMutationState.error ? (
                          <p className="message-inline error">
                            {descriptorMutationState.error}
                          </p>
                        ) : null}
                        {descriptorEditorOpen && descriptorEditorState ? (
                          <div className="note-editor descriptor-editor">
                            <div className="memory-section-header">
                              <div>
                                <p className="detail-label">Edit mode</p>
                                <p className="timeline-service">
                                  {descriptorEditorState.mode === "form"
                                    ? "Common field editor"
                                    : "Advanced YAML editor"}
                                </p>
                              </div>
                              <p className="step-meta">
                                {descriptorEditorState.mode === "form"
                                  ? "Match patterns, endpoints, and dependencies only."
                                  : "Raw YAML saves still preserve descriptor id and category."}
                              </p>
                            </div>
                            {descriptorEditorState.mode === "form" ? (
                              <div className="note-editor-grid">
                                <label className="note-field">
                                  <span>Image patterns</span>
                                  <textarea
                                    onChange={(event) =>
                                      updateDescriptorEditor((current) => ({
                                        ...current,
                                        imagePatterns: event.target.value,
                                      }))
                                    }
                                    rows={5}
                                    value={descriptorEditorState.imagePatterns}
                                  />
                                  <span className="step-meta">One pattern per line.</span>
                                </label>
                                <label className="note-field">
                                  <span>Container name patterns</span>
                                  <textarea
                                    onChange={(event) =>
                                      updateDescriptorEditor((current) => ({
                                        ...current,
                                        containerNamePatterns: event.target.value,
                                      }))
                                    }
                                    rows={5}
                                    value={descriptorEditorState.containerNamePatterns}
                                  />
                                  <span className="step-meta">One pattern per line.</span>
                                </label>
                                <label className="note-field note-field-wide">
                                  <span>Share dependencies</span>
                                  <textarea
                                    onChange={(event) =>
                                      updateDescriptorEditor((current) => ({
                                        ...current,
                                        shareDependencies: event.target.value,
                                      }))
                                    }
                                    rows={3}
                                    value={descriptorEditorState.shareDependencies}
                                  />
                                  <span className="step-meta">One share name per line.</span>
                                </label>
                                <div className="note-field note-field-wide">
                                  <span>Container dependencies</span>
                                  <div className="descriptor-editor-list">
                                    {descriptorEditorState.containerDependencies.map(
                                      (dependency) => (
                                        <article
                                          className="descriptor-editor-row"
                                          key={dependency.clientId}
                                        >
                                          <div className="note-editor-grid">
                                            <label className="note-field">
                                              <span>Name</span>
                                              <input
                                                onChange={(event) =>
                                                  updateDescriptorDependency(
                                                    dependency.clientId,
                                                    "name",
                                                    event.target.value,
                                                  )
                                                }
                                                type="text"
                                                value={dependency.name}
                                              />
                                            </label>
                                            <label className="note-field">
                                              <span>Alternatives</span>
                                              <input
                                                onChange={(event) =>
                                                  updateDescriptorDependency(
                                                    dependency.clientId,
                                                    "alternatives",
                                                    event.target.value,
                                                  )
                                                }
                                                placeholder="Comma-separated"
                                                type="text"
                                                value={dependency.alternatives}
                                              />
                                            </label>
                                          </div>
                                          <div className="descriptor-editor-actions">
                                            <span className="step-meta">
                                              Leave alternatives blank when there is no fallback.
                                            </span>
                                            <button
                                              className="note-button note-button-danger"
                                              onClick={() =>
                                                removeDescriptorDependency(dependency.clientId)
                                              }
                                              type="button"
                                            >
                                              Remove dependency
                                            </button>
                                          </div>
                                        </article>
                                      ),
                                    )}
                                  </div>
                                  <div className="descriptor-editor-actions">
                                    <span className="step-meta">
                                      Dependencies are saved as deterministic descriptor entries.
                                    </span>
                                    <button
                                      className="note-button note-button-ghost"
                                      onClick={addDescriptorDependency}
                                      type="button"
                                    >
                                      Add dependency
                                    </button>
                                  </div>
                                </div>
                                <div className="note-field note-field-wide">
                                  <span>Endpoints</span>
                                  <div className="descriptor-editor-list">
                                    {descriptorEditorState.endpoints.map((endpoint) => (
                                      <article
                                        className="descriptor-editor-row"
                                        key={endpoint.clientId}
                                      >
                                        <div className="note-editor-grid">
                                          <label className="note-field">
                                            <span>Name</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "name",
                                                  event.target.value,
                                                )
                                              }
                                              type="text"
                                              value={endpoint.name}
                                            />
                                          </label>
                                          <label className="note-field">
                                            <span>Port</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "port",
                                                  event.target.value,
                                                )
                                              }
                                              min="1"
                                              step="1"
                                              type="number"
                                              value={endpoint.port}
                                            />
                                          </label>
                                          <label className="note-field">
                                            <span>Path</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "path",
                                                  event.target.value,
                                                )
                                              }
                                              type="text"
                                              value={endpoint.path}
                                            />
                                          </label>
                                          <label className="note-field">
                                            <span>Auth</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "auth",
                                                  event.target.value,
                                                )
                                              }
                                              type="text"
                                              value={endpoint.auth}
                                            />
                                          </label>
                                          <label className="note-field">
                                            <span>Auth header</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "authHeader",
                                                  event.target.value,
                                                )
                                              }
                                              type="text"
                                              value={endpoint.authHeader}
                                            />
                                          </label>
                                          <label className="note-field">
                                            <span>Healthy when</span>
                                            <input
                                              onChange={(event) =>
                                                updateDescriptorEndpoint(
                                                  endpoint.clientId,
                                                  "healthyWhen",
                                                  event.target.value,
                                                )
                                              }
                                              type="text"
                                              value={endpoint.healthyWhen}
                                            />
                                          </label>
                                        </div>
                                        <div className="descriptor-editor-actions">
                                          <span className="step-meta">
                                            Ports must remain valid integer values.
                                          </span>
                                          <button
                                            className="note-button note-button-danger"
                                            onClick={() =>
                                              removeDescriptorEndpoint(endpoint.clientId)
                                            }
                                            type="button"
                                          >
                                            Remove endpoint
                                          </button>
                                        </div>
                                      </article>
                                    ))}
                                  </div>
                                  <div className="descriptor-editor-actions">
                                    <span className="step-meta">
                                      Endpoint names remain deterministic keys in the saved
                                      descriptor.
                                    </span>
                                    <button
                                      className="note-button note-button-ghost"
                                      onClick={addDescriptorEndpoint}
                                      type="button"
                                    >
                                      Add endpoint
                                    </button>
                                  </div>
                                </div>
                              </div>
                            ) : (
                              <label className="note-field note-field-wide">
                                <span>Descriptor YAML</span>
                                <textarea
                                  className="descriptor-editor-textarea"
                                  onChange={(event) =>
                                    updateDescriptorEditor((current) => ({
                                      ...current,
                                      rawYaml: event.target.value,
                                    }))
                                  }
                                  rows={18}
                                  value={descriptorEditorState.rawYaml}
                                />
                              </label>
                            )}
                            {descriptorValidationState.error ? (
                              <p className="message-inline error">
                                {descriptorValidationState.error}
                              </p>
                            ) : null}
                            {descriptorValidationState.result ? (
                              <div className="descriptor-preview">
                                <div className="memory-section-header">
                                  <div>
                                    <p className="detail-label">Validation preview</p>
                                    <p className="timeline-service">
                                      {descriptorValidationState.result.valid
                                        ? "Descriptor edits are valid"
                                        : "Descriptor edits need attention"}
                                    </p>
                                  </div>
                                  {descriptorValidationState.result.preview ? (
                                    <p className="step-meta">
                                      Save target:{" "}
                                      {
                                        descriptorValidationState.result.preview
                                          .write_target_path
                                      }
                                    </p>
                                  ) : null}
                                </div>
                                {descriptorValidationState.result.errors.length > 0 ? (
                                  <ul className="warning-list descriptor-preview-list">
                                    {descriptorValidationState.result.errors.map((error) => (
                                      <li key={`descriptor-error-${error}`}>{error}</li>
                                    ))}
                                  </ul>
                                ) : null}
                                {descriptorValidationState.result.warnings.length > 0 ? (
                                  <ul className="warning-list descriptor-preview-list">
                                    {descriptorValidationState.result.warnings.map((warning) => (
                                      <li key={`descriptor-warning-${warning}`}>{warning}</li>
                                    ))}
                                  </ul>
                                ) : null}
                                {descriptorValidationState.result.preview ? (
                                  <div className="detail-grid descriptor-preview-grid">
                                    <article className="service-inline-item">
                                      <p className="detail-label">Match impact</p>
                                      <p className="muted service-inline-copy">
                                        Current service likely{" "}
                                        {descriptorValidationState.result.preview.match
                                          .current_service_likely_matches
                                          ? "still matches"
                                          : "no longer matches"}{" "}
                                        the edited descriptor.
                                      </p>
                                      {descriptorValidationState.result.preview.match
                                        .affected_services.length > 0 ? (
                                        <ul className="endpoint-list">
                                          {descriptorValidationState.result.preview.match.affected_services.map(
                                            (affectedService) => (
                                              <li key={affectedService.service_id}>
                                                {affectedService.service_name} ·{" "}
                                                {affectedService.likely_matches
                                                  ? "likely matches"
                                                  : "review rematch"}
                                              </li>
                                            ),
                                          )}
                                        </ul>
                                      ) : null}
                                    </article>
                                    <article className="service-inline-item">
                                      <p className="detail-label">Dependency impact</p>
                                      <ul className="endpoint-list">
                                        <li>
                                          Added containers:{" "}
                                          {formatListPreview(
                                            descriptorValidationState.result.preview
                                              .dependency_impact
                                              .added_container_dependencies,
                                          )}
                                        </li>
                                        <li>
                                          Removed containers:{" "}
                                          {formatListPreview(
                                            descriptorValidationState.result.preview
                                              .dependency_impact
                                              .removed_container_dependencies,
                                          )}
                                        </li>
                                        <li>
                                          Added shares:{" "}
                                          {formatListPreview(
                                            descriptorValidationState.result.preview
                                              .dependency_impact.added_share_dependencies,
                                          )}
                                        </li>
                                        <li>
                                          Removed shares:{" "}
                                          {formatListPreview(
                                            descriptorValidationState.result.preview
                                              .dependency_impact
                                              .removed_share_dependencies,
                                          )}
                                        </li>
                                      </ul>
                                    </article>
                                  </div>
                                ) : null}
                              </div>
                            ) : null}
                            <div className="note-action-row">
                              <button
                                className="note-button note-button-ghost"
                                disabled={
                                  descriptorMutationState.saving ||
                                  descriptorValidationState.validating
                                }
                                onClick={cancelDescriptorEdit}
                                type="button"
                              >
                                Close editor
                              </button>
                              <button
                                className="note-button note-button-ghost"
                                disabled={
                                  descriptorMutationState.saving ||
                                  descriptorValidationState.validating
                                }
                                onClick={() => {
                                  void validateDescriptorEdit();
                                }}
                                type="button"
                              >
                                {descriptorValidationState.validating
                                  ? "Validating…"
                                  : "Validate and preview"}
                              </button>
                              <button
                                className="note-button note-button-primary"
                                disabled={
                                  descriptorMutationState.saving ||
                                  descriptorValidationState.validating ||
                                  !descriptorValidationState.result?.valid
                                }
                                onClick={() => {
                                  void saveDescriptorEdit();
                                }}
                                type="button"
                              >
                                {descriptorMutationState.saving
                                  ? "Saving…"
                                  : "Save descriptor"}
                              </button>
                            </div>
                          </div>
                        ) : null}
                        <div className="detail-grid">
                          <article className="system-profile-card">
                            <div className="timeline-topline">
                              <div>
                                <p className="timeline-service">
                                  {serviceDescriptorState.detail.name}
                                </p>
                                <p className="step-meta">
                                  {serviceDescriptorState.detail.descriptor_id}
                                </p>
                              </div>
                              <div className="adapter-state-strip">
                                <span className="chip ghost">
                                  {formatLabel(serviceDescriptorState.detail.source)}
                                </span>
                                <span className="chip ghost">
                                  {serviceDescriptorState.detail.verified
                                    ? "Verified"
                                    : "Needs review"}
                                </span>
                              </div>
                            </div>
                            <ul className="system-profile-list compact">
                              <li>
                                <span>Category</span>
                                <strong>{serviceDescriptorState.detail.category}</strong>
                              </li>
                              <li>
                                <span>Path</span>
                                <strong>{serviceDescriptorState.detail.file_path}</strong>
                              </li>
                              <li>
                                <span>Project URL</span>
                                <strong>
                                  {formatOptionalValue(serviceDescriptorState.detail.project_url)}
                                </strong>
                              </li>
                              <li>
                                <span>Icon</span>
                                <strong>
                                  {formatOptionalValue(serviceDescriptorState.detail.icon)}
                                </strong>
                              </li>
                            </ul>
                            <div className="service-inline-list">
                              <article className="service-inline-item">
                                <p className="detail-label">Match rules</p>
                                <ul className="chip-list service-inline-chip-list">
                                  {serviceDescriptorState.detail.match.image_patterns.map(
                                    (pattern) => (
                                      <li key={`image-${pattern}`}>
                                        <span className="chip ghost">{pattern}</span>
                                      </li>
                                    ),
                                  )}
                                  {serviceDescriptorState.detail.match.container_name_patterns.map(
                                    (pattern) => (
                                      <li key={`name-${pattern}`}>
                                        <span className="chip ghost">{pattern}</span>
                                      </li>
                                    ),
                                  )}
                                </ul>
                              </article>
                            </div>
                          </article>
                          <article className="system-profile-card">
                            <p className="timeline-service">Endpoints and DNS</p>
                            {serviceDescriptorState.detail.endpoints.length > 0 ? (
                              <div className="service-inline-list">
                                {serviceDescriptorState.detail.endpoints.map((endpoint) => (
                                  <article className="service-inline-item" key={endpoint.name}>
                                    <div className="timeline-topline">
                                      <p className="timeline-service">{endpoint.name}</p>
                                      <span className="chip ghost">{endpoint.port}</span>
                                    </div>
                                    <p className="muted service-inline-copy">
                                      {formatOptionalValue(endpoint.path)}
                                      {endpoint.healthy_when
                                        ? ` · healthy when ${formatLabel(endpoint.healthy_when)}`
                                        : ""}
                                    </p>
                                    <p className="step-meta">
                                      Auth {formatOptionalLabel(endpoint.auth)} · header{" "}
                                      {formatOptionalValue(endpoint.auth_header)}
                                    </p>
                                  </article>
                                ))}
                              </div>
                            ) : (
                              <p className="muted service-inline-copy">
                                No explicit descriptor endpoints are defined.
                              </p>
                            )}
                            {serviceDescriptorState.detail.dns_targets.length > 0 ? (
                              <ul className="endpoint-list">
                                {serviceDescriptorState.detail.dns_targets.map((target) => (
                                  <li key={`${target.host}-${target.record_type}`}>
                                    {target.host} · {target.record_type} ·{" "}
                                    {target.expected_values.join(", ")}
                                  </li>
                                ))}
                              </ul>
                            ) : null}
                          </article>
                          <article className="system-profile-card">
                            <p className="timeline-service">Dependencies and failure modes</p>
                            {serviceDescriptorState.detail.typical_dependency_containers.length >
                              0 ||
                            serviceDescriptorState.detail.typical_dependency_shares.length > 0 ? (
                              <div className="service-inline-list">
                                {serviceDescriptorState.detail.typical_dependency_containers.map(
                                  (dependency) => (
                                    <article
                                      className="service-inline-item"
                                      key={`dep-${dependency.name}`}
                                    >
                                      <p className="timeline-service">{dependency.name}</p>
                                      <p className="muted service-inline-copy">
                                        Alternatives:{" "}
                                        {dependency.alternatives.length > 0
                                          ? dependency.alternatives.join(", ")
                                          : "None"}
                                      </p>
                                    </article>
                                  ),
                                )}
                                {serviceDescriptorState.detail.typical_dependency_shares.length >
                                0 ? (
                                  <article className="service-inline-item">
                                    <p className="timeline-service">Share dependencies</p>
                                    <ul className="chip-list service-inline-chip-list">
                                      {serviceDescriptorState.detail.typical_dependency_shares.map(
                                        (share) => (
                                          <li key={share}>
                                            <span className="chip ghost">{share}</span>
                                          </li>
                                        ),
                                      )}
                                    </ul>
                                  </article>
                                ) : null}
                              </div>
                            ) : (
                              <p className="muted service-inline-copy">
                                No typical dependencies are declared in this descriptor.
                              </p>
                            )}
                            {serviceDescriptorState.detail.common_failure_modes.length > 0 ? (
                              <div className="service-inline-list">
                                {serviceDescriptorState.detail.common_failure_modes.map((mode) => (
                                  <article
                                    className="service-inline-item"
                                    key={`${mode.trigger}-${mode.likely_cause}`}
                                  >
                                    <p className="timeline-service">{mode.trigger}</p>
                                    <p className="muted service-inline-copy">{mode.likely_cause}</p>
                                    {mode.check_first.length > 0 ? (
                                      <p className="step-meta">
                                        Check first: {mode.check_first.join(", ")}
                                      </p>
                                    ) : null}
                                  </article>
                                ))}
                              </div>
                            ) : null}
                          </article>
                          <article className="system-profile-card">
                            <p className="timeline-service">Inspection and credentials</p>
                            {serviceDescriptorState.detail.inspection_surfaces.length > 0 ? (
                              <div className="service-inline-list">
                                {serviceDescriptorState.detail.inspection_surfaces.map((surface) => (
                                  <article className="service-inline-item" key={surface.id}>
                                    <div className="timeline-topline">
                                      <p className="timeline-service">{surface.id}</p>
                                      <div className="adapter-state-strip">
                                        <span className="chip ghost">
                                          {formatLabel(surface.type)}
                                        </span>
                                        <span className="chip ghost">
                                          {surface.read_only ? "Read-only" : "Writable"}
                                        </span>
                                      </div>
                                    </div>
                                    <p className="muted service-inline-copy">
                                      {surface.description}
                                    </p>
                                    <p className="step-meta">
                                      Endpoint {formatOptionalValue(surface.endpoint)} · auth{" "}
                                      {formatOptionalLabel(surface.auth)} · confidence{" "}
                                      {formatOptionalLabel(surface.confidence_effect)}
                                    </p>
                                    {surface.facts_provided.length > 0 ? (
                                      <ul className="chip-list service-inline-chip-list">
                                        {surface.facts_provided.map((factName) => (
                                          <li key={`${surface.id}-${factName}`}>
                                            <span className="chip ghost">
                                              {formatLabel(factName)}
                                            </span>
                                          </li>
                                        ))}
                                      </ul>
                                    ) : null}
                                  </article>
                                ))}
                              </div>
                            ) : (
                              <p className="muted service-inline-copy">
                                No deep-inspection surfaces are declared in this descriptor.
                              </p>
                            )}
                            {serviceDescriptorState.detail.credential_hints.length > 0 ? (
                              <div className="service-inline-list">
                                {serviceDescriptorState.detail.credential_hints.map((hint) => (
                                  <article className="service-inline-item" key={hint.key}>
                                    <div className="timeline-topline">
                                      <p className="timeline-service">{hint.description}</p>
                                      <span className="chip ghost">{hint.key}</span>
                                    </div>
                                    <p className="muted service-inline-copy">{hint.location}</p>
                                    {hint.prompt ? (
                                      <p className="step-meta">{hint.prompt}</p>
                                    ) : null}
                                  </article>
                                ))}
                              </div>
                            ) : null}
                          </article>
                          <article className="system-profile-card system-profile-card-wide">
                            <p className="timeline-service">Investigation context</p>
                            <p className="muted service-inline-copy">
                              {serviceDescriptorState.detail.investigation_context ??
                                "No additional investigation context is documented in this descriptor."}
                            </p>
                            {(serviceDescriptorState.detail.log_signals.errors.length > 0 ||
                              serviceDescriptorState.detail.log_signals.warnings.length > 0) ? (
                              <div className="detail-grid">
                                <article className="service-inline-item">
                                  <p className="detail-label">Error signals</p>
                                  <ul className="chip-list service-inline-chip-list">
                                    {serviceDescriptorState.detail.log_signals.errors.map(
                                      (signal) => (
                                        <li key={`error-${signal}`}>
                                          <span className="chip ghost">{signal}</span>
                                        </li>
                                      ),
                                    )}
                                  </ul>
                                </article>
                                <article className="service-inline-item">
                                  <p className="detail-label">Warning signals</p>
                                  <ul className="chip-list service-inline-chip-list">
                                    {serviceDescriptorState.detail.log_signals.warnings.map(
                                      (signal) => (
                                        <li key={`warning-${signal}`}>
                                          <span className="chip ghost">{signal}</span>
                                        </li>
                                      ),
                                    )}
                                  </ul>
                                </article>
                              </div>
                            ) : null}
                          </article>
                        </div>
                      </>
                    ) : (
                      <p className="muted service-inline-copy">
                        Rendered descriptor view is not currently available for this service.
                      </p>
                    )}
                  </div>
                </div>
              ) : serviceDetailState.loading ? (
                <p className="muted">Loading selected service detail…</p>
              ) : serviceDetailState.error ? (
                <p className="muted">{serviceDetailState.error}</p>
              ) : (
                <p className="muted">
                  Select a service to see its current insight level and adapter status.
                </p>
              )}
            </section>

            <section className="panel detail-panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Investigation Detail</p>
                  <h2>{selectedIncident?.title ?? "No incident selected"}</h2>
                </div>
                {selectedIncident ? (
                  <div className="panel-status">
                    <span className={`severity severity-${selectedIncident.severity}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="incident-status">{formatLabel(selectedIncident.status)}</span>
                  </div>
                ) : null}
              </div>

              {selectedIncident && selectedInvestigation ? (
                <div className="investigation-grid">
                  <div className="action-strip">
                    <span className="action-pill">
                      Incident {formatLabel(selectedIncident.status)}
                    </span>
                    <span className="action-pill">
                      Investigation {formatLabel(selectedInvestigation.status)}
                    </span>
                    <span className="action-pill">
                      Action {formatLabel(selectedInvestigation.remediation?.status ?? "none")}
                    </span>
                    <span className="action-pill">
                      {selectedIncident.approved_actions.length} approvals recorded
                    </span>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Affected Services</p>
                    <ul className="chip-list">
                      {selectedIncident.affected_services.map((serviceId) => (
                        <li key={serviceId}>
                          <span className="chip">{serviceNames.get(serviceId) ?? serviceId}</span>
                        </li>
                      ))}
                    </ul>
                    {selectedIncident.triggering_symptom ? (
                      <p className="muted">Symptom: {selectedIncident.triggering_symptom}</p>
                    ) : null}
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Evidence</p>
                    {selectedInvestigation.evidence_steps.length > 0 ? (
                      <ol className="step-list">
                        {selectedInvestigation.evidence_steps.map((step) => (
                          <li key={`${step.order}-${step.action}`} className="step-item">
                            <p className="step-heading">
                              {step.order}. {formatLabel(step.action)}
                            </p>
                            <p className="step-meta">
                              {step.target} · {formatTimestamp(step.timestamp)}
                            </p>
                            <p>{step.result_summary}</p>
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p className="muted">No evidence steps were persisted.</p>
                    )}
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Inference</p>
                    <p className="investigation-root">
                      {selectedInvestigation.root_cause ??
                        selectedIncident.suspected_cause ??
                        selectedIncident.triggering_symptom ??
                        "No root cause recorded yet."}
                    </p>
                    <p className="muted">
                      Confidence {selectedInvestigation.confidence.toFixed(2)} · recurrence{" "}
                      {selectedInvestigation.recurrence_count} · model{" "}
                      {formatLabel(selectedInvestigation.model_used)}
                    </p>
                    {hasInvestigationTelemetry(selectedInvestigation) ? (
                      <p className="muted">
                        Local {formatCount(selectedInvestigation.local_input_tokens)} in /{" "}
                        {formatCount(selectedInvestigation.local_output_tokens)} out · Cloud{" "}
                        {formatCount(selectedInvestigation.cloud_input_tokens)} in /{" "}
                        {formatCount(selectedInvestigation.cloud_output_tokens)} out · Estimated{" "}
                        {formatUsd(selectedInvestigation.estimated_total_cost_usd)}
                        {selectedInvestigation.cloud_escalation_reason
                          ? ` · Escalation ${formatEscalationReasonSummary(
                              selectedInvestigation.cloud_escalation_reason,
                            )}`
                          : ""}
                      </p>
                    ) : null}
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Recommendation</p>
                    {selectedInvestigation.remediation ? (
                      <>
                        <p className="recommendation-lead">
                          {formatLabel(selectedInvestigation.remediation.action_type)}{" "}
                          {selectedInvestigation.remediation.target}
                        </p>
                        <p className="muted">{selectedInvestigation.remediation.rationale}</p>
                        <p className="muted">
                          Risk {formatLabel(
                            selectedInvestigation.remediation.risk_assessment.overall_risk,
                          )}{" "}
                          · reversible{" "}
                          {selectedInvestigation.remediation.risk_assessment.reversible
                            ? "yes"
                            : "no"}
                        </p>
                        {selectedInvestigation.remediation.risk_assessment.checks.length > 0 ? (
                          <ul className="risk-check-list">
                            {selectedInvestigation.remediation.risk_assessment.checks.map(
                              (check) => (
                                <li key={`${check.check}-${check.result}`} className="risk-check">
                                  <span className={`check-result result-${check.result}`}>
                                    {formatLabel(check.result)}
                                  </span>
                                  <div>
                                    <p className="risk-check-title">{check.check}</p>
                                    <p className="muted">{check.detail}</p>
                                  </div>
                                </li>
                              ),
                            )}
                          </ul>
                        ) : null}
                        {selectedInvestigation.remediation.risk_assessment.warnings.length > 0 ? (
                          <ul className="warning-list">
                            {selectedInvestigation.remediation.risk_assessment.warnings.map(
                              (warning) => (
                                <li key={warning}>{warning}</li>
                              ),
                            )}
                          </ul>
                        ) : null}
                      </>
                    ) : (
                      <p className="muted">
                        No restart recommendation is justified from the current evidence.
                      </p>
                    )}
                  </div>
                </div>
              ) : selectedIncident ? (
                <p className="muted">No investigation has been persisted for this incident yet.</p>
              ) : (
                <p className="muted">No incidents are currently persisted.</p>
              )}
            </section>

            <section className="panel incident-panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">Incidents Feed</p>
                  <h2>Active and recent</h2>
                </div>
                <p className="panel-meta">{sortedIncidents.length} tracked</p>
              </div>

              <div className="incident-list">
                {sortedIncidents.length > 0 ? (
                  sortedIncidents.map((incident, index) => (
                    <article
                      key={incident.id}
                      className={`incident-card ${
                        incident.id === selectedIncident?.id ? "selected" : ""
                      }`}
                      style={{ animationDelay: `${index * 70}ms` }}
                      onClick={() => {
                        setSelectedIncidentId(incident.id);
                        setSelectedServiceId(incident.affected_services[0] ?? null);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedIncidentId(incident.id);
                          setSelectedServiceId(incident.affected_services[0] ?? null);
                        }
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <div className="incident-heading">
                        <span className={`severity severity-${incident.severity}`}>
                          {incident.severity}
                        </span>
                        <span className="incident-status">{formatLabel(incident.status)}</span>
                      </div>
                      <h3>{incident.title}</h3>
                      <p className="muted">
                        {incident.affected_services
                          .map((serviceId) => serviceNames.get(serviceId) ?? serviceId)
                          .join(", ") || "No services recorded"}
                      </p>
                      <p className="incident-cause">
                        {incident.triggering_symptom ??
                          incident.suspected_cause ??
                          "No suspected cause recorded yet."}
                      </p>
                    </article>
                  ))
                ) : (
                  <p className="muted">No incidents are currently persisted.</p>
                )}
              </div>
            </section>
          </aside>
        </main>

        <section className="phase-two-grid">
          <section className="panel phase-two-panel" id="finding-review-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Noise Control</p>
                <h2>Finding review</h2>
              </div>
              <p className="panel-meta">
                {activeReviewFindings.length} active · {dismissedReviewFindings.length} dismissed
              </p>
            </div>

            {findingFeedbackMutationState.error ? (
              <p className="message-inline error">{findingFeedbackMutationState.error}</p>
            ) : null}
            {findingFeedbackMutationState.auditChangeId ? (
              <p className="step-meta">
                Last feedback logged in the change timeline as{" "}
                {findingFeedbackMutationState.auditChangeId}.
              </p>
            ) : null}

            {findingReview === null ? (
              <p className="muted">Loading finding feedback state…</p>
            ) : (
              <>
                <div className="timeline-list">
                  {findingSuggestions.length > 0 ? (
                    findingSuggestions.map((suggestion) => (
                      <article
                        className="queue-item finding-feedback-suggestion"
                        key={`${suggestion.service_id}-${suggestion.check_id}`}
                      >
                        <div className="timeline-topline">
                          <span className="chip ghost">{formatLabel(suggestion.action)}</span>
                          <span className="step-meta">
                            {suggestion.dismissal_count} dismissals
                          </span>
                        </div>
                        <p className="timeline-service">
                          {suggestion.service_name} · {suggestion.check_label}
                        </p>
                        <p className="muted">{suggestion.message}</p>
                        <div className="note-action-row">
                          <button
                            className="note-button note-button-ghost"
                            onClick={() => setSelectedServiceId(suggestion.service_id)}
                            type="button"
                          >
                            Focus service
                          </button>
                        </div>
                      </article>
                    ))
                  ) : (
                    <p className="muted">
                      No repeated dismissal patterns currently justify a suppression or threshold
                      recommendation.
                    </p>
                  )}
                </div>

                <div className="detail-grid finding-feedback-grid">
                  <article className="system-profile-card">
                    <p className="timeline-service">Active findings</p>
                    {activeReviewFindings.length > 0 ? (
                      <div className="service-inline-list">
                        {activeReviewFindings.slice(0, 5).map((item) => {
                          const selectedReason =
                            findingFeedbackReasonById[item.finding.id] ?? "false_positive";
                          const dismissing =
                            findingFeedbackMutationState.dismissingFindingId === item.finding.id;
                          return (
                            <article className="service-inline-item" key={item.finding.id}>
                              <div className="timeline-topline">
                                <p className="timeline-service">
                                  {item.service_name} · {item.domain_label}
                                </p>
                                <span className={`severity severity-${item.finding.severity}`}>
                                  {item.finding.severity}
                                </span>
                              </div>
                              <p className="muted service-inline-copy">{item.finding.summary}</p>
                              <p className="step-meta">
                                Created {formatTimestamp(item.finding.created_at)} ·{" "}
                                {item.dismissal_count_for_pattern} prior dismissals for this
                                service/check
                              </p>
                              {item.suggestion ? (
                                <p className="muted service-inline-copy">{item.suggestion.message}</p>
                              ) : null}
                              <div className="finding-feedback-controls">
                                <label className="note-field">
                                  <span className="detail-label">Dismissal reason</span>
                                  <select
                                    onChange={(event) => {
                                      const nextReason = event.target
                                        .value as FindingFeedbackReason;
                                      setFindingFeedbackReasonById((current) => ({
                                        ...current,
                                        [item.finding.id]: nextReason,
                                      }));
                                    }}
                                    value={selectedReason}
                                  >
                                    <option value="false_positive">False positive</option>
                                    <option value="expected_behavior">Expected behavior</option>
                                    <option value="not_important">Not important</option>
                                    <option value="already_aware">Already aware</option>
                                  </select>
                                </label>
                                <div className="note-action-row finding-feedback-action-row">
                                  <button
                                    className="note-button note-button-primary"
                                    disabled={dismissing}
                                    onClick={() => {
                                      void dismissFindingAsNoise(item.finding.id);
                                    }}
                                    type="button"
                                  >
                                    {dismissing ? "Saving…" : "Dismiss as noise"}
                                  </button>
                                </div>
                              </div>
                            </article>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="muted">
                        No active findings currently need operator review on this panel.
                      </p>
                    )}
                  </article>

                  <article className="system-profile-card">
                    <p className="timeline-service">Recently dismissed</p>
                    {dismissedReviewFindings.length > 0 ? (
                      <div className="service-inline-list">
                        {dismissedReviewFindings.slice(0, 5).map((item) => (
                          <article className="service-inline-item" key={item.finding.id}>
                            <div className="timeline-topline">
                              <p className="timeline-service">
                                {item.service_name} · {item.domain_label}
                              </p>
                              <span className="chip ghost">
                                {item.dismissal_reason === null
                                  ? "Dismissed"
                                  : formatLabel(item.dismissal_reason)}
                              </span>
                            </div>
                            <p className="muted service-inline-copy">{item.finding.summary}</p>
                            <p className="step-meta">
                              Dismissed{" "}
                              {item.finding.resolved_at === null
                                ? "recently"
                                : formatTimestamp(item.finding.resolved_at)}
                            </p>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <p className="muted">
                        Dismissed findings will remain reviewable here before any explicit
                        suppression decision is made elsewhere.
                      </p>
                    )}
                  </article>
                </div>
              </>
            )}
          </section>

          <section className="panel phase-two-panel" id="credential-vault-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Noise Control</p>
                <h2>Maintenance mode</h2>
              </div>
              <p className="panel-meta">
                {maintenanceModeDetail?.global_window ? "Global active" : "Scoped only"}
              </p>
            </div>

            {maintenanceModeMutationState.error ? (
              <p className="message-inline error">{maintenanceModeMutationState.error}</p>
            ) : null}
            {maintenanceModeMutationState.auditChangeId ? (
              <p className="step-meta">
                Last maintenance change logged as {maintenanceModeMutationState.auditChangeId}.
              </p>
            ) : null}

            {maintenanceModeState.loading && maintenanceModeDetail === null ? (
              <p className="muted">Loading maintenance state…</p>
            ) : maintenanceModeState.error ? (
              <p className="message-inline error">{maintenanceModeState.error}</p>
            ) : maintenanceModeDetail ? (
              <>
                <div className="detail-grid finding-feedback-grid">
                  <article className="system-profile-card">
                    <p className="timeline-service">Global window</p>
                    {maintenanceModeDetail.global_window ? (
                      <>
                        <p className="muted service-inline-copy">
                          Active until{" "}
                          {formatTimestamp(maintenanceModeDetail.global_window.expires_at)}.
                        </p>
                        <p className="step-meta">
                          {maintenanceModeDetail.global_window.minutes_remaining} minutes remaining
                        </p>
                        <div className="note-action-row finding-feedback-action-row">
                          <button
                            className="note-button note-button-danger"
                            disabled={maintenanceModeMutationState.clearingServiceId === "global"}
                            onClick={() => {
                              void clearGlobalMaintenance();
                            }}
                            type="button"
                          >
                            {maintenanceModeMutationState.clearingServiceId === "global"
                              ? "Clearing…"
                              : "Clear global maintenance"}
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <label className="note-field">
                          <span className="detail-label">Duration minutes</span>
                          <input
                            onChange={(event) => {
                              const value = event.target.value;
                              setMaintenanceModeEditorState((current) => ({
                                ...current,
                                globalDurationMinutes: value,
                              }));
                            }}
                            type="number"
                            value={maintenanceModeEditorState.globalDurationMinutes}
                          />
                        </label>
                        <div className="note-action-row finding-feedback-action-row">
                          <button
                            className="note-button note-button-primary"
                            disabled={maintenanceModeMutationState.savingTarget === "global"}
                            onClick={() => {
                              void enableGlobalMaintenance();
                            }}
                            type="button"
                          >
                            {maintenanceModeMutationState.savingTarget === "global"
                              ? "Saving…"
                              : "Enable global maintenance"}
                          </button>
                        </div>
                      </>
                    )}
                  </article>

                  <article className="system-profile-card">
                    <p className="timeline-service">Per-service window</p>
                    <label className="note-field">
                      <span className="detail-label">Service</span>
                      <select
                        onChange={(event) => {
                          const value = event.target.value;
                          setMaintenanceModeEditorState((current) => ({
                            ...current,
                            serviceId: value,
                          }));
                        }}
                        value={maintenanceModeEditorState.serviceId}
                      >
                        {(state.graph?.services ?? []).map((service) => (
                          <option key={service.id} value={service.id}>
                            {service.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="note-field">
                      <span className="detail-label">Duration minutes</span>
                      <input
                        onChange={(event) => {
                          const value = event.target.value;
                          setMaintenanceModeEditorState((current) => ({
                            ...current,
                            serviceDurationMinutes: value,
                          }));
                        }}
                        type="number"
                        value={maintenanceModeEditorState.serviceDurationMinutes}
                      />
                    </label>
                    <div className="note-action-row finding-feedback-action-row">
                      <button
                        className="note-button note-button-primary"
                        disabled={maintenanceModeMutationState.savingTarget === "service"}
                        onClick={() => {
                          void enableServiceMaintenance();
                        }}
                        type="button"
                      >
                        {maintenanceModeMutationState.savingTarget === "service"
                          ? "Saving…"
                          : "Enable service maintenance"}
                      </button>
                    </div>
                  </article>
                </div>

                <p className="muted service-inline-copy maintenance-guardrail">
                  {maintenanceModeDetail.self_health_guardrail}
                </p>

                <div className="timeline-list">
                  {maintenanceModeDetail.service_windows.length > 0 ? (
                    maintenanceModeDetail.service_windows.map((window) => (
                      <article className="queue-item" key={`${window.scope}-${window.service_id}`}>
                        <div className="timeline-topline">
                          <p className="timeline-service">
                            {window.service_name ?? window.service_id ?? "Global"}
                          </p>
                          <span className="chip ghost">
                            {window.minutes_remaining} minutes left
                          </span>
                        </div>
                        <p className="muted">
                          Active until {formatTimestamp(window.expires_at)}.
                        </p>
                        <div className="note-action-row">
                          <button
                            className="note-button note-button-ghost"
                            onClick={() => {
                              if (window.service_id !== null) {
                                setSelectedServiceId(window.service_id);
                              }
                            }}
                            type="button"
                          >
                            Focus service
                          </button>
                          <button
                            className="note-button note-button-danger"
                            disabled={
                              maintenanceModeMutationState.clearingServiceId === window.service_id
                            }
                            onClick={() => {
                              if (window.service_id !== null) {
                                void clearServiceMaintenance(window.service_id);
                              }
                            }}
                            type="button"
                          >
                            {maintenanceModeMutationState.clearingServiceId === window.service_id
                              ? "Clearing…"
                              : "Clear window"}
                          </button>
                        </div>
                      </article>
                    ))
                  ) : (
                    <p className="muted">
                      No per-service maintenance windows are currently active.
                    </p>
                  )}
                </div>
              </>
            ) : (
              <p className="muted">Maintenance state is currently unavailable.</p>
            )}
          </section>

          <section className="panel phase-two-panel" id="model-usage-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">AI Usage</p>
                <h2>Model usage and cost</h2>
              </div>
              <p className="panel-meta">
                {modelUsageDashboard.telemetryBackedInvestigationCount > 0
                  ? `${modelUsageDashboard.telemetryBackedInvestigationCount} telemetry-backed`
                  : "No data yet"}
              </p>
            </div>

            <div className="queue-section">
              <p className="muted">
                Totals come only from persisted per-investigation telemetry. Older
                investigations without token or cost fields stay out of the dashboard, and
                budget status uses the active model-settings cloud call caps.
              </p>
            </div>

            {modelUsageDashboard.telemetryBackedInvestigationCount > 0 ? (
              <>
                <div className="detail-grid usage-summary-grid">
                  {modelUsageDashboard.windows.map((window) => (
                    <article
                      key={window.key}
                      className="system-profile-card usage-summary-card"
                    >
                      <div className="timeline-topline">
                        <p className="timeline-service">{window.label}</p>
                        <span className="chip ghost">
                          {window.investigationCount} investigations
                        </span>
                      </div>
                      <ul className="system-profile-list compact">
                        <li>
                          <span>Local calls</span>
                          <strong>{formatCount(window.localModelCalls)}</strong>
                        </li>
                        <li>
                          <span>Cloud calls</span>
                          <strong>{formatCount(window.cloudModelCalls)}</strong>
                        </li>
                        <li>
                          <span>Local tokens</span>
                          <strong>
                            {formatCount(window.localInputTokens + window.localOutputTokens)}
                          </strong>
                        </li>
                        <li>
                          <span>Cloud tokens</span>
                          <strong>
                            {formatCount(window.cloudInputTokens + window.cloudOutputTokens)}
                          </strong>
                        </li>
                        <li>
                          <span>Estimated cloud cost</span>
                          <strong>{formatUsd(window.estimatedCloudCostUsd)}</strong>
                        </li>
                        <li>
                          <span>Estimated total cost</span>
                          <strong>{formatUsd(window.estimatedTotalCostUsd)}</strong>
                        </li>
                      </ul>
                    </article>
                  ))}
                </div>

                {cloudCostEstimateGap ? (
                  <p className="message-inline warning">
                    Cloud usage was recorded, but cost estimation is unavailable for the
                    current openai-compatible provider catalog in Phase 3C. Token usage and
                    call counts remain authoritative.
                  </p>
                ) : null}

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Budget status</p>
                      <span
                        className={`chip ${
                          modelSettingsDetail?.active.escalation.max_cloud_calls_per_day &&
                          todayModelUsageWindow !== null &&
                          todayModelUsageWindow.cloudModelCalls >=
                            modelSettingsDetail.active.escalation.max_cloud_calls_per_day
                            ? "warning"
                            : "ghost"
                        }`}
                      >
                        {todayModelUsageWindow === null ||
                        modelSettingsDetail === null ||
                        todayModelUsageWindow.cloudModelCalls <
                          modelSettingsDetail.active.escalation.max_cloud_calls_per_day
                          ? "Within cap"
                          : "Daily cap reached"}
                      </span>
                    </div>
                    {modelSettingsDetail ? (
                      <ul className="system-profile-list compact">
                        <li>
                          <span>Today cloud calls</span>
                          <strong>{formatCount(todayModelUsageWindow?.cloudModelCalls ?? 0)}</strong>
                        </li>
                        <li>
                          <span>Daily cloud cap</span>
                          <strong>
                            {formatCount(
                              modelSettingsDetail.active.escalation.max_cloud_calls_per_day,
                            )}
                          </strong>
                        </li>
                        <li>
                          <span>Remaining today</span>
                          <strong>
                            {formatCount(
                              Math.max(
                                modelSettingsDetail.active.escalation.max_cloud_calls_per_day -
                                  (todayModelUsageWindow?.cloudModelCalls ?? 0),
                                0,
                              ),
                            )}
                          </strong>
                        </li>
                        <li>
                          <span>Per-incident cap</span>
                          <strong>
                            {formatCount(
                              modelSettingsDetail.active.escalation.max_cloud_calls_per_incident,
                            )}
                          </strong>
                        </li>
                        <li>
                          <span>Highest incident usage</span>
                          <strong>{formatCount(maxIncidentCloudCallsUsed)}</strong>
                        </li>
                        <li>
                          <span>Spend today</span>
                          <strong>
                            {formatUsd(todayModelUsageWindow?.estimatedCloudCostUsd ?? 0)}
                          </strong>
                        </li>
                      </ul>
                    ) : (
                      <p className="muted">
                        Model settings are unavailable, so call-budget status cannot be
                        rendered yet.
                      </p>
                    )}
                    {incidentsAtCloudCallBudget.length > 0 ? (
                      <p className="muted">
                        {incidentsAtCloudCallBudget.length} incident
                        {incidentsAtCloudCallBudget.length === 1 ? "" : "s"} at the
                        per-incident cloud cap.
                      </p>
                    ) : null}
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Escalation analysis</p>
                      <span className="chip ghost">
                        {modelUsageDashboard.escalations.length} reason
                        {modelUsageDashboard.escalations.length === 1 ? "" : "s"}
                      </span>
                    </div>
                    {modelUsageDashboard.escalations.length > 0 ? (
                      <ul className="system-profile-list compact usage-reason-list">
                        {modelUsageDashboard.escalations.map((entry) => (
                          <li key={entry.reason}>
                            <span>{entry.label}</span>
                            <strong>
                              {formatCount(entry.matchedInvestigations)} matched ·{" "}
                              {formatCount(entry.executedInvestigations)} executed
                            </strong>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="muted">
                        No persisted cloud-escalation triggers have been recorded yet.
                      </p>
                    )}
                  </article>
                </div>

                <div className="queue-section">
                  <div className="memory-section-header">
                    <div>
                      <p className="detail-label">Per-incident breakdown</p>
                      <p className="muted">
                        Incident rows aggregate all telemetry-backed investigations tied to the
                        same incident.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="timeline-list">
                  {modelUsageDashboard.incidents.map((entry) => (
                    <article key={entry.incidentId} className="timeline-item">
                      <div className="timeline-topline">
                        <div className="action-strip">
                          <span className={`severity severity-${entry.severity}`}>
                            {entry.severity}
                          </span>
                          <span className="chip ghost">{formatLabel(entry.status)}</span>
                          <span className="chip ghost">
                            {entry.investigationCount} investigations
                          </span>
                        </div>
                        <span className="step-meta">
                          {entry.latestInvestigationAt
                            ? formatTimestamp(entry.latestInvestigationAt)
                            : "No completion time"}
                        </span>
                      </div>
                      <p className="timeline-service">{entry.incidentTitle}</p>
                      <div className="detail-grid usage-breakdown-grid">
                        <div>
                          <p className="detail-label">Calls</p>
                          <p className="muted">
                            Local {formatCount(entry.localModelCalls)} · Cloud{" "}
                            {formatCount(entry.cloudModelCalls)}
                          </p>
                        </div>
                        <div>
                          <p className="detail-label">Tokens</p>
                          <p className="muted">
                            Local{" "}
                            {formatCount(
                              entry.localInputTokens + entry.localOutputTokens,
                            )}{" "}
                            · Cloud{" "}
                            {formatCount(
                              entry.cloudInputTokens + entry.cloudOutputTokens,
                            )}
                          </p>
                        </div>
                        <div>
                          <p className="detail-label">Estimated cost</p>
                          <p className="muted">
                            Cloud {formatUsd(entry.estimatedCloudCostUsd)} · Total{" "}
                            {formatUsd(entry.estimatedTotalCostUsd)}
                          </p>
                        </div>
                        <div>
                          <p className="detail-label">Escalation triggers</p>
                          {entry.cloudEscalationReasons.length > 0 ? (
                            <ul className="chip-list">
                              {entry.cloudEscalationReasons.map((reason) => (
                                <li key={`${entry.incidentId}-${reason}`}>
                                  <span className="chip ghost">
                                    {formatCloudEscalationReason(reason)}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="muted">No cloud escalation was recorded.</p>
                          )}
                        </div>
                      </div>
                      <div className="note-action-row">
                        <button
                          className="note-button note-button-ghost"
                          type="button"
                          onClick={() => {
                            setSelectedIncidentId(entry.incidentId);
                            scrollToPanel("investigation-detail-panel");
                          }}
                        >
                          Open incident
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              </>
            ) : (
              <p className="muted">
                No telemetry-backed investigations have been persisted yet. New
                investigations created after P3C-25 will populate today, week, month, and
                per-incident usage totals here.
              </p>
            )}
          </section>

          <section className="panel phase-two-panel" id="audit-trail-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Audit Trail</p>
                <h2>Chronological event stream</h2>
              </div>
              <p className="panel-meta">
                {filteredAuditTrailEntries.length} shown · {auditTrailEntries.length} retained
              </p>
            </div>

            <div className="queue-section">
              <p className="muted">
                Operator-visible history across graph edits, descriptor workflow, settings,
                vault changes, maintenance windows, and finding-noise controls. The active
                policy keeps {activeAuditDetailRetentionDays} days of detailed values and{" "}
                {activeAuditSummaryRetentionDays} days of summary visibility.
              </p>
            </div>

            <div className="note-editor-grid audit-filter-grid">
              <label className="note-field">
                <span className="detail-label">Type</span>
                <select
                  value={auditTrailFilters.type}
                  onChange={(event) => {
                    setAuditTrailFilters((current) => ({
                      ...current,
                      type: event.target.value as AuditTrailFilterState["type"],
                    }));
                  }}
                >
                  <option value="all">All event types</option>
                  {auditTypeOptions.map((option) => (
                    <option key={option} value={option}>
                      {formatLabel(option)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="note-field">
                <span className="detail-label">Service</span>
                <select
                  value={auditTrailFilters.serviceId}
                  onChange={(event) => {
                    setAuditTrailFilters((current) => ({
                      ...current,
                      serviceId: event.target.value,
                    }));
                  }}
                >
                  <option value="all">All services</option>
                  <option value={GLOBAL_AUDIT_SERVICE_FILTER}>Global only</option>
                  {services.map((service) => (
                    <option key={service.id} value={service.id}>
                      {service.name}
                    </option>
                  ))}
                </select>
              </label>

              <label className="note-field">
                <span className="detail-label">Date from</span>
                <input
                  type="date"
                  value={auditTrailFilters.dateFrom}
                  onChange={(event) => {
                    setAuditTrailFilters((current) => ({
                      ...current,
                      dateFrom: event.target.value,
                    }));
                  }}
                />
              </label>

              <label className="note-field">
                <span className="detail-label">Date to</span>
                <input
                  type="date"
                  value={auditTrailFilters.dateTo}
                  onChange={(event) => {
                    setAuditTrailFilters((current) => ({
                      ...current,
                      dateTo: event.target.value,
                    }));
                  }}
                />
              </label>
            </div>

            <div className="note-action-row">
              <button
                className="note-button note-button-primary"
                type="button"
                onClick={() => {
                  exportAuditTrailEntries(filteredAuditTrailEntries, "json");
                }}
              >
                Export JSON
              </button>
              <button
                className="note-button note-button-ghost"
                type="button"
                onClick={() => {
                  exportAuditTrailEntries(filteredAuditTrailEntries, "csv");
                }}
              >
                Export CSV
              </button>
              <button
                className="note-button note-button-ghost"
                type="button"
                onClick={() => {
                  setAuditTrailFilters({
                    type: "all",
                    serviceId: "all",
                    dateFrom: "",
                    dateTo: "",
                  });
                }}
              >
                Clear filters
              </button>
              <button
                className="note-button note-button-ghost"
                type="button"
                onClick={() => {
                  scrollToPanel("system-settings-panel");
                }}
              >
                Manage retention
              </button>
            </div>

            <div className="system-profile-grid audit-retention-grid">
              <article className="system-profile-card">
                <div className="timeline-topline">
                  <p className="timeline-service">Active retention</p>
                  <span className="chip ghost">In effect</span>
                </div>
                <ul className="system-profile-list compact">
                  <li>
                    <span>Detailed values</span>
                    <strong>{activeAuditDetailRetentionDays} days</strong>
                  </li>
                  <li>
                    <span>Summary events</span>
                    <strong>{activeAuditSummaryRetentionDays} days</strong>
                  </li>
                </ul>
              </article>

              <article className="system-profile-card">
                <div className="timeline-topline">
                  <p className="timeline-service">Staged retention</p>
                  <span className={`chip ${systemSettingsDetail?.apply_required ? "warning" : "ghost"}`}>
                    {systemSettingsDetail?.apply_required ? "Apply pending" : "Aligned"}
                  </span>
                </div>
                <ul className="system-profile-list compact">
                  <li>
                    <span>Detailed values</span>
                    <strong>{stagedAuditDetailRetentionDays} days</strong>
                  </li>
                  <li>
                    <span>Summary events</span>
                    <strong>{stagedAuditSummaryRetentionDays} days</strong>
                  </li>
                </ul>
              </article>
            </div>

            <div className="timeline-list">
              {filteredAuditTrailEntries.length > 0 ? (
                filteredAuditTrailEntries.map((entry) => (
                  <article
                    key={entry.change.id}
                    className={`timeline-item ${
                      highlightedChangeIds.has(entry.change.id) ? "highlighted" : ""
                    }`}
                  >
                    <div className="timeline-topline">
                      <div className="action-strip audit-chip-strip">
                        <span className="chip">{formatLabel(entry.auditType)}</span>
                        <span className="chip ghost">{formatLabel(entry.change.type)}</span>
                        <span className="chip ghost">
                          {entry.detailAvailable ? "Detailed" : "Summary only"}
                        </span>
                      </div>
                      <span className="step-meta">{formatTimestamp(entry.change.timestamp)}</span>
                    </div>
                    <p className="timeline-service">{entry.change.description}</p>
                    <div className="detail-grid audit-event-grid">
                      <div>
                        <p className="detail-label">Target</p>
                        <p className="muted">{entry.targetLabel}</p>
                      </div>
                      <div>
                        <p className="detail-label">Trigger</p>
                        <p className="muted">{auditEventTriggerSummary(entry.change)}</p>
                      </div>
                      <div>
                        <p className="detail-label">Result</p>
                        <p className={entry.detailAvailable ? "audit-value" : "muted"}>
                          {entry.detailAvailable
                            ? auditEventResultSummary(entry.change)
                            : `Summary retained under the active ${activeAuditSummaryRetentionDays}-day policy.`}
                        </p>
                      </div>
                      <div>
                        <p className="detail-label">Links</p>
                        {entry.change.correlated_incidents.length > 0 ||
                        entry.linkedInvestigationIds.length > 0 ? (
                          <ul className="chip-list">
                            {entry.change.correlated_incidents.map((incidentId) => (
                              <li key={`${entry.change.id}-${incidentId}`}>
                                <span className="chip ghost">Incident {incidentId}</span>
                              </li>
                            ))}
                            {entry.linkedInvestigationIds.map((investigationId) => (
                              <li key={`${entry.change.id}-${investigationId}`}>
                                <span className="chip ghost">
                                  Investigation {investigationId}
                                </span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="muted">No related incident or investigation is linked.</p>
                        )}
                      </div>
                      {entry.detailAvailable && entry.change.old_value ? (
                        <div className="detail-block">
                          <p className="detail-label">Prior value</p>
                          <p className="audit-value">{entry.change.old_value}</p>
                        </div>
                      ) : null}
                      {entry.detailAvailable && entry.change.new_value ? (
                        <div className="detail-block">
                          <p className="detail-label">Current value</p>
                          <p className="audit-value">{entry.change.new_value}</p>
                        </div>
                      ) : null}
                    </div>

                    <div className="note-action-row">
                      {entry.change.service_id ? (
                        <button
                          className="note-button note-button-ghost"
                          type="button"
                          onClick={() => {
                            setSelectedServiceId(entry.change.service_id);
                            scrollToPanel("service-detail-panel");
                          }}
                        >
                          Open service
                        </button>
                      ) : null}
                      {entry.change.correlated_incidents.map((incidentId) => (
                        <button
                          className="note-button note-button-ghost"
                          key={`${entry.change.id}-${incidentId}-incident`}
                          type="button"
                          onClick={() => {
                            openAuditIncident(incidentId, entry.change.service_id);
                          }}
                        >
                          Open incident {incidentId}
                        </button>
                      ))}
                      {entry.linkedInvestigationIds.map((investigationId, index) => (
                        <button
                          className="note-button note-button-ghost"
                          key={`${entry.change.id}-${investigationId}-investigation`}
                          type="button"
                          onClick={() => {
                            openAuditIncident(
                              entry.change.correlated_incidents[index] ?? entry.change.correlated_incidents[0],
                              entry.change.service_id,
                            );
                          }}
                        >
                          Open investigation {investigationId}
                        </button>
                      ))}
                    </div>
                  </article>
                ))
              ) : (
                <p className="muted">
                  No audit events match the current type, service, and date filters.
                </p>
              )}
            </div>
          </section>

            <section className="panel phase-two-panel" id="system-settings-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Settings</p>
                <h2>Credential vault</h2>
              </div>
              <p className="panel-meta">
                {credentialVaultState.loading && credentialVaultDetail === null
                  ? "Refreshing…"
                  : credentialVaultDetail?.status.unlocked
                    ? "Unlocked"
                    : credentialVaultDetail?.status.initialized
                      ? "Locked"
                      : "Not initialized"}
              </p>
            </div>

            {credentialVaultState.loading && credentialVaultDetail === null ? (
              <p className="muted">Loading credential vault status…</p>
            ) : credentialVaultState.error ? (
              <p className="message-inline error">{credentialVaultState.error}</p>
            ) : credentialVaultDetail ? (
              <>
                <div className="action-strip">
                  <span className="action-pill">
                    {credentialVaultDetail.status.stored_credentials} stored
                  </span>
                  <span className="action-pill">
                    Auto-lock {credentialVaultDetail.auto_lock_minutes} min
                  </span>
                  <span className="action-pill">
                    {credentialVaultDetail.status.unlocked
                      ? credentialVaultDetail.status.unlock_expires_at
                        ? `Unlocked until ${formatTimestamp(
                            credentialVaultDetail.status.unlock_expires_at,
                          )}`
                        : "Unlocked"
                      : "Locked"}
                  </span>
                </div>

                <div className="queue-section">
                  <p className="muted">
                    Stored credentials are listed by service and label only. Secret values never
                    leave the vault, and the explicit test flow only verifies that Kaval can still
                    decrypt the stored entries with the current master key.
                  </p>
                </div>

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Vault state</p>
                      <span className="chip ghost">
                        {credentialVaultDetail.status.initialized ? "Initialized" : "Bootstrap pending"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Lock state</span>
                        <strong>
                          {credentialVaultDetail.status.unlocked ? "Unlocked" : "Locked"}
                        </strong>
                      </li>
                      <li>
                        <span>Stored credentials</span>
                        <strong>{credentialVaultDetail.status.stored_credentials}</strong>
                      </li>
                      <li>
                        <span>Unlock expires</span>
                        <strong>
                          {credentialVaultDetail.status.unlock_expires_at
                            ? formatTimestamp(credentialVaultDetail.status.unlock_expires_at)
                            : "Not unlocked"}
                        </strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Credential coverage</p>
                      <span className="chip ghost">
                        {
                          credentialVaultDetail.credentials.filter(
                            (credential) => credential.last_tested_at === null,
                          ).length
                        }{" "}
                        never tested
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Settings-managed</span>
                        <strong>
                          {
                            credentialVaultDetail.credentials.filter(
                              (credential) => credential.source === "managed_setting",
                            ).length
                          }
                        </strong>
                      </li>
                      <li>
                        <span>Investigation requests</span>
                        <strong>
                          {
                            credentialVaultDetail.credentials.filter(
                              (credential) => credential.source === "credential_request",
                            ).length
                          }
                        </strong>
                      </li>
                      <li>
                        <span>Recently used</span>
                        <strong>
                          {
                            credentialVaultDetail.credentials.filter(
                              (credential) => credential.last_used_at !== null,
                            ).length
                          }
                        </strong>
                      </li>
                    </ul>
                  </article>
                </div>

                <div className="queue-section">
                  <div className="memory-section-header">
                    <div>
                      <p className="detail-label">Stored credentials</p>
                      <p className="muted">
                        These entries show only metadata needed for safe admin review.
                      </p>
                    </div>
                    <button
                      className="note-button note-button-ghost"
                      disabled={credentialVaultState.loading}
                      type="button"
                      onClick={() => {
                        void loadCredentialVault();
                      }}
                    >
                      Refresh
                    </button>
                  </div>

                  {credentialVaultDetail.credentials.length === 0 ? (
                    <p className="muted">No credentials are currently stored in the vault.</p>
                  ) : (
                    <div className="vault-credential-list">
                      {credentialVaultDetail.credentials.map((credential) => (
                        <article
                          className="vault-credential-card"
                          key={credential.reference_id}
                        >
                          <div className="timeline-topline">
                            <p className="timeline-service">{credential.service_name}</p>
                            <span className="chip ghost">
                              {formatLabel(credential.source)}
                            </span>
                          </div>
                          <p className="muted">{credential.credential_description}</p>
                          <ul className="system-profile-list compact">
                            <li>
                              <span>Stored</span>
                              <strong>{formatTimestamp(credential.created_at)}</strong>
                            </li>
                            <li>
                              <span>Updated</span>
                              <strong>{formatTimestamp(credential.updated_at)}</strong>
                            </li>
                            <li>
                              <span>Last used</span>
                              <strong>
                                {credential.last_used_at
                                  ? formatTimestamp(credential.last_used_at)
                                  : "Not yet used"}
                              </strong>
                            </li>
                            <li>
                              <span>Last tested</span>
                              <strong>
                                {credential.last_tested_at
                                  ? formatTimestamp(credential.last_tested_at)
                                  : "Never tested"}
                              </strong>
                            </li>
                            <li>
                              <span>Expiry</span>
                              <strong>
                                {credential.expires_at
                                  ? formatTimestamp(credential.expires_at)
                                  : "Not tracked"}
                              </strong>
                            </li>
                          </ul>
                        </article>
                      ))}
                    </div>
                  )}
                </div>

                <form
                  className="note-editor model-settings-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void changeCredentialVaultPassword();
                  }}
                >
                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Access control</p>
                        <p className="muted">
                          Unlocking never returns stored values. Locking clears the in-memory key
                          immediately.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid vault-access-grid">
                      <label className="note-field note-field-wide">
                        <span className="detail-label">
                          {credentialVaultDetail.status.initialized
                            ? "Master passphrase"
                            : "New master passphrase"}
                        </span>
                        <input
                          type="password"
                          value={credentialVaultEditorState.unlockPassphrase}
                          onChange={(event) => {
                            updateCredentialVaultEditor((current) => ({
                              ...current,
                              unlockPassphrase: event.target.value,
                            }));
                          }}
                          placeholder={
                            credentialVaultDetail.status.initialized
                              ? "Enter passphrase to unlock"
                              : "Enter passphrase to initialize the vault"
                          }
                        />
                      </label>
                    </div>
                    <div className="note-action-row">
                      <button
                        className="note-button note-button-primary"
                        disabled={credentialVaultMutationState.unlocking}
                        type="button"
                        onClick={() => {
                          void unlockCredentialVault();
                        }}
                      >
                        {credentialVaultMutationState.unlocking
                          ? "Unlocking…"
                          : credentialVaultDetail.status.initialized
                            ? "Unlock vault"
                            : "Initialize and unlock"}
                      </button>
                      <button
                        className="note-button note-button-ghost"
                        disabled={
                          credentialVaultMutationState.locking ||
                          !credentialVaultDetail.status.unlocked
                        }
                        type="button"
                        onClick={() => {
                          void lockCredentialVault();
                        }}
                      >
                        {credentialVaultMutationState.locking ? "Locking…" : "Lock vault"}
                      </button>
                      <button
                        className="note-button note-button-ghost"
                        disabled={
                          credentialVaultMutationState.testing ||
                          !credentialVaultDetail.status.unlocked ||
                          credentialVaultDetail.status.stored_credentials === 0
                        }
                        type="button"
                        onClick={() => {
                          void testCredentialVault();
                        }}
                      >
                        {credentialVaultMutationState.testing
                          ? "Testing…"
                          : "Test all credentials"}
                      </button>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Rotate master passphrase</p>
                        <p className="muted">
                          This re-encrypts stored credentials in place and keeps the vault unlocked
                          on success.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid vault-password-grid">
                      <label className="note-field">
                        <span className="detail-label">Current passphrase</span>
                        <input
                          type="password"
                          value={credentialVaultEditorState.currentPassphrase}
                          onChange={(event) => {
                            updateCredentialVaultEditor((current) => ({
                              ...current,
                              currentPassphrase: event.target.value,
                            }));
                          }}
                          placeholder="Current master passphrase"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">New passphrase</span>
                        <input
                          type="password"
                          value={credentialVaultEditorState.newPassphrase}
                          onChange={(event) => {
                            updateCredentialVaultEditor((current) => ({
                              ...current,
                              newPassphrase: event.target.value,
                            }));
                          }}
                          placeholder="New master passphrase"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Confirm new passphrase</span>
                        <input
                          type="password"
                          value={credentialVaultEditorState.confirmNewPassphrase}
                          onChange={(event) => {
                            updateCredentialVaultEditor((current) => ({
                              ...current,
                              confirmNewPassphrase: event.target.value,
                            }));
                          }}
                          placeholder="Repeat the new passphrase"
                        />
                      </label>
                    </div>
                  </div>

                  {credentialVaultMutationState.testResult ? (
                    <div className="queue-section">
                      <p
                        className={`message-inline ${
                          credentialVaultMutationState.testResult.ok ? "" : "error"
                        }`}
                      >
                        Tested {credentialVaultMutationState.testResult.readable_credentials}/
                        {credentialVaultMutationState.testResult.tested_credentials} stored
                        credentials at{" "}
                        {formatTimestamp(credentialVaultMutationState.testResult.checked_at)}:{" "}
                        {credentialVaultMutationState.testResult.message}
                      </p>
                      {credentialVaultMutationState.testResult.results.length > 0 ? (
                        <div className="vault-test-result-list">
                          {credentialVaultMutationState.testResult.results.map((result) => (
                            <article
                              className="queue-item"
                              key={`${result.reference_id}:${result.checked_at}`}
                            >
                              <div className="timeline-topline">
                                <span className={`chip ${result.ok ? "ghost" : "warning"}`}>
                                  {result.ok ? "Readable" : "Unreadable"}
                                </span>
                                <span className="step-meta">
                                  {formatTimestamp(result.checked_at)}
                                </span>
                              </div>
                              <p className="timeline-service">{result.service_name}</p>
                              <p className="muted">
                                {result.credential_description}: {result.message}
                              </p>
                            </article>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ) : null}

                  <div className="note-action-row">
                    {credentialVaultMutationState.error ? (
                      <p className="note-error">{credentialVaultMutationState.error}</p>
                    ) : null}
                    <button
                      className="note-button note-button-primary"
                      disabled={
                        credentialVaultMutationState.changingPassword ||
                        !credentialVaultDetail.status.initialized
                      }
                      type="submit"
                    >
                      {credentialVaultMutationState.changingPassword
                        ? "Changing…"
                        : "Change master passphrase"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={credentialVaultState.loading}
                      type="button"
                      onClick={() => {
                        void loadCredentialVault();
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                  {credentialVaultMutationState.auditChangeId ? (
                    <p className="step-meta model-settings-audit">
                      Logged in the change timeline as{" "}
                      {credentialVaultMutationState.auditChangeId}.
                    </p>
                  ) : null}
                </form>
              </>
            ) : (
              <p className="muted">Credential vault management is not available yet.</p>
            )}
          </section>

          <section className="panel phase-two-panel" id="model-configuration-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Approval Queue</p>
                <h2>Pending decisions</h2>
              </div>
              <p className="panel-meta">
                {approvalIncidents.length + pendingCredentialRequests.length} waiting
              </p>
            </div>

            <div className="queue-section">
              <p className="detail-label">Remediation approvals</p>
              {approvalIncidents.length > 0 ? (
                <div className="queue-list">
                  {approvalIncidents.map((incident) => {
                    const investigation = investigationByIncidentId.get(incident.id) ?? null;
                    return (
                      <article key={incident.id} className="queue-item">
                        <div className="timeline-topline">
                          <span className={`severity severity-${incident.severity}`}>
                            {incident.severity}
                          </span>
                          <span className="incident-status">{formatLabel(incident.status)}</span>
                        </div>
                        <p className="timeline-service">{incident.title}</p>
                        <p className="muted">
                          {investigation?.remediation
                            ? `${formatLabel(investigation.remediation.action_type)} ${
                                investigation.remediation.target
                              }`
                            : "No remediation detail persisted."}
                        </p>
                      </article>
                    );
                  })}
                </div>
              ) : (
                <p className="muted">No remediation approvals are currently waiting.</p>
              )}
            </div>

            <div className="queue-section">
              <p className="detail-label">Credential requests</p>
              {pendingCredentialRequests.length > 0 ? (
                <div className="queue-list">
                  {pendingCredentialRequests.map((request) => (
                    <article key={request.id} className="queue-item">
                      <div className="timeline-topline">
                        <span className="chip ghost">{formatLabel(request.status)}</span>
                        <span className="step-meta">{formatTimestamp(request.requested_at)}</span>
                      </div>
                      <p className="timeline-service">{request.service_name}</p>
                      <p className="muted">{request.credential_description}</p>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="muted">No credential requests are currently waiting.</p>
              )}
            </div>
          </section>

          <section className="panel phase-two-panel" id="model-configuration-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Settings</p>
                <h2>Model configuration</h2>
              </div>
              <p className="panel-meta">
                {modelSettingsState.loading && modelSettingsDetail === null
                  ? "Refreshing…"
                  : modelSettingsDetail?.apply_required
                    ? "Apply pending"
                    : "Runtime current"}
              </p>
            </div>

            {modelSettingsState.loading && modelSettingsDetail === null ? (
              <p className="muted">Loading model settings…</p>
            ) : modelSettingsState.error ? (
              <p className="message-inline error">{modelSettingsState.error}</p>
            ) : modelSettingsDetail && modelSettingsEditorState ? (
              <>
                <div className="action-strip">
                  <span className="action-pill">
                    Persisted {modelSettingsDetail.config_path}
                  </span>
                  <span className="action-pill">
                    {modelSettingsDetail.apply_required ? "Staged changes pending" : "Active and staged aligned"}
                  </span>
                  <span className="action-pill">
                    Testing uses {formatLabel(modelSettingsTestScope)}
                  </span>
                </div>

                <div className="queue-section">
                  <p className="muted">
                    Non-secret settings persist in `kaval.yaml`. API keys stay in the vault or
                    env bootstrap, and Core only switches runtime behavior after an explicit apply.
                  </p>
                  {modelSettingsDetail.load_error ? (
                    <p className="message-inline error">{modelSettingsDetail.load_error}</p>
                  ) : null}
                </div>

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Active runtime</p>
                      <span className="chip ghost">
                        {modelSettingsDetail.last_applied_at
                          ? `Applied ${formatTimestamp(modelSettingsDetail.last_applied_at)}`
                          : "Not yet applied"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Local model</span>
                        <strong>
                          {modelSettingsDetail.active.local.configured
                            ? `${modelSettingsDetail.active.local.model} · ${modelSettingsDetail.active.local.base_url}`
                            : "Not configured"}
                        </strong>
                      </li>
                      <li>
                        <span>Cloud model</span>
                        <strong>
                          {modelSettingsDetail.active.cloud.configured
                            ? `${formatLabel(modelSettingsDetail.active.cloud.provider)} · ${modelSettingsDetail.active.cloud.model}`
                            : "Not configured"}
                        </strong>
                      </li>
                      <li>
                        <span>Cloud budget</span>
                        <strong>
                          {modelSettingsDetail.active.escalation.max_cloud_calls_per_day}/day ·{" "}
                          {modelSettingsDetail.active.escalation.max_cloud_calls_per_incident}
                          /incident
                        </strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Staged config</p>
                      <span className="chip ghost">
                        Local key {formatLabel(modelSettingsDetail.staged.local.api_key_source)}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Local model</span>
                        <strong>
                          {modelSettingsDetail.staged.local.configured
                            ? `${modelSettingsDetail.staged.local.model} · ${modelSettingsDetail.staged.local.base_url}`
                            : "Not configured"}
                        </strong>
                      </li>
                      <li>
                        <span>Cloud model</span>
                        <strong>
                          {modelSettingsDetail.staged.cloud.configured
                            ? `${formatLabel(modelSettingsDetail.staged.cloud.provider)} · ${modelSettingsDetail.staged.cloud.model}`
                            : "Not configured"}
                        </strong>
                      </li>
                      <li>
                        <span>Cloud key source</span>
                        <strong>{formatLabel(modelSettingsDetail.staged.cloud.api_key_source)}</strong>
                      </li>
                    </ul>
                  </article>
                </div>

                <form
                  className="note-editor model-settings-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveModelSettings();
                  }}
                >
                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Local model</p>
                        <p className="muted">
                          OpenAI-compatible endpoint used for local investigation and descriptor
                          generation.
                        </p>
                      </div>
                      <span className="chip ghost">
                        {modelSettingsDetail.staged.local.api_key_configured
                          ? `Key ${formatLabel(modelSettingsDetail.staged.local.api_key_source)}`
                          : "No key configured"}
                      </span>
                    </div>
                    <div className="note-editor-grid">
                      <div className="note-toggle-row note-field-wide">
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.localEnabled}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                localEnabled: event.target.checked,
                              }));
                            }}
                          />
                          <span>Enable local model</span>
                        </label>
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.clearLocalStoredApiKey}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                clearLocalStoredApiKey: event.target.checked,
                                localApiKey: event.target.checked ? "" : current.localApiKey,
                              }));
                            }}
                          />
                          <span>Clear stored local key</span>
                        </label>
                      </div>
                      <label className="note-field">
                        <span className="detail-label">Model</span>
                        <input
                          type="text"
                          value={modelSettingsEditorState.localModel}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              localModel: event.target.value,
                            }));
                          }}
                          placeholder="qwen3:14b"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Base URL</span>
                        <input
                          type="url"
                          value={modelSettingsEditorState.localBaseUrl}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              localBaseUrl: event.target.value,
                            }));
                          }}
                          placeholder="http://localhost:11434"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Timeout Seconds</span>
                        <input
                          type="number"
                          min="1"
                          step="0.5"
                          value={modelSettingsEditorState.localTimeoutSeconds}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              localTimeoutSeconds: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">New API Key</span>
                        <input
                          type="password"
                          value={modelSettingsEditorState.localApiKey}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              localApiKey: event.target.value,
                              clearLocalStoredApiKey: false,
                            }));
                          }}
                          placeholder="Leave blank to keep the current source"
                        />
                      </label>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Cloud model</p>
                        <p className="muted">
                          Optional escalation path for complex incidents and bounded cloud usage.
                        </p>
                      </div>
                      <span className="chip ghost">
                        {modelSettingsDetail.staged.cloud.api_key_configured
                          ? `Key ${formatLabel(modelSettingsDetail.staged.cloud.api_key_source)}`
                          : "No key configured"}
                      </span>
                    </div>
                    <div className="note-editor-grid">
                      <div className="note-toggle-row note-field-wide">
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.cloudEnabled}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                cloudEnabled: event.target.checked,
                              }));
                            }}
                          />
                          <span>Enable cloud model</span>
                        </label>
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.clearCloudStoredApiKey}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                clearCloudStoredApiKey: event.target.checked,
                                cloudApiKey: event.target.checked ? "" : current.cloudApiKey,
                              }));
                            }}
                          />
                          <span>Clear stored cloud key</span>
                        </label>
                      </div>
                      <label className="note-field">
                        <span className="detail-label">Provider</span>
                        <select
                          value={modelSettingsEditorState.cloudProvider}
                          onChange={(event) => {
                            const provider = event.target.value as
                              | "anthropic"
                              | "openai"
                              | "openai_compatible";
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudProvider: provider,
                              cloudBaseUrl:
                                provider === "anthropic"
                                  ? "https://api.anthropic.com"
                                  : provider === "openai"
                                    ? "https://api.openai.com"
                                    : current.cloudBaseUrl,
                            }));
                          }}
                        >
                          <option value="anthropic">Anthropic</option>
                          <option value="openai">OpenAI</option>
                          <option value="openai_compatible">OpenAI Compatible</option>
                        </select>
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Model</span>
                        <input
                          type="text"
                          value={modelSettingsEditorState.cloudModel}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudModel: event.target.value,
                            }));
                          }}
                          placeholder="claude-sonnet-4-20250514"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Base URL</span>
                        <input
                          type="url"
                          value={modelSettingsEditorState.cloudBaseUrl}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudBaseUrl: event.target.value,
                            }));
                          }}
                          placeholder="https://api.anthropic.com"
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Timeout Seconds</span>
                        <input
                          type="number"
                          min="1"
                          step="0.5"
                          value={modelSettingsEditorState.cloudTimeoutSeconds}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudTimeoutSeconds: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Max Output Tokens</span>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={modelSettingsEditorState.cloudMaxOutputTokens}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudMaxOutputTokens: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">New API Key</span>
                        <input
                          type="password"
                          value={modelSettingsEditorState.cloudApiKey}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              cloudApiKey: event.target.value,
                              clearCloudStoredApiKey: false,
                            }));
                          }}
                          placeholder="Leave blank to keep the current source"
                        />
                      </label>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Escalation and cost controls</p>
                        <p className="muted">
                          These fields map directly to the current escalation policy and call caps.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid">
                      <label className="note-field">
                        <span className="detail-label">Escalate Above Finding Count</span>
                        <input
                          type="number"
                          min="0"
                          step="1"
                          value={modelSettingsEditorState.escalationFindingCountGt}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              escalationFindingCountGt: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Escalate Below Confidence</span>
                        <input
                          type="number"
                          min="0"
                          max="1"
                          step="0.05"
                          value={modelSettingsEditorState.escalationLocalConfidenceLt}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              escalationLocalConfidenceLt: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Cloud Calls Per Day</span>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={modelSettingsEditorState.escalationMaxCloudCallsPerDay}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              escalationMaxCloudCallsPerDay: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Cloud Calls Per Incident</span>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={modelSettingsEditorState.escalationMaxCloudCallsPerIncident}
                          onChange={(event) => {
                            updateModelSettingsEditor((current) => ({
                              ...current,
                              escalationMaxCloudCallsPerIncident: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <div className="note-toggle-row note-field-wide">
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.escalationOnMultipleDomains}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                escalationOnMultipleDomains: event.target.checked,
                              }));
                            }}
                          />
                          <span>Escalate on multiple domains</span>
                        </label>
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.escalationOnChangelogResearch}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                escalationOnChangelogResearch: event.target.checked,
                              }));
                            }}
                          />
                          <span>Escalate on changelog research</span>
                        </label>
                        <label className="note-toggle">
                          <input
                            checked={modelSettingsEditorState.escalationOnUserRequest}
                            type="checkbox"
                            onChange={(event) => {
                              updateModelSettingsEditor((current) => ({
                                ...current,
                                escalationOnUserRequest: event.target.checked,
                              }));
                            }}
                          />
                          <span>Escalate on user request</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  {modelSettingsMutationState.testResult ? (
                    <p
                      className={`message-inline ${
                        modelSettingsMutationState.testResult.ok ? "" : "error"
                      }`}
                    >
                      {formatLabel(modelSettingsMutationState.testResult.target)}{" "}
                      {formatLabel(modelSettingsMutationState.testResult.scope)} test at{" "}
                      {formatTimestamp(modelSettingsMutationState.testResult.checked_at)}:{" "}
                      {modelSettingsMutationState.testResult.message}
                    </p>
                  ) : null}

                  <div className="note-action-row">
                    {modelSettingsMutationState.error ? (
                      <p className="note-error">{modelSettingsMutationState.error}</p>
                    ) : null}
                    <button
                      className="note-button note-button-primary"
                      disabled={modelSettingsMutationState.saving}
                      type="submit"
                    >
                      {modelSettingsMutationState.saving ? "Saving…" : "Save staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        modelSettingsMutationState.applying ||
                        modelSettingsDetail.apply_required === false
                      }
                      type="button"
                      onClick={() => {
                        void applyModelSettings();
                      }}
                    >
                      {modelSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        modelSettingsMutationState.testingTarget !== null ||
                        !modelSettingsEditorState.localEnabled ||
                        !modelSettingsEditorState.localModel
                      }
                      type="button"
                      onClick={() => {
                        void testModelSettings("local");
                      }}
                    >
                      {modelSettingsMutationState.testingTarget === "local"
                        ? "Testing local…"
                        : `Test ${modelSettingsTestScope} local`}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        modelSettingsMutationState.testingTarget !== null ||
                        !modelSettingsEditorState.cloudEnabled ||
                        !modelSettingsEditorState.cloudModel
                      }
                      type="button"
                      onClick={() => {
                        void testModelSettings("cloud");
                      }}
                    >
                      {modelSettingsMutationState.testingTarget === "cloud"
                        ? "Testing cloud…"
                        : `Test ${modelSettingsTestScope} cloud`}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={modelSettingsState.loading}
                      type="button"
                      onClick={() => {
                        void loadModelSettings();
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                  {modelSettingsMutationState.auditChangeId ? (
                    <p className="step-meta model-settings-audit">
                      Logged in the change timeline as {modelSettingsMutationState.auditChangeId}.
                    </p>
                  ) : null}
                </form>
              </>
            ) : (
              <p className="muted">Model settings are not available yet.</p>
            )}
          </section>

          <section className="panel phase-two-panel" id="notification-settings-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Settings</p>
                <h2>Notification channels</h2>
              </div>
              <p className="panel-meta">
                {notificationSettingsState.loading && notificationSettingsDetail === null
                  ? "Refreshing…"
                  : notificationSettingsDetail?.apply_required
                    ? "Apply pending"
                    : "Runtime current"}
              </p>
            </div>

            {notificationSettingsState.loading && notificationSettingsDetail === null ? (
              <p className="muted">Loading notification settings…</p>
            ) : notificationSettingsState.error ? (
              <p className="message-inline error">{notificationSettingsState.error}</p>
            ) : notificationSettingsDetail && notificationSettingsEditorState ? (
              <>
                <div className="action-strip">
                  <span className="action-pill">
                    Persisted {notificationSettingsDetail.config_path}
                  </span>
                  <span className="action-pill">
                    {notificationSettingsDetail.apply_required
                      ? "Staged changes pending"
                      : "Active and staged aligned"}
                  </span>
                  <span className="action-pill">
                    Testing sends through {formatLabel(notificationSettingsTestScope)}
                  </span>
                </div>

                <div className="queue-section">
                  <p className="muted">
                    Channel destinations stay secret. This panel stores only metadata in
                    `kaval.yaml`, keeps destination URLs in the vault or env bootstrap, and
                    only changes live routing after an explicit apply.
                  </p>
                  {notificationSettingsDetail.load_error ? (
                    <p className="message-inline error">{notificationSettingsDetail.load_error}</p>
                  ) : null}
                </div>

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Active runtime</p>
                      <span className="chip ghost">
                        {notificationSettingsDetail.last_applied_at
                          ? `Applied ${formatTimestamp(notificationSettingsDetail.last_applied_at)}`
                          : "Not yet applied"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Configured channels</span>
                        <strong>{notificationSettingsDetail.active.configured_channel_count}</strong>
                      </li>
                      <li>
                        <span>High severity</span>
                        <strong>
                          {formatLabel(notificationSettingsDetail.active.routing.high)}
                        </strong>
                      </li>
                      <li>
                        <span>Quiet hours</span>
                        <strong>
                          {notificationSettingsDetail.active.quiet_hours.enabled
                            ? `${notificationSettingsDetail.active.quiet_hours.start_time_local}–${notificationSettingsDetail.active.quiet_hours.end_time_local} ${notificationSettingsDetail.active.quiet_hours.timezone}`
                            : "Disabled"}
                        </strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Staged config</p>
                      <span className="chip ghost">
                        {notificationSettingsDetail.staged.quiet_hours.active_now
                          ? "Quiet hours active now"
                          : "Quiet hours idle now"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Configured channels</span>
                        <strong>{notificationSettingsDetail.staged.configured_channel_count}</strong>
                      </li>
                      <li>
                        <span>Dedup window</span>
                        <strong>
                          {notificationSettingsDetail.staged.routing.dedup_window_minutes} minutes
                        </strong>
                      </li>
                      <li>
                        <span>Digest window</span>
                        <strong>
                          {notificationSettingsDetail.staged.routing.digest_window_minutes} minutes
                        </strong>
                      </li>
                    </ul>
                  </article>
                </div>

                <form
                  className="note-editor model-settings-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveNotificationSettings();
                  }}
                >
                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Channels</p>
                        <p className="muted">
                          Add one Apprise destination per channel. Test sends are explicit and
                          only target the selected channel.
                        </p>
                      </div>
                      <button
                        className="note-button note-button-ghost"
                        type="button"
                        onClick={addNotificationSettingsChannel}
                      >
                        Add channel
                      </button>
                    </div>

                    {notificationSettingsEditorState.channels.length === 0 ? (
                      <p className="muted">No channels configured yet.</p>
                    ) : (
                      <div className="notification-channel-list">
                        {notificationSettingsEditorState.channels.map((channel) => (
                          <article className="notification-channel-card" key={channel.clientId}>
                            <div className="timeline-topline">
                              <p className="timeline-service">
                                {channel.name || "Unnamed channel"}
                              </p>
                              <span className="chip ghost">
                                {channel.destinationConfigured
                                  ? `${formatLabel(channel.destinationSource)} ${formatLabel(channel.kind)}`
                                  : "Destination required"}
                              </span>
                            </div>

                            <div className="note-editor-grid">
                              <label className="note-field">
                                <span className="detail-label">Name</span>
                                <input
                                  type="text"
                                  value={channel.name}
                                  onChange={(event) => {
                                    updateNotificationSettingsEditor((current) => ({
                                      ...current,
                                      channels: current.channels.map((item) =>
                                        item.clientId === channel.clientId
                                          ? {
                                              ...item,
                                              name: event.target.value,
                                            }
                                          : item,
                                      ),
                                    }));
                                  }}
                                  placeholder="Primary alerts"
                                />
                              </label>
                              <label className="note-field">
                                <span className="detail-label">New Destination URL</span>
                                <input
                                  type="password"
                                  value={channel.destination}
                                  onChange={(event) => {
                                    updateNotificationSettingsEditor((current) => ({
                                      ...current,
                                      channels: current.channels.map((item) =>
                                        item.clientId === channel.clientId
                                          ? {
                                              ...item,
                                              destination: event.target.value,
                                              destinationConfigured:
                                                Boolean(event.target.value.trim()) ||
                                                item.destinationConfigured,
                                              kind:
                                                guessNotificationChannelKind(event.target.value) ??
                                                item.kind,
                                            }
                                          : item,
                                      ),
                                    }));
                                  }}
                                  placeholder="Leave blank to keep the current destination"
                                />
                              </label>
                              <div className="note-toggle-row note-field-wide">
                                <label className="note-toggle">
                                  <input
                                    checked={channel.enabled}
                                    type="checkbox"
                                    onChange={(event) => {
                                      updateNotificationSettingsEditor((current) => ({
                                        ...current,
                                        channels: current.channels.map((item) =>
                                          item.clientId === channel.clientId
                                            ? {
                                                ...item,
                                                enabled: event.target.checked,
                                              }
                                            : item,
                                        ),
                                      }));
                                    }}
                                  />
                                  <span>Enable channel</span>
                                </label>
                                <button
                                  className="note-button note-button-ghost"
                                  disabled={
                                    notificationSettingsMutationState.testingChannelId !== null ||
                                    channel.channelId === null ||
                                    !channel.enabled ||
                                    !channel.destinationConfigured
                                  }
                                  type="button"
                                  onClick={() => {
                                    if (channel.channelId !== null) {
                                      void testNotificationChannel(channel.channelId);
                                    }
                                  }}
                                >
                                  {notificationSettingsMutationState.testingChannelId ===
                                  channel.channelId
                                    ? "Testing…"
                                    : `Test ${notificationSettingsTestScope}`}
                                </button>
                                <button
                                  className="note-button note-button-ghost"
                                  type="button"
                                  onClick={() => {
                                    removeNotificationSettingsChannel(channel.clientId);
                                  }}
                                >
                                  Remove
                                </button>
                              </div>
                            </div>
                          </article>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Severity routing</p>
                        <p className="muted">
                          These controls map directly to the existing incident routing engine.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid">
                      <label className="note-field">
                        <span className="detail-label">Critical</span>
                        <select
                          value={notificationSettingsEditorState.criticalRoute}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              criticalRoute: event.target.value as NotificationSettingsRoute,
                            }));
                          }}
                        >
                          {notificationRouteOptions.map((option) => (
                            <option key={option} value={option}>
                              {formatLabel(option)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="note-field">
                        <span className="detail-label">High</span>
                        <select
                          value={notificationSettingsEditorState.highRoute}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              highRoute: event.target.value as NotificationSettingsRoute,
                            }));
                          }}
                        >
                          {notificationRouteOptions.map((option) => (
                            <option key={option} value={option}>
                              {formatLabel(option)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Medium</span>
                        <select
                          value={notificationSettingsEditorState.mediumRoute}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              mediumRoute: event.target.value as NotificationSettingsRoute,
                            }));
                          }}
                        >
                          {notificationRouteOptions.map((option) => (
                            <option key={option} value={option}>
                              {formatLabel(option)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Low</span>
                        <select
                          value={notificationSettingsEditorState.lowRoute}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              lowRoute: event.target.value as NotificationSettingsRoute,
                            }));
                          }}
                        >
                          {notificationRouteOptions.map((option) => (
                            <option key={option} value={option}>
                              {formatLabel(option)}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Dedup Window Minutes</span>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={notificationSettingsEditorState.dedupWindowMinutes}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              dedupWindowMinutes: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Digest Window Minutes</span>
                        <input
                          type="number"
                          min="1"
                          step="1"
                          value={notificationSettingsEditorState.digestWindowMinutes}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              digestWindowMinutes: event.target.value,
                            }));
                          }}
                        />
                      </label>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Quiet hours</p>
                        <p className="muted">
                          Non-critical alerts hold until quiet hours end, then release once as a
                          digest or summary.
                        </p>
                      </div>
                      <span className="chip ghost">
                        {notificationSettingsDetail.staged.quiet_hours.quiet_until
                          ? `Next release ${formatTimestamp(notificationSettingsDetail.staged.quiet_hours.quiet_until)}`
                          : "No hold active"}
                      </span>
                    </div>
                    <div className="note-editor-grid">
                      <div className="note-toggle-row note-field-wide">
                        <label className="note-toggle">
                          <input
                            checked={notificationSettingsEditorState.quietHoursEnabled}
                            type="checkbox"
                            onChange={(event) => {
                              updateNotificationSettingsEditor((current) => ({
                                ...current,
                                quietHoursEnabled: event.target.checked,
                              }));
                            }}
                          />
                          <span>Enable quiet hours</span>
                        </label>
                      </div>
                      <label className="note-field">
                        <span className="detail-label">Start</span>
                        <input
                          type="time"
                          value={notificationSettingsEditorState.quietHoursStart}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              quietHoursStart: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">End</span>
                        <input
                          type="time"
                          value={notificationSettingsEditorState.quietHoursEnd}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              quietHoursEnd: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field note-field-wide">
                        <span className="detail-label">Timezone</span>
                        <input
                          type="text"
                          value={notificationSettingsEditorState.quietHoursTimezone}
                          onChange={(event) => {
                            updateNotificationSettingsEditor((current) => ({
                              ...current,
                              quietHoursTimezone: event.target.value,
                            }));
                          }}
                          placeholder="America/Chicago"
                        />
                      </label>
                    </div>
                  </div>

                  {notificationSettingsMutationState.testResult ? (
                    <p
                      className={`message-inline ${
                        notificationSettingsMutationState.testResult.ok ? "" : "error"
                      }`}
                    >
                      Channel {notificationSettingsMutationState.testResult.channel_id}{" "}
                      {formatLabel(notificationSettingsMutationState.testResult.scope)} test at{" "}
                      {formatTimestamp(notificationSettingsMutationState.testResult.checked_at)}:{" "}
                      {notificationSettingsMutationState.testResult.message}
                    </p>
                  ) : null}

                  <div className="note-action-row">
                    {notificationSettingsMutationState.error ? (
                      <p className="note-error">{notificationSettingsMutationState.error}</p>
                    ) : null}
                    <button
                      className="note-button note-button-primary"
                      disabled={notificationSettingsMutationState.saving}
                      type="submit"
                    >
                      {notificationSettingsMutationState.saving ? "Saving…" : "Save staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        notificationSettingsMutationState.applying ||
                        notificationSettingsDetail.apply_required === false
                      }
                      type="button"
                      onClick={() => {
                        void applyNotificationSettings();
                      }}
                    >
                      {notificationSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={notificationSettingsState.loading}
                      type="button"
                      onClick={() => {
                        void loadNotificationSettings();
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                  {notificationSettingsMutationState.auditChangeId ? (
                    <p className="step-meta model-settings-audit">
                      Logged in the change timeline as{" "}
                      {notificationSettingsMutationState.auditChangeId}.
                    </p>
                  ) : null}
                </form>
              </>
            ) : (
              <p className="muted">Notification settings are not available yet.</p>
            )}
          </section>

          <section className="panel phase-two-panel" id="descriptor-review-queue-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Settings</p>
                <h2>Monitoring configuration</h2>
              </div>
              <p className="panel-meta">
                {monitoringSettingsState.loading && monitoringSettingsDetail === null
                  ? "Refreshing…"
                  : monitoringSettingsDetail?.apply_required
                    ? "Apply pending"
                    : "Runtime current"}
              </p>
            </div>

            {monitoringSettingsState.loading && monitoringSettingsDetail === null ? (
              <p className="muted">Loading monitoring settings…</p>
            ) : monitoringSettingsState.error ? (
              <p className="message-inline error">{monitoringSettingsState.error}</p>
            ) : monitoringSettingsDetail && monitoringSettingsEditorState ? (
              <>
                <div className="action-strip">
                  <span className="action-pill">
                    Persisted {monitoringSettingsDetail.config_path}
                  </span>
                  <span className="action-pill">
                    {monitoringSettingsDetail.apply_required
                      ? "Staged changes pending"
                      : "Active and staged aligned"}
                  </span>
                  <span className="action-pill">
                    {monitoringSettingsDetail.active.service_overrides.length} active service
                    override
                    {monitoringSettingsDetail.active.service_overrides.length === 1 ? "" : "s"}
                  </span>
                </div>

                <div className="queue-section">
                  <p className="muted">
                    Global check defaults persist in `kaval.yaml`. Service-level overrides stay in
                    the DB, but they still respect the same explicit apply path before runtime use.
                  </p>
                  {monitoringSettingsDetail.load_error ? (
                    <p className="message-inline error">{monitoringSettingsDetail.load_error}</p>
                  ) : null}
                </div>

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Active runtime</p>
                      <span className="chip ghost">
                        {monitoringSettingsDetail.last_applied_at
                          ? `Applied ${formatTimestamp(monitoringSettingsDetail.last_applied_at)}`
                          : "Not yet applied"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Enabled checks</span>
                        <strong>
                          {
                            monitoringSettingsDetail.active.checks.filter((check) => check.enabled)
                              .length
                          }
                        </strong>
                      </li>
                      <li>
                        <span>Service overrides</span>
                        <strong>{monitoringSettingsDetail.active.service_overrides.length}</strong>
                      </li>
                      <li>
                        <span>Effective service rows</span>
                        <strong>{monitoringSettingsDetail.active.effective_services.length}</strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Staged config</p>
                      <span className="chip ghost">
                        {monitoringSettingsDetail.staged.service_overrides.length} override
                        {monitoringSettingsDetail.staged.service_overrides.length === 1 ? "" : "s"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Enabled checks</span>
                        <strong>
                          {
                            monitoringSettingsDetail.staged.checks.filter((check) => check.enabled)
                              .length
                          }
                        </strong>
                      </li>
                      <li>
                        <span>Disabled checks</span>
                        <strong>
                          {
                            monitoringSettingsDetail.staged.checks.filter((check) => !check.enabled)
                              .length
                          }
                        </strong>
                      </li>
                      <li>
                        <span>Preview service rows</span>
                        <strong>{monitoringSettingsDetail.staged.effective_services.length}</strong>
                      </li>
                    </ul>
                  </article>
                </div>

                <form
                  className="note-editor model-settings-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveMonitoringSettings();
                  }}
                >
                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Global checks</p>
                        <p className="muted">
                          These settings map directly to the current scheduler cadence contract.
                        </p>
                      </div>
                    </div>
                    <div className="monitoring-check-list">
                      {monitoringSettingsEditorState.checks.map((check) => {
                        const thresholdMeta = monitoringThresholdMeta(check.checkId);
                        return (
                          <article className="monitoring-check-card" key={check.checkId}>
                            <div className="timeline-topline">
                              <p className="timeline-service">{check.label}</p>
                              <span className="chip ghost">
                                Default {check.defaultIntervalSeconds}s
                                {thresholdMeta
                                  ? ` · ${formatMonitoringThresholdDefault(check, thresholdMeta)}`
                                  : ""}
                              </span>
                            </div>
                            <p className="muted">{check.description}</p>
                            <div className="note-editor-grid">
                              <label className="note-toggle note-field-wide">
                                <input
                                  checked={check.enabled}
                                  type="checkbox"
                                  onChange={(event) => {
                                    updateMonitoringSettingsEditor((current) => ({
                                      ...current,
                                      checks: current.checks.map((item) =>
                                        item.checkId === check.checkId
                                          ? {
                                              ...item,
                                              enabled: event.target.checked,
                                            }
                                          : item,
                                      ),
                                    }));
                                  }}
                                />
                                <span>Enable check</span>
                              </label>
                              <label className="note-field">
                                <span className="detail-label">Interval Seconds</span>
                                <input
                                  type="number"
                                  min="1"
                                  step="1"
                                  value={check.intervalSeconds}
                                  onChange={(event) => {
                                    updateMonitoringSettingsEditor((current) => ({
                                      ...current,
                                      checks: current.checks.map((item) =>
                                        item.checkId === check.checkId
                                          ? {
                                              ...item,
                                              intervalSeconds: event.target.value,
                                            }
                                          : item,
                                      ),
                                    }));
                                  }}
                                />
                              </label>
                              {thresholdMeta ? (
                                <label className="note-field">
                                  <span className="detail-label">{thresholdMeta.label}</span>
                                  <input
                                    type="number"
                                    min={thresholdMeta.min}
                                    step={thresholdMeta.step}
                                    value={monitoringThresholdEditorValue(check, thresholdMeta.key)}
                                    onChange={(event) => {
                                      updateMonitoringSettingsEditor((current) => ({
                                        ...current,
                                        checks: current.checks.map((item) =>
                                          item.checkId === check.checkId
                                            ? updateMonitoringThresholdEditorValue(
                                                item,
                                                thresholdMeta.key,
                                                event.target.value,
                                              )
                                            : item,
                                        ),
                                      }));
                                    }}
                                  />
                                </label>
                              ) : null}
                            </div>
                          </article>
                        );
                      })}
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Service overrides</p>
                        <p className="muted">
                          Use overrides only when one service needs a tighter or quieter cadence
                          than the global baseline.
                        </p>
                      </div>
                      <button
                        className="note-button note-button-ghost"
                        type="button"
                        onClick={addMonitoringServiceOverride}
                      >
                        Add override
                      </button>
                    </div>

                    {monitoringSettingsEditorState.serviceOverrides.length === 0 ? (
                      <p className="muted">No staged service overrides yet.</p>
                    ) : (
                      <div className="monitoring-check-list">
                        {monitoringSettingsEditorState.serviceOverrides.map((override) => {
                          const applicableChecks = applicableMonitoringChecks(
                            override.serviceId,
                            monitoringSettingsEditorState.checks,
                            services,
                          );
                          const thresholdMeta = monitoringThresholdMeta(override.checkId);
                          return (
                            <article className="monitoring-check-card" key={override.clientId}>
                              <div className="note-editor-grid">
                                <label className="note-field">
                                  <span className="detail-label">Service</span>
                                  <select
                                    value={override.serviceId}
                                    onChange={(event) => {
                                      const nextServiceId = event.target.value;
                                      updateMonitoringSettingsEditor((current) => {
                                        const currentChecks = applicableMonitoringChecks(
                                          nextServiceId,
                                          current.checks,
                                          services,
                                        );
                                        return {
                                          ...current,
                                          serviceOverrides: current.serviceOverrides.map((item) =>
                                            item.clientId === override.clientId
                                              ? {
                                                  ...item,
                                                  serviceId: nextServiceId,
                                                  checkId:
                                                    currentChecks.find(
                                                      (check) => check.checkId === item.checkId,
                                                    )?.checkId ??
                                                    currentChecks[0]?.checkId ??
                                                    "",
                                                  tlsWarningDays: "",
                                                  restartDeltaThreshold: "",
                                                  probeTimeoutSeconds: "",
                                                }
                                              : item,
                                          ),
                                        };
                                      });
                                    }}
                                  >
                                    {services.map((service) => (
                                      <option key={service.id} value={service.id}>
                                        {service.name}
                                      </option>
                                    ))}
                                  </select>
                                </label>
                                <label className="note-field">
                                  <span className="detail-label">Check</span>
                                  <select
                                    value={override.checkId}
                                    onChange={(event) => {
                                      updateMonitoringSettingsEditor((current) => ({
                                        ...current,
                                        serviceOverrides: current.serviceOverrides.map((item) =>
                                            item.clientId === override.clientId
                                              ? {
                                                  ...item,
                                                  checkId: event.target.value,
                                                  tlsWarningDays: "",
                                                  restartDeltaThreshold: "",
                                                  probeTimeoutSeconds: "",
                                                }
                                              : item,
                                        ),
                                      }));
                                    }}
                                  >
                                    {applicableChecks.map((check) => (
                                      <option key={check.checkId} value={check.checkId}>
                                        {check.label}
                                      </option>
                                    ))}
                                  </select>
                                </label>
                                <label className="note-field">
                                  <span className="detail-label">Enablement</span>
                                  <select
                                    value={override.enabledMode}
                                    onChange={(event) => {
                                      updateMonitoringSettingsEditor((current) => ({
                                        ...current,
                                        serviceOverrides: current.serviceOverrides.map((item) =>
                                          item.clientId === override.clientId
                                            ? {
                                                ...item,
                                                enabledMode: event.target.value as
                                                  | "inherit"
                                                  | "enabled"
                                                  | "disabled",
                                              }
                                            : item,
                                        ),
                                      }));
                                    }}
                                  >
                                    <option value="inherit">Inherit global</option>
                                    <option value="enabled">Force enabled</option>
                                    <option value="disabled">Force disabled</option>
                                  </select>
                                </label>
                                <label className="note-field">
                                  <span className="detail-label">Interval Seconds</span>
                                  <input
                                    type="number"
                                    min="1"
                                    step="1"
                                    value={override.intervalSeconds}
                                    onChange={(event) => {
                                      updateMonitoringSettingsEditor((current) => ({
                                        ...current,
                                        serviceOverrides: current.serviceOverrides.map((item) =>
                                          item.clientId === override.clientId
                                            ? {
                                                ...item,
                                                intervalSeconds: event.target.value,
                                              }
                                            : item,
                                        ),
                                      }));
                                    }}
                                    placeholder="Leave blank to inherit"
                                  />
                                </label>
                                {thresholdMeta ? (
                                  <label className="note-field">
                                    <span className="detail-label">{thresholdMeta.label}</span>
                                    <input
                                      type="number"
                                      min={thresholdMeta.min}
                                      step={thresholdMeta.step}
                                      value={monitoringThresholdEditorValue(override, thresholdMeta.key)}
                                      onChange={(event) => {
                                        updateMonitoringSettingsEditor((current) => ({
                                          ...current,
                                          serviceOverrides: current.serviceOverrides.map((item) =>
                                            item.clientId === override.clientId
                                              ? updateMonitoringThresholdEditorValue(
                                                  item,
                                                  thresholdMeta.key,
                                                  event.target.value,
                                                )
                                              : item,
                                          ),
                                        }));
                                      }}
                                      placeholder="Leave blank to inherit"
                                    />
                                  </label>
                                ) : null}
                              </div>
                              <div className="note-action-row">
                                <button
                                  className="note-button note-button-ghost"
                                  type="button"
                                  onClick={() => {
                                    removeMonitoringServiceOverride(override.clientId);
                                  }}
                                >
                                  Remove override
                                </button>
                              </div>
                            </article>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Effective runtime</p>
                        <p className="muted">
                          This is the cadence actually active right now, after global defaults,
                          service overrides, and any active incident acceleration are applied.
                        </p>
                      </div>
                    </div>
                    <div className="monitoring-effective-grid">
                      {monitoringSettingsDetail.active.effective_services.map((service) => (
                        <article className="system-profile-card" key={service.service_id}>
                          <div className="timeline-topline">
                            <p className="timeline-service">{service.service_name}</p>
                            <span className={`status-pill state-${service.service_status}`}>
                              {formatLabel(service.service_status)}
                            </span>
                          </div>
                          <ul className="system-profile-list compact">
                            {service.checks.map((check) => (
                              <li key={`${service.service_id}:${check.check_id}`}>
                                <span>{check.label}</span>
                                <strong>
                                  {check.enabled
                                    ? `${check.effective_interval_seconds}s`
                                    : "Disabled"}
                                </strong>
                                <span className="muted">
                                  {formatLabel(check.source)}
                                  {formatMonitoringThresholdSummary(check)
                                    ? ` · ${formatMonitoringThresholdSummary(check)}`
                                    : ""}
                                  {check.accelerated_now ? " · accelerated" : ""}
                                </span>
                              </li>
                            ))}
                          </ul>
                        </article>
                      ))}
                    </div>
                  </div>

                  {monitoringSettingsDetail.apply_required ? (
                    <div className="queue-section">
                      <div className="memory-section-header">
                        <div>
                          <p className="detail-label">Staged preview</p>
                          <p className="muted">
                            Preview of the service/check cadence that will go live after apply.
                          </p>
                        </div>
                      </div>
                      <div className="monitoring-effective-grid">
                        {monitoringSettingsDetail.staged.effective_services.map((service) => (
                          <article className="system-profile-card" key={service.service_id}>
                            <div className="timeline-topline">
                              <p className="timeline-service">{service.service_name}</p>
                              <span className={`status-pill state-${service.service_status}`}>
                                {formatLabel(service.service_status)}
                              </span>
                            </div>
                            <ul className="system-profile-list compact">
                              {service.checks.map((check) => (
                                <li key={`${service.service_id}:${check.check_id}`}>
                                  <span>{check.label}</span>
                                  <strong>
                                    {check.enabled
                                      ? `${check.effective_interval_seconds}s`
                                      : "Disabled"}
                                  </strong>
                                  <span className="muted">
                                    {formatLabel(check.source)}
                                    {formatMonitoringThresholdSummary(check)
                                      ? ` · ${formatMonitoringThresholdSummary(check)}`
                                      : ""}
                                    {check.accelerated_now ? " · accelerated" : ""}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          </article>
                        ))}
                      </div>
                    </div>
                  ) : null}

                  <div className="note-action-row">
                    {monitoringSettingsMutationState.error ? (
                      <p className="note-error">{monitoringSettingsMutationState.error}</p>
                    ) : null}
                    <button
                      className="note-button note-button-primary"
                      disabled={monitoringSettingsMutationState.saving}
                      type="submit"
                    >
                      {monitoringSettingsMutationState.saving ? "Saving…" : "Save staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        monitoringSettingsMutationState.applying ||
                        monitoringSettingsDetail.apply_required === false
                      }
                      type="button"
                      onClick={() => {
                        void applyMonitoringSettings();
                      }}
                    >
                      {monitoringSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={monitoringSettingsState.loading}
                      type="button"
                      onClick={() => {
                        void loadMonitoringSettings();
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                  {monitoringSettingsMutationState.auditChangeId ? (
                    <p className="step-meta model-settings-audit">
                      Logged in the change timeline as{" "}
                      {monitoringSettingsMutationState.auditChangeId}.
                    </p>
                  ) : null}
                </form>
              </>
            ) : (
              <p className="muted">Monitoring settings are not available yet.</p>
            )}
          </section>

          <section className="panel phase-two-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Settings</p>
                <h2>System</h2>
              </div>
              <p className="panel-meta">
                {systemSettingsState.loading && systemSettingsDetail === null
                  ? "Refreshing…"
                  : systemSettingsDetail?.apply_required
                    ? "Apply pending"
                    : `Runtime ${formatLabel(systemSettingsDetail?.about.runtime_log_level ?? "info")}`}
              </p>
            </div>

            {systemSettingsState.loading && systemSettingsDetail === null ? (
              <p className="muted">Loading system settings…</p>
            ) : systemSettingsState.error ? (
              <p className="message-inline error">{systemSettingsState.error}</p>
            ) : systemSettingsDetail && systemSettingsEditorState ? (
              <>
                <div className="action-strip">
                  <span className="action-pill">
                    Persisted {systemSettingsDetail.config_path}
                  </span>
                  <span className="action-pill">
                    DB {formatByteSize(systemSettingsDetail.database.size_bytes)}
                  </span>
                  <span className="action-pill">
                    {systemSettingsDetail.apply_required
                      ? "Staged changes pending"
                      : "Active and staged aligned"}
                  </span>
                </div>

                <div className="queue-section">
                  <p className="muted">
                    Global non-secret system settings persist in `kaval.yaml`. This panel only
                    exposes explicit save/apply flows plus read-only database, import/export, and
                    about metadata. Backup and import execution remain out of scope until Phase 4.
                  </p>
                  {systemSettingsDetail.load_error ? (
                    <p className="message-inline error">{systemSettingsDetail.load_error}</p>
                  ) : null}
                </div>

                <div className="detail-grid">
                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Runtime</p>
                      <span className="chip ghost">
                        {systemSettingsDetail.last_applied_at
                          ? `Applied ${formatTimestamp(systemSettingsDetail.last_applied_at)}`
                          : "Not yet applied"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Runtime log level</span>
                        <strong>{formatLabel(systemSettingsDetail.about.runtime_log_level)}</strong>
                      </li>
                      <li>
                        <span>Staged log level</span>
                        <strong>{formatLabel(systemSettingsDetail.staged.log_level)}</strong>
                      </li>
                      <li>
                        <span>Detailed audit retention</span>
                        <strong>{activeAuditDetailRetentionDays} days</strong>
                      </li>
                      <li>
                        <span>Summary audit retention</span>
                        <strong>{activeAuditSummaryRetentionDays} days</strong>
                      </li>
                      <li>
                        <span>Uptime</span>
                        <strong>
                          {formatDurationSeconds(systemSettingsDetail.about.uptime_seconds)}
                        </strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card">
                    <div className="timeline-topline">
                      <p className="timeline-service">Database maintenance</p>
                      <span
                        className={`chip ${
                          systemSettingsDetail.database.quick_check_ok &&
                          systemSettingsDetail.database.migrations_current
                            ? "ghost"
                            : "warning"
                        }`}
                      >
                        {systemSettingsDetail.database.quick_check_ok &&
                        systemSettingsDetail.database.migrations_current
                          ? "Healthy"
                          : "Review required"}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Size</span>
                        <strong>{formatByteSize(systemSettingsDetail.database.size_bytes)}</strong>
                      </li>
                      <li>
                        <span>Journal mode</span>
                        <strong>{systemSettingsDetail.database.journal_mode}</strong>
                      </li>
                      <li>
                        <span>Quick check</span>
                        <strong>{systemSettingsDetail.database.quick_check_result}</strong>
                      </li>
                      <li>
                        <span>Migrations</span>
                        <strong>
                          {systemSettingsDetail.database.migrations_current
                            ? "Current"
                            : "Pending"}
                        </strong>
                      </li>
                    </ul>
                  </article>

                  <article className="system-profile-card system-profile-card-wide">
                    <div className="timeline-topline">
                      <p className="timeline-service">About</p>
                      <span className="chip ghost">
                        {systemSettingsDetail.about.api_title} {systemSettingsDetail.about.api_version}
                      </span>
                    </div>
                    <ul className="system-profile-list compact">
                      <li>
                        <span>Build summary</span>
                        <strong>
                          {systemSettingsDetail.about.api_summary ?? "No summary recorded"}
                        </strong>
                      </li>
                      <li>
                        <span>Started</span>
                        <strong>{formatTimestamp(systemSettingsDetail.about.started_at)}</strong>
                      </li>
                      <li>
                        <span>Web bundle</span>
                        <strong>
                          {systemSettingsDetail.about.web_bundle_present
                            ? "Embedded bundle present"
                            : "No embedded bundle"}
                        </strong>
                      </li>
                      <li>
                        <span>Local model</span>
                        <strong>{systemSettingsDetail.about.model_status.local_model_summary}</strong>
                      </li>
                      <li>
                        <span>Cloud model</span>
                        <strong>{systemSettingsDetail.about.model_status.cloud_model_summary}</strong>
                      </li>
                      <li>
                        <span>Escalation policy</span>
                        <strong>{systemSettingsDetail.about.model_status.escalation_summary}</strong>
                      </li>
                    </ul>
                  </article>
                </div>

                <form
                  className="note-editor model-settings-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveSystemSettings();
                  }}
                >
                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Runtime log level</p>
                        <p className="muted">
                          Saving updates the staged config in `kaval.yaml`. Apply updates the
                          current process at the next explicit safe boundary.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid">
                      <label className="note-field">
                        <span className="detail-label">Log level</span>
                        <select
                          value={systemSettingsEditorState.logLevel}
                          onChange={(event) => {
                            updateSystemSettingsEditor((current) => ({
                              ...current,
                              logLevel: event.target.value as SystemSettingsLogLevel,
                            }));
                          }}
                        >
                          {systemLogLevelOptions.map((level) => (
                            <option key={level} value={level}>
                              {formatLabel(level)}
                            </option>
                          ))}
                        </select>
                      </label>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Audit history retention</p>
                        <p className="muted">
                          These windows control how long the audit trail keeps detailed values
                          versus summary-only visibility after an explicit apply.
                        </p>
                      </div>
                    </div>
                    <div className="note-editor-grid">
                      <label className="note-field">
                        <span className="detail-label">Detailed events retention</span>
                        <input
                          inputMode="numeric"
                          min="1"
                          step="1"
                          value={systemSettingsEditorState.auditDetailRetentionDays}
                          onChange={(event) => {
                            updateSystemSettingsEditor((current) => ({
                              ...current,
                              auditDetailRetentionDays: event.target.value,
                            }));
                          }}
                        />
                      </label>
                      <label className="note-field">
                        <span className="detail-label">Summary events retention</span>
                        <input
                          inputMode="numeric"
                          min="1"
                          step="1"
                          value={systemSettingsEditorState.auditSummaryRetentionDays}
                          onChange={(event) => {
                            updateSystemSettingsEditor((current) => ({
                              ...current,
                              auditSummaryRetentionDays: event.target.value,
                            }));
                          }}
                        />
                      </label>
                    </div>
                  </div>

                  <div className="queue-section">
                    <div className="memory-section-header">
                      <div>
                        <p className="detail-label">Backup, export, and import guidance</p>
                        <p className="muted">
                          {systemSettingsDetail.transfer_guidance.phase_guardrail}
                        </p>
                      </div>
                    </div>
                    <div className="detail-grid">
                      {systemSettingsDetail.transfer_guidance.exports.map((item) => (
                        <article className="system-profile-card" key={`export:${item.target}`}>
                          <div className="timeline-topline">
                            <p className="timeline-service">{item.label}</p>
                            <span className="chip warning">
                              {formatLabel(item.sensitivity)} sensitivity
                            </span>
                          </div>
                          <p className="muted">{item.warning}</p>
                        </article>
                      ))}
                      {systemSettingsDetail.transfer_guidance.imports.map((item) => (
                        <article className="system-profile-card" key={`import:${item.target}`}>
                          <div className="timeline-topline">
                            <p className="timeline-service">{item.label}</p>
                            <span className="chip ghost">Warn only</span>
                          </div>
                          <p className="muted">{item.warning}</p>
                        </article>
                      ))}
                    </div>
                  </div>

                  <div className="note-action-row">
                    {systemSettingsMutationState.error ? (
                      <p className="note-error">{systemSettingsMutationState.error}</p>
                    ) : null}
                    <button
                      className="note-button note-button-primary"
                      disabled={systemSettingsMutationState.saving}
                      type="submit"
                    >
                      {systemSettingsMutationState.saving ? "Saving…" : "Save staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={
                        systemSettingsMutationState.applying ||
                        systemSettingsDetail.apply_required === false
                      }
                      type="button"
                      onClick={() => {
                        void applySystemSettings();
                      }}
                    >
                      {systemSettingsMutationState.applying ? "Applying…" : "Apply staged"}
                    </button>
                    <button
                      className="note-button note-button-ghost"
                      disabled={systemSettingsState.loading}
                      type="button"
                      onClick={() => {
                        void loadSystemSettings();
                      }}
                    >
                      Refresh
                    </button>
                  </div>
                  {systemSettingsMutationState.auditChangeId ? (
                    <p className="step-meta model-settings-audit">
                      Logged in the change timeline as{" "}
                      {systemSettingsMutationState.auditChangeId}.
                    </p>
                  ) : null}
                </form>
              </>
            ) : (
              <p className="muted">System settings are not available yet.</p>
            )}
          </section>

          <section className="panel phase-two-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Descriptor Review Queue</p>
                <h2>Auto-generated descriptors</h2>
              </div>
              <p className="panel-meta">
                {quarantinedDescriptorQueueState.loading && descriptorReviewQueueCount === 0
                  ? "Refreshing…"
                  : `${descriptorReviewQueueCount} queued`}
              </p>
            </div>

            <div className="action-strip">
              <span className="action-pill">{pendingDescriptorReviewCount} pending</span>
              <span className="action-pill">{deferredDescriptorReviewCount} deferred</span>
              <span className="action-pill">Quarantined until promotion</span>
              <button
                className="note-button note-button-ghost"
                disabled={
                  quarantinedDescriptorMutationState.submitting ||
                  quarantinedDescriptorQueueState.loading
                }
                onClick={() => {
                  void loadQuarantinedDescriptorQueue();
                }}
                type="button"
              >
                {quarantinedDescriptorQueueState.loading ? "Refreshing…" : "Refresh queue"}
              </button>
            </div>

            <div className="queue-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">Review contract</p>
                  <p className="muted">
                    These descriptors stay inactive for matching, incident grouping, and action
                    recommendations until an explicit promotion writes a reviewed copy into
                    `services/user/...`.
                  </p>
                </div>
                {selectedQuarantinedDescriptor ? (
                  <span className="chip ghost">
                    {selectedQuarantinedMatchingServices.length} likely matches
                  </span>
                ) : null}
              </div>

              {quarantinedDescriptorMutationState.auditChangeId ? (
                <p className="message-inline">
                  Last review action logged as {quarantinedDescriptorMutationState.auditChangeId}.
                </p>
              ) : null}
              {quarantinedDescriptorQueueState.error ? (
                <p className="message-inline error">
                  {quarantinedDescriptorQueueState.error}
                </p>
              ) : null}
              {quarantinedDescriptorMutationState.error ? (
                <p className="message-inline error">
                  {quarantinedDescriptorMutationState.error}
                </p>
              ) : null}

              {quarantinedDescriptorQueueState.loading && descriptorReviewQueueCount === 0 ? (
                <p className="muted">Loading quarantined descriptor queue…</p>
              ) : descriptorReviewQueueCount === 0 ? (
                <p className="muted">
                  No auto-generated descriptors are currently waiting for review.
                </p>
              ) : (
                <div className="descriptor-review-layout">
                  <div className="queue-list descriptor-review-queue-list">
                    {quarantinedDescriptorQueueState.items.map((item) => {
                      const isSelected =
                        item.descriptor.descriptor_id ===
                        selectedQuarantinedDescriptor?.descriptor.descriptor_id;
                      const matchesSelectedService =
                        selectedServiceId !== null &&
                        item.matching_services.some((service) => service.id === selectedServiceId);
                      return (
                        <button
                          className={`queue-item descriptor-review-queue-item ${
                            isSelected ? "selected" : ""
                          } ${item.review_state === "pending" ? "review" : ""} ${
                            matchesSelectedService ? "relevant" : ""
                          }`}
                          key={item.descriptor.descriptor_id}
                          onClick={() =>
                            setSelectedQuarantinedDescriptorId(item.descriptor.descriptor_id)
                          }
                          type="button"
                        >
                          <div className="timeline-topline">
                            <span
                              className={
                                item.review_state === "pending" ? "chip" : "chip ghost"
                              }
                            >
                              {formatLabel(item.review_state)}
                            </span>
                            <span className="step-meta">
                              {formatTimestamp(item.review_updated_at)}
                            </span>
                          </div>
                          <p className="timeline-service">{item.descriptor.name}</p>
                          <p className="muted">{item.descriptor.descriptor_id}</p>
                          <div className="memory-badge-strip">
                            <span className="chip ghost">{item.descriptor.category}</span>
                            <span className="chip ghost">
                              {item.matching_services.length} likely matches
                            </span>
                            {matchesSelectedService ? (
                              <span className="chip">Selected service</span>
                            ) : null}
                          </div>
                        </button>
                      );
                    })}
                  </div>

                  {selectedQuarantinedDescriptor ? (
                    <div className="descriptor-review-detail">
                      <div className="detail-grid">
                        <article className="system-profile-card">
                          <div className="timeline-topline">
                            <div>
                              <p className="timeline-service">
                                {selectedQuarantinedDescriptor.descriptor.name}
                              </p>
                              <p className="step-meta">
                                {selectedQuarantinedDescriptor.descriptor.descriptor_id}
                              </p>
                            </div>
                            <div className="adapter-state-strip">
                              <span className="chip ghost">Auto-generated</span>
                              <span
                                className={
                                  selectedQuarantinedDescriptor.review_state === "pending"
                                    ? "chip"
                                    : "chip ghost"
                                }
                              >
                                {formatLabel(selectedQuarantinedDescriptor.review_state)}
                              </span>
                            </div>
                          </div>
                          <ul className="system-profile-list compact">
                            <li>
                              <span>Queue path</span>
                              <strong>{selectedQuarantinedDescriptor.descriptor.file_path}</strong>
                            </li>
                            <li>
                              <span>Promotion target</span>
                              <strong>
                                {selectedQuarantinedDescriptor.descriptor.write_target_path}
                              </strong>
                            </li>
                            <li>
                              <span>Generated</span>
                              <strong>
                                {selectedQuarantinedDescriptor.descriptor.generated_at
                                  ? formatTimestamp(
                                      selectedQuarantinedDescriptor.descriptor.generated_at,
                                    )
                                  : "Unknown"}
                              </strong>
                            </li>
                            <li>
                              <span>Last review</span>
                              <strong>
                                {formatTimestamp(selectedQuarantinedDescriptor.review_updated_at)}
                              </strong>
                            </li>
                          </ul>
                          <div className="service-inline-list">
                            <article className="service-inline-item">
                              <p className="detail-label">Match rules</p>
                              <ul className="chip-list service-inline-chip-list">
                                {selectedQuarantinedDescriptor.descriptor.match.image_patterns.map(
                                  (pattern) => (
                                    <li key={`queue-image-${pattern}`}>
                                      <span className="chip ghost">{pattern}</span>
                                    </li>
                                  ),
                                )}
                                {selectedQuarantinedDescriptor.descriptor.match.container_name_patterns.map(
                                  (pattern) => (
                                    <li key={`queue-name-${pattern}`}>
                                      <span className="chip ghost">{pattern}</span>
                                    </li>
                                  ),
                                )}
                              </ul>
                            </article>
                            <article className="service-inline-item">
                              <p className="detail-label">Rendered candidate</p>
                              <p className="muted service-inline-copy">
                                {selectedQuarantinedDescriptor.descriptor.investigation_context ??
                                  "No investigation context was generated for this candidate."}
                              </p>
                              <p className="step-meta">
                                Endpoints{" "}
                                {selectedQuarantinedDescriptor.descriptor.endpoints.length} ·
                                container dependencies{" "}
                                {
                                  selectedQuarantinedDescriptor.descriptor
                                    .typical_dependency_containers.length
                                }{" "}
                                · share dependencies{" "}
                                {
                                  selectedQuarantinedDescriptor.descriptor
                                    .typical_dependency_shares.length
                                }
                              </p>
                            </article>
                          </div>
                        </article>

                        <article className="system-profile-card">
                          <p className="timeline-service">Container metadata</p>
                          {selectedQuarantinedMatchingServices.length > 0 ? (
                            <div className="service-inline-list">
                              {selectedQuarantinedMatchingServices.map((service) => (
                                <article className="service-inline-item" key={service.id}>
                                  <div className="timeline-topline">
                                    <div>
                                      <p className="timeline-service">{service.name}</p>
                                      <p className="step-meta">{service.id}</p>
                                    </div>
                                    <div className="adapter-state-strip">
                                      <span className={`status-pill status-${service.status}`}>
                                        {statusLabel[service.status]}
                                      </span>
                                      <button
                                        className="note-button note-button-ghost"
                                        onClick={() => setSelectedServiceId(service.id)}
                                        type="button"
                                      >
                                        Open service
                                      </button>
                                    </div>
                                  </div>
                                  <ul className="system-profile-list compact">
                                    <li>
                                      <span>Image</span>
                                      <strong>{formatOptionalValue(service.image)}</strong>
                                    </li>
                                    <li>
                                      <span>Container ID</span>
                                      <strong>
                                        {formatOptionalValue(service.container_id)}
                                      </strong>
                                    </li>
                                    <li>
                                      <span>Current descriptor</span>
                                      <strong>
                                        {formatOptionalValue(service.descriptor_id)}
                                      </strong>
                                    </li>
                                    <li>
                                      <span>Findings / incidents</span>
                                      <strong>
                                        {service.active_findings} / {service.active_incidents}
                                      </strong>
                                    </li>
                                  </ul>
                                  {service.endpoints.length > 0 ? (
                                    <ul className="endpoint-list">
                                      {service.endpoints.slice(0, 3).map((endpoint) => (
                                        <li
                                          key={`${service.id}-${endpoint.name}-${endpoint.port ?? "none"}`}
                                        >
                                          {endpoint.name} ·{" "}
                                          {endpoint.url ??
                                            `${endpoint.host ?? "host"}:${
                                              endpoint.port ?? "?"
                                            }${endpoint.path ?? ""}`}
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <p className="step-meta">
                                      No explicit endpoints have been discovered for this
                                      container yet.
                                    </p>
                                  )}
                                </article>
                              ))}
                            </div>
                          ) : (
                            <p className="muted service-inline-copy">
                              No current unmatched container metadata aligns with this candidate.
                            </p>
                          )}
                        </article>

                        <article className="system-profile-card system-profile-card-wide">
                          <div className="memory-section-header">
                            <div>
                              <p className="detail-label">Review actions</p>
                              <p className="muted">
                                Promote writes a reviewed descriptor to `services/user/...`.
                                Defer and dismiss remain quarantine-only actions.
                              </p>
                            </div>
                            <div className="action-strip">
                              <button
                                className={`note-button ${
                                  quarantinedDescriptorEditorState.open
                                    ? "note-button-primary"
                                    : "note-button-ghost"
                                }`}
                                disabled={quarantinedDescriptorMutationState.submitting}
                                onClick={() =>
                                  setQuarantinedDescriptorEditorState((current) => ({
                                    ...current,
                                    open: !current.open,
                                  }))
                                }
                                type="button"
                              >
                                {quarantinedDescriptorEditorState.open
                                  ? "Close YAML draft"
                                  : "Edit YAML draft"}
                              </button>
                              <button
                                className="note-button note-button-ghost"
                                disabled={
                                  quarantinedDescriptorMutationState.submitting ||
                                  quarantinedDescriptorEditorState.open
                                }
                                onClick={() => {
                                  void runQuarantinedDescriptorAction("defer");
                                }}
                                type="button"
                              >
                                {quarantinedDescriptorMutationState.submitting &&
                                quarantinedDescriptorMutationState.action === "defer"
                                  ? "Deferring…"
                                  : "Defer"}
                              </button>
                              <button
                                className="note-button note-button-danger"
                                disabled={
                                  quarantinedDescriptorMutationState.submitting ||
                                  quarantinedDescriptorEditorState.open
                                }
                                onClick={() => {
                                  void runQuarantinedDescriptorAction("dismiss");
                                }}
                                type="button"
                              >
                                {quarantinedDescriptorMutationState.submitting &&
                                quarantinedDescriptorMutationState.action === "dismiss"
                                  ? "Dismissing…"
                                  : "Dismiss"}
                              </button>
                              <button
                                className="note-button note-button-primary"
                                disabled={
                                  quarantinedDescriptorMutationState.submitting ||
                                  quarantinedDescriptorEditorState.open
                                }
                                onClick={() => {
                                  void runQuarantinedDescriptorAction("promote");
                                }}
                                type="button"
                              >
                                {quarantinedDescriptorMutationState.submitting &&
                                quarantinedDescriptorMutationState.action === "promote"
                                  ? "Promoting…"
                                  : "Promote"}
                              </button>
                            </div>
                          </div>

                          {quarantinedDescriptorEditorState.open ? (
                            <div className="note-editor descriptor-editor descriptor-review-editor">
                              <label className="note-field note-field-wide">
                                <span>Quarantined descriptor YAML</span>
                                <textarea
                                  className="descriptor-editor-textarea"
                                  onChange={(event) =>
                                    setQuarantinedDescriptorEditorState((current) => ({
                                      ...current,
                                      rawYaml: event.target.value,
                                    }))
                                  }
                                  rows={18}
                                  value={quarantinedDescriptorEditorState.rawYaml}
                                />
                              </label>
                              <p className="step-meta">
                                Saving here updates only the quarantined draft. Promotion remains
                                a separate explicit action.
                              </p>
                              <div className="note-action-row">
                                <button
                                  className="note-button note-button-ghost"
                                  disabled={quarantinedDescriptorMutationState.submitting}
                                  onClick={() =>
                                    setQuarantinedDescriptorEditorState((current) => ({
                                      ...current,
                                      rawYaml:
                                        selectedQuarantinedDescriptor.descriptor.raw_yaml,
                                      open: false,
                                    }))
                                  }
                                  type="button"
                                >
                                  Close draft
                                </button>
                                <button
                                  className="note-button note-button-ghost"
                                  disabled={
                                    quarantinedDescriptorMutationState.submitting ||
                                    !selectedQuarantinedDraftDirty
                                  }
                                  onClick={() =>
                                    setQuarantinedDescriptorEditorState((current) => ({
                                      ...current,
                                      rawYaml:
                                        selectedQuarantinedDescriptor.descriptor.raw_yaml,
                                    }))
                                  }
                                  type="button"
                                >
                                  Reset draft
                                </button>
                                <button
                                  className="note-button note-button-primary"
                                  disabled={
                                    quarantinedDescriptorMutationState.submitting ||
                                    !selectedQuarantinedDraftDirty
                                  }
                                  onClick={() => {
                                    void saveQuarantinedDescriptorDraft();
                                  }}
                                  type="button"
                                >
                                  {quarantinedDescriptorMutationState.submitting &&
                                  quarantinedDescriptorMutationState.action === "save"
                                    ? "Saving draft…"
                                    : "Save draft"}
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="detail-grid">
                              <article className="service-inline-item">
                                <p className="detail-label">Generated endpoints</p>
                                {selectedQuarantinedDescriptor.descriptor.endpoints.length > 0 ? (
                                  <ul className="endpoint-list">
                                    {selectedQuarantinedDescriptor.descriptor.endpoints.map(
                                      (endpoint) => (
                                        <li key={`queue-endpoint-${endpoint.name}`}>
                                          {endpoint.name} · {endpoint.port}
                                          {endpoint.path ? ` · ${endpoint.path}` : ""}
                                          {endpoint.healthy_when
                                            ? ` · ${endpoint.healthy_when}`
                                            : ""}
                                        </li>
                                      ),
                                    )}
                                  </ul>
                                ) : (
                                  <p className="muted service-inline-copy">
                                    No endpoints were generated for this candidate.
                                  </p>
                                )}
                              </article>
                              <article className="service-inline-item">
                                <p className="detail-label">Generated dependencies</p>
                                {selectedQuarantinedDescriptor.descriptor
                                  .typical_dependency_containers.length > 0 ||
                                selectedQuarantinedDescriptor.descriptor
                                  .typical_dependency_shares.length > 0 ? (
                                  <>
                                    {selectedQuarantinedDescriptor.descriptor
                                      .typical_dependency_containers.length > 0 ? (
                                      <ul className="chip-list service-inline-chip-list">
                                        {selectedQuarantinedDescriptor.descriptor.typical_dependency_containers.map(
                                          (dependency) => (
                                            <li key={`queue-dependency-${dependency.name}`}>
                                              <span className="chip ghost">
                                                {dependency.name}
                                              </span>
                                            </li>
                                          ),
                                        )}
                                      </ul>
                                    ) : null}
                                    {selectedQuarantinedDescriptor.descriptor
                                      .typical_dependency_shares.length > 0 ? (
                                      <p className="step-meta">
                                        Shares:{" "}
                                        {selectedQuarantinedDescriptor.descriptor.typical_dependency_shares.join(
                                          ", ",
                                        )}
                                      </p>
                                    ) : null}
                                  </>
                                ) : (
                                  <p className="muted service-inline-copy">
                                    No dependencies were generated for this candidate.
                                  </p>
                                )}
                              </article>
                            </div>
                          )}
                        </article>
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </section>

          <section className="panel phase-two-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Memory Browser</p>
                <h2>{memoryBrowserHeading}</h2>
              </div>
              <p className="panel-meta">{memoryBrowserMeta}</p>
            </div>

            <div className="memory-tab-strip" role="tablist" aria-label="Memory browser tabs">
              <MemoryTabButton
                active={activeMemoryTab === "journal"}
                label="Journal"
                onClick={() => setActiveMemoryTab("journal")}
              />
              <MemoryTabButton
                active={activeMemoryTab === "notes"}
                label="Notes"
                onClick={() => setActiveMemoryTab("notes")}
              />
              <MemoryTabButton
                active={activeMemoryTab === "system"}
                label="System"
                onClick={() => setActiveMemoryTab("system")}
              />
              <MemoryTabButton
                active={activeMemoryTab === "recurrence"}
                label="Recurrence"
                onClick={() => setActiveMemoryTab("recurrence")}
              />
              <MemoryTabButton
                active={activeMemoryTab === "facts"}
                label="Facts"
                onClick={() => setActiveMemoryTab("facts")}
              />
            </div>

            {activeMemoryTab === "journal" ? (
              <div className="memory-summary-grid">
                <MemorySummaryStat label="Confirmed" value={confirmedJournalCount} tone="calm" />
                <MemorySummaryStat
                  label="User confirmed"
                  value={userConfirmedJournalCount}
                  tone="warm"
                />
                <MemorySummaryStat
                  label="Needs review"
                  value={journalEntriesNeedingReviewCount}
                  tone="alert"
                />
              </div>
            ) : activeMemoryTab === "notes" ? (
              <div className="memory-summary-grid">
                <MemorySummaryStat label="Active notes" value={sortedUserNotes.length} tone="calm" />
                <MemorySummaryStat
                  label="Excluded"
                  value={excludedNotesCount}
                  tone="alert"
                />
                <MemorySummaryStat
                  label="Stale"
                  value={staleNotesCount}
                  tone="warm"
                />
              </div>
            ) : state.systemProfile ? (
              <div className="memory-summary-grid">
                <MemorySummaryStat
                  label="Containers"
                  value={state.systemProfile.services_summary.total_containers}
                  tone="calm"
                />
                <MemorySummaryStat
                  label="VMs"
                  value={state.systemProfile.services_summary.total_vms}
                  tone="warm"
                />
                <MemorySummaryStat label="Storage used" value={systemProfileStorageUsage} tone="alert" />
              </div>
            ) : activeMemoryTab === "recurrence" ? (
              <div className="memory-summary-grid">
                <MemorySummaryStat
                  label="Active patterns"
                  value={recurrencePatterns.length}
                  tone="calm"
                />
                <MemorySummaryStat
                  label="Services impacted"
                  value={impactedRecurrenceServicesCount}
                  tone="warm"
                />
                <MemorySummaryStat
                  label="Highest recurrence"
                  value={highestRecurrenceCount === 0 ? "None" : `${highestRecurrenceCount}x`}
                  tone="alert"
                />
              </div>
            ) : (
              <div className="memory-summary-grid">
                <MemorySummaryStat
                  label="Adapters checked"
                  value={
                    serviceAdapterFactsState.loading ? "…" : selectedServiceFactAdapters.length
                  }
                  tone="calm"
                />
                <MemorySummaryStat
                  label="Current facts"
                  value={serviceAdapterFactsState.loading ? "…" : currentFactsCount}
                  tone="warm"
                />
                <MemorySummaryStat
                  label="Needs caution"
                  value={serviceAdapterFactsState.loading ? "…" : attentionFactsCount}
                  tone="alert"
                />
              </div>
            )}

            {activeMemoryTab === "journal" ? (
            <div className="memory-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">Journal tab</p>
                  <p className="muted">
                    Auto-written incident journal entries with explicit provenance, confidence,
                    and freshness context.
                  </p>
                </div>
                {selectedService ? (
                  <span className="chip ghost">
                    {selectedServiceJournalCount} linked to {selectedService.name}
                  </span>
                ) : null}
              </div>
              {sortedJournalEntries.length > 0 ? (
                <div className="memory-list memory-journal-list">
                  {sortedJournalEntries.map((entry) => {
                    const linkedToSelectedService =
                      selectedService !== null && entry.services.includes(selectedService.id);
                    const needsReview = journalEntryNeedsReview(entry);
                    const active = entry.incident_id === selectedIncident?.id;
                    const nextServiceId = entry.services[0] ?? selectedService?.id ?? null;

                    return (
                    <article
                      key={entry.id}
                      className={`memory-item journal-entry-card ${
                        active ? "selected" : ""
                      } ${linkedToSelectedService ? "relevant" : ""} ${
                        needsReview ? "review" : ""
                      }`}
                      onClick={() => {
                        setSelectedIncidentId(entry.incident_id);
                        setSelectedServiceId(nextServiceId);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedIncidentId(entry.incident_id);
                          setSelectedServiceId(nextServiceId);
                        }
                      }}
                      role="button"
                      tabIndex={0}
                    >
                      <div className="timeline-topline">
                        <div className="memory-badge-strip">
                          <span
                            className={`status-pill journal-confidence confidence-${entry.confidence}`}
                          >
                            {formatLabel(entry.confidence)}
                          </span>
                          <span className="chip ghost">{journalProvenanceLabel(entry)}</span>
                          {entry.user_confirmed ? <span className="chip">User confirmed</span> : null}
                          {needsReview ? (
                            <span className="chip review-chip">
                              {entry.superseded_by ? "Superseded" : "Needs review"}
                            </span>
                          ) : null}
                        </div>
                        <span className="step-meta">{formatDate(entry.date)}</span>
                      </div>
                      <p className="timeline-service">{entry.summary}</p>
                      <div className="memory-service-row">
                        <ul className="chip-list">
                          {entry.services.map((serviceId) => (
                            <li key={`${entry.id}-${serviceId}`}>
                              <span className="chip ghost">
                                {serviceNames.get(serviceId) ?? serviceId}
                              </span>
                            </li>
                          ))}
                        </ul>
                        <span className="step-meta">Incident {entry.incident_id}</span>
                      </div>
                      <div className="journal-copy-grid">
                        <div className="journal-copy-block">
                          <p className="detail-label">Root cause</p>
                          <p className="muted">{entry.root_cause}</p>
                        </div>
                        <div className="journal-copy-block">
                          <p className="detail-label">Resolution</p>
                          <p className="muted">{entry.resolution}</p>
                        </div>
                      </div>
                      <div className="journal-provenance-line">
                        <span className="step-meta">
                          Source {journalSourceSummary(entry)} · model{" "}
                          {formatLabel(entry.model_used)}
                        </span>
                        <span className="step-meta">{journalTrustSummary(entry)}</span>
                      </div>
                      {entry.applies_to_version ? (
                        <p className="step-meta">Version scope: {entry.applies_to_version}</p>
                      ) : null}
                      <p className="memory-link">Open linked investigation</p>
                    </article>
                    );
                  })}
                </div>
              ) : (
                <p className="muted">No journal entries are currently persisted.</p>
              )}
            </div>
            ) : null}

            {activeMemoryTab === "notes" ? (
            <div className="memory-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">Notes tab</p>
                  <p className="muted">
                    User-managed notes grouped by service with explicit model-safety and freshness
                    context.
                  </p>
                </div>
                <span className="chip ghost">
                  {selectedService ? `${selectedServiceNoteCount} linked to ${selectedService.name}` : `${globalNotesCount} global`}
                </span>
              </div>

              <form
                className="note-editor"
                onSubmit={(event) => {
                  event.preventDefault();
                  void submitNoteEditor();
                }}
              >
                <div className="memory-section-header">
                  <div>
                    <p className="detail-label">
                      {editingNoteId === null ? "Quick add note" : "Edit note"}
                    </p>
                    <p className="muted">
                      Notes marked excluded never enter model prompts. Global notes stay detached
                      from any one service.
                    </p>
                  </div>
                  {editingNoteId !== null ? (
                    <button
                      className="note-button note-button-ghost"
                      type="button"
                      onClick={() => {
                        setEditingNoteId(null);
                        setNoteEditorState(createEmptyNoteEditorState(selectedService?.id ?? null));
                        setNoteMutationState((current) => ({
                          ...current,
                          error: null,
                        }));
                      }}
                    >
                      Cancel edit
                    </button>
                  ) : null}
                </div>
                <div className="note-editor-grid">
                  <label className="note-field">
                    <span className="detail-label">Service</span>
                    <select
                      value={noteEditorState.serviceId}
                      onChange={(event) => {
                        setNoteEditorState((current) => ({
                          ...current,
                          serviceId: event.target.value,
                        }));
                      }}
                    >
                      <option value="">Global note</option>
                      {services
                        .slice()
                        .sort((left, right) => left.name.localeCompare(right.name))
                        .map((service) => (
                          <option key={service.id} value={service.id}>
                            {service.name}
                          </option>
                        ))}
                    </select>
                  </label>

                  <label className="note-field note-field-wide">
                    <span className="detail-label">Note</span>
                    <textarea
                      rows={4}
                      value={noteEditorState.note}
                      onChange={(event) => {
                        setNoteEditorState((current) => ({
                          ...current,
                          note: event.target.value,
                        }));
                      }}
                      placeholder="Add the operator context Kaval should preserve here."
                    />
                  </label>

                  <label className="note-field">
                    <span className="detail-label">Last verified</span>
                    <input
                      type="datetime-local"
                      value={noteEditorState.lastVerifiedAt}
                      onChange={(event) => {
                        setNoteEditorState((current) => ({
                          ...current,
                          lastVerifiedAt: event.target.value,
                        }));
                      }}
                    />
                  </label>

                  <div className="note-toggle-row">
                    <label className="note-toggle">
                      <input
                        checked={noteEditorState.safeForModel}
                        type="checkbox"
                        onChange={(event) => {
                          setNoteEditorState((current) => ({
                            ...current,
                            safeForModel: event.target.checked,
                          }));
                        }}
                      />
                      <span>Safe for model use</span>
                    </label>
                    <label className="note-toggle">
                      <input
                        checked={noteEditorState.stale}
                        type="checkbox"
                        onChange={(event) => {
                          setNoteEditorState((current) => ({
                            ...current,
                            stale: event.target.checked,
                          }));
                        }}
                      />
                      <span>Mark as stale</span>
                    </label>
                  </div>
                </div>

                <div className="note-action-row">
                  {noteMutationState.error ? (
                    <p className="note-error">{noteMutationState.error}</p>
                  ) : null}
                  <button
                    className="note-button note-button-primary"
                    disabled={noteMutationState.saving && noteMutationState.targetNoteId === editingNoteId}
                    type="submit"
                  >
                    {noteMutationState.saving && noteMutationState.targetNoteId === editingNoteId
                      ? "Saving…"
                      : editingNoteId === null
                        ? "Add note"
                        : "Save note"}
                  </button>
                </div>
              </form>

              <div className="memory-section-header">
                <label className="note-search">
                  <span className="detail-label">Search notes</span>
                  <input
                    type="search"
                    value={noteSearch}
                    onChange={(event) => setNoteSearch(event.target.value)}
                    placeholder="Search text or service name"
                  />
                </label>
                <span className="chip ghost">{filteredUserNotes.length} matching</span>
              </div>

              {userNoteGroups.length > 0 ? (
                <div className="memory-list note-group-list">
                  {userNoteGroups.map((group) => (
                    <section key={group.key} className="note-group">
                      <div className="memory-section-header">
                        <div>
                          <p className="detail-label">{group.label}</p>
                          <p className="muted">
                            {group.serviceId === null
                              ? "General operator context not tied to a single service."
                              : "Notes attached to one service in operational memory."}
                          </p>
                        </div>
                        <span className="chip ghost">{group.notes.length} notes</span>
                      </div>

                      <div className="memory-list">
                        {group.notes.map((note) => {
                          const noteBusy =
                            noteMutationState.saving &&
                            noteMutationState.targetNoteId === note.id;
                          const relevant =
                            selectedService !== null && note.service_id === selectedService.id;

                          return (
                            <article
                              key={note.id}
                              className={`memory-item note-card ${relevant ? "relevant" : ""} ${
                                !note.safe_for_model ? "excluded" : ""
                              } ${note.stale ? "review" : ""}`}
                            >
                              <div className="timeline-topline">
                                <div className="memory-badge-strip">
                                  <span className="chip ghost">User-created</span>
                                  <span
                                    className={`status-pill ${
                                      note.safe_for_model ? "note-safe" : "note-excluded"
                                    }`}
                                  >
                                    {note.safe_for_model ? "Model-safe" : "Excluded"}
                                  </span>
                                  {note.stale ? <span className="chip review-chip">Stale</span> : null}
                                </div>
                                <span className="step-meta">{formatTimestamp(note.updated_at)}</span>
                              </div>
                              <p className="timeline-service">
                                {note.service_id
                                  ? serviceNames.get(note.service_id) ?? note.service_id
                                  : "General note"}
                              </p>
                              <p className="muted">{note.note}</p>
                              <div className="journal-provenance-line">
                                <span className="step-meta">
                                  {note.last_verified_at
                                    ? `Verified ${formatTimestamp(note.last_verified_at)}`
                                    : "Not yet re-verified"}
                                </span>
                                <span className="step-meta">
                                  {note.safe_for_model
                                    ? "Eligible for prompt use"
                                    : "Never included in prompts"}
                                </span>
                              </div>
                              <div className="note-action-row">
                                <button
                                  className="note-button note-button-ghost"
                                  type="button"
                                  onClick={() => {
                                    setEditingNoteId(note.id);
                                    setNoteEditorState(createNoteEditorState(note));
                                    setNoteMutationState((current) => ({
                                      ...current,
                                      error: null,
                                    }));
                                  }}
                                >
                                  Edit
                                </button>
                                <button
                                  className="note-button note-button-ghost"
                                  disabled={noteBusy}
                                  type="button"
                                  onClick={() => {
                                    void archiveNote(note.id);
                                  }}
                                >
                                  {noteBusy ? "Working…" : "Archive"}
                                </button>
                                <button
                                  className="note-button note-button-danger"
                                  disabled={noteBusy}
                                  type="button"
                                  onClick={() => {
                                    void deleteNote(note.id);
                                  }}
                                >
                                  {noteBusy ? "Working…" : "Delete"}
                                </button>
                              </div>
                            </article>
                          );
                        })}
                      </div>
                    </section>
                  ))}
                </div>
              ) : (
                <p className="muted">No user notes match the current filters.</p>
              )}
            </div>
            ) : null}

            {activeMemoryTab === "system" ? (
            <div className="memory-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">System tab</p>
                  <p className="muted">
                    Current auto-generated system memory snapshot with explicit provenance.
                    Historical profile diff is only shown where stored, and the current repo state
                    exposes a single snapshot.
                  </p>
                </div>
                {state.systemProfile ? (
                  <span className="chip ghost">
                    Updated {formatTimestamp(state.systemProfile.last_updated)}
                  </span>
                ) : null}
              </div>

              {state.systemProfile ? (
                <>
                  <article className="system-profile-snapshot">
                    <div className="timeline-topline">
                      <div className="memory-badge-strip">
                        <span className="chip ghost">Auto-generated snapshot</span>
                        <span className="chip ghost">{state.systemProfile.hostname}</span>
                        <span className="chip ghost">
                          Unraid {state.systemProfile.unraid_version}
                        </span>
                        {state.systemProfile.networking.ssl_strategy ? (
                          <span className="chip">{state.systemProfile.networking.ssl_strategy}</span>
                        ) : null}
                      </div>
                      <span className="step-meta">
                        Source operational memory · {formatTimestamp(state.systemProfile.last_updated)}
                      </span>
                    </div>
                    <p className="timeline-service">Current system profile</p>
                    <p className="muted">
                      This tab shows the latest persisted profile only. No historical system
                      profile diff has been stored yet, so Kaval does not infer prior values here.
                    </p>
                  </article>

                  <div className="system-profile-grid">
                    <article className="system-profile-card">
                      <p className="detail-label">Hardware</p>
                      <ul className="system-profile-list">
                        <li>
                          <span>CPU</span>
                          <strong>{state.systemProfile.hardware.cpu}</strong>
                        </li>
                        <li>
                          <span>Memory</span>
                          <strong>{formatGigabytes(state.systemProfile.hardware.memory_gb)}</strong>
                        </li>
                        <li>
                          <span>GPU</span>
                          <strong>{formatOptionalValue(state.systemProfile.hardware.gpu)}</strong>
                        </li>
                        <li>
                          <span>UPS</span>
                          <strong>{formatOptionalValue(state.systemProfile.hardware.ups)}</strong>
                        </li>
                      </ul>
                    </article>

                    <article className="system-profile-card">
                      <p className="detail-label">Storage</p>
                      <ul className="system-profile-list">
                        <li>
                          <span>Parity drives</span>
                          <strong>{state.systemProfile.storage.array.parity_drives}</strong>
                        </li>
                        <li>
                          <span>Data drives</span>
                          <strong>{state.systemProfile.storage.array.data_drives}</strong>
                        </li>
                        <li>
                          <span>Cache</span>
                          <strong>{formatOptionalValue(state.systemProfile.storage.array.cache)}</strong>
                        </li>
                        <li>
                          <span>Capacity</span>
                          <strong>
                            {formatTerabytes(state.systemProfile.storage.array.used_tb)} of{" "}
                            {formatTerabytes(state.systemProfile.storage.array.total_tb)}
                          </strong>
                        </li>
                      </ul>
                    </article>

                    <article className="system-profile-card">
                      <p className="detail-label">Networking</p>
                      <ul className="system-profile-list">
                        <li>
                          <span>Domain</span>
                          <strong>{formatOptionalValue(state.systemProfile.networking.domain)}</strong>
                        </li>
                        <li>
                          <span>DNS provider</span>
                          <strong>
                            {formatOptionalValue(state.systemProfile.networking.dns_provider)}
                          </strong>
                        </li>
                        <li>
                          <span>Reverse proxy</span>
                          <strong>
                            {formatOptionalValue(state.systemProfile.networking.reverse_proxy)}
                          </strong>
                        </li>
                        <li>
                          <span>Tunnel</span>
                          <strong>{formatOptionalValue(state.systemProfile.networking.tunnel)}</strong>
                        </li>
                        <li>
                          <span>VPN</span>
                          <strong>{formatOptionalValue(state.systemProfile.networking.vpn)}</strong>
                        </li>
                        <li>
                          <span>DNS resolver</span>
                          <strong>
                            {formatOptionalValue(state.systemProfile.networking.dns_resolver)}
                          </strong>
                        </li>
                        <li>
                          <span>SSL strategy</span>
                          <strong>
                            {formatOptionalValue(state.systemProfile.networking.ssl_strategy)}
                          </strong>
                        </li>
                      </ul>
                    </article>

                    <article className="system-profile-card">
                      <p className="detail-label">Service inventory</p>
                      <ul className="system-profile-list">
                        <li>
                          <span>Matched descriptors</span>
                          <strong>{state.systemProfile.services_summary.matched_descriptors}</strong>
                        </li>
                        <li>
                          <span>Containers</span>
                          <strong>{state.systemProfile.services_summary.total_containers}</strong>
                        </li>
                        <li>
                          <span>Virtual machines</span>
                          <strong>{state.systemProfile.services_summary.total_vms}</strong>
                        </li>
                        <li>
                          <span>Plugins</span>
                          <strong>{state.systemProfile.plugins.length}</strong>
                        </li>
                      </ul>
                    </article>

                    <article className="system-profile-card system-profile-card-wide">
                      <p className="detail-label">Virtual machines</p>
                      {state.systemProfile.vms.length > 0 ? (
                        <div className="system-vm-list">
                          {state.systemProfile.vms.map((vm) => (
                            <article className="system-vm-card" key={vm.name}>
                              <div className="timeline-topline">
                                <p className="timeline-service">{vm.name}</p>
                                <span className="chip ghost">
                                  {vm.gpu_passthrough ? "GPU passthrough" : "No passthrough"}
                                </span>
                              </div>
                              <ul className="system-profile-list compact">
                                <li>
                                  <span>Purpose</span>
                                  <strong>{vm.purpose}</strong>
                                </li>
                                <li>
                                  <span>OS</span>
                                  <strong>{formatOptionalValue(vm.os)}</strong>
                                </li>
                                <li>
                                  <span>Type</span>
                                  <strong>{formatOptionalValue(vm.type)}</strong>
                                </li>
                                <li>
                                  <span>Quirks</span>
                                  <strong>{formatOptionalValue(vm.quirks)}</strong>
                                </li>
                              </ul>
                            </article>
                          ))}
                        </div>
                      ) : (
                        <p className="muted">No virtual machines are recorded in this snapshot.</p>
                      )}
                    </article>

                    <article className="system-profile-card system-profile-card-wide">
                      <div className="timeline-topline">
                        <p className="detail-label">Plugin facets</p>
                        <span className="chip ghost">
                          {state.systemProfile.plugins.length} tracked
                        </span>
                      </div>
                      {state.systemProfile.plugins.length > 0 ? (
                        <div className="system-plugin-list">
                          {state.systemProfile.plugins.map((plugin) => (
                            <article className="system-plugin-card" key={plugin.name}>
                              <div className="timeline-topline">
                                <p className="timeline-service">{plugin.name}</p>
                                <div className="adapter-state-strip">
                                  <span className="chip ghost">
                                    {plugin.enabled === null
                                      ? "State unknown"
                                      : plugin.enabled
                                        ? "Enabled"
                                        : "Disabled"}
                                  </span>
                                  <span className="chip ghost">
                                    {plugin.update_available === null
                                      ? "Update unknown"
                                      : plugin.update_available
                                        ? "Update available"
                                        : "Up to date"}
                                  </span>
                                </div>
                              </div>
                              <ul className="system-profile-list compact">
                                <li>
                                  <span>Version</span>
                                  <strong>{formatOptionalValue(plugin.version)}</strong>
                                </li>
                                <li>
                                  <span>Impacted services</span>
                                  <strong>{plugin.impacted_services.length}</strong>
                                </li>
                              </ul>
                              {plugin.impacted_services.length > 0 ? (
                                <>
                                  <p className="step-meta">
                                    Impact annotations come only from explicit descriptor
                                    `plugin_dependencies` metadata.
                                  </p>
                                  <ul className="chip-list service-inline-chip-list">
                                    {plugin.impacted_services.map((service) => (
                                      <li
                                        key={`${plugin.name}-${service.service_id}-${service.descriptor_id}`}
                                      >
                                        <span className="chip ghost">{service.service_name}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </>
                              ) : (
                                <p className="muted service-inline-copy">
                                  No current descriptor declares this plugin as a service impact.
                                </p>
                              )}
                            </article>
                          ))}
                        </div>
                      ) : (
                        <p className="muted">
                          No persisted plugin facets are recorded in this snapshot.
                        </p>
                      )}
                    </article>

                    <article className="system-profile-card system-profile-card-wide">
                      <p className="detail-label">Diff and history</p>
                      <p className="muted">
                        Historical system-profile versions are not stored in the current Phase 3B
                        repo state. This view intentionally shows only current values and last
                        update time, not inferred before/after comparisons.
                      </p>
                    </article>
                  </div>
                </>
              ) : (
                <p className="muted">
                  No system profile has been persisted yet, so the system tab cannot show a current
                  snapshot.
                </p>
              )}
            </div>
            ) : null}

            {activeMemoryTab === "recurrence" ? (
            <div className="memory-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">Recurrence tab</p>
                  <p className="muted">
                    Active recurrence patterns derived from recurrence-backed journal entries.
                    Fix guidance below stays advisory and is limited to persisted journal lessons
                    and exact service-scope history.
                  </p>
                </div>
                <span className="chip ghost">
                  {selectedService
                    ? `${selectedServiceRecurrenceCount} linked to ${selectedService.name}`
                    : `${impactedRecurrenceServicesCount} services impacted`}
                </span>
              </div>

              {recurrencePatterns.length > 0 ? (
                <div className="memory-list recurrence-pattern-list">
                  {recurrencePatterns.map((pattern) => {
                    const { activeEntry, priorEntries } = pattern;
                    const relevant =
                      selectedService !== null &&
                      activeEntry.services.includes(selectedService.id);
                    const active = activeEntry.incident_id === selectedIncident?.id;
                    const nextServiceId = activeEntry.services[0] ?? selectedService?.id ?? null;

                    return (
                      <article
                        key={activeEntry.id}
                        className={`memory-item recurrence-card ${
                          active ? "selected" : ""
                        } ${relevant ? "relevant" : ""}`}
                        onClick={() => {
                          setSelectedIncidentId(activeEntry.incident_id);
                          setSelectedServiceId(nextServiceId);
                        }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedIncidentId(activeEntry.incident_id);
                            setSelectedServiceId(nextServiceId);
                          }
                        }}
                        role="button"
                        tabIndex={0}
                      >
                        <div className="timeline-topline">
                          <div className="memory-badge-strip">
                            <span
                              className={`status-pill journal-confidence confidence-${activeEntry.confidence}`}
                            >
                              {formatLabel(activeEntry.confidence)}
                            </span>
                            <span className="chip ghost">Recurrence-backed</span>
                            <span className="chip">{activeEntry.recurrence_count}x seen</span>
                          </div>
                          <span className="step-meta">{formatDate(activeEntry.date)}</span>
                        </div>
                        <p className="timeline-service">{activeEntry.summary}</p>
                        <div className="memory-service-row">
                          <ul className="chip-list">
                            {activeEntry.services.map((serviceId) => (
                              <li key={`${activeEntry.id}-${serviceId}`}>
                                <span className="chip ghost">
                                  {serviceNames.get(serviceId) ?? serviceId}
                                </span>
                              </li>
                            ))}
                          </ul>
                          <span className="step-meta">Incident {activeEntry.incident_id}</span>
                        </div>
                        <div className="journal-copy-grid">
                          <div className="journal-copy-block">
                            <p className="detail-label">Latest resolution</p>
                            <p className="muted">{activeEntry.resolution}</p>
                          </div>
                          <div className="journal-copy-block">
                            <p className="detail-label">Advisory fix direction</p>
                            <p className="muted">{activeEntry.lesson}</p>
                          </div>
                        </div>
                        <div className="journal-provenance-line">
                          <span className="step-meta">
                            Derived from recurrence-backed journal history
                          </span>
                          <span className="step-meta">{journalTrustSummary(activeEntry)}</span>
                        </div>

                        <div className="recurrence-support-block">
                          <p className="detail-label">Supporting history</p>
                          {priorEntries.length > 0 ? (
                            <ul className="recurrence-resolution-list">
                              {priorEntries.map((entry) => (
                                <li key={entry.id}>
                                  <span className="step-meta">{formatDate(entry.date)}</span>
                                  <p className="muted">
                                    {entry.summary} Resolution: {entry.resolution}
                                  </p>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="muted">
                              No prior exact service-scope resolutions are stored beyond the active
                              recurrence marker.
                            </p>
                          )}
                        </div>
                        <p className="memory-link">Open linked investigation</p>
                      </article>
                    );
                  })}
                </div>
              ) : (
                <p className="muted">
                  No active recurrence patterns are currently persisted in operational memory.
                </p>
              )}
            </div>
            ) : null}

            {activeMemoryTab === "facts" ? (
            <div className="memory-section">
              <div className="memory-section-header">
                <div>
                  <p className="detail-label">Facts tab</p>
                  <p className="muted">
                    Read-only adapter-imported facts for the selected service. Kaval only shows
                    prompt-safe payloads here and marks stale, unavailable, or redacted data
                    explicitly instead of inferring missing facts.
                  </p>
                </div>
                <span className="chip ghost">
                  {selectedService
                    ? `${selectedServiceFactAdapters.length} adapters on ${selectedService.name}`
                    : "No service selected"}
                </span>
              </div>

              {selectedService === null ? (
                <p className="muted">
                  Select a service to inspect the current adapter-backed facts contract.
                </p>
              ) : serviceAdapterFactsState.loading ? (
                <p className="muted">
                  Loading adapter facts for {selectedService.name}…
                </p>
              ) : serviceAdapterFactsState.error ? (
                <p className="muted">{serviceAdapterFactsState.error}</p>
              ) : selectedServiceFacts ? (
                <>
                  <article className="system-profile-snapshot fact-snapshot">
                    <div className="timeline-topline">
                      <div className="memory-badge-strip">
                        <span className="chip ghost">Read-only</span>
                        <span className="chip ghost">Prompt-safe facts only</span>
                        {redactedFactPathCount > 0 ? (
                          <span className="chip">{redactedFactPathCount} redacted paths</span>
                        ) : null}
                        {staleFactsCount > 0 ? (
                          <span className="chip review-chip">{staleFactsCount} stale</span>
                        ) : null}
                      </div>
                      <span className="step-meta">
                        Checked {formatTimestamp(selectedServiceFacts.checked_at)}
                      </span>
                    </div>
                    <p className="timeline-service">{selectedServiceFacts.service_name}</p>
                    <p className="muted">
                      Facts remain tied to the selected service and their original adapter source.
                      Redacted or unavailable fields stay absent rather than being guessed back
                      into the UI.
                    </p>
                  </article>

                  {selectedServiceFactAdapters.length > 0 ? (
                    <div className="memory-list fact-list">
                      {selectedServiceFactAdapters.map((adapter) => (
                        <article
                          key={adapter.adapter_id}
                          className={`memory-item fact-card fact-${adapter.freshness} ${
                            adapter.facts_available ? "fact-available" : "fact-missing"
                          }`}
                        >
                          <div className="timeline-topline">
                            <div className="memory-badge-strip">
                              <span className="chip ghost">{formatLabel(adapter.source)}</span>
                              <span
                                className={`status-pill fact-freshness fact-freshness-${adapter.freshness}`}
                              >
                                {formatLabel(adapter.freshness)}
                              </span>
                              <span className="chip ghost">
                                {formatLabel(adapter.configuration_state)}
                              </span>
                              <span className="chip ghost">
                                {formatLabel(adapter.health_state)}
                              </span>
                              {adapter.read_only ? (
                                <span className="chip ghost">Read-only</span>
                              ) : null}
                            </div>
                            <span className="step-meta">
                              {adapter.facts_observed_at
                                ? `Observed ${formatTimestamp(adapter.facts_observed_at)}`
                                : `Checked ${formatTimestamp(selectedServiceFacts.checked_at)}`}
                            </span>
                          </div>
                          <p className="timeline-service">{adapter.display_name}</p>
                          <p className="muted">{adapter.configuration_summary}</p>
                          <p className="muted">{adapter.health_summary}</p>

                          <div className="fact-meta-grid">
                            <div className="journal-copy-block">
                              <p className="detail-label">Trust and freshness</p>
                              <ul className="system-profile-list compact fact-meta-list">
                                <li>
                                  <span>Service</span>
                                  <strong>{adapter.service_name}</strong>
                                </li>
                                <li>
                                  <span>Source</span>
                                  <strong>{formatLabel(adapter.source)}</strong>
                                </li>
                                <li>
                                  <span>Freshness</span>
                                  <strong>{formatLabel(adapter.freshness)}</strong>
                                </li>
                                <li>
                                  <span>Next refresh</span>
                                  <strong>{formatOptionalTimestamp(adapter.next_refresh_at)}</strong>
                                </li>
                                <li>
                                  <span>Stale after</span>
                                  <strong>{formatOptionalTimestamp(adapter.stale_at)}</strong>
                                </li>
                              </ul>
                            </div>
                            <div className="journal-copy-block">
                              <p className="detail-label">Execution context</p>
                              <ul className="system-profile-list compact fact-meta-list">
                                <li>
                                  <span>Execution</span>
                                  <strong>{formatOptionalLabel(adapter.execution_status)}</strong>
                                </li>
                                <li>
                                  <span>Refresh cadence</span>
                                  <strong>{adapter.refresh_interval_minutes} min</strong>
                                </li>
                                <li>
                                  <span>Redaction</span>
                                  <strong>
                                    {formatOptionalLabel(adapter.applied_redaction_level)}
                                  </strong>
                                </li>
                                <li>
                                  <span>Excluded paths</span>
                                  <strong>
                                    {adapter.excluded_paths.length > 0
                                      ? adapter.excluded_paths.join(", ")
                                      : "None"}
                                  </strong>
                                </li>
                                <li>
                                  <span>Reason</span>
                                  <strong>{formatOptionalValue(adapter.reason)}</strong>
                                </li>
                              </ul>
                            </div>
                          </div>

                          {adapter.missing_credentials.length > 0 ? (
                            <p className="step-meta">
                              Missing credentials:{" "}
                              {adapter.missing_credentials
                                .map((credential) => formatLabel(credential))
                                .join(", ")}
                            </p>
                          ) : null}

                          {adapter.supported_fact_names.length > 0 ? (
                            <ul className="chip-list fact-chip-list">
                              {adapter.supported_fact_names.map((factName) => (
                                <li key={`${adapter.adapter_id}-${factName}`}>
                                  <span className="chip ghost">{formatLabel(factName)}</span>
                                </li>
                              ))}
                            </ul>
                          ) : null}

                          {adapter.facts_available ? (
                            <>
                              <p className="step-meta">
                                {adapter.freshness === "current"
                                  ? "Prompt-safe fact values below are current for the last successful adapter read."
                                  : "Prompt-safe fact values below are retained for context but are stale and should not be treated as confirmed current state."}
                              </p>
                              <div className="fact-value-grid">
                                {Object.entries(adapter.facts).map(([factName, value]) => (
                                  <article
                                    className="fact-value-card"
                                    key={`${adapter.adapter_id}-${factName}`}
                                  >
                                    <p className="detail-label">{formatLabel(factName)}</p>
                                    <pre className="fact-json-block">
                                      {formatFactValue(value)}
                                    </pre>
                                  </article>
                                ))}
                              </div>
                            </>
                          ) : (
                            <p className="muted">
                              No prompt-safe fact values are currently available for this adapter.
                            </p>
                          )}
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p className="muted">
                      No adapter-backed facts are available for this service in the current repo
                      state.
                    </p>
                  )}
                </>
              ) : (
                <p className="muted">
                  No adapter facts have been loaded for the selected service yet.
                </p>
              )}
            </div>
            ) : null}
          </section>
        </section>
        </>
      ) : null}
    </div>
  );
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Kaval UI could not load ${url}.`);
  }
  return (await response.json()) as T;
}

async function fetchOptionalJson<T>(url: string): Promise<T | null> {
  const response = await fetch(url);
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Kaval UI could not load ${url}.`);
  }
  return (await response.json()) as T;
}

async function readApiError(response: Response, fallback: string): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    if (typeof payload.detail === "string" && payload.detail) {
      return payload.detail;
    }
  } catch {
    return fallback;
  }
  return fallback;
}

async function loadSupplementalPanels(): Promise<SupplementalPanelsState> {
  const [
    capabilityHealth,
    changes,
    credentialRequests,
    effectiveness,
    findingReview,
    journalEntries,
    recommendations,
    systemProfile,
    userNotes,
  ] =
    await Promise.all([
      fetchJson<CapabilityHealthReport>("/api/v1/capability-health"),
      fetchJson<Change[]>("/api/v1/changes"),
      fetchJson<CredentialRequest[]>("/api/v1/credential-requests"),
      fetchJson<EffectivenessReport>("/api/v1/effectiveness"),
      fetchJson<FindingReviewResponse>("/api/v1/findings/review"),
      fetchJson<JournalEntry[]>("/api/v1/journal-entries"),
      fetchJson<RecommendationsResponse>("/api/v1/recommendations"),
      fetchOptionalJson<SystemProfile>("/api/v1/system-profile"),
      fetchJson<UserNote[]>("/api/v1/user-notes"),
    ]);
  return {
    capabilityHealth,
    changes,
    credentialRequests,
    effectiveness,
    findingReview,
    journalEntries,
    recommendations,
    systemProfile,
    userNotes,
  };
}

function scrollToPanel(panelId: string): void {
  if (typeof document === "undefined") {
    return;
  }
  window.requestAnimationFrame(() => {
    document.getElementById(panelId)?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  });
}

function buildAuditTrailEntry(
  change: Change,
  retention: {
    activeDetailRetentionDays: number;
    activeSummaryRetentionDays: number;
  },
  serviceNames: Map<string, string>,
  investigationByIncidentId: Map<string, Investigation>,
): AuditTrailEntry | null {
  const timestampMs = Date.parse(change.timestamp);
  if (!Number.isFinite(timestampMs)) {
    return null;
  }
  const nowMs = Date.now();
  const detailCutoffMs =
    nowMs - retention.activeDetailRetentionDays * 24 * 60 * 60 * 1000;
  const summaryCutoffMs =
    nowMs - retention.activeSummaryRetentionDays * 24 * 60 * 60 * 1000;
  if (timestampMs < summaryCutoffMs) {
    return null;
  }
  const linkedInvestigationIds = Array.from(
    new Set(
      change.correlated_incidents.flatMap((incidentId) => {
        const investigation = investigationByIncidentId.get(incidentId);
        return investigation ? [investigation.id] : [];
      }),
    ),
  );
  return {
    change,
    auditType: deriveAuditEventType(change),
    targetLabel:
      change.service_id === null
        ? "Global"
        : serviceNames.get(change.service_id) ?? change.service_id,
    detailAvailable: timestampMs >= detailCutoffMs,
    linkedInvestigationIds,
  };
}

function deriveAuditEventType(change: Change): AuditEventType {
  if (change.type !== "config_change") {
    switch (change.type) {
      case "service_added":
      case "service_removed":
      case "service_missing":
      case "service_renamed_or_rematched":
        return "service_lifecycle";
      case "image_update":
        return "image_update";
      case "container_restart":
        return "container_restart";
      case "plugin_update":
        return "plugin_update";
      case "unraid_event":
        return "system_event";
      case "external_change":
        return "external_change";
      default:
        return "config_change";
    }
  }

  const description = change.description.toLowerCase();
  if (description.includes("dependency edge")) {
    return "graph_edit";
  }
  if (description.includes("descriptor")) {
    return "descriptor";
  }
  if (description.includes("model settings")) {
    return "model_settings";
  }
  if (description.includes("notification settings")) {
    return "notification_settings";
  }
  if (
    description.includes("monitoring settings") ||
    description.includes("monitoring overrides") ||
    description.includes("suppressed ") ||
    description.includes("restored inherited monitoring")
  ) {
    return "monitoring_settings";
  }
  if (description.includes("system settings")) {
    return "system_settings";
  }
  if (description.includes("credential vault")) {
    return "credential_vault";
  }
  if (description.includes("maintenance")) {
    return "maintenance";
  }
  if (description.includes("dismissed finding")) {
    return "finding_feedback";
  }
  return "config_change";
}

function auditTrailEntryMatchesFilters(
  entry: AuditTrailEntry,
  filters: AuditTrailFilterState,
): boolean {
  if (filters.type !== "all" && entry.auditType !== filters.type) {
    return false;
  }
  if (filters.serviceId === GLOBAL_AUDIT_SERVICE_FILTER && entry.change.service_id !== null) {
    return false;
  }
  if (
    filters.serviceId !== "all" &&
    filters.serviceId !== GLOBAL_AUDIT_SERVICE_FILTER &&
    entry.change.service_id !== filters.serviceId
  ) {
    return false;
  }
  const timestampMs = Date.parse(entry.change.timestamp);
  if (!Number.isFinite(timestampMs)) {
    return false;
  }
  if (filters.dateFrom) {
    const startMs = Date.parse(`${filters.dateFrom}T00:00:00`);
    if (Number.isFinite(startMs) && timestampMs < startMs) {
      return false;
    }
  }
  if (filters.dateTo) {
    const endMs = Date.parse(`${filters.dateTo}T23:59:59.999`);
    if (Number.isFinite(endMs) && timestampMs > endMs) {
      return false;
    }
  }
  return true;
}

function auditEventTriggerSummary(change: Change): string {
  switch (deriveAuditEventType(change)) {
    case "service_lifecycle":
      return "Discovery and lifecycle tracking";
    case "image_update":
    case "container_restart":
      return "Runtime change detection";
    case "plugin_update":
    case "system_event":
    case "external_change":
      return "External or host-level signal";
    default:
      return "Explicit admin UI/API operation";
  }
}

function auditEventResultSummary(change: Change): string {
  if (change.new_value) {
    return change.new_value;
  }
  if (change.old_value) {
    return "Recorded as a clear or removal from the prior state.";
  }
  return "No result payload was recorded for this event.";
}

type AuditTrailExportFormat = "json" | "csv";

function exportAuditTrailEntries(
  entries: AuditTrailEntry[],
  format: AuditTrailExportFormat,
): void {
  const dateSuffix = new Date().toISOString().slice(0, 10);
  if (format === "json") {
    downloadTextFile(
      `kaval-audit-trail-${dateSuffix}.json`,
      `${JSON.stringify(entries.map(buildAuditTrailExportRecord), null, 2)}\n`,
      "application/json",
    );
    return;
  }
  const rows = entries.map((entry) => {
    const record = buildAuditTrailExportRecord(entry);
    return [
      record.id,
      record.timestamp,
      record.audit_type,
      record.change_type,
      record.target,
      record.description,
      record.trigger,
      record.result,
      record.prior_value,
      record.detail_state,
      record.correlated_incidents.join(" | "),
      record.investigation_ids.join(" | "),
    ];
  });
  const header = [
    "id",
    "timestamp",
    "audit_type",
    "change_type",
    "target",
    "description",
    "trigger",
    "result",
    "prior_value",
    "detail_state",
    "correlated_incidents",
    "investigation_ids",
  ];
  const csv = [header, ...rows]
    .map((row) => row.map((value) => csvEscape(value)).join(","))
    .join("\n");
  downloadTextFile(
    `kaval-audit-trail-${dateSuffix}.csv`,
    `${csv}\n`,
    "text/csv;charset=utf-8",
  );
}

function buildAuditTrailExportRecord(entry: AuditTrailEntry): AuditTrailExportRecord {
  return {
    id: entry.change.id,
    timestamp: entry.change.timestamp,
    audit_type: entry.auditType,
    change_type: entry.change.type,
    target: entry.targetLabel,
    description: entry.change.description,
    trigger: auditEventTriggerSummary(entry.change),
    result: entry.detailAvailable ? auditEventResultSummary(entry.change) : "summary_only",
    prior_value: entry.detailAvailable ? entry.change.old_value ?? "" : "",
    detail_state: entry.detailAvailable ? "detailed" : "summary_only",
    correlated_incidents: entry.change.correlated_incidents,
    investigation_ids: entry.linkedInvestigationIds,
  };
}

function buildModelUsageDashboard(
  investigations: Investigation[],
  incidents: Incident[],
): ModelUsageDashboardData {
  const telemetryBackedInvestigations = investigations.filter(hasInvestigationTelemetry);
  const incidentById = new Map(incidents.map((incident) => [incident.id, incident]));
  const windows: ModelUsageWindowSummary[] = [
    buildModelUsageWindow("today", "Today", telemetryBackedInvestigations),
    buildModelUsageWindow("week", "This week", telemetryBackedInvestigations),
    buildModelUsageWindow("month", "This month", telemetryBackedInvestigations),
  ];

  const incidentEntries = Array.from(
    telemetryBackedInvestigations.reduce(
      (entries, investigation) => {
        const existing = entries.get(investigation.incident_id);
        const incident = incidentById.get(investigation.incident_id);
        const latestTimestamp =
          existing?.latestInvestigationAt ??
          recordedInvestigationTimestamp(investigation);
        const nextLatestTimestamp = maxTimestamp(
          latestTimestamp,
          recordedInvestigationTimestamp(investigation),
        );
        const nextReasons = Array.from(
          new Set([
            ...(existing?.cloudEscalationReasons ?? []),
            ...parseCloudEscalationReasons(investigation.cloud_escalation_reason),
          ]),
        );
        entries.set(investigation.incident_id, {
          incidentId: investigation.incident_id,
          incidentTitle: incident?.title ?? `Incident ${investigation.incident_id}`,
          severity: incident?.severity ?? "unknown",
          status: incident?.status ?? "unknown",
          investigationCount: (existing?.investigationCount ?? 0) + 1,
          localModelCalls:
            (existing?.localModelCalls ?? 0) + countLocalModelCalls(investigation),
          cloudModelCalls:
            (existing?.cloudModelCalls ?? 0) + investigation.cloud_model_calls,
          localInputTokens:
            (existing?.localInputTokens ?? 0) + investigation.local_input_tokens,
          localOutputTokens:
            (existing?.localOutputTokens ?? 0) + investigation.local_output_tokens,
          cloudInputTokens:
            (existing?.cloudInputTokens ?? 0) + investigation.cloud_input_tokens,
          cloudOutputTokens:
            (existing?.cloudOutputTokens ?? 0) + investigation.cloud_output_tokens,
          estimatedCloudCostUsd:
            (existing?.estimatedCloudCostUsd ?? 0) +
            investigation.estimated_cloud_cost_usd,
          estimatedTotalCostUsd:
            (existing?.estimatedTotalCostUsd ?? 0) +
            investigation.estimated_total_cost_usd,
          cloudEscalationReasons: nextReasons,
          latestInvestigationAt: nextLatestTimestamp,
        });
        return entries;
      },
      new Map<string, ModelUsageIncidentBreakdown>(),
    ).values(),
  ).sort((left, right) => {
    if (right.estimatedTotalCostUsd !== left.estimatedTotalCostUsd) {
      return right.estimatedTotalCostUsd - left.estimatedTotalCostUsd;
    }
    return (right.latestInvestigationAt ?? "").localeCompare(left.latestInvestigationAt ?? "");
  });

  const escalationEntries = Array.from(
    telemetryBackedInvestigations.reduce(
      (entries, investigation) => {
        const reasons = parseCloudEscalationReasons(investigation.cloud_escalation_reason);
        for (const reason of reasons) {
          const existing = entries.get(reason);
          entries.set(reason, {
            reason,
            label: formatCloudEscalationReason(reason),
            matchedInvestigations: (existing?.matchedInvestigations ?? 0) + 1,
            executedInvestigations:
              (existing?.executedInvestigations ?? 0) +
              (investigation.cloud_model_calls > 0 ? 1 : 0),
            cloudCallCount:
              (existing?.cloudCallCount ?? 0) + investigation.cloud_model_calls,
          });
        }
        return entries;
      },
      new Map<string, ModelUsageEscalationSummary>(),
    ).values(),
  ).sort((left, right) => right.matchedInvestigations - left.matchedInvestigations);

  return {
    telemetryBackedInvestigationCount: telemetryBackedInvestigations.length,
    windows,
    incidents: incidentEntries,
    escalations: escalationEntries,
  };
}

function buildModelUsageWindow(
  key: ModelUsageWindowSummary["key"],
  label: string,
  investigations: Investigation[],
): ModelUsageWindowSummary {
  const startMs = startOfWindowMs(key);
  const matchingInvestigations = investigations.filter((investigation) => {
    const timestamp = recordedInvestigationTimestamp(investigation);
    if (timestamp === null) {
      return false;
    }
    const timestampMs = Date.parse(timestamp);
    return Number.isFinite(timestampMs) && timestampMs >= startMs;
  });
  return matchingInvestigations.reduce<ModelUsageWindowSummary>(
    (summary, investigation) => ({
      ...summary,
      investigationCount: summary.investigationCount + 1,
      localModelCalls: summary.localModelCalls + countLocalModelCalls(investigation),
      cloudModelCalls: summary.cloudModelCalls + investigation.cloud_model_calls,
      localInputTokens: summary.localInputTokens + investigation.local_input_tokens,
      localOutputTokens: summary.localOutputTokens + investigation.local_output_tokens,
      cloudInputTokens: summary.cloudInputTokens + investigation.cloud_input_tokens,
      cloudOutputTokens: summary.cloudOutputTokens + investigation.cloud_output_tokens,
      estimatedCloudCostUsd:
        summary.estimatedCloudCostUsd + investigation.estimated_cloud_cost_usd,
      estimatedTotalCostUsd:
        summary.estimatedTotalCostUsd + investigation.estimated_total_cost_usd,
    }),
    {
      key,
      label,
      investigationCount: 0,
      localModelCalls: 0,
      cloudModelCalls: 0,
      localInputTokens: 0,
      localOutputTokens: 0,
      cloudInputTokens: 0,
      cloudOutputTokens: 0,
      estimatedCloudCostUsd: 0,
      estimatedTotalCostUsd: 0,
    },
  );
}

function hasInvestigationTelemetry(investigation: Investigation): boolean {
  return (
    investigation.local_input_tokens > 0 ||
    investigation.local_output_tokens > 0 ||
    investigation.cloud_input_tokens > 0 ||
    investigation.cloud_output_tokens > 0 ||
    investigation.estimated_cloud_cost_usd > 0 ||
    investigation.estimated_total_cost_usd > 0 ||
    investigation.cloud_escalation_reason !== null
  );
}

function countLocalModelCalls(investigation: Investigation): number {
  return investigation.model_used === "local" || investigation.model_used === "both" ? 1 : 0;
}

function parseCloudEscalationReasons(reason: string | null): string[] {
  if (!reason) {
    return [];
  }
  return reason
    .split("|")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function formatCloudEscalationReason(reason: string): string {
  const labels: Record<string, string> = {
    finding_count_threshold: "Finding count threshold",
    local_confidence_threshold: "Low local confidence",
    multiple_domains_affected: "Multiple domains affected",
    changelog_research_needed: "Changelog research needed",
    user_requested_deep_analysis: "User requested deep analysis",
  };
  return labels[reason] ?? formatLabel(reason);
}

function formatEscalationReasonSummary(reason: string | null): string {
  const parts = parseCloudEscalationReasons(reason).map((entry) =>
    formatCloudEscalationReason(entry),
  );
  return parts.length > 0 ? parts.join(", ") : "None";
}

function recordedInvestigationTimestamp(investigation: Investigation): string | null {
  return investigation.completed_at ?? investigation.started_at ?? null;
}

function startOfWindowMs(key: ModelUsageWindowSummary["key"]): number {
  const now = new Date();
  if (key === "today") {
    return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  }
  if (key === "week") {
    const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    return weekStart.getTime();
  }
  return new Date(now.getFullYear(), now.getMonth(), 1).getTime();
}

function maxTimestamp(left: string | null, right: string | null): string | null {
  if (left === null) {
    return right;
  }
  if (right === null) {
    return left;
  }
  return left.localeCompare(right) >= 0 ? left : right;
}

function csvEscape(value: string | string[]): string {
  const serialized = Array.isArray(value) ? value.join(" | ") : value;
  return `"${serialized.replace(/"/g, '""')}"`;
}

function downloadTextFile(filename: string, contents: string, mimeType: string): void {
  if (typeof document === "undefined") {
    return;
  }
  const blob = new Blob([contents], { type: mimeType });
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function formatLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatCount(value: number): string {
  return value.toLocaleString();
}

function formatUsd(value: number): string {
  if (value >= 1 || value === 0) {
    return `$${value.toFixed(2)}`;
  }
  if (value >= 0.01) {
    return `$${value.toFixed(3)}`;
  }
  return `$${value.toFixed(4)}`;
}

function formatListPreview(values: string[]): string {
  return values.length > 0 ? values.join(", ") : "None";
}

function descriptorIdSegment(detail: ServiceDescriptorView): string {
  const prefix = `${detail.category}/`;
  return detail.descriptor_id.startsWith(prefix)
    ? detail.descriptor_id.slice(prefix.length)
    : detail.descriptor_id;
}

function createDescriptorEditorState(
  detail: ServiceDescriptorView,
  mode: DescriptorEditorMode = "form",
): DescriptorEditorState {
  return {
    mode,
    imagePatterns: serializeEditorList(detail.match.image_patterns),
    containerNamePatterns: serializeEditorList(detail.match.container_name_patterns),
    shareDependencies: serializeEditorList(detail.typical_dependency_shares),
    endpoints:
      detail.endpoints.length > 0
        ? detail.endpoints.map((endpoint) => ({
            clientId: createClientId(),
            name: endpoint.name,
            port: String(endpoint.port),
            path: endpoint.path ?? "",
            auth: endpoint.auth ?? "",
            authHeader: endpoint.auth_header ?? "",
            healthyWhen: endpoint.healthy_when ?? "",
          }))
        : [createEmptyDescriptorEndpointState()],
    containerDependencies:
      detail.typical_dependency_containers.length > 0
        ? detail.typical_dependency_containers.map((dependency) => ({
            clientId: createClientId(),
            name: dependency.name,
            alternatives: dependency.alternatives.join(", "),
          }))
        : [createEmptyDescriptorDependencyState()],
    rawYaml: detail.raw_yaml,
  };
}

function buildDescriptorSavePayload(
  editorState: DescriptorEditorState,
): Record<string, unknown> {
  if (editorState.mode === "yaml") {
    return {
      mode: "yaml",
      raw_yaml: editorState.rawYaml,
    };
  }
  return {
    mode: "form",
    match: {
      image_patterns: parseEditorLines(editorState.imagePatterns),
      container_name_patterns: parseEditorLines(editorState.containerNamePatterns),
    },
    endpoints: editorState.endpoints.map((endpoint) => ({
      name: endpoint.name.trim(),
      port: Number(endpoint.port),
      path: blankToNull(endpoint.path),
      auth: blankToNull(endpoint.auth),
      auth_header: blankToNull(endpoint.authHeader),
      healthy_when: blankToNull(endpoint.healthyWhen),
    })),
    typical_dependency_containers: editorState.containerDependencies.map((dependency) => ({
      name: dependency.name.trim(),
      alternatives: parseCommaSeparated(dependency.alternatives),
    })),
    typical_dependency_shares: parseEditorLines(editorState.shareDependencies),
  };
}

function createModelSettingsEditorState(
  detail: ModelSettingsResponse,
): ModelSettingsEditorState {
  return {
    localEnabled: detail.staged.local.enabled,
    localModel: detail.staged.local.model ?? "",
    localBaseUrl: detail.staged.local.base_url,
    localTimeoutSeconds: String(detail.staged.local.timeout_seconds),
    localApiKey: "",
    clearLocalStoredApiKey: false,
    cloudEnabled: detail.staged.cloud.enabled,
    cloudProvider: detail.staged.cloud.provider,
    cloudModel: detail.staged.cloud.model ?? "",
    cloudBaseUrl: detail.staged.cloud.base_url,
    cloudTimeoutSeconds: String(detail.staged.cloud.timeout_seconds),
    cloudMaxOutputTokens: String(detail.staged.cloud.max_output_tokens),
    cloudApiKey: "",
    clearCloudStoredApiKey: false,
    escalationFindingCountGt: String(detail.staged.escalation.finding_count_gt),
    escalationLocalConfidenceLt: String(detail.staged.escalation.local_confidence_lt),
    escalationOnMultipleDomains: detail.staged.escalation.escalate_on_multiple_domains,
    escalationOnChangelogResearch: detail.staged.escalation.escalate_on_changelog_research,
    escalationOnUserRequest: detail.staged.escalation.escalate_on_user_request,
    escalationMaxCloudCallsPerDay: String(detail.staged.escalation.max_cloud_calls_per_day),
    escalationMaxCloudCallsPerIncident: String(
      detail.staged.escalation.max_cloud_calls_per_incident,
    ),
  };
}

function buildModelSettingsUpdatePayload(
  editorState: ModelSettingsEditorState,
): Record<string, unknown> {
  return {
    local: {
      enabled: editorState.localEnabled,
      model: blankToNull(editorState.localModel),
      base_url: editorState.localBaseUrl.trim(),
      timeout_seconds: parseNumericInput(
        editorState.localTimeoutSeconds,
        "Local timeout seconds",
      ),
      api_key: blankToNull(editorState.localApiKey),
      clear_stored_api_key: editorState.clearLocalStoredApiKey,
    },
    cloud: {
      enabled: editorState.cloudEnabled,
      provider: editorState.cloudProvider,
      model: blankToNull(editorState.cloudModel),
      base_url: editorState.cloudBaseUrl.trim(),
      timeout_seconds: parseNumericInput(
        editorState.cloudTimeoutSeconds,
        "Cloud timeout seconds",
      ),
      max_output_tokens: parseIntegerInput(
        editorState.cloudMaxOutputTokens,
        "Cloud max output tokens",
      ),
      api_key: blankToNull(editorState.cloudApiKey),
      clear_stored_api_key: editorState.clearCloudStoredApiKey,
    },
    escalation: {
      finding_count_gt: parseIntegerInput(
        editorState.escalationFindingCountGt,
        "Escalation finding count",
      ),
      local_confidence_lt: parseNumericInput(
        editorState.escalationLocalConfidenceLt,
        "Escalation confidence threshold",
      ),
      escalate_on_multiple_domains: editorState.escalationOnMultipleDomains,
      escalate_on_changelog_research: editorState.escalationOnChangelogResearch,
      escalate_on_user_request: editorState.escalationOnUserRequest,
      max_cloud_calls_per_day: parseIntegerInput(
        editorState.escalationMaxCloudCallsPerDay,
        "Cloud calls per day",
      ),
      max_cloud_calls_per_incident: parseIntegerInput(
        editorState.escalationMaxCloudCallsPerIncident,
        "Cloud calls per incident",
      ),
    },
  };
}

function createNotificationSettingsEditorState(
  detail: NotificationSettingsResponse,
): NotificationSettingsEditorState {
  return {
    channels: detail.staged.channels.map((channel) => ({
      clientId: createClientId(),
      channelId: channel.id,
      name: channel.name,
      enabled: channel.enabled,
      kind: channel.kind,
      destination: "",
      destinationConfigured: channel.destination_configured,
      destinationSource: channel.destination_source,
    })),
    criticalRoute: detail.staged.routing.critical,
    highRoute: detail.staged.routing.high,
    mediumRoute: detail.staged.routing.medium,
    lowRoute: detail.staged.routing.low,
    dedupWindowMinutes: String(detail.staged.routing.dedup_window_minutes),
    digestWindowMinutes: String(detail.staged.routing.digest_window_minutes),
    quietHoursEnabled: detail.staged.quiet_hours.enabled,
    quietHoursStart: detail.staged.quiet_hours.start_time_local,
    quietHoursEnd: detail.staged.quiet_hours.end_time_local,
    quietHoursTimezone: detail.staged.quiet_hours.timezone,
  };
}

function buildNotificationSettingsUpdatePayload(
  editorState: NotificationSettingsEditorState,
): Record<string, unknown> {
  return {
    channels: editorState.channels.map((channel) => ({
      id: channel.channelId,
      name: channel.name.trim(),
      enabled: channel.enabled,
      destination: blankToNull(channel.destination),
    })),
    routing: {
      critical: editorState.criticalRoute,
      high: editorState.highRoute,
      medium: editorState.mediumRoute,
      low: editorState.lowRoute,
      dedup_window_minutes: parseIntegerInput(
        editorState.dedupWindowMinutes,
        "Notification dedup window",
      ),
      digest_window_minutes: parseIntegerInput(
        editorState.digestWindowMinutes,
        "Notification digest window",
      ),
    },
    quiet_hours: {
      enabled: editorState.quietHoursEnabled,
      start_time_local: editorState.quietHoursStart.trim(),
      end_time_local: editorState.quietHoursEnd.trim(),
      timezone: editorState.quietHoursTimezone.trim(),
    },
  };
}

function createSystemSettingsEditorState(
  detail: SystemSettingsResponse,
): SystemSettingsEditorState {
  return {
    logLevel: detail.staged.log_level,
    auditDetailRetentionDays: String(detail.staged.audit_detail_retention_days),
    auditSummaryRetentionDays: String(detail.staged.audit_summary_retention_days),
  };
}

function buildSystemSettingsUpdatePayload(
  editorState: SystemSettingsEditorState,
): Record<string, unknown> {
  const auditDetailRetentionDays = parseIntegerInput(
    editorState.auditDetailRetentionDays,
    "Detailed audit retention",
  );
  const auditSummaryRetentionDays = parseIntegerInput(
    editorState.auditSummaryRetentionDays,
    "Summary audit retention",
  );
  if (auditDetailRetentionDays <= 0) {
    throw new Error("Detailed audit retention must be a positive integer.");
  }
  if (auditSummaryRetentionDays <= 0) {
    throw new Error("Summary audit retention must be a positive integer.");
  }
  if (auditSummaryRetentionDays < auditDetailRetentionDays) {
    throw new Error(
      "Summary audit retention must be greater than or equal to detailed audit retention.",
    );
  }
  return {
    log_level: editorState.logLevel,
    audit_detail_retention_days: auditDetailRetentionDays,
    audit_summary_retention_days: auditSummaryRetentionDays,
  };
}

function createMonitoringSettingsEditorState(
  detail: MonitoringSettingsResponse,
): MonitoringSettingsEditorState {
  return {
    checks: detail.staged.checks.map((check) => ({
      checkId: check.check_id,
      label: check.label,
      description: check.description,
      enabled: check.enabled,
      intervalSeconds: String(check.interval_seconds),
      tlsWarningDays:
        check.tls_warning_days === null ? "" : String(check.tls_warning_days),
      restartDeltaThreshold:
        check.restart_delta_threshold === null
          ? ""
          : String(check.restart_delta_threshold),
      probeTimeoutSeconds:
        check.probe_timeout_seconds === null
          ? ""
          : String(check.probe_timeout_seconds),
      defaultEnabled: check.default_enabled,
      defaultIntervalSeconds: check.default_interval_seconds,
      defaultTlsWarningDays: check.default_tls_warning_days,
      defaultRestartDeltaThreshold: check.default_restart_delta_threshold,
      defaultProbeTimeoutSeconds: check.default_probe_timeout_seconds,
    })),
    serviceOverrides: detail.staged.service_overrides.map((override) => ({
      clientId: createClientId(),
      serviceId: override.service_id,
      checkId: override.check_id,
      enabledMode:
        override.enabled === null
          ? "inherit"
          : override.enabled
            ? "enabled"
            : "disabled",
      intervalSeconds:
        override.interval_seconds === null ? "" : String(override.interval_seconds),
      tlsWarningDays:
        override.tls_warning_days === null ? "" : String(override.tls_warning_days),
      restartDeltaThreshold:
        override.restart_delta_threshold === null
          ? ""
          : String(override.restart_delta_threshold),
      probeTimeoutSeconds:
        override.probe_timeout_seconds === null
          ? ""
          : String(override.probe_timeout_seconds),
    })),
  };
}

function buildMonitoringSettingsUpdatePayload(
  editorState: MonitoringSettingsEditorState,
): Record<string, unknown> {
  return {
    checks: editorState.checks.map((check) => ({
      check_id: check.checkId,
      enabled: check.enabled,
      interval_seconds: parseIntegerInput(
        check.intervalSeconds,
        `${check.label} interval seconds`,
      ),
      tls_warning_days: parseOptionalIntegerInput(
        check.tlsWarningDays,
        `${check.label} TLS warning days`,
      ),
      restart_delta_threshold: parseOptionalIntegerInput(
        check.restartDeltaThreshold,
        `${check.label} restart delta threshold`,
      ),
      probe_timeout_seconds: parseOptionalFloatInput(
        check.probeTimeoutSeconds,
        `${check.label} probe timeout seconds`,
      ),
    })),
    service_overrides: editorState.serviceOverrides
      .map((override) => ({
        service_id: override.serviceId,
        check_id: override.checkId,
        enabled:
          override.enabledMode === "inherit"
            ? null
            : override.enabledMode === "enabled",
        interval_seconds: parseOptionalIntegerInput(
          override.intervalSeconds,
          `${override.checkId} override interval`,
        ),
        tls_warning_days: parseOptionalIntegerInput(
          override.tlsWarningDays,
          `${override.checkId} override TLS warning days`,
        ),
        restart_delta_threshold: parseOptionalIntegerInput(
          override.restartDeltaThreshold,
          `${override.checkId} override restart delta threshold`,
        ),
        probe_timeout_seconds: parseOptionalFloatInput(
          override.probeTimeoutSeconds,
          `${override.checkId} override probe timeout seconds`,
        ),
      }))
      .filter(
        (override) =>
          override.service_id.trim().length > 0 &&
          override.check_id.trim().length > 0 &&
          (
            override.enabled !== null ||
            override.interval_seconds !== null ||
            override.tls_warning_days !== null ||
            override.restart_delta_threshold !== null ||
            override.probe_timeout_seconds !== null
          ),
      ),
  };
}

function applicableMonitoringChecks(
  serviceId: string,
  checks: MonitoringCheckEditorState[],
  services: Service[],
): MonitoringCheckEditorState[] {
  const service = services.find((item) => item.id === serviceId);
  if (!service) {
    return checks;
  }
  return checks.filter((check) => monitoringCheckAppliesToService(check.checkId, service));
}

function monitoringCheckAppliesToService(checkId: string, service: Service): boolean {
  if (checkId === "container_health" || checkId === "restart_storm") {
    return service.type === "container" && service.container_id !== null;
  }
  if (checkId === "endpoint_probe") {
    return service.endpoints.some(
      (endpoint) =>
        (endpoint.protocol === "http" || endpoint.protocol === "https") &&
        !endpoint.auth_required,
    );
  }
  if (checkId === "vm_health") {
    return service.type === "vm" && service.vm_id !== null;
  }
  if (checkId === "tls_cert") {
    return service.endpoints.some((endpoint) => endpoint.protocol === "https");
  }
  if (checkId === "dns_resolution") {
    return service.dns_targets.length > 0;
  }
  if (checkId === "log_pattern") {
    return (
      service.type === "container" &&
      service.container_id !== null &&
      service.descriptor_id !== null
    );
  }
  if (checkId === "unraid_system") {
    return service.type === "system" || service.type === "share";
  }
  if (checkId === "dependency_chain") {
    return service.dependencies.length > 0;
  }
  return false;
}

function createDraftNotificationChannel(): NotificationChannelEditorState {
  return {
    clientId: createClientId(),
    channelId: null,
    name: "",
    enabled: true,
    kind: "apprise",
    destination: "",
    destinationConfigured: false,
    destinationSource: "unset",
  };
}

function guessNotificationChannelKind(destination: string): string | null {
  const trimmed = destination.trim();
  if (!trimmed) {
    return null;
  }
  const [scheme] = trimmed.split("://", 1);
  return scheme ? scheme.toLowerCase() : "apprise";
}

function createEmptyDescriptorEndpointState(): DescriptorEditorEndpointState {
  return {
    clientId: createClientId(),
    name: "",
    port: "",
    path: "",
    auth: "",
    authHeader: "",
    healthyWhen: "",
  };
}

function createEmptyDescriptorDependencyState(): DescriptorEditorDependencyState {
  return {
    clientId: createClientId(),
    name: "",
    alternatives: "",
  };
}

function serializeEditorList(values: string[]): string {
  return values.join("\n");
}

function parseEditorLines(value: string): string[] {
  return value
    .split("\n")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function parseCommaSeparated(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function blankToNull(value: string): string | null {
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : null;
}

function parseNumericInput(value: string, label: string): number {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be numeric.`);
  }
  return parsed;
}

function parseIntegerInput(value: string, label: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${label} must be an integer.`);
  }
  return parsed;
}

function parseOptionalIntegerInput(value: string, label: string): number | null {
  const normalized = value.trim();
  if (normalized.length === 0) {
    return null;
  }
  return parseIntegerInput(normalized, label);
}

function parseOptionalFloatInput(value: string, label: string): number | null {
  const normalized = value.trim();
  if (normalized.length === 0) {
    return null;
  }
  const parsed = Number.parseFloat(normalized);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive number.`);
  }
  return parsed;
}

type MonitoringThresholdKey =
  | "tlsWarningDays"
  | "restartDeltaThreshold"
  | "probeTimeoutSeconds";

function monitoringThresholdMeta(
  checkId: string,
):
  | {
      key: MonitoringThresholdKey;
      label: string;
      min: string;
      step: string;
    }
  | null {
  if (checkId === "tls_cert") {
    return {
      key: "tlsWarningDays",
      label: "TLS Warning Days",
      min: "1",
      step: "1",
    };
  }
  if (checkId === "restart_storm") {
    return {
      key: "restartDeltaThreshold",
      label: "Restart Delta Threshold",
      min: "1",
      step: "1",
    };
  }
  if (checkId === "endpoint_probe") {
    return {
      key: "probeTimeoutSeconds",
      label: "Probe Timeout Seconds",
      min: "0.1",
      step: "0.1",
    };
  }
  return null;
}

function monitoringThresholdEditorValue(
  editor:
    | MonitoringCheckEditorState
    | MonitoringServiceOverrideEditorState,
  key: MonitoringThresholdKey,
): string {
  if (key === "tlsWarningDays") {
    return editor.tlsWarningDays;
  }
  if (key === "restartDeltaThreshold") {
    return editor.restartDeltaThreshold;
  }
  return editor.probeTimeoutSeconds;
}

function updateMonitoringThresholdEditorValue<
  T extends MonitoringCheckEditorState | MonitoringServiceOverrideEditorState,
>(editor: T, key: MonitoringThresholdKey, value: string): T {
  if (key === "tlsWarningDays") {
    return { ...editor, tlsWarningDays: value };
  }
  if (key === "restartDeltaThreshold") {
    return { ...editor, restartDeltaThreshold: value };
  }
  return { ...editor, probeTimeoutSeconds: value };
}

function formatMonitoringThresholdDefault(
  check: MonitoringCheckEditorState,
  meta: {
    key: MonitoringThresholdKey;
  },
): string {
  if (meta.key === "tlsWarningDays") {
    return `warn ${check.defaultTlsWarningDays ?? "?"}d`;
  }
  if (meta.key === "restartDeltaThreshold") {
    return `delta ${check.defaultRestartDeltaThreshold ?? "?"}`;
  }
  return `timeout ${check.defaultProbeTimeoutSeconds ?? "?"}s`;
}

function formatMonitoringThresholdSummary(check: {
  tls_warning_days: number | null;
  restart_delta_threshold: number | null;
  probe_timeout_seconds: number | null;
  threshold_source?: "global_default" | "service_override" | null;
}): string | null {
  if (check.tls_warning_days !== null) {
    return `warn ${check.tls_warning_days}d${
      check.threshold_source ? ` (${formatLabel(check.threshold_source)})` : ""
    }`;
  }
  if (check.restart_delta_threshold !== null) {
    return `delta ${check.restart_delta_threshold}${
      check.threshold_source ? ` (${formatLabel(check.threshold_source)})` : ""
    }`;
  }
  if (check.probe_timeout_seconds !== null) {
    return `timeout ${check.probe_timeout_seconds}s${
      check.threshold_source ? ` (${formatLabel(check.threshold_source)})` : ""
    }`;
  }
  return null;
}

function createClientId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `client-${Math.random().toString(36).slice(2, 10)}`;
}

function labelForInsight(level: number): string {
  return insightLabel[level as keyof typeof insightLabel] ?? `Level ${level}`;
}

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDate(value: string): string {
  return new Date(`${value}T00:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatGigabytes(value: number): string {
  return formatStorageQuantity(value, "GB");
}

function formatOptionalValue(value: string | null): string {
  return value && value.trim() ? value : "Not recorded";
}

function formatOptionalLabel(value: string | null): string {
  return value ? formatLabel(value) : "Not recorded";
}

function formatOptionalTimestamp(value: string | null): string {
  return value ? formatTimestamp(value) : "Not scheduled";
}

function formatServiceEndpointSummary(service: Service): string {
  if (service.endpoints.length === 0) {
    return "No published ports recorded";
  }
  return service.endpoints
    .map((endpoint) =>
      endpoint.port === null
        ? endpoint.name
        : `${endpoint.port}/${endpoint.protocol.toUpperCase()}`,
    )
    .join(", ");
}

function buildGuidedSetupLimitationSummary(
  service: Service,
  nodeMeta: GraphResponse["node_meta"][number] | null,
): string {
  const insightLevel = service.insight?.level ?? 0;
  if (service.descriptor_id === null) {
    return "No matched descriptor is attached yet, so Kaval is limited to generic monitoring.";
  }
  if (nodeMeta !== null && nodeMeta.target_insight_level >= 4 && insightLevel < 4) {
    return "Deep inspection is not configured yet, so Kaval cannot verify richer service facts.";
  }
  if (nodeMeta !== null && nodeMeta.target_insight_level >= 3 && insightLevel < 3) {
    return "Local investigation readiness is still incomplete for this service.";
  }
  if (nodeMeta !== null && nodeMeta.target_insight_level > insightLevel) {
    return `This service can still improve from Level ${insightLevel} to Level ${nodeMeta.target_insight_level}.`;
  }
  return "Current insight is bounded by the descriptor and capability state already configured.";
}

function formatFactValue(value: JsonValue): string {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }
  return JSON.stringify(value, null, 2);
}

function formatTerabytes(value: number): string {
  return formatStorageQuantity(value, "TB");
}

function formatStorageQuantity(value: number, unit: string): string {
  const precision = Number.isInteger(value) ? 0 : 1;
  return `${value.toFixed(precision)} ${unit}`;
}

function formatByteSize(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatDurationSeconds(value: number): string {
  const totalSeconds = Math.max(Math.floor(value), 0);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function journalProvenanceLabel(entry: JournalEntry): string {
  if (entry.recurrence_count > 1) {
    return "Recurrence-backed";
  }
  return "Incident journal";
}

function journalSourceSummary(entry: JournalEntry): string {
  if (entry.recurrence_count > 1) {
    return "incident journal reinforced by recurrence";
  }
  return "auto-written from the linked incident";
}

function journalEntryNeedsReview(entry: JournalEntry): boolean {
  return (
    entry.superseded_by !== null ||
    entry.confidence === "speculative" ||
    isJournalEntryStale(entry)
  );
}

function journalTrustSummary(entry: JournalEntry): string {
  if (entry.superseded_by !== null) {
    return `superseded by ${entry.superseded_by}`;
  }
  if (isJournalEntryStale(entry)) {
    return "staleness window expired";
  }
  if (entry.last_verified_at) {
    return `verified ${formatTimestamp(entry.last_verified_at)}`;
  }
  if (entry.user_confirmed) {
    return "user confirmed";
  }
  return "not re-verified yet";
}

function isJournalEntryStale(entry: JournalEntry): boolean {
  if (entry.stale_after_days === null) {
    return false;
  }
  const referenceTime = new Date(entry.last_verified_at ?? `${entry.date}T00:00:00Z`);
  return referenceTime.getTime() + entry.stale_after_days * 24 * 60 * 60 * 1000 < Date.now();
}

function createEmptyNoteEditorState(selectedServiceId: string | null): NoteEditorState {
  return {
    serviceId: selectedServiceId ?? "",
    note: "",
    safeForModel: true,
    stale: false,
    lastVerifiedAt: "",
  };
}

function createNoteEditorState(note: UserNote): NoteEditorState {
  return {
    serviceId: note.service_id ?? "",
    note: note.note,
    safeForModel: note.safe_for_model,
    stale: note.stale,
    lastVerifiedAt: formatDateTimeLocal(note.last_verified_at),
  };
}

function formatDateTimeLocal(value: string | null): string {
  if (value === null) {
    return "";
  }
  const date = new Date(value);
  const offsetMilliseconds = date.getTimezoneOffset() * 60 * 1000;
  return new Date(date.getTime() - offsetMilliseconds).toISOString().slice(0, 16);
}

function filterUserNotes(
  notes: UserNote[],
  query: string,
  serviceNames: Map<string, string>,
): UserNote[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return notes;
  }
  return notes.filter((note) => {
    const serviceName = note.service_id ? serviceNames.get(note.service_id) ?? note.service_id : "general";
    return `${serviceName}\n${note.note}`.toLowerCase().includes(normalizedQuery);
  });
}

function groupUserNotes(
  notes: UserNote[],
  serviceNames: Map<string, string>,
  selectedServiceId: string | null,
): UserNoteGroup[] {
  const groups = new Map<string, UserNoteGroup>();
  for (const note of notes) {
    const key = note.service_id ?? "__global__";
    const existing = groups.get(key);
    const label =
      note.service_id === null
        ? "Global notes"
        : serviceNames.get(note.service_id) ?? note.service_id;
    if (existing) {
      existing.notes.push(note);
      continue;
    }
    groups.set(key, {
      key,
      label,
      serviceId: note.service_id,
      notes: [note],
    });
  }
  return [...groups.values()].sort((left, right) => {
    if (left.serviceId === selectedServiceId) {
      return -1;
    }
    if (right.serviceId === selectedServiceId) {
      return 1;
    }
    if (left.serviceId === null) {
      return 1;
    }
    if (right.serviceId === null) {
      return -1;
    }
    return left.label.localeCompare(right.label);
  });
}

function buildRecurrencePatterns(journalEntries: JournalEntry[]): RecurrencePatternView[] {
  const activeEntries = journalEntries.filter(
    (entry) => entry.recurrence_count > 1 && entry.superseded_by === null,
  );
  return activeEntries
    .map((activeEntry) => ({
      activeEntry,
      priorEntries: journalEntries
        .filter(
          (entry) =>
            entry.id !== activeEntry.id &&
            entry.confidence !== "speculative" &&
            entry.superseded_by === null &&
            hasSameServiceScope(entry.services, activeEntry.services),
        )
        .slice(0, 3),
    }))
    .sort((left, right) => {
      if (right.activeEntry.recurrence_count !== left.activeEntry.recurrence_count) {
        return right.activeEntry.recurrence_count - left.activeEntry.recurrence_count;
      }
      return right.activeEntry.date.localeCompare(left.activeEntry.date);
    });
}

function hasSameServiceScope(left: string[], right: string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const leftServices = [...left].sort();
  const rightServices = [...right].sort();
  return leftServices.every((serviceId, index) => serviceId === rightServices[index]);
}

function chooseIncidentId(incidents: Incident[], currentId: string | null): string | null {
  if (currentId !== null && incidents.some((incident) => incident.id === currentId)) {
    return currentId;
  }
  return latestIncident(incidents)?.id ?? null;
}

function chooseQuarantinedDescriptorId(
  items: QuarantinedDescriptorQueueItem[],
  currentId: string | null,
  selectedServiceId: string | null,
): string | null {
  if (selectedServiceId !== null) {
    const matchingSelectedService = items.find((item) =>
      item.matching_services.some((service) => service.id === selectedServiceId),
    );
    if (matchingSelectedService !== undefined) {
      return matchingSelectedService.descriptor.descriptor_id;
    }
  }
  if (
    currentId !== null &&
    items.some((item) => item.descriptor.descriptor_id === currentId)
  ) {
    return currentId;
  }
  return items[0]?.descriptor.descriptor_id ?? null;
}

function chooseServiceId(
  services: Service[],
  incidents: Incident[],
  currentServiceId: string | null,
  selectedIncidentId: string | null,
): string | null {
  if (currentServiceId !== null && services.some((service) => service.id === currentServiceId)) {
    return currentServiceId;
  }

  const selectedIncident =
    incidents.find((incident) => incident.id === selectedIncidentId) ??
    latestIncident(incidents) ??
    null;
  const incidentServiceId = selectedIncident?.affected_services.find((serviceId) =>
    services.some((service) => service.id === serviceId),
  );
  return incidentServiceId ?? services[0]?.id ?? null;
}

function latestIncident(incidents: Incident[]): Incident | null {
  return (
    [...incidents].sort((left, right) => right.updated_at.localeCompare(left.updated_at))[0] ??
    null
  );
}

function buildServiceReferenceMap(services: Service[]): Map<string, string> {
  const referenceMap = new Map<string, string>();
  for (const service of services) {
    const imageParts = service.image === null ? [] : service.image.split("/");
    const imageName =
      imageParts.length === 0 ? null : imageParts[imageParts.length - 1].split(":")[0];
    const suffixReference =
      service.id.includes("-") ? service.id.slice(service.id.indexOf("-") + 1) : null;
    const references = new Set([
      service.id,
      service.name,
      service.container_id,
      service.descriptor_id,
      imageName,
      suffixReference,
      ...service.lifecycle.previous_names,
    ]);
    for (const reference of references) {
      if (!reference) {
        continue;
      }
      referenceMap.set(normalizeServiceReference(reference), service.id);
    }
  }
  return referenceMap;
}

function normalizeServiceReference(reference: string): string {
  return reference.trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function matchServiceReference(
  reference: string | null | undefined,
  serviceReferenceMap: Map<string, string>,
): string | null {
  if (!reference) {
    return null;
  }
  return serviceReferenceMap.get(normalizeServiceReference(reference)) ?? null;
}

function buildIncidentGraphFocus(
  incident: Incident,
  investigation: Investigation | null,
  services: Service[],
  edges: GraphEdge[],
  serviceReferenceMap: Map<string, string>,
): IncidentGraphFocus | null {
  if (services.length === 0) {
    return null;
  }

  const serviceIds = new Set(services.map((service) => service.id));
  const affectedServiceIds = incident.affected_services.filter((serviceId) =>
    serviceIds.has(serviceId),
  );
  const evidenceServiceIds = Array.from(
    new Set(
      (investigation?.evidence_steps ?? [])
        .map((step) => matchServiceReference(step.target, serviceReferenceMap))
        .filter((serviceId): serviceId is string => serviceId !== null),
    ),
  );
  const remediationServiceId = matchServiceReference(
    investigation?.remediation?.target ?? null,
    serviceReferenceMap,
  );
  const rootServiceId =
    matchServiceReference(incident.root_cause_service, serviceReferenceMap) ??
    remediationServiceId ??
    evidenceServiceIds[0] ??
    affectedServiceIds[0] ??
    null;

  const highlightedServiceIds = new Set<string>(affectedServiceIds);
  if (rootServiceId !== null) {
    highlightedServiceIds.add(rootServiceId);
  }
  if (remediationServiceId !== null) {
    highlightedServiceIds.add(remediationServiceId);
  }
  for (const serviceId of evidenceServiceIds) {
    highlightedServiceIds.add(serviceId);
  }

  if (highlightedServiceIds.size === 0) {
    return null;
  }

  const highlightedEdgeKeys = new Set<string>();
  if (rootServiceId !== null) {
    for (const serviceId of highlightedServiceIds) {
      if (serviceId === rootServiceId) {
        continue;
      }
      const path = findShortestIncidentPath(rootServiceId, serviceId, edges);
      if (path === null) {
        continue;
      }
      for (const pathServiceId of path.serviceIds) {
        highlightedServiceIds.add(pathServiceId);
      }
      for (const key of path.edgeKeys) {
        highlightedEdgeKeys.add(key);
      }
    }
  }

  if (highlightedEdgeKeys.size === 0) {
    for (const edge of edges) {
      if (
        highlightedServiceIds.has(edge.source_service_id) &&
        highlightedServiceIds.has(edge.target_service_id)
      ) {
        highlightedEdgeKeys.add(edgeKey(edge));
      }
    }
  }

  return {
    rootServiceId,
    serviceIds: [...highlightedServiceIds],
    edgeKeys: [...highlightedEdgeKeys],
    evidenceServiceIds,
  };
}

function findShortestIncidentPath(
  startServiceId: string,
  targetServiceId: string,
  edges: GraphEdge[],
): { serviceIds: string[]; edgeKeys: string[] } | null {
  if (startServiceId === targetServiceId) {
    return {
      serviceIds: [startServiceId],
      edgeKeys: [],
    };
  }

  const adjacency = new Map<string, Array<{ serviceId: string; edgeKey: string }>>();
  for (const edge of edges) {
    const key = edgeKey(edge);
    const sourceNeighbors = adjacency.get(edge.source_service_id) ?? [];
    sourceNeighbors.push({
      serviceId: edge.target_service_id,
      edgeKey: key,
    });
    adjacency.set(edge.source_service_id, sourceNeighbors);

    const targetNeighbors = adjacency.get(edge.target_service_id) ?? [];
    targetNeighbors.push({
      serviceId: edge.source_service_id,
      edgeKey: key,
    });
    adjacency.set(edge.target_service_id, targetNeighbors);
  }

  const queue: Array<{ serviceId: string; serviceIds: string[]; edgeKeys: string[] }> = [
    {
      serviceId: startServiceId,
      serviceIds: [startServiceId],
      edgeKeys: [],
    },
  ];
  const visited = new Set([startServiceId]);

  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) {
      break;
    }
    for (const neighbor of adjacency.get(current.serviceId) ?? []) {
      if (visited.has(neighbor.serviceId)) {
        continue;
      }
      const nextPath = {
        serviceId: neighbor.serviceId,
        serviceIds: [...current.serviceIds, neighbor.serviceId],
        edgeKeys: [...current.edgeKeys, neighbor.edgeKey],
      };
      if (neighbor.serviceId === targetServiceId) {
        return nextPath;
      }
      visited.add(neighbor.serviceId);
      queue.push(nextPath);
    }
  }

  return null;
}

function SummaryTile(props: {
  label: string;
  value: number | string;
  accent: "warm" | "alert" | "ice";
}) {
  return (
    <div className={`summary-tile ${props.accent}`}>
      <p>{props.label}</p>
      <strong>{props.value}</strong>
    </div>
  );
}

function MemorySummaryStat(props: {
  label: string;
  value: number | string;
  tone: "alert" | "calm" | "warm";
}) {
  return (
    <article className={`memory-summary-card ${props.tone}`}>
      <p>{props.label}</p>
      <strong>{props.value}</strong>
    </article>
  );
}

function MemoryTabButton(props: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      aria-selected={props.active}
      className={`memory-tab-button ${props.active ? "active" : ""}`}
      onClick={props.onClick}
      role="tab"
      type="button"
    >
      {props.label}
    </button>
  );
}

function LegendSwatch(props: {
  tone: GraphEdge["confidence"];
  label: string;
  detail: string;
}) {
  return (
    <div className="legend-item">
      <span className={`legend-line ${props.tone}`} />
      <span>
        <strong>{props.label}</strong>
        <small>{props.detail}</small>
      </span>
    </div>
  );
}

function edgeKey(edge: GraphEdge): string {
  return `${edge.source_service_id}::${edge.target_service_id}`;
}

function buildGraphEdgeSourceSummary(edge: GraphEdge): string {
  const detail = edge.description ? ` ${edge.description}` : "";
  return `${formatLabel(edge.source)} · ${formatLabel(edge.confidence)}.${detail}`;
}

function graphEdgeConfidenceDetail(confidence: GraphEdge["confidence"]): string {
  switch (confidence) {
    case "user_confirmed":
      return "Highest trust. User-confirmed edges should guide investigations directly.";
    case "runtime_observed":
      return "Strong runtime evidence from service facts or adapters reinforces this edge.";
    case "configured":
      return "Known configuration supports this dependency, but it is not yet manually confirmed.";
    case "inferred":
      return "Topology or descriptor logic suggests this edge and may still need review.";
    case "auto_generated":
      return "Suggested automatically. Review before treating it as operator-approved context.";
    default:
      return "Dependency confidence is available but not yet described in this UI.";
  }
}

function edgeNeedsConfirmation(edge: GraphEdge): boolean {
  return edge.confidence === "inferred" || edge.confidence === "auto_generated";
}

function edgeMarkerPosition(source: NodeLayout, target: NodeLayout): { x: number; y: number } {
  return {
    x: (source.x + CARD_WIDTH + target.x) / 2,
    y: (source.y + target.y) / 2 + CARD_HEIGHT / 2,
  };
}

function buildEdgeTitle(edge: GraphEdge, sourceName: string, targetName: string): string {
  const detail = edge.description ? ` ${edge.description}` : "";
  return `${sourceName} -> ${targetName}. ${formatLabel(edge.confidence)} via ${formatLabel(edge.source)}.${detail}`;
}

function buildNodeAttentionBadges(
  service: Service,
  nodeMeta: GraphResponse["node_meta"][number] | null,
): Array<{ kind: "identify" | "configure"; label: string }> {
  const badges: Array<{ kind: "identify" | "configure"; label: string }> = [];
  if (service.type === "container" && service.descriptor_id === null) {
    badges.push({ kind: "identify", label: "Identify" });
  }
  const insightLevel = service.insight?.level ?? 0;
  if (
    nodeMeta !== null &&
    nodeMeta.target_insight_level >= 4 &&
    insightLevel < 4
  ) {
    badges.push({ kind: "configure", label: "Configure" });
  }
  return badges;
}

function ServiceNode(props: {
  layout: NodeLayout;
  nodeMeta: GraphResponse["node_meta"][number] | null;
  filteredOut: boolean;
  incidentFocused: boolean;
  incidentRoot: boolean;
  incidentEvidence: boolean;
  selected: boolean;
  onSelect: (serviceId: string) => void;
}) {
  const {
    layout,
    nodeMeta,
    filteredOut,
    incidentFocused,
    incidentRoot,
    incidentEvidence,
    selected,
    onSelect,
  } = props;
  const insightLevel = layout.service.insight?.level ?? 0;
  const insightName = insightLabel[insightLevel as keyof typeof insightLabel] ?? "Unknown";
  const isVm = layout.service.type === "vm";
  const improveAvailable =
    nodeMeta !== null &&
    nodeMeta.improve_available &&
    nodeMeta.target_insight_level > insightLevel;
  const attentionBadges = buildNodeAttentionBadges(layout.service, nodeMeta);
  const vmHostedSurfaceBadges = isVm ? buildVmHostedSurfaceBadges(layout.service) : [];

  return (
    <g
      className={`service-node ${layout.service.status} ${isVm ? "vm" : ""} ${selected ? "selected" : ""} ${filteredOut ? "filtered-out" : ""} ${incidentFocused ? "incident-focused" : ""} ${incidentRoot ? "incident-root" : ""} ${incidentEvidence ? "incident-evidence" : ""}`}
      onClick={() => onSelect(layout.service.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(layout.service.id);
        }
      }}
      role="button"
      tabIndex={0}
      transform={`translate(${layout.x}, ${layout.y})`}
    >
      <title>
        {incidentRoot
          ? `Incident root cause focus. Insight Level ${insightLevel}: ${insightName}.`
          : incidentEvidence
            ? `Investigation evidence focus. Insight Level ${insightLevel}: ${insightName}.`
            : improveAvailable
              ? `Insight Level ${insightLevel}: ${insightName}. Improve path available in service detail up to Level ${nodeMeta?.target_insight_level}.`
              : `Insight Level ${insightLevel}: ${insightName}`}
      </title>
      <rect width={CARD_WIDTH} height={CARD_HEIGHT} rx={28} />
      <g className={`insight-badge insight-${insightLevel}`} transform="translate(148 14)">
        <rect width={54} height={20} rx={10} />
        <text x={27} y={14} textAnchor="middle">
          {`L${insightLevel}`}
        </text>
      </g>
      {improveAvailable ? (
        <g className="improve-badge" transform="translate(18 14)">
          <rect width={74} height={20} rx={10} />
          <text x={37} y={14} textAnchor="middle">
            Improve
          </text>
        </g>
      ) : null}
      {isVm ? (
        <g className="vm-badge" transform="translate(96 14)">
          <rect width={42} height={20} rx={10} />
          <text x={21} y={14} textAnchor="middle">
            VM
          </text>
        </g>
      ) : null}
      {attentionBadges.map((badge, index) => (
        <g
          key={`${layout.service.id}-${badge.kind}`}
          className={`node-attention-badge ${badge.kind}`}
          transform={`translate(${18 + index * 78} -10)`}
        >
          <rect width={70} height={18} rx={9} />
          <text x={35} y={13} textAnchor="middle">
            {badge.label}
          </text>
        </g>
      ))}
      <text className="node-name" x={18} y={30}>
        {layout.service.name}
      </text>
      <text className="node-meta" x={18} y={52}>
        {layout.service.type} · {statusLabel[layout.service.status]}
      </text>
      <text className="node-meta" x={18} y={74}>
        {layout.service.active_findings} findings · {layout.service.active_incidents} incidents
      </text>
      {isVm ? (
        <text className="node-meta vm-node-meta" x={18} y={90}>
          {vmHostedSurfaceBadges[0]?.empty
            ? "Hosted: state only"
            : `${layout.service.endpoints.length} hosted surfaces`}
        </text>
      ) : null}
      {isVm ? (
        <g className="vm-child-strip" transform={`translate(18 ${CARD_HEIGHT + 8})`}>
          <line className="vm-child-connector" x1={10} x2={10} y1={-8} y2={0} />
          {vmHostedSurfaceBadges.map((badge, index) => (
            <g
              className={`vm-child-badge ${badge.empty ? "empty" : ""}`}
              key={`${layout.service.id}-${badge.label}-${index}`}
              transform={`translate(${index * (VM_CHILD_BADGE_WIDTH + VM_CHILD_BADGE_GAP)} 0)`}
            >
              <rect height={18} rx={9} width={VM_CHILD_BADGE_WIDTH} />
              <text textAnchor="middle" x={VM_CHILD_BADGE_WIDTH / 2} y={12}>
                {badge.label}
              </text>
            </g>
          ))}
        </g>
      ) : null}
    </g>
  );
}

function groupServicesByCategory(services: Service[]): Array<[string, Service[]]> {
  const groups = new Map<string, Service[]>();
  for (const service of services) {
    const existing = groups.get(service.category) ?? [];
    existing.push(service);
    groups.set(service.category, existing);
  }
  return [...groups.entries()]
    .map(
      ([category, groupedServices]): [string, Service[]] => [
        category,
        [...groupedServices].sort((left, right) => left.name.localeCompare(right.name)),
      ],
    )
    .sort(([left], [right]) => left.localeCompare(right));
}

function buildLayouts(categories: Array<[string, Service[]]>): NodeLayout[] {
  const layouts: NodeLayout[] = [];
  categories.forEach(([, services], categoryIndex) => {
    services.forEach((service, serviceIndex) => {
      layouts.push({
        service,
        x: 48 + categoryIndex * COLUMN_WIDTH,
        y: HEADER_HEIGHT + serviceIndex * ROW_GAP,
      });
    });
  });
  return layouts;
}

function buildVmHostedSurfaceLabels(service: Service): string[] {
  if (service.type !== "vm") {
    return [];
  }
  return service.endpoints.map((endpoint) => formatVmHostedSurfaceLabel(endpoint));
}

function buildVmHostedSurfaceBadges(service: Service): VmHostedSurfaceBadge[] {
  const labels = buildVmHostedSurfaceLabels(service);
  if (labels.length === 0) {
    return [{ label: "State only", empty: true }];
  }
  if (labels.length <= MAX_VM_CHILD_BADGES) {
    return labels.map((label) => ({ label, empty: false }));
  }
  return [
    { label: labels[0], empty: false },
    { label: `+${labels.length - 1} more`, empty: false },
  ];
}

function formatVmHostedSurfaceLabel(endpoint: Service["endpoints"][number]): string {
  const base = endpoint.name.trim() || endpoint.protocol.toUpperCase();
  const suffix =
    endpoint.port !== null
      ? String(endpoint.port)
      : endpoint.protocol === "https"
        ? "HTTPS"
        : endpoint.protocol === "http"
          ? "HTTP"
          : endpoint.protocol.toUpperCase();
  return truncateVmBadgeLabel(`${base} ${suffix}`);
}

function truncateVmBadgeLabel(value: string, maxLength = 14): string {
  const trimmed = value.trim();
  if (trimmed.length <= maxLength) {
    return trimmed;
  }
  return `${trimmed.slice(0, maxLength - 1)}…`;
}

function edgePath(source: NodeLayout, target: NodeLayout): string {
  const startX = source.x + CARD_WIDTH;
  const startY = source.y + CARD_HEIGHT / 2;
  const endX = target.x;
  const endY = target.y + CARD_HEIGHT / 2;
  const controlOffset = Math.max((endX - startX) * 0.5, 80);
  return [
    `M ${startX} ${startY}`,
    `C ${startX + controlOffset} ${startY}`,
    `${endX - controlOffset} ${endY}`,
    `${endX} ${endY}`,
  ].join(" ");
}
