import { startTransition, useDeferredValue, useEffect, useState } from "react";

import type {
  Change,
  CapabilityHealthReport,
  CredentialRequest,
  EffectivenessReport,
  GraphEdge,
  GraphEdgeMutationResponse,
  GraphResponse,
  Incident,
  Investigation,
  JournalEntry,
  JsonValue,
  QuarantinedDescriptorActionResponse,
  QuarantinedDescriptorQueueItem,
  RealtimeSnapshot,
  ServiceAdapterFactsItem,
  ServiceAdapterFactsResponse,
  Service,
  ServiceDescriptorSaveResponse,
  ServiceDescriptorValidationResponse,
  ServiceDescriptorView,
  ServiceStatus,
  ServiceDetailResponse,
  SystemProfile,
  UserNote,
  WidgetSummary,
} from "./types";

const CARD_WIDTH = 220;
const CARD_HEIGHT = 96;
const COLUMN_WIDTH = 280;
const HEADER_HEIGHT = 72;
const ROW_GAP = 128;

interface LoadState {
  graph: GraphResponse | null;
  capabilityHealth: CapabilityHealthReport | null;
  changes: Change[];
  credentialRequests: CredentialRequest[];
  effectiveness: EffectivenessReport | null;
  incidents: Incident[];
  investigations: Investigation[];
  journalEntries: JournalEntry[];
  systemProfile: SystemProfile | null;
  userNotes: UserNote[];
  widget: WidgetSummary | null;
  error: string | null;
  loading: boolean;
}

interface ServiceDetailState {
  detail: ServiceDetailResponse | null;
  error: string | null;
  loading: boolean;
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
  journalEntries: [],
  systemProfile: null,
  userNotes: [],
};

interface NodeLayout {
  service: Service;
  x: number;
  y: number;
}

type SupplementalPanelsState = Pick<
  LoadState,
  | "capabilityHealth"
  | "changes"
  | "credentialRequests"
  | "effectiveness"
  | "journalEntries"
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
  const selectedServiceFacts =
    selectedService !== null && serviceAdapterFactsState.detail?.service_id === selectedService.id
      ? serviceAdapterFactsState.detail
      : null;
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

        <main className="content">
          <section className="map-panel panel">
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
            <section className="panel detail-panel">
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

            <section className="panel detail-panel">
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
                      <p className="muted service-inline-copy">
                        No matched descriptor is currently attached to this service, so rendered
                        descriptor view mode is unavailable until the service is identified.
                      </p>
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
          <section className="panel phase-two-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">Change Timeline</p>
                <h2>Correlated changes</h2>
              </div>
              <p className="panel-meta">{sortedChanges.length} tracked</p>
            </div>

            <div className="timeline-list">
              {sortedChanges.length > 0 ? (
                sortedChanges.slice(0, 8).map((change) => (
                  <article
                    key={change.id}
                    className={`timeline-item ${
                      highlightedChangeIds.has(change.id) ? "highlighted" : ""
                    }`}
                  >
                    <div className="timeline-topline">
                      <span className="chip ghost">{formatLabel(change.type)}</span>
                      <span className="step-meta">{formatTimestamp(change.timestamp)}</span>
                    </div>
                    <p className="timeline-service">
                      {change.service_id ? serviceNames.get(change.service_id) ?? change.service_id : "Global"}
                    </p>
                    <p className="muted">{change.description}</p>
                  </article>
                ))
              ) : (
                <p className="muted">No change events are currently persisted.</p>
              )}
            </div>
          </section>

          <section className="panel phase-two-panel">
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
    journalEntries,
    systemProfile,
    userNotes,
  ] =
    await Promise.all([
      fetchJson<CapabilityHealthReport>("/api/v1/capability-health"),
      fetchJson<Change[]>("/api/v1/changes"),
      fetchJson<CredentialRequest[]>("/api/v1/credential-requests"),
      fetchJson<EffectivenessReport>("/api/v1/effectiveness"),
      fetchJson<JournalEntry[]>("/api/v1/journal-entries"),
      fetchOptionalJson<SystemProfile>("/api/v1/system-profile"),
      fetchJson<UserNote[]>("/api/v1/user-notes"),
    ]);
  return {
    capabilityHealth,
    changes,
    credentialRequests,
    effectiveness,
    journalEntries,
    systemProfile,
    userNotes,
  };
}

function formatLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
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
  const improveAvailable =
    nodeMeta !== null &&
    nodeMeta.improve_available &&
    nodeMeta.target_insight_level > insightLevel;
  const attentionBadges = buildNodeAttentionBadges(layout.service, nodeMeta);

  return (
    <g
      className={`service-node ${layout.service.status} ${selected ? "selected" : ""} ${filteredOut ? "filtered-out" : ""} ${incidentFocused ? "incident-focused" : ""} ${incidentRoot ? "incident-root" : ""} ${incidentEvidence ? "incident-evidence" : ""}`}
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
