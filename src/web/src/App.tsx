import { startTransition, useDeferredValue, useEffect, useState } from "react";

import type {
  Change,
  CapabilityHealthReport,
  CredentialRequest,
  EffectivenessReport,
  GraphEdge,
  GraphResponse,
  Incident,
  Investigation,
  JournalEntry,
  JsonValue,
  RealtimeSnapshot,
  ServiceAdapterFactsItem,
  ServiceAdapterFactsResponse,
  Service,
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

  const services = state.graph?.services ?? [];
  const edges = state.graph?.edges ?? [];
  const serviceNames = new Map(services.map((service) => [service.id, service.name]));
  const categories = groupServicesByCategory(services);
  const layouts = buildLayouts(categories);
  const layoutById = new Map(layouts.map((layout) => [layout.service.id, layout]));
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

  async function submitNoteEditor() {
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
      service_id: noteEditorState.serviceId || null,
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
                  return (
                    <path
                      key={`${edge.source_service_id}-${edge.target_service_id}`}
                      className={`edge edge-${edge.confidence}`}
                      d={edgePath(source, target)}
                    />
                  );
                })}

                {layouts.map((layout) => (
                  <ServiceNode
                    key={layout.service.id}
                    layout={layout}
                    selected={layout.service.id === selectedService?.id}
                    onSelect={setSelectedServiceId}
                  />
                ))}
              </svg>
            </div>

            <div className="legend">
              <LegendSwatch tone="configured" label="Configured edge" />
              <LegendSwatch tone="inferred" label="Inferred edge" />
              <LegendSwatch tone="runtime_observed" label="Runtime observed edge" />
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
                    <p className="detail-label">Insight Level</p>
                    <p className="service-detail-lead">
                      Level {selectedServiceDetail.insight_section.current_level}:{" "}
                      {labelForInsight(selectedServiceDetail.insight_section.current_level)}
                    </p>
                    <p className="muted">
                      Current insight reflects the shipped Phase 3A capability chain already
                      active for this service.
                    </p>
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Deep Inspection</p>
                    {selectedServiceDetail.insight_section.adapter_available ? (
                      <div className="adapter-list">
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
                                    <span className="chip">{formatLabel(factName)}</span>
                                  </li>
                                ))}
                              </ul>
                            ) : null}
                          </article>
                        ))}
                      </div>
                    ) : (
                      <p className="muted">
                        No shipped deep-inspection adapter is currently available for this
                        service.
                      </p>
                    )}
                    {!selectedServiceDetail.insight_section.fact_summary_available ? (
                      <p className="muted">
                        Imported adapter fact summaries are not available yet in this Phase 3A
                        surface.
                      </p>
                    ) : null}
                  </div>

                  <div className="detail-block">
                    <p className="detail-label">Improve</p>
                    {selectedServiceDetail.insight_section.improve_actions.length > 0 ? (
                      <div className="improve-list">
                        {selectedServiceDetail.insight_section.improve_actions.map((action) => (
                          <article key={`${action.kind}-${action.title}`} className="improve-card">
                            <p className="improve-title">{action.title}</p>
                            <p className="muted">{action.detail}</p>
                          </article>
                        ))}
                      </div>
                    ) : (
                      <p className="muted">
                        No immediate improvement action is available from the current Phase 3A
                        foundations.
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

function LegendSwatch(props: { tone: GraphEdge["confidence"]; label: string }) {
  return (
    <div className="legend-item">
      <span className={`legend-line ${props.tone}`} />
      <span>{props.label}</span>
    </div>
  );
}

function ServiceNode(props: {
  layout: NodeLayout;
  selected: boolean;
  onSelect: (serviceId: string) => void;
}) {
  const { layout, selected, onSelect } = props;
  const insightLevel = layout.service.insight?.level ?? 0;
  const insightName = insightLabel[insightLevel as keyof typeof insightLabel] ?? "Unknown";

  return (
    <g
      className={`service-node ${layout.service.status} ${selected ? "selected" : ""}`}
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
      <title>{`Insight Level ${insightLevel}: ${insightName}`}</title>
      <rect width={CARD_WIDTH} height={CARD_HEIGHT} rx={28} />
      <g className={`insight-badge insight-${insightLevel}`} transform="translate(148 14)">
        <rect width={54} height={20} rx={10} />
        <text x={27} y={14} textAnchor="middle">
          {`L${insightLevel}`}
        </text>
      </g>
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
