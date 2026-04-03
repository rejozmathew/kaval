import { startTransition, useEffect, useState } from "react";

import type {
  Change,
  CredentialRequest,
  GraphEdge,
  GraphResponse,
  Incident,
  Investigation,
  JournalEntry,
  RealtimeSnapshot,
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
  changes: Change[];
  credentialRequests: CredentialRequest[];
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

const EMPTY_SUPPLEMENTAL_STATE: SupplementalPanelsState = {
  changes: [],
  credentialRequests: [],
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
  "changes" | "credentialRequests" | "journalEntries" | "systemProfile" | "userNotes"
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
  const surfaceWidth = Math.max(categories.length * COLUMN_WIDTH + 120, 720);
  const surfaceHeight =
    Math.max(...layouts.map((layout) => layout.y), 0) + CARD_HEIGHT + HEADER_HEIGHT + 96;

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
        </div>
      </header>

      {state.loading ? (
        <section className="message-card">Loading Phase 2A investigation state…</section>
      ) : null}
      {state.error ? <section className="message-card error">{state.error}</section> : null}

      {!state.loading && !state.error && state.graph && state.widget ? (
        <>
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
                <h2>Profile, journal, and notes</h2>
              </div>
              <p className="panel-meta">
                {sortedJournalEntries.length} journal · {sortedUserNotes.length} notes
              </p>
            </div>

            {state.systemProfile ? (
              <div className="memory-section">
                <p className="detail-label">System profile</p>
                <ul className="chip-list">
                  <li><span className="chip ghost">{state.systemProfile.hostname}</span></li>
                  <li><span className="chip ghost">Unraid {state.systemProfile.unraid_version}</span></li>
                  {state.systemProfile.networking.ssl_strategy ? (
                    <li>
                      <span className="chip">{state.systemProfile.networking.ssl_strategy}</span>
                    </li>
                  ) : null}
                </ul>
              </div>
            ) : null}

            <div className="memory-section">
              <p className="detail-label">Journal</p>
              {sortedJournalEntries.length > 0 ? (
                <div className="memory-list">
                  {sortedJournalEntries.slice(0, 4).map((entry) => (
                    <article key={entry.id} className="memory-item">
                      <div className="timeline-topline">
                        <span className="chip ghost">{entry.confidence}</span>
                        <span className="step-meta">{entry.date}</span>
                      </div>
                      <p className="timeline-service">{entry.summary}</p>
                      <p className="muted">
                        recurrence {entry.recurrence_count} · model {formatLabel(entry.model_used)}
                      </p>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="muted">No journal entries are currently persisted.</p>
              )}
            </div>

            <div className="memory-section">
              <p className="detail-label">User notes</p>
              {sortedUserNotes.length > 0 ? (
                <div className="memory-list">
                  {sortedUserNotes.slice(0, 4).map((note) => (
                    <article key={note.id} className="memory-item">
                      <div className="timeline-topline">
                        <span className="chip ghost">
                          {note.safe_for_model ? "model-safe" : "excluded"}
                        </span>
                        <span className="step-meta">{formatTimestamp(note.updated_at)}</span>
                      </div>
                      <p className="timeline-service">
                        {note.service_id ? serviceNames.get(note.service_id) ?? note.service_id : "General"}
                      </p>
                      <p className="muted">{note.note}</p>
                    </article>
                  ))}
                </div>
              ) : (
                <p className="muted">No user notes are currently persisted.</p>
              )}
            </div>
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
  const [changes, credentialRequests, journalEntries, systemProfile, userNotes] =
    await Promise.all([
      fetchJson<Change[]>("/api/v1/changes"),
      fetchJson<CredentialRequest[]>("/api/v1/credential-requests"),
      fetchJson<JournalEntry[]>("/api/v1/journal-entries"),
      fetchOptionalJson<SystemProfile>("/api/v1/system-profile"),
      fetchJson<UserNote[]>("/api/v1/user-notes"),
    ]);
  return {
    changes,
    credentialRequests,
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
  value: number;
  accent: "warm" | "alert" | "ice";
}) {
  return (
    <div className={`summary-tile ${props.accent}`}>
      <p>{props.label}</p>
      <strong>{props.value}</strong>
    </div>
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
