import { startTransition, useEffect, useState } from "react";

import type {
  GraphEdge,
  GraphResponse,
  Incident,
  Investigation,
  RealtimeSnapshot,
  Service,
  WidgetSummary,
} from "./types";

const CARD_WIDTH = 220;
const CARD_HEIGHT = 96;
const COLUMN_WIDTH = 280;
const HEADER_HEIGHT = 72;
const ROW_GAP = 128;

interface LoadState {
  graph: GraphResponse | null;
  incidents: Incident[];
  investigations: Investigation[];
  widget: WidgetSummary | null;
  error: string | null;
  loading: boolean;
}

interface NodeLayout {
  service: Service;
  x: number;
  y: number;
}

const statusLabel = {
  healthy: "Healthy",
  degraded: "Degraded",
  down: "Down",
  stopped: "Stopped",
  unknown: "Unknown",
} as const;

export default function App() {
  const [state, setState] = useState<LoadState>({
    graph: null,
    incidents: [],
    investigations: [],
    widget: null,
    error: null,
    loading: true,
  });
  const [selectedServiceId, setSelectedServiceId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [liveState, setLiveState] = useState<"connecting" | "live" | "offline">("connecting");

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [graphResponse, incidentResponse, investigationResponse, widgetResponse] =
          await Promise.all([
          fetch("/api/v1/graph"),
          fetch("/api/v1/incidents"),
          fetch("/api/v1/investigations"),
          fetch("/api/v1/widget"),
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
        startTransition(() => {
          setState({
            graph: snapshot.graph,
            incidents: snapshot.incidents,
            investigations: snapshot.investigations,
            widget: snapshot.widget,
            error: null,
            loading: false,
          });
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

  const services = state.graph?.services ?? [];
  const edges = state.graph?.edges ?? [];
  const serviceNames = new Map(services.map((service) => [service.id, service.name]));
  const categories = groupServicesByCategory(services);
  const layouts = buildLayouts(categories);
  const layoutById = new Map(layouts.map((layout) => [layout.service.id, layout]));
  const selectedService =
    services.find((service) => service.id === selectedServiceId) ?? layouts[0]?.service ?? null;
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
  const surfaceWidth = Math.max(categories.length * COLUMN_WIDTH + 120, 720);
  const surfaceHeight =
    Math.max(...layouts.map((layout) => layout.y), 0) + CARD_HEIGHT + HEADER_HEIGHT + 96;

  return (
    <div className="shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <header className="hero">
        <div>
          <p className="eyebrow">Kaval Phase 2A</p>
          <h1>Incidents with evidence, inference, and a bounded next step.</h1>
          <p className="hero-copy">
            Deterministic monitoring plus structured investigation detail. The current
            view stays incident-centered: evidence trail, root-cause inference, and the
            current restart-only action state when Phase 2A remediation is in play.
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
      ) : null}
    </div>
  );
}

function formatLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
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
      <rect width={CARD_WIDTH} height={CARD_HEIGHT} rx={28} />
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
