# Phase 3A — Deep Capability Foundation

## Objective

Establish the service insight model, deep inspection adapter framework, Kaval capability health system, formalized monitoring cadence, and service lifecycle handling. Include minimum UI visibility so users can see insight levels and adapter status from day one of this capability.

## Requirements Reference

Phase 3/4 Requirements Expansion v2: Sections 2 (Insight Model), 3 (Deep Inspection), 4 (Capability Health), 13 (Monitoring Cadence), 14 (Service Lifecycle Events)

## Deliverables

- Service insight level model (Level 0-5) with per-service tracking
- Descriptor schema extension for inspection surface declarations
- ServiceAdapter protocol and AdapterResult model
- Priority adapters: NPM, Radarr, Authentik, Cloudflare, Pi-hole (5 adapters)
- Kaval capability health model (10 layers) and health dashboard
- Adapter self-diagnostic checks and degradation behavior
- Monitoring cadence formalization (per-check defaults, incident-triggered acceleration)
- Service lifecycle event handling (added, removed, updated, renamed)
- Minimum insight visibility UI: insight level badges on service map nodes, service detail panel insight section, Kaval health panel, effectiveness score stub

## Global execution guardrails

These apply to every P3A task.

1. **Read-only deep inspection only.** No Phase 3A task may broaden Kaval’s system-modifying action scope. Adapters and external integrations remain read-only.
2. **Descriptor / adapter split remains strict.** Descriptors declare capability. Adapter code performs extraction. Do not push procedural logic into YAML descriptors.
3. **Use the existing repo shape.** Prefer extending existing modules under `src/kaval/` and existing React/FastAPI surfaces rather than inventing parallel subsystems.
4. **One task at a time.** Do not start later P3A tasks early unless a current task explicitly requires a small shared foundation.
5. **Status discipline.** After each completed task, update `STATUS.md` with files changed, validations run, blockers/failures, and next task.
6. **Stop on contract conflicts.** If the baseline PRD, requirements expansion, approved CRs/ADRs, and this phase plan conflict, stop and record the blocker instead of silently choosing one.
7. **Test and docs are part of the task.** Where a task changes a contract, API, schema, or UI behavior, add/update tests and any immediately relevant docs/config.
8. **No hidden broad rewrites.** If a task appears to require sweeping refactors outside its declared touch surfaces, stop and record the blocker.
9. **Execution prompts still restate the task.** For each implementation run, the active-task prompt must still restate expected files, exact validation commands, acceptance criteria, and blockers before coding begins.

## Suggested repository touch surfaces

These are the most likely file areas for P3A work based on the current repo structure. They are guides, not exhaustive lists.

- `src/kaval/models.py`
- `src/kaval/database.py`
- `src/kaval/api/`
- `src/kaval/discovery/`
- `src/kaval/investigation/`
- `src/kaval/integrations/`
- `src/kaval/memory/`
- `src/kaval/monitoring/`
- `src/kaval/runtime/`
- `src/web/`
- `services/`
- `schemas/`
- `tests/unit/`
- `tests/integration/`
- `tests/contract/`
- `tests/scenario/`
- `tests/security/`

## Tasks

- P3A-01 Service insight level model and per-service tracking
- P3A-02 Descriptor schema extension: inspection surfaces, auth mode, facts, version range
- P3A-03 ServiceAdapter protocol, AdapterResult model, adapter registry
- P3A-04 Adapter credential integration (vault/UAC flow for adapter auth)
- P3A-05 Adapter: Nginx Proxy Manager (REST API — proxy hosts, certs, upstreams)
- P3A-06 Adapter: Radarr (REST API — download clients, indexers, queue health)
- P3A-07 Adapter: Authentik (REST API — apps, providers, outposts, health)
- P3A-08 Adapter: Cloudflare (Public API — DNS records, SSL mode, tunnel routes)
- P3A-09 Adapter: Pi-hole (REST API — upstream DNS, blocklist status, DHCP)
- P3A-10 Adapter self-diagnostic checks (connection, auth, schema, version)
- P3A-11 Adapter degradation and fallback behavior
- P3A-12 Kaval capability health model (10 layers: discovery, scheduler, local model, cloud model, notifications, vault, adapters, webhooks, executor, database)
- P3A-13 Monitoring cadence formalization (per-check defaults, incident-triggered acceleration, configurable intervals)
- P3A-14 Topology refresh model (event-driven primary, periodic reconciliation backstop)
- P3A-15 Service lifecycle event handling (added, updated, removed, renamed with map/history/notification behavior)
- P3A-16 Adapter fact refresh cadence (per-adapter schedule, rate-limit awareness, staleness marking)
- P3A-17 UI: Insight level badges on service map nodes
- P3A-18 UI: Service detail panel — insight section with adapter status, imported facts, "improve" affordances
- P3A-19 UI: Kaval health panel (capability layer status dashboard)
- P3A-20 UI: Effectiveness score display (stub — equal-weighted v1 formula)
- P3A-21 Two-level redaction for adapter facts (redact_for_local vs redact_for_cloud)
- P3A-22 Evidence gathering integration: invoke adapters during Tier 1 evidence collection when credentials available
- P3A-23 Confidence upgrade: adapter-confirmed edges upgrade from inferred to runtime_observed
- P3A-24 Contract tests: adapter interface, adapter result schema, insight level transitions
- P3A-25 Scenario tests: adapter degradation (break each adapter → verify fallback), lifecycle events (container added/removed)

## Dependency notes

- P3A-01 depends on existing `models.py` and service/discovery code from Phase 1
- P3A-02 depends on P3A-01 and existing descriptor schema from P1-03
- P3A-03 depends on P3A-01 and P3A-02
- P3A-04 depends on existing vault/UAC from Phase 2B
- P3A-05..09 depend on P3A-03 and P3A-04
- P3A-10..11 depend on P3A-03
- P3A-12 is independent (cross-cutting capability health, not adapter-specific)
- P3A-13..14 depend on existing scheduler and discovery/change foundations from Phase 1/2
- P3A-15 depends on existing change tracker and incident manager
- P3A-16 depends on P3A-03 and P3A-13
- P3A-17..20 depend on P3A-01, P3A-12, and existing React UI from P1-21/P2A/P2B
- P3A-21 depends on the existing redaction module from P2B-10 and on adapter fact serialization surfaces
- P3A-22 depends on P3A-03..09 and P3A-21 and the existing investigation workflow from P2A/P2B
- P3A-23 depends on P3A-22 and existing dependency-mapper / graph logic from Phase 1
- P3A-24..25 depend on the relevant interface, lifecycle, UI, and evidence work above

## Exit criteria

- Every service has a visible insight level (0-5) in the service map and detail panel
- At least 5 priority adapters operational with fixture-based tests
- Adapter degradation produces visible status change and fallback to base inference
- Kaval health dashboard shows status of all 10 capability layers
- New container added → appears in service map within one reconciliation cycle
- Container removed → handled per lifecycle model (map updated, history preserved, lifecycle state classified or marked for operator review)
- Adapter facts included in investigation evidence when credentials configured
- Dependency edge confidence upgrades from inferred to runtime_observed after adapter confirmation
- All adapter facts pass two-level redaction before LLM prompt inclusion

## Review gates

- All adapters are read-only — no state mutations through any adapter
- Adapter code is separate from descriptor declarations (no procedural logic in descriptors)
- Phase 3/4 action boundary maintained: no new system-modifying actions
- Security review for adapter credential handling and fact redaction

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `ruff check .`
- `mypy src`

## Notes

- Adapters prefer stable structured APIs over UI scraping.
- No headless browser automation.
- Adapter refresh cadence is separate from core check cadence (default: 30-60 min background, immediate on investigation trigger).
- The effectiveness score uses equal weighting in v1; future versions may weight by centrality.
- Service lifecycle "intentional removal" requires user confirmation — Kaval does not guess intent.

---

# Task execution packets

Each packet below is meant to give Codex enough task-local guidance to execute safely without broadening scope.

## P3A-01 — Service insight level model and per-service tracking

**Goal**
Create the canonical insight-level representation (Level 0–5), define how it is stored/computed per service, and make it available to backend/API/UI consumers as a stable contract.

**Primary touch surfaces**
- `src/kaval/models.py`
- `src/kaval/database.py`
- `src/kaval/api/schemas.py`
- `schemas/`
- `tests/unit/test_models.py`
- `tests/unit/test_database.py`
- `tests/contract/`

**Acceptance criteria**
- A typed insight-level field or equivalent stable representation exists for services.
- The meaning of each level matches the requirements expansion.
- The representation is persisted or derivable consistently enough for later API/UI use.
- Any changed checked-in schema artifacts are regenerated/updated.

**Validation focus**
- unit tests for model validation and persistence
- contract tests for any schema export changes
- typecheck

**Stop conditions**
- If this task appears to require descriptor extensions or adapter registry design, stop at the minimal interface needed and leave those to P3A-02/P3A-03.
- Do not add UI here.

## P3A-02 — Descriptor schema extension

**Goal**
Extend the descriptor contract to declare deeper inspection capability without embedding procedural execution logic.

**Primary touch surfaces**
- `src/kaval/discovery/descriptors.py`
- `src/kaval/schema_export.py`
- `schemas/service_descriptor.json`
- `services/` (only if sample descriptors need minimal updates)
- `tests/unit/test_service_descriptors.py`
- `tests/contract/test_service_descriptors.py`
- `tests/contract/test_schemas.py`

**Acceptance criteria**
- Descriptor schema supports inspection surfaces, auth mode, facts, confidence effect, and version range.
- Descriptor parsing/validation enforces the descriptor/adapter responsibility split.
- Existing descriptors remain valid unless intentionally updated.

**Validation focus**
- descriptor loading tests
- schema contract tests
- minimal descriptor fixture coverage

**Stop conditions**
- Do not implement HTTP extraction logic in descriptors.
- Do not start adapter-specific service updates beyond minimal examples.

## P3A-03 — ServiceAdapter protocol, AdapterResult model, adapter registry

**Goal**
Create the internal typed adapter interface and registration mechanism that all deep-inspection adapters will use.

**Primary touch surfaces**
- `src/kaval/integrations/` or `src/kaval/investigation/` (choose one canonical home)
- `src/kaval/models.py` or dedicated adapter models module
- `tests/unit/test_adapter_*` or equivalent new test module
- `tests/contract/` if adapter result shape becomes a formal contract

**Acceptance criteria**
- `ServiceAdapter` protocol/interface exists.
- `AdapterResult` and any discovered-edge helper models are typed and validated.
- A registry or lookup mechanism exists for mapping descriptor surface IDs to adapter implementations.

**Validation focus**
- unit tests for registration, success/failure result shapes, and non-raising degradation behavior
- typecheck

**Stop conditions**
- Do not implement real service adapters here.
- Do not wire evidence gathering yet.

## P3A-04 — Adapter credential integration

**Goal**
Integrate deep adapters with the existing vault/UAC/credential request flow from Phase 2B before any adapter-specific implementation begins.

**Primary touch surfaces**
- `src/kaval/credentials/`
- adapter registry/execution path
- `src/kaval/api/` if any setup/test routes are required
- tests for credential retrieval/injection

**Acceptance criteria**
- Adapters can request and consume credentials through existing approved mechanisms.
- No raw credential values are exposed in UI, logs, prompts, or adapter outputs.
- Unconfigured adapters are visible as unconfigured, not broken.

**Validation focus**
- security tests
- unit tests for credential retrieval and unconfigured-path behavior

**Stop conditions**
- Do not redesign the vault.
- Do not add new credential storage modes unless clearly required and documented.

## P3A-05 — Nginx Proxy Manager adapter

**Goal**
Implement a read-only NPM adapter that extracts proxy hosts, domains, upstreams, and cert bindings via stable API surfaces.

**Primary touch surfaces**
- adapter module under the canonical adapter package
- fixtures under `tests/fixtures/`
- unit/integration tests for NPM adapter behavior
- possibly descriptor updates for NPM inspection surfaces if not already covered in P3A-02

**Acceptance criteria**
- NPM adapter authenticates through existing credential paths.
- It extracts structured proxy-host facts without UI scraping.
- It returns healthy/degraded/auth_failed/etc. states via `AdapterResult`.

**Validation focus**
- fixture-backed adapter tests
- redaction/pathological-response safety where relevant

**Stop conditions**
- No headless browser logic.
- No config mutation.
- No write APIs.

## P3A-06 — Radarr adapter

**Goal**
Implement a read-only Radarr adapter for download clients, indexers, queue health, and related facts useful to investigation.

**Primary touch surfaces**
- Radarr adapter module
- descriptor sample/supporting files if required
- fixtures/tests for Radarr responses

**Acceptance criteria**
- Extracted facts are structured and investigation-relevant.
- Fact names align with descriptor declarations.
- Failures degrade gracefully.

**Validation focus**
- fixture-backed tests
- version compatibility handling where practical

**Stop conditions**
- No UI work.
- No ARR-family generalization yet unless it is a tiny shared helper.

## P3A-07 — Authentik adapter

**Goal**
Implement a read-only Authentik adapter for apps, providers, outposts, and service-health-relevant identity facts.

**Primary touch surfaces**
- Authentik adapter module
- fixtures/tests
- optional descriptor surface declarations if not already in place

**Acceptance criteria**
- Adapter returns identity topology facts useful to investigations.
- Auth and schema failures are distinguishable.

**Validation focus**
- adapter unit/integration tests
- security-focused tests around secret handling if needed

**Stop conditions**
- No state changes in Authentik.
- No OAuth/browser automation.

## P3A-08 — Cloudflare adapter

**Goal**
Implement a read-only Cloudflare adapter for DNS records, SSL mode, and tunnel-route facts useful to ingress investigations.

**Primary touch surfaces**
- Cloudflare adapter module
- fixtures/tests
- any provider-specific helper modules

**Acceptance criteria**
- Cloudflare facts are fetched read-only and normalized.
- External API rate-limit awareness is designed in at least minimally.
- Failures degrade cleanly.

**Validation focus**
- fixture-backed tests
- security tests around token handling/redaction if required

**Stop conditions**
- No Cloudflare write actions.
- No assumptions that every user has Cloudflare configured.

## P3A-09 — Pi-hole adapter

**Goal**
Implement a read-only Pi-hole adapter for upstream DNS, blocklist, and DHCP-related health/config facts.

**Primary touch surfaces**
- Pi-hole adapter module
- fixtures/tests

**Acceptance criteria**
- Adapter returns structured network/DNS facts relevant to investigations.
- Missing credentials or unavailable API degrades gracefully.

**Validation focus**
- adapter unit/integration tests

**Stop conditions**
- No mutation of Pi-hole config.

## P3A-10 — Adapter self-diagnostic checks

**Goal**
Implement the health-check routines that test adapter connection, auth, schema compatibility, and version support.

**Primary touch surfaces**
- adapter health modules
- scheduler/invocation hooks for diagnostic cadence
- tests for each health status path

**Acceptance criteria**
- Diagnostic checks can produce healthy/auth_failed/connection_failed/version_incompatible/parse_error/degraded.
- Diagnostic failures do not crash the adapter or service monitor path.

**Validation focus**
- unit tests for each diagnostic status
- typecheck

**Stop conditions**
- Do not yet build the full UI health dashboard here.

## P3A-11 — Adapter degradation and fallback behavior

**Goal**
Define and implement what happens when an adapter becomes unhealthy: fallback to base inference, visible degradation, and confidence downgrades/staleness handling.

**Primary touch surfaces**
- adapter execution path
- dependency/confidence mapping logic
- maybe database fields for last successful adapter fact sync
- tests

**Acceptance criteria**
- Kaval falls back to base inference without breaking investigations.
- Runtime-observed facts/edges become stale or revert per policy.
- User-visible degradation state is represented in data/API.

**Validation focus**
- scenario-style tests for fallback paths
- unit tests for confidence downgrade rules

**Stop conditions**
- Do not implement broad notification policy here beyond what is necessary for later 3B self-health routing.

## P3A-12 — Kaval capability health model

**Goal**
Create the broader Kaval self-health model across discovery, scheduler, models, notifications, vault, adapters, webhooks, executor, and database.

**Primary touch surfaces**
- `src/kaval/runtime/` and adjacent API/data-model modules
- API schemas/routes for self-health exposure
- data models/tests

**Acceptance criteria**
- A typed internal representation exists for all 10 capability layers.
- Kaval can report healthy/degraded/critical-equivalent status with explanations.
- The model is usable by later UI tasks.

**Validation focus**
- unit tests for capability-health aggregation
- API tests if exposed now

**Stop conditions**
- Do not build the full dashboard UI here.
- Do not over-couple capability health to service health.

## P3A-13 — Monitoring cadence formalization

**Goal**
Make check cadence defaults explicit and configurable, including incident-triggered acceleration.

**Primary touch surfaces**
- `src/kaval/monitoring/scheduler.py`
- check configuration models
- maybe settings/config persistence surfaces
- tests for due logic and acceleration behavior

**Acceptance criteria**
- Check types have explicit defaults.
- Acceleration during incidents is bounded and testable.
- Global/per-check/per-service overrides have a defined data shape, even if UI comes later.

**Validation focus**
- scheduler unit tests
- config parsing tests

**Stop conditions**
- Do not build the full settings UI here.

## P3A-14 — Topology refresh model

**Goal**
Formalize event-driven topology refresh with periodic reconciliation as a backstop.

**Primary touch surfaces**
- discovery pipeline
- change tracker
- service graph refresh logic
- tests/scenarios around add/remove/change detection

**Acceptance criteria**
- New services can enter the active map within the intended refresh model.
- Periodic reconciliation exists or is represented clearly enough for later implementation.
- Docker/Unraid events do not silently corrupt graph state.

**Validation focus**
- integration/scenario tests for add/remove/update discovery

**Stop conditions**
- If current runtime lacks the needed event source entirely, record the blocker rather than inventing speculative behavior.

## P3A-15 — Service lifecycle event handling

**Goal**
Implement the service lifecycle behavior rules for added, updated, restarted, removed, removed-during-maintenance, and renamed/rematched services.

**Primary touch surfaces**
- change tracker
- incident manager
- database/history retention logic
- API schemas if lifecycle status is exposed
- tests/scenarios

**Acceptance criteria**
- Lifecycle transitions are explicit and testable.
- Removed services leave history behind instead of disappearing from all context.
- “Intentional removal” is not guessed; it must be tied to trusted signals such as maintenance mode or user confirmation.

**Validation focus**
- lifecycle scenario tests
- integration tests for map/history retention

**Stop conditions**
- Do not add destructive actions.
- Do not auto-delete state/history.

## P3A-16 — Adapter fact refresh cadence

**Goal**
Define and implement the scheduler behavior for adapter fact refreshes separate from core checks.

**Primary touch surfaces**
- adapter scheduler hooks
- config model for adapter refresh interval
- tests around cadence and staleness

**Acceptance criteria**
- Adapter refreshes have a separate cadence from checks.
- Investigation-triggered refresh is supported or explicitly represented.
- Rate-limited providers can use safer default intervals.

**Validation focus**
- scheduler/unit tests

**Stop conditions**
- No per-adapter UI tuning yet unless data contracts require it.

## P3A-17 — UI: Insight level badges on service map nodes

**Goal**
Expose per-service insight levels visually in the existing map UI.

**Primary touch surfaces**
- `src/web/` React map components
- API data shape used by the map
- UI tests/build validation

**Acceptance criteria**
- Each service node shows an insight level indicator.
- Rendering does not break existing graph usability.

**Validation focus**
- UI build
- integration/API tests if node payload changed

**Stop conditions**
- Keep the UI minimal here; richer detail belongs to later tasks.

## P3A-18 — UI: Service detail insight section

**Goal**
Add the minimum insight section to the service detail panel, including adapter status, imported facts, and improve affordances.

**Primary touch surfaces**
- `src/web/`
- backend API routes/schemas for service detail data
- tests

**Acceptance criteria**
- User can see current insight level, adapter health/config state, and imported fact summary.
- Improve affordances are visible where a service can be made smarter.

**Validation focus**
- UI build
- integration tests for service detail payload

**Stop conditions**
- Do not turn this into the full service detail panel; that belongs to 3C.

## P3A-19 — UI: Kaval health panel

**Goal**
Provide a minimal dashboard/panel showing Kaval capability-layer health.

**Primary touch surfaces**
- `src/web/`
- backend API for capability health

**Acceptance criteria**
- The panel shows per-capability layer status and explanation.
- It clearly distinguishes Kaval-health issues from service-health issues.

**Validation focus**
- UI build
- API tests

**Stop conditions**
- Keep this focused on visibility, not alert routing policy.

## P3A-20 — UI: Effectiveness score stub

**Goal**
Expose the initial equal-weighted effectiveness score and a minimal breakdown.

**Primary touch surfaces**
- UI summary/dashboard
- API or computed aggregation layer
- tests

**Acceptance criteria**
- Score is computed with the v1 equal-weighted formula.
- Breakdown is simple and transparent enough that users understand the number.

**Validation focus**
- unit tests for aggregation
- UI build

**Stop conditions**
- Do not over-engineer weighting in v1.

## P3A-21 — Two-level redaction for adapter facts

**Goal**
Ensure adapter-imported facts follow the existing local-safe/cloud-safe redaction model before they can enter model prompts.

**Primary touch surfaces**
- `src/kaval/memory/redaction.py`
- adapter fact serialization path
- investigation prompt assembly
- tests/security

**Acceptance criteria**
- Adapter facts are redacted appropriately before local/cloud prompt inclusion.
- Sensitive fact fields can be excluded entirely when needed.
- The redaction behavior is available before evidence-gathering integration begins using adapter facts in model-facing context.

**Validation focus**
- security tests
- prompt redaction tests

**Stop conditions**
- Do not duplicate the redaction system; extend the existing one.

## P3A-22 — Evidence gathering integration

**Goal**
Wire adapters into Tier 1 evidence gathering so investigations can consume adapter facts when available.

**Primary touch surfaces**
- `src/kaval/investigation/evidence.py`
- `src/kaval/investigation/workflow.py`
- adapter registry/invocation path
- tests

**Acceptance criteria**
- Investigations invoke available adapters when credentials and adapter health allow.
- Adapter facts are included as structured evidence.
- Missing/unhealthy adapters do not break the investigation workflow.
- Any model-facing use of adapter facts respects the redaction path established in P3A-21.

**Validation focus**
- workflow tests
- prompt/evidence tests
- security tests if adapter facts enter model-facing context

**Stop conditions**
- Do not broaden remediation scope.
- Do not let adapter failures crash investigations.

## P3A-23 — Confidence upgrade

**Goal**
Upgrade dependency edges from inferred/configured to `runtime_observed` when adapter facts confirm them.

**Primary touch surfaces**
- dependency mapper / graph logic
- service graph persistence
- tests

**Acceptance criteria**
- Confirmed relationships from adapter facts upgrade confidence deterministically.
- Reversion/staleness behavior remains compatible with P3A-11.

**Validation focus**
- unit tests for edge confidence transitions
- graph/API tests if payloads change

**Stop conditions**
- Do not create auto-confirmation of relationships from weak evidence.

## P3A-24 — Contract tests

**Goal**
Add the contract-level validation needed to keep the new insight/adapter interfaces stable.

**Primary touch surfaces**
- `tests/contract/`
- schema exports if any are formalized

**Acceptance criteria**
- Adapter result/interface contracts are validated.
- Insight-level transitions or serialized forms are covered where appropriate.

**Validation focus**
- contract tests

**Stop conditions**
- Keep contract coverage aligned to actual public/stable interfaces, not every private helper.

## P3A-25 — Scenario tests

**Goal**
Prove the phase with scenario coverage for adapter degradation and lifecycle events.

**Primary touch surfaces**
- `tests/scenario/`
- fixtures

**Acceptance criteria**
- At least one adapter degradation path demonstrates visible fallback.
- Lifecycle tests cover add/remove/update semantics at the service-map/history level.

**Validation focus**
- scenario tests
- security tests if relevant to degradation paths

**Stop conditions**
- Do not over-pack every adapter into scenario coverage if unit/integration coverage already proves most logic; focus on the most load-bearing cross-cutting flows.
