# Phase 3C — Admin UX, Guided Setup, Noise Control, Descriptors

## Objective

Complete the admin and configuration experience. Deliver the guided first-hour setup flow, interactive dependency graph editing, settings management, noise control, auto-generated descriptor workflow, and descriptor catalog expansion. Make Kaval accessible and configurable for someone just installing the product.

## Requirements Reference

Phase 3/4 Requirements Expansion v2: Sections 5 (First-Hour Experience), 6 (Interactive Graph), 7 (Admin UX), 11 (Noise Control), 12 (Action Boundary — reassert), 16 (Auto-Generated Descriptors), 18 (Descriptor Expansion), 19 (VMs/Plugins graph/UX), 21 (Audit Trail), 22 (Cost Dashboard)

## Deliverables

- Guided setup flow (5 steps: discovery summary, dependency review, effectiveness assessment, notification setup, model config)
- Interactive dependency graph: edge confidence visualization, node insight badges, click-to-edit edges, graph filters
- Service detail panel: identity, health, insight, dependencies, credentials, memory, notification sections
- Descriptor editor UI: view mode, edit mode, YAML editor, validation, auto-generated review queue
- Settings UI: model config, notification channels, check intervals, vault management, system
- Noise control: per-service check suppression, threshold adjustment, finding feedback loop, maintenance mode
- Audit trail UI with chronological event stream and filters
- Model usage / cost dashboard
- Auto-generated descriptor quarantine workflow and promotion UI
- 15+ additional shipped descriptors (target: 35+ total)
- VM graph representation and guided VM setup prompts
- Plugin classification as system facets with impact annotations

## Global execution guardrails

- Phase 3C is an admin/UX phase. It must not broaden the approved system action scope.
- All settings, descriptor, suppression, and maintenance flows are deterministic UI/API operations and must never be LLM-driven.
- The single-admin v1 access assumption remains in force. Do not accidentally introduce partial RBAC semantics in this phase.
- Auto-generated descriptors remain quarantined until reviewed and promoted. They must not influence action recommendations or incident grouping before promotion.
- Favor additive UI/API surfaces over broad rewrites of the existing service map, investigation UI, and memory flows.
- Guided setup should be implemented last in this phase as a composition layer over already-built graph, settings, and effectiveness surfaces.
- For execution runs, the active-task prompt must still restate exact files, validations, and blockers before coding begins.

## Suggested repository touch surfaces

Use these as likely touch surfaces, not as blanket permission:

- `src/web/` (React UI, styles, types, route/view state, graph/detail/settings/guided-setup surfaces)
- `src/kaval/api/` (`app.py`, `schemas.py`, any additional read/write admin endpoints)
- `src/kaval/database.py`
- `src/kaval/models.py`
- `src/kaval/memory/`
- `src/kaval/investigation/`
- `src/kaval/credentials/`
- `src/kaval/discovery/` (descriptor handling, service metadata)
- `services/` (descriptor catalog)
- `schemas/` (if descriptor/model schema changes are required)
- `tests/unit/`
- `tests/integration/`
- `tests/contract/`
- `tests/scenario/`
- `tests/security/`
- `STATUS.md`
- `README.md` or other user-facing docs only when a completed task materially changes operator-facing behavior

## Tasks

- P3C-01 Interactive graph: edge confidence visualization (solid/dashed/dotted/faint by confidence type)
- P3C-02 Interactive graph: edge hover/click (source of truth, confidence, confirm/edit/remove)
- P3C-03 Interactive graph: node insight depth indicators and "improve" badges
- P3C-04 Interactive graph: add dependency flow, missing information indicators
- P3C-05 Interactive graph: filters (category, health status, insight level, confidence)
- P3C-06 Interactive graph: incident mode (highlight failure path, fade unaffected)
- P3C-07 Service detail panel: full implementation (identity, health, insight, deps, creds, memory, notifications)
- P3C-08 Descriptor editor: view mode (rendered, not raw YAML)
- P3C-09 Descriptor editor: edit mode (form-based common fields + YAML editor for advanced)
- P3C-10 Descriptor editor: validation on save (schema check, policy lint, preview)
- P3C-11 Auto-generated descriptor: trigger (unmatched container + local model → quarantined descriptor)
- P3C-12 Auto-generated descriptor: review queue UI (side-by-side view, promote/edit/dismiss/defer)
- P3C-13 Auto-generated descriptor: community export path (clean YAML for GitHub PR)
- P3C-14 Settings: model configuration (local endpoint, cloud provider, escalation thresholds, cost controls, test connection)
- P3C-15 Settings: notification channels (add/remove/test, per-severity routing, dedup, quiet hours)
- P3C-16 Settings: monitoring configuration (global intervals, per-check enable/disable, per-service overrides)
- P3C-17 Settings: credential vault management (list, test, lock/unlock, master password change)
- P3C-18 Settings: system (database maintenance, log level, backup/export with sensitivity warning, import, about page)
- P3C-19 Noise control: per-service check suppression toggles in service detail
- P3C-20 Noise control: per-check threshold adjustment (cert expiry days, restart storm threshold, probe timeout)
- P3C-21 Noise control: finding feedback loop ("dismiss as false positive" → auto-suggest suppression after N dismissals)
- P3C-22 Noise control: maintenance mode (per-service and global, time-bound, visible indicator, self-health guardrail)
- P3C-23 Proactive suggestions engine ("3 services without descriptors," "API key not tested in 30 days," etc.)
- P3C-24 Audit trail UI (chronological event stream, filters by type/service/date, export, retention config)
- P3C-25 Model usage / cost dashboard (today/week/month, per-incident breakdown, escalation analysis, budget status)
- P3C-26 VM graph representation (distinct node type, hosted service child nodes, guided VM setup prompt)
- P3C-27 Plugin system facets (system profile display, change timeline entries, impact annotations on dependent services)
- P3C-28 Descriptor expansion: 20 additional shipped descriptors (target categories: media, downloads, networking, identity, cloud, monitoring, databases, system, home automation)
- P3C-29 Descriptor contract test expansion for new descriptors
- P3C-30 Guided setup: Step 1 — Discovery summary (what was found, unknown containers, identify/skip)
- P3C-31 Guided setup: Step 2 — Dependency review (confirm/correct inferred edges, confidence display)
- P3C-32 Guided setup: Step 3 — Effectiveness assessment (per-service insight level, "improve" suggestions)
- P3C-33 Guided setup: Step 4 — Notification setup (channel config, test notification, severity preferences)
- P3C-34 Guided setup: Step 5 — Model configuration (auto-detect local model, cloud config, escalation)
- P3C-35 End-to-end scenario: first-run guided setup flow complete walkthrough
- P3C-36 End-to-end scenario: descriptor auto-generation → quarantine → review → promote → monitoring active

## Dependency notes

- P3C-01 depends on the existing React Flow service map from Phase 1 and confidence/edge data already available from discovery and investigation surfaces.
- P3C-02 depends on P3C-01 plus API exposure of edge source-of-truth / confidence metadata.
- P3C-03 depends on P3A-17 (insight badges data) and the existing service map node rendering path.
- P3C-04 depends on P3C-02 and backend support for add/edit/remove dependency operations.
- P3C-05 depends on P3C-01..04 and API/query support for graph filtering.
- P3C-06 depends on P3C-01..05 and incident/path context from the existing investigation graph APIs.
- P3C-07 depends on P3A-18 (insight section foundation), Phase 3B memory/alerting APIs, and existing service/finding/investigation data.
- P3C-08..10 depend on the existing descriptor schema from P1-03 and the current `services/` catalog.
- P3C-11 depends on local model availability from Phase 2A/2B and unmatched-container detection from existing discovery flows.
- P3C-12 depends on P3C-11 and the quarantine/promotion state model.
- P3C-13 depends on P3C-12.
- P3C-14 depends on existing local/cloud model config surfaces from Phase 2A/2B and the current admin/config persistence model.
- P3C-15 depends on the notification bus and routing behavior from Phase 2A/3B.
- P3C-16 depends on the scheduler/check configuration surfaces from Phase 1 and monitoring cadence semantics from Phase 3A.
- P3C-17 depends on the credential vault and request-flow behavior from Phase 2B.
- P3C-18 depends on existing database/admin persistence surfaces and any backup/export APIs already planned for Phase 4 must remain out of scope here.
- P3C-19 depends on P3C-07 and the existing check framework from P1-06.
- P3C-20 depends on P3C-19 and the threshold-bearing checks from Phase 1.
- P3C-21 depends on P3C-19..20 and the finding/incident history needed to derive feedback suggestions.
- P3C-22 depends on P3C-15..16 and the maintenance/self-health rules defined in the requirements expansion.
- P3C-23 depends on P3C-07, P3C-11..12, P3C-17, P3C-19..22, and effectiveness data from Phase 3A.
- P3C-24 depends on existing audit/event data accumulated across earlier phases and any new admin changes introduced here.
- P3C-25 depends on model-usage tracking from P2A-04 and P2B-05 plus any admin-facing aggregation APIs added here.
- P3C-26 depends on the graph surfaces from P3C-01..06 and VM discovery/state already present from Phase 1.
- P3C-27 depends on existing system profile/change timeline data and should not promote plugins to full service nodes.
- P3C-28 is largely independent and can be parallelized across contributors once the descriptor editor / quarantine model is stable.
- P3C-29 depends on P3C-28 and the existing descriptor contract harness.
- P3C-30 depends on the underlying graph, effectiveness, and unknown-container surfaces being complete (P3C-03..06, P3C-23, P3C-26..27).
- P3C-31 depends on dependency editing from P3C-02..04.
- P3C-32 depends on effectiveness scoring/suggestions from Phase 3A and P3C-23.
- P3C-33 depends on notification channel setup from P3C-15.
- P3C-34 depends on model configuration from P3C-14.
- P3C-35 depends on P3C-30..34.
- P3C-36 depends on P3C-11..13, P3C-28..29, and the post-promotion monitoring activation path.

## Exit criteria

- New user installs Kaval → guided setup walks through 5 steps → sees insight levels, effectiveness score, and improvement suggestions
- User can click an edge in the graph → see confidence source → confirm, edit, or remove
- User can suppress a check for a specific service → check stops firing for that service → suppression is visible in service detail and audit trail
- Auto-generated descriptor created for unknown container → visible in review queue → user promotes → monitoring activates only after promotion
- Settings UI covers model config, notifications, monitoring intervals, vault, and system
- Maintenance mode: user activates for 2 hours → normal findings suppressed → critical self-health still fires unless explicitly disabled by a later-approved design → mode auto-expires
- Audit trail shows full event history with filters
- Cost dashboard shows model usage with per-incident breakdown
- 35+ total shipped descriptors with contract tests passing
- VMs appear in graph with distinct styling; plugins appear in system profile/facet views with impact annotations

## Review gates

- Action boundary reasserted: no new system-modifying actions in this phase
- Settings changes are admin UI operations, never LLM-driven
- Auto-generated descriptor quarantine rules enforced: never used for action recommendations or incident grouping before promotion
- Single-admin v1 access model: all admin UIs assume trusted local admin
- Suppression guardrails: no auto-suppression of critical checks without explicit user confirmation
- Guided setup is a composition layer over already-built capability surfaces; it must not invent hidden configuration paths that bypass the main admin UX

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `cd src/web && npm run build`
- `ruff check .`
- `mypy src`

## Notes

- The guided setup flow is the most important UX deliverable in this phase. It should be implemented after the underlying graph, effectiveness, and settings surfaces exist.
- Settings persistence model (YAML vs DB vs hybrid) may need an ADR (ADR-018 candidate).
- Descriptor expansion can be parallelized across contributors — each descriptor is independent.
- v1 access model is single trusted local admin. Documentation must state this assumption.

---

## Task execution packets

### P3C-01 Interactive graph: edge confidence visualization
- **Goal:** Render confidence state clearly on graph edges so users can distinguish confirmed, configured, inferred, and auto-generated relationships.
- **Primary touch surfaces:** `src/web/`, graph-related API payloads if missing, UI tests.
- **Acceptance criteria:**
  - edge styles map deterministically to confidence types
  - legend/help text exists or the meaning is otherwise obvious in UI
  - no regression to existing graph rendering for services without dependency edges
- **Validation focus:** frontend build, graph UI tests, integration/API tests if payloads changed.
- **Stop if:** confidence data is not available from the current API surfaces and a backend contract change is required.

### P3C-02 Interactive graph: edge hover/click
- **Goal:** Show source-of-truth, confidence explanation, and confirm/edit/remove affordances for each edge.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`.
- **Acceptance criteria:**
  - edge hover/click reveals source-of-truth metadata
  - confirm/edit/remove paths are deterministic and auditable
  - no hidden action path bypasses existing admin assumptions
- **Validation focus:** frontend build, API/integration tests, audit-related tests if mutation events are recorded.
- **Stop if:** the current backend cannot represent edge provenance without a new contract decision.

### P3C-03 Interactive graph: node insight depth indicators and "improve" badges
- **Goal:** Expose service insight depth directly in the graph and surface available upgrade actions.
- **Primary touch surfaces:** `src/web/`, existing service map API payloads.
- **Acceptance criteria:**
  - every node displays current insight level
  - services below max achievable level show a non-intrusive improve indicator
  - improve indicator links to a deterministic follow-up path, not a placeholder
- **Validation focus:** frontend build, UI tests.
- **Stop if:** max-achievable insight is not computable from current backend data.

### P3C-04 Interactive graph: add dependency flow, missing information indicators
- **Goal:** Let users add/repair edges and mark low-confidence or missing-information spots visibly.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, dependency persistence layer if needed.
- **Acceptance criteria:**
  - add/edit/remove edge flow is explicit and reviewable
  - missing-information indicators appear only where the system actually lacks confidence/data
  - edge changes persist and appear in subsequent graph loads
- **Validation focus:** integration tests for dependency mutation/persistence, frontend build.
- **Stop if:** dependency mutation would silently alter grouping/action behavior without an explicit contract review.

### P3C-05 Interactive graph: filters
- **Goal:** Add graph filters for category, health, insight level, and confidence.
- **Primary touch surfaces:** `src/web/`, possibly API query/filter support.
- **Acceptance criteria:**
  - filters are composable and reversible
  - filtered graph preserves layout stability as much as practical
  - no hidden services/edges disappear from auditability permanently; filters are view-only
- **Validation focus:** frontend build, UI tests.
- **Stop if:** the graph data shape is too coarse to support the required filters cleanly.

### P3C-06 Interactive graph: incident mode
- **Goal:** During incidents, highlight the likely failure path and fade unrelated services.
- **Primary touch surfaces:** `src/web/`, existing graph/investigation APIs.
- **Acceptance criteria:**
  - incident mode is tied to a selected incident or investigation context
  - relevant nodes/edges are highlighted consistently
  - unaffected services are faded, not removed
- **Validation focus:** frontend build, investigation UI integration tests.
- **Stop if:** current graph APIs cannot expose enough context to derive a credible incident path.

### P3C-07 Service detail panel: full implementation
- **Goal:** Expand the existing service detail into the full admin/operator panel covering identity, health, insight, dependencies, credentials, memory, and notification state.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, `src/kaval/database.py`.
- **Acceptance criteria:**
  - all listed sections render from real backend data, not placeholders
  - memory and notification sections reuse Phase 3B surfaces instead of duplicating logic
  - panel is navigable from the graph and any services list surface
- **Validation focus:** frontend build, API integration tests, unit tests for any new response assembly.
- **Stop if:** this task starts pulling in broad unrelated admin-page work that belongs to later settings tasks.

### P3C-08 Descriptor editor: view mode
- **Goal:** Provide a readable rendered descriptor view for shipped, user, and quarantined descriptors.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, descriptor loading surfaces.
- **Acceptance criteria:**
  - descriptor data is shown structurally, not as raw YAML by default
  - source type (shipped/user/auto-generated) is visible
  - no secret-bearing fields are exposed accidentally
- **Validation focus:** frontend build, descriptor API tests.
- **Stop if:** descriptor provenance/source type is not available in current APIs.

### P3C-09 Descriptor editor: edit mode
- **Goal:** Support safe editing of common descriptor fields with an advanced YAML fallback.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, descriptor persistence layer.
- **Acceptance criteria:**
  - common fields can be edited via form controls
  - advanced YAML editor exists for expert users
  - edits are isolated to allowed descriptor locations, not shipped defaults unless your repo model explicitly permits overrides
- **Validation focus:** API tests, contract tests if schema/export paths change, frontend build.
- **Stop if:** the repository lacks a clear writable descriptor override location.

### P3C-10 Descriptor editor: validation on save
- **Goal:** Validate descriptor edits before save and preview likely impact.
- **Primary touch surfaces:** `src/kaval/discovery/`, `src/kaval/api/`, `src/web/`, `schemas/` if needed.
- **Acceptance criteria:**
  - save is blocked on schema/policy failure
  - preview explains likely match/dependency impact
  - validation errors are understandable to operators
- **Validation focus:** contract tests, descriptor tests, frontend build.
- **Stop if:** preview logic would require broad rematching of the entire environment without a bounded implementation.

### P3C-11 Auto-generated descriptor: trigger
- **Goal:** Generate a quarantined descriptor candidate for an unmatched container using the local model path only.
- **Primary touch surfaces:** `src/kaval/discovery/`, `src/kaval/investigation/` or descriptor-generation module, `src/kaval/api/`.
- **Acceptance criteria:**
  - unmatched container can produce a quarantined descriptor candidate
  - generated descriptor is clearly marked quarantined
  - no generated descriptor becomes active automatically
- **Validation focus:** unit tests, security tests, descriptor contract tests if shape changes.
- **Stop if:** generation would require cloud-only behavior or bypass the quarantine model.

### P3C-12 Auto-generated descriptor: review queue UI
- **Goal:** Provide a review queue for promote/edit/dismiss/defer decisions on quarantined descriptors.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, descriptor provenance/persistence logic.
- **Acceptance criteria:**
  - quarantined descriptors are visible in a dedicated queue
  - side-by-side comparison is available where requirements call for it
  - promote/edit/dismiss/defer actions are recorded and auditable
- **Validation focus:** frontend build, integration tests, descriptor state transition tests.
- **Stop if:** the quarantine state model is not explicit enough to support UI actions safely.

### P3C-13 Auto-generated descriptor: community export path
- **Goal:** Export reviewed descriptors in a clean community-contribution format.
- **Primary touch surfaces:** `src/kaval/api/`, descriptor serialization, docs if export workflow is user-visible.
- **Acceptance criteria:**
  - exported descriptor omits local/private metadata not suitable for contribution
  - export format is reviewable and deterministic
  - promotion and export remain separate operations
- **Validation focus:** descriptor contract tests, integration tests.
- **Stop if:** export semantics are not yet defined well enough to avoid leaking local operator data.

### P3C-14 Settings: model configuration
- **Goal:** Build the model configuration UI for local/cloud providers, escalation thresholds, cost controls, and test connection.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, model config persistence surfaces.
- **Acceptance criteria:**
  - operator can view/update local/cloud model settings
  - test connection is explicit and safe
  - escalation/cost controls map to existing runtime behavior
- **Validation focus:** API tests, security tests for secret handling, frontend build.
- **Stop if:** settings persistence model is unresolved enough to require ADR-018 before implementation.

### P3C-15 Settings: notification channels
- **Goal:** Build the notification settings UI for channels, routing, dedup, and quiet hours.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, notification config/persistence surfaces.
- **Acceptance criteria:**
  - channels can be added/removed/tested
  - per-severity routing and dedup settings are editable
  - quiet hours are visible and understandable
- **Validation focus:** integration tests, frontend build.
- **Stop if:** testing channels would require unsafe live-send behavior without bounded mocks or explicit operator confirmation.

### P3C-16 Settings: monitoring configuration
- **Goal:** Expose global/per-check/per-service monitoring interval and enable/disable controls.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, scheduler/config surfaces.
- **Acceptance criteria:**
  - global and override semantics are explicit
  - changes affect the real scheduler/check configuration model
  - operators can tell what effective interval is active for a service/check
- **Validation focus:** unit/integration tests around config application, frontend build.
- **Stop if:** cadence semantics from Phase 3A are not yet stable enough to surface safely.

### P3C-17 Settings: credential vault management
- **Goal:** Provide the operator-facing vault management UI.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, `src/kaval/credentials/`.
- **Acceptance criteria:**
  - credentials are listed by name/service only, never by raw secret value
  - test/lock/unlock/change-password flows are explicit
  - vault state is understandable without leaking sensitive data
- **Validation focus:** security tests, API tests, frontend build.
- **Stop if:** any UI path risks exposing raw secrets in responses, logs, or browser state.

### P3C-18 Settings: system
- **Goal:** Expose system/admin settings such as DB maintenance, log level, import/export warnings, and about page.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, database/admin surfaces.
- **Acceptance criteria:**
  - system settings are clearly separated from service-specific settings
  - backup/export warnings mention sensitivity explicitly
  - about page reflects real runtime/build/model state
- **Validation focus:** API tests, frontend build.
- **Stop if:** this task starts implementing Phase 4 backup/restore functionality rather than Phase 3C configuration surfaces.

### P3C-19 Noise control: per-service check suppression
- **Goal:** Let operators suppress specific checks for specific services and make that visible.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, scheduler/check config persistence, audit surfaces.
- **Acceptance criteria:**
  - suppression toggles exist in service detail
  - suppressed checks no longer produce findings for that service
  - suppression is visible in service detail and audit history
- **Validation focus:** integration tests, scenario tests, frontend build.
- **Stop if:** suppression semantics start acting like hidden permanent deletes of check definitions.

### P3C-20 Noise control: per-check threshold adjustment
- **Goal:** Allow threshold tuning for checks that support it.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, check configuration surfaces.
- **Acceptance criteria:**
  - threshold-bearing checks expose tunable values
  - effective thresholds are visible to the operator
  - threshold changes affect future findings deterministically
- **Validation focus:** unit/integration tests around check behavior, frontend build.
- **Stop if:** the implementation attempts to invent threshold knobs for checks that do not have meaningful bounded thresholds.

### P3C-21 Noise control: finding feedback loop
- **Goal:** Capture false-positive feedback and suggest suppression/tuning after repeated dismissals.
- **Primary touch surfaces:** `src/kaval/api/`, `src/kaval/database.py`, `src/web/`.
- **Acceptance criteria:**
  - operator can mark findings as false positive/noise
  - the system tracks repeated dismissals
  - suggestions are surfaced, not silently auto-applied
- **Validation focus:** integration tests, audit/history tests, frontend build.
- **Stop if:** the implementation starts automatically suppressing critical checks without explicit confirmation.

### P3C-22 Noise control: maintenance mode
- **Goal:** Add time-bound per-service and global maintenance mode with visible indicators and self-health guardrail.
- **Primary touch surfaces:** `src/kaval/api/`, `src/web/`, scheduler/notification config surfaces.
- **Acceptance criteria:**
  - maintenance can be set per-service and globally with expiry
  - mode is visibly active in UI
  - normal findings are suppressed per requirements
  - critical Kaval self-health remains unsuppressed unless a future approved design changes that
- **Validation focus:** scenario tests, integration tests, frontend build.
- **Stop if:** maintenance mode semantics would suppress all self-health or action-boundary alerts by default.

### P3C-23 Proactive suggestions engine
- **Goal:** Surface improvement suggestions such as missing descriptors, stale credentials, or noisy checks.
- **Primary touch surfaces:** `src/kaval/api/`, aggregation logic, `src/web/`.
- **Acceptance criteria:**
  - suggestions are derived from real state, not placeholders
  - suggestion ordering is understandable and consistent
  - suggestions link to the relevant admin/action surfaces
- **Validation focus:** unit tests for suggestion ranking, integration tests, frontend build.
- **Stop if:** suggestions require inference logic that has not yet been stabilized in earlier tasks.

### P3C-24 Audit trail UI
- **Goal:** Provide chronological operator-visible audit history with useful filters.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, audit/event persistence surfaces.
- **Acceptance criteria:**
  - event stream includes the categories introduced in this phase
  - filters by type/service/date work
  - export/retention controls match the requirements expansion
- **Validation focus:** integration tests, frontend build.
- **Stop if:** the underlying audit/event data model is not rich enough to support the required views.

### P3C-25 Model usage / cost dashboard
- **Goal:** Expose model usage and cost information to operators using persisted per-investigation telemetry gathered at investigation time.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, `src/kaval/models.py`, `src/kaval/investigation/`, investigation/model usage aggregation.
- **Acceptance criteria:**
  - investigations created after this task persist `local_input_tokens`, `local_output_tokens`, `cloud_input_tokens`, `cloud_output_tokens`, `estimated_cloud_cost_usd`, `estimated_total_cost_usd`, and `cloud_escalation_reason` alongside the existing model-usage fields
  - dashboard shows today/week/month and per-incident breakdown only from persisted telemetry, with a deterministic empty state when no telemetry-backed investigations exist yet
  - escalation analysis and budget status reflect persisted telemetry plus the existing active model-settings budget controls
  - no secret or provider token data leaks into the dashboard
- **Validation focus:** unit tests for telemetry persistence, integration tests, contract tests if API payloads change, frontend build, security tests.
- **Stop if:** the implementation would require retrospective pricing guesses, provider price lookups, or inferred escalation reasons instead of the approved persisted telemetry contract.

### P3C-26 VM graph representation
- **Goal:** Represent VMs distinctly in the graph and provide a guided VM setup prompt.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, VM-related discovery/service representation.
- **Acceptance criteria:**
  - VMs have distinct visual treatment
  - hosted-service child nodes or equivalent representation are deterministic
  - guided VM setup prompt is informative and bounded to current v1 capability
- **Validation focus:** integration tests, frontend build.
- **Stop if:** implementation drifts into unsupported VM guest introspection instead of graph/UX representation.

### P3C-27 Plugin system facets
- **Goal:** Surface plugins as system facets with impact annotations, not first-class service nodes.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`, system profile/change timeline surfaces.
- **Acceptance criteria:**
  - plugins appear in system/facet views
  - plugin inventory and status are persisted as read-only plugin facets on the existing `SystemProfile` read path
  - `plugin_update` change records come from deterministic discovery diffs for installed / removed / version_changed / state_changed transitions
  - plugin changes can annotate impacted services where known
  - plugin-to-service impact annotations derive only from explicit descriptor `plugin_dependencies` metadata
  - plugins are not promoted to normal service nodes in the graph
- **Validation focus:** integration tests, frontend build.
- **Stop if:** plugin representation begins to conflict with the requirements-expansion classification, requires inferred plugin impacts, or broadens into plugin management/actions.

### P3C-28 Descriptor expansion: 20 additional shipped descriptors
- **Goal:** Increase shipped descriptor coverage to 35+ total.
- **Primary touch surfaces:** `services/`, descriptor tests, maybe docs/changelog if catalog summaries are maintained.
- **Acceptance criteria:**
  - 20 new descriptors land in the required categories
  - each descriptor is schema-valid and follows quality standards
  - no descriptor uses quarantined/auto-generated logic without explicit review/promotion
- **Validation focus:** contract tests, descriptor tests.
- **Stop if:** the descriptor authoring workflow/policy is not stable enough to evaluate new additions consistently.

### P3C-29 Descriptor contract test expansion
- **Goal:** Expand the contract harness for the larger descriptor catalog.
- **Primary touch surfaces:** `tests/contract/`, descriptor fixtures/tests.
- **Acceptance criteria:**
  - all new descriptors are covered by contract validation
  - the contract suite remains maintainable and reasonably fast
  - failures identify which descriptor broke and why
- **Validation focus:** contract tests.
- **Stop if:** contract expectations need a schema/policy change not yet approved.

### P3C-30 Guided setup: Step 1 — Discovery summary
- **Goal:** Build the first step of guided setup on top of real discovery state.
- **Primary touch surfaces:** `src/web/`, `src/kaval/api/`.
- **Acceptance criteria:**
  - summary shows real counts and matched/unknown breakdown
  - identify/skip affordances exist for unknown containers
  - no duplicate logic diverges from the main discovery/service map surfaces
- **Validation focus:** frontend build, integration tests.
- **Stop if:** unknown-container identity/edit flows are not ready enough to make this step actionable.

### P3C-31 Guided setup: Step 2 — Dependency review
- **Goal:** Reuse graph confidence/editing capabilities in a first-run flow for edge confirmation.
- **Primary touch surfaces:** `src/web/`, graph APIs.
- **Acceptance criteria:**
  - user can review and confirm/correct inferred edges during setup
  - confidence sources are visible in setup context
  - confirmed changes reuse the same mutation path as the main graph UI
- **Validation focus:** frontend build, integration tests.
- **Stop if:** setup creates a second, inconsistent dependency-editing implementation.

### P3C-32 Guided setup: Step 3 — Effectiveness assessment
- **Goal:** Present insight-level/effectiveness state and targeted improvement suggestions during setup.
- **Primary touch surfaces:** `src/web/`, effectiveness/suggestions APIs.
- **Acceptance criteria:**
  - per-service insight/effectiveness state is visible
  - improve suggestions are tied to actual missing capabilities
  - step explains why Kaval is limited for some services
- **Validation focus:** frontend build, integration tests.
- **Stop if:** effectiveness semantics are still too unstable to present credibly.

### P3C-33 Guided setup: Step 4 — Notification setup
- **Goal:** Let the operator configure and test notification setup during onboarding.
- **Primary touch surfaces:** `src/web/`, notification config APIs.
- **Acceptance criteria:**
  - user can select/configure a channel
  - test notification path is explicit and safe
  - severity preference choices persist
- **Validation focus:** integration tests, frontend build.
- **Stop if:** this step would bypass the same notification settings model used elsewhere.

### P3C-34 Guided setup: Step 5 — Model configuration
- **Goal:** Let the operator validate local/cloud model setup during onboarding.
- **Primary touch surfaces:** `src/web/`, model config APIs.
- **Acceptance criteria:**
  - local model auto-detect or test path exists where required
  - cloud setup remains optional
  - escalation/cost context is explained clearly
- **Validation focus:** integration tests, frontend build.
- **Stop if:** onboarding starts introducing provider-specific assumptions that conflict with the current generic model approach.

### P3C-35 End-to-end scenario: first-run guided setup flow
- **Goal:** Prove the full first-run setup experience works as a coherent flow.
- **Primary touch surfaces:** `tests/scenario/`, `tests/integration/`, maybe frontend E2E harness if available.
- **Acceptance criteria:**
  - scenario covers all five setup steps
  - expected artifacts/settings/confirmations persist
  - no step dead-ends on missing backend support
- **Validation focus:** scenario tests, integration tests, frontend build.
- **Stop if:** multiple preceding guided-setup steps remain partially stubbed.

### P3C-36 End-to-end scenario: descriptor auto-generation → quarantine → review → promote → monitoring active
- **Goal:** Validate the full quarantined-descriptor lifecycle end to end.
- **Primary touch surfaces:** `tests/scenario/`, `tests/integration/`, descriptor tests.
- **Acceptance criteria:**
  - unknown container triggers quarantined descriptor candidate
  - descriptor remains inactive until review/promotion
  - after promotion, monitoring activates and contract checks still pass
- **Validation focus:** scenario tests, contract tests, integration tests.
- **Stop if:** promotion still does not connect cleanly to descriptor activation and monitoring surfaces.
