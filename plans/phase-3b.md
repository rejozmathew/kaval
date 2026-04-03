# Phase 3B — Integration + User-Facing Capability

## Objective

Make Kaval the investigation brain sitting on top of existing monitoring tools via webhook ingestion. Complete the user-facing operational memory experience. Formalize the alerting operational model. Add Prometheus metrics and Homepage widget.

## Requirements Reference

Phase 3/4 Requirements Expansion v2 final:
- Section 8 (Webhooks)
- Section 9 (Metrics)
- Section 10 (Operational Memory UX)
- Section 15 (Alerting Model)
- Section 17 (External Integrations — Cloudflare/Authentik wiring into investigation)
- Section 20 (Widget)

## Deliverables

- Webhook receiver with per-source API key auth
- Normalized webhook event schema and ingestion pipeline
- Source normalizers: Uptime Kuma, Grafana, Prometheus Alertmanager, Netdata, generic JSON
- Webhook security: payload redaction, rate limiting, retention policy, replay protection
- Webhook → finding → incident pipeline wiring
- Prometheus `/metrics` endpoint with cardinality-controlled labels
- User notes CRUD API + Telegram memory commands
- Memory browser UI (journal, notes, system profile, recurrence, adapter facts tabs)
- Memory provenance indicators and trust display
- Alerting operational model: severity routing, digest behavior, quiet hours, multi-issue handling
- Kaval self-health notifications
- Cloudflare + Authentik integration wiring into investigation evidence path
- Homepage/Homarr widget API

## Global execution rules

- Execute one task at a time, in order.
- Do not start later Phase 3B tasks early unless this plan explicitly marks them as parallel-safe and the active run prompt allows it.
- Treat `docs/prd.md` as the baseline product and architecture source of truth.
- Treat `docs/phase3_4_requirements_expansion.md` as the authoritative Phase 3/4 requirements source.
- Treat approved CRs and ADRs as authoritative overrides where applicable.
- Preserve the Phase 2A/2B action boundary: no new system-modifying actions are introduced in this phase.
- All new integrations in this phase remain read-only.
- Keep webhook, memory, alerting, and external-integration changes typed, explicit, and testable.
- Keep STATUS updates minimal and append-only where possible.
- If the active task reveals a contradiction between the PRD baseline, requirements expansion, approved CRs/ADRs, or this phase plan, stop and record the blocker before proceeding.

## Suggested repository touch surfaces

These are guidance surfaces, not hard guarantees. The active task prompt should still restate expected files before implementation.

- `src/kaval/api/`
- `src/kaval/database.py`
- `src/kaval/models.py`
- `src/kaval/notifications/`
- `src/kaval/memory/`
- `src/kaval/investigation/`
- `src/kaval/integrations/`
- `src/kaval/webhooks/` (or equivalent new package if created)
- `src/kaval/metrics/` (or equivalent new package if created)
- `src/web/src/`
- `tests/unit/`
- `tests/integration/`
- `tests/scenario/`
- `tests/security/`
- `tests/fixtures/`
- `STATUS.md`
- `README.md` / `CHANGELOG.md` only if required by the completed task or AGENTS.md

## Tasks

- P3B-01 Normalized webhook event schema (WebhookEvent model)
- P3B-02 Webhook receiver endpoint with per-source API key auth
- P3B-03 Webhook security: rate limiting, payload size limit, raw payload redaction, retention policy
- P3B-04 Webhook deduplication and resolution handling
- P3B-05 Normalizer: Uptime Kuma
- P3B-06 Normalizer: Grafana
- P3B-07 Normalizer: Prometheus Alertmanager
- P3B-08 Normalizer: Netdata
- P3B-09 Normalizer: Generic JSON (configurable field mappings)
- P3B-10 Webhook service matching (exact, tag, fuzzy, multi-service, unmatched)
- P3B-11 Webhook → finding creation → incident grouping pipeline wiring
- P3B-12 Prometheus `/metrics` endpoint (service, investigation, adapter, action, webhook, system metrics)
- P3B-13 Metrics cardinality controls (category-level labels only, no unbounded instance IDs)
- P3B-14 User notes full CRUD API (create, edit, version history, archive, delete)
- P3B-15 Telegram memory commands (`/note`, `/notes`, `/journal`, `/recurrence`)
- P3B-16 Memory browser UI: journal tab with provenance indicators
- P3B-17 Memory browser UI: notes tab with trust indicators (`safe_for_model`, stale, source)
- P3B-18 Memory browser UI: system profile tab with diff view
- P3B-19 Memory browser UI: recurrence tab with permanent-fix suggestions
- P3B-20 Memory browser UI: facts tab (adapter-imported facts, per service)
- P3B-21 Alerting: severity routing implementation (immediate/dedup/digest/dashboard-only)
- P3B-22 Alerting: quiet hours and maintenance mode interaction (with self-health guardrail)
- P3B-23 Alerting: multi-issue summary notifications
- P3B-24 Alerting: Kaval self-health notifications (opt-in, critical self-health always fires through maintenance)
- P3B-25 Cloudflare integration: adapter facts → investigation evidence path (DNS records, SSL mode, tunnel routes)
- P3B-26 Authentik integration: adapter facts → investigation evidence path (apps, providers, outpost health)
- P3B-27 Homepage/Homarr widget API (`/api/v1/widget` with configurable auth)
- P3B-28 Scenario tests: webhook-driven investigation (Uptime Kuma alert → finding → investigation → notification)
- P3B-29 Scenario tests: multi-service Prometheus alert → grouped incident
- P3B-30 Integration tests: memory browser provenance, alerting routing, self-health notification

## Dependency notes

- P3B-01 defines the canonical internal webhook event model and should land before the rest of the webhook stack.
- P3B-02 depends on P3B-01 and existing FastAPI/API routing foundations from Phase 1/2.
- P3B-03 depends on P3B-01 and P3B-02.
- P3B-04 depends on P3B-01 and P3B-02.
- P3B-05..09 depend on P3B-01 and P3B-02.
- P3B-10 depends on P3B-01, P3B-02, and the normalized-source outputs from P3B-05..09.
- P3B-11 depends on P3B-01, P3B-04, P3B-10, and the existing incident manager from Phase 1.
- P3B-12 can begin independently of webhook work, but should align with the capability-health and action-boundary model already established in Phase 3A.
- P3B-13 depends on P3B-12.
- P3B-14 depends on the existing Operational Memory backend from Phase 2B and the current API/database foundations.
- P3B-15 depends on P3B-14 and the existing Telegram/interactive notification path from Phase 2A.
- P3B-16..19 depend on P3B-14 and the existing React UI/API surfaces.
- P3B-20 depends on P3B-14, existing React UI/API surfaces, and Phase 3A adapter fact integration (`P3A-22` in the corrected 3A plan).
- P3B-21 depends on the existing notification bus from Phase 2A and on clear incident/finding state from existing systems.
- P3B-22 depends on P3B-21 and existing maintenance/suppression semantics where available.
- P3B-23 depends on P3B-21 and P3B-22.
- P3B-24 depends on P3A-12 capability-health modeling and P3B-21/P3B-22 alert-routing behavior.
- P3B-25 depends on the Phase 3A Cloudflare adapter (`P3A-08`) and Phase 3A evidence integration (`P3A-22`).
- P3B-26 depends on the Phase 3A Authentik adapter (`P3A-07`) and Phase 3A evidence integration (`P3A-22`).
- P3B-27 is lightweight and mostly independent, but should align with the latest service/incident summary models.
- P3B-28 depends on the webhook stack and the investigation/notification path being complete enough to run end-to-end.
- P3B-29 depends on multi-service matching/grouping behavior from P3B-10..11.
- P3B-30 depends on the memory-browser tabs, alerting model, and self-health-notification path.

## Exit criteria

- External monitoring tool (Uptime Kuma) sends webhook → Kaval creates finding → groups into incident → investigates → notifies.
- Multi-service Prometheus alert → properly matched and grouped.
- Webhook endpoints enforce auth, rate limits, payload size limits, replay protection, and payload redaction.
- `/metrics` returns valid Prometheus exposition format with cardinality-controlled labels.
- User can create, edit, archive, and delete notes via UI/API and interact with memory via Telegram commands.
- Memory browser shows all 5 tabs with provenance indicators and trust context.
- Severity routing works: critical = immediate, medium = digest, low = dashboard-only.
- Quiet hours hold non-critical notifications while critical issues still push through.
- Global maintenance does not suppress critical Kaval self-health failures.
- Widget API returns valid JSON summary consumable by Homepage/Homarr.
- Cloudflare and Authentik adapter facts appear in investigation evidence when configured.

## Review gates

- Webhook auth: no unauthenticated webhook acceptance.
- Raw payload redaction: secret patterns removed before storage.
- Query-string auth documented as compatibility fallback only.
- All integrations remain read-only per the action boundary.
- `/metrics` does not expose sensitive data and avoids unbounded label cardinality.
- Self-health notification guardrail: critical self-health fires through global maintenance unless explicitly and separately configured otherwise in a later approved design change.

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `cd src/web && npm run build`
- `ruff check .`
- `mypy src`

## Notes

- Query-string webhook auth (`?key=`) is a fallback for tools that cannot set headers. Header auth is preferred.
- Raw webhook payloads are retained for 30 days by default, then purged.
- Metrics must avoid high-cardinality labels — no raw incident IDs, container IDs, or arbitrary user-defined names unless explicitly bounded.
- Telegram memory commands extend the existing interactive handler from P2A-08.
- For execution runs, the active-task prompt should still restate files, exact validation commands, acceptance criteria, and blockers before coding.

---

## Task execution packets

These packets add task-level execution detail for coding agents. They do not change task order or authority.

### P3B-01 — Normalized webhook event schema
**Goal**
Define the canonical internal webhook event model with explicit fields for source identity, dedup support, matching hints, severity, raw payload handling, and normalized status.

**Primary touch surfaces**
- `src/kaval/models.py` and/or a webhook-specific models module
- `src/kaval/api/schemas.py` if API serialization contracts are affected
- `tests/unit/`
- `tests/contract/`

**Acceptance criteria**
- Canonical webhook event model exists and is typed.
- Source-specific payloads can normalize into this structure without lossy ambiguity for v1-supported fields.
- The model is suitable for deduplication, matching, routing, and retention/security policy.

**Validation focus**
- unit tests for schema/model construction
- contract/schema validation if checked-in contracts are affected
- typecheck

**Stop conditions**
- stop if the normalized model cannot support both single-service and multi-service/group alerts cleanly
- stop if the schema would force later normalizers into source-specific hacks instead of normalized fields

### P3B-02 — Webhook receiver endpoint with per-source API key auth
**Goal**
Add the webhook ingress surface with per-source authentication and a clean routing model that supports multiple source types without widening the trust boundary.

**Primary touch surfaces**
- `src/kaval/api/`
- `src/kaval/webhooks/` (or equivalent new package)
- `tests/integration/`
- `tests/security/`

**Acceptance criteria**
- Source-specific webhook endpoints or equivalent routing exist.
- Per-source API key auth is enforced.
- Unauthorized requests are rejected consistently.

**Validation focus**
- integration tests for auth and routing
- security tests for unauthenticated rejection

**Stop conditions**
- stop if webhook auth would require weakening the current admin/action boundary
- stop if the receiver design cannot cleanly separate source auth from later normalization logic

### P3B-03 — Webhook security
**Goal**
Implement the non-negotiable security controls around ingress: rate limiting, payload size limits, raw payload redaction, and retention boundaries.

**Primary touch surfaces**
- `src/kaval/webhooks/`
- `src/kaval/memory/redaction.py` or shared redaction helpers
- persistence layer if webhook payload retention is stored
- `tests/security/`
- `tests/unit/`

**Acceptance criteria**
- Rate limits are enforced.
- Payload size limits are enforced.
- Raw payloads are redacted before storage.
- Retention policy boundaries are defined in implementation/config.

**Validation focus**
- security tests for secret redaction, oversize payload rejection, and throttling
- unit tests for retention policy helpers if present

**Stop conditions**
- stop if raw payloads would be stored before redaction
- stop if retention behavior cannot be expressed clearly without broader storage-policy clarification

### P3B-04 — Webhook deduplication and resolution handling
**Goal**
Add duplicate suppression, replay-aware acknowledgement, and resolution handling so webhook sources do not create noisy or inconsistent findings.

**Primary touch surfaces**
- `src/kaval/webhooks/`
- persistence layer / incident state helpers
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- Duplicate events are acknowledged but not reprocessed within the defined window.
- Resolution events update the corresponding state path correctly.
- Flapping behavior is handled deterministically.

**Validation focus**
- unit and integration tests for dedup/resolution state transitions

**Stop conditions**
- stop if dedup requires a later task’s matching logic to exist first in an inseparable way
- stop if source_event semantics differ enough across sources to require a normalized-model revision

### P3B-05 — Normalizer: Uptime Kuma
**Goal**
Implement source-specific normalization for Uptime Kuma into the canonical webhook model.

**Primary touch surfaces**
- `src/kaval/webhooks/normalizers/` (or equivalent)
- `tests/fixtures/`
- `tests/unit/`

**Acceptance criteria**
- Uptime Kuma payloads normalize deterministically into the internal event model.
- Required fields for matching and routing are preserved.

**Validation focus**
- fixture-backed unit tests

**Stop conditions**
- stop if Kuma payload variants require changes to P3B-01 rather than ad hoc normalizer hacks

### P3B-06 — Normalizer: Grafana
**Goal**
Implement Grafana alert payload normalization into the canonical model.

**Primary touch surfaces**
- same as P3B-05

**Acceptance criteria**
- Grafana payloads normalize deterministically.
- Labels/annotations/URLs needed for later matching and evidence are preserved.

**Validation focus**
- fixture-backed unit tests

**Stop conditions**
- stop if Grafana alert variants expose a missing field/shape in the normalized schema

### P3B-07 — Normalizer: Prometheus Alertmanager
**Goal**
Implement Prometheus Alertmanager webhook normalization, including grouped/multi-service alert representation.

**Primary touch surfaces**
- same as P3B-05

**Acceptance criteria**
- Alertmanager payloads normalize correctly.
- Grouped/multi-service signals are preserved in a way usable by later matching/grouping.

**Validation focus**
- fixture-backed unit tests with grouped alerts

**Stop conditions**
- stop if grouped-alert semantics cannot be expressed cleanly in the canonical event schema

### P3B-08 — Normalizer: Netdata
**Goal**
Implement Netdata alarm normalization.

**Primary touch surfaces**
- same as P3B-05

**Acceptance criteria**
- Netdata alarms normalize deterministically.
- Severity/title/body/tags remain usable for later matching.

**Validation focus**
- fixture-backed unit tests

**Stop conditions**
- stop if Netdata alarm shapes require schema changes rather than normalizer-specific mapping

### P3B-09 — Normalizer: Generic JSON
**Goal**
Add a configurable generic JSON normalizer for sources without a first-class built-in normalizer.

**Primary touch surfaces**
- `src/kaval/webhooks/`
- config surfaces
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- Field mapping can be configured without code changes.
- Generic JSON payloads can normalize into the canonical model for basic use cases.

**Validation focus**
- unit tests for field-mapping behavior
- integration tests if config-driven routing is added

**Stop conditions**
- stop if the generic mapping model becomes complex enough to need its own schema/ADR

### P3B-10 — Webhook service matching
**Goal**
Implement the service-matching layer for normalized webhook events before they become findings.

**Primary touch surfaces**
- `src/kaval/webhooks/`
- service/discovery lookup helpers
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- Exact, tag-based, fuzzy, multi-service, and unmatched paths are supported.
- Matching behavior is deterministic and explainable.

**Validation focus**
- fixture-backed matching tests
- integration tests for representative service-match cases

**Stop conditions**
- stop if matching logic would silently guess across multiple services without enough evidence
- stop if grouped alerts need a separate explicit grouping model first

### P3B-11 — Webhook → finding → incident wiring
**Goal**
Connect normalized and matched webhook events into the existing finding and incident pipeline.

**Primary touch surfaces**
- `src/kaval/webhooks/`
- finding/incident manager code
- `tests/integration/`
- `tests/scenario/`

**Acceptance criteria**
- New matched webhook events create findings correctly.
- Findings enter normal grouping/incident flow.
- Unmatched or grouped webhook cases follow the defined behavior.

**Validation focus**
- integration tests from webhook receipt to incident state

**Stop conditions**
- stop if the existing incident manager cannot represent grouped external-alert cases without a model change

### P3B-12 — Prometheus /metrics endpoint
**Goal**
Expose Prometheus metrics for Kaval’s core service, investigation, adapter, action, webhook, and system signals.

**Primary touch surfaces**
- `src/kaval/api/`
- `src/kaval/metrics/` (or equivalent)
- `tests/integration/`

**Acceptance criteria**
- `/metrics` exists and emits valid Prometheus exposition format.
- Metric families cover the required high-level categories.

**Validation focus**
- integration tests for endpoint format and representative metrics

**Stop conditions**
- stop if metrics require unbounded labels to meet the stated goals

### P3B-13 — Metrics cardinality controls
**Goal**
Constrain metrics labeling so the endpoint is operationally safe for Prometheus.

**Primary touch surfaces**
- same as P3B-12
- `tests/unit/` / `tests/integration/`

**Acceptance criteria**
- No unbounded/raw IDs are exposed as labels unless explicitly bounded.
- Cardinality rules are encoded in implementation and tests.

**Validation focus**
- tests for label-shape constraints

**Stop conditions**
- stop if any required metric can only be expressed with high-cardinality labels

### P3B-14 — User notes full CRUD API
**Goal**
Complete the user-notes API surface on top of the Phase 2B memory backend.

**Primary touch surfaces**
- `src/kaval/api/`
- `src/kaval/memory/`
- `src/kaval/database.py`
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- Create, edit, version history, archive, and delete paths exist and are typed.
- Trust/safe-for-model/staleness semantics remain consistent with Phase 2B.

**Validation focus**
- API integration tests
- unit tests for persistence/state transitions

**Stop conditions**
- stop if note lifecycle behavior conflicts with the existing memory trust model

### P3B-15 — Telegram memory commands
**Goal**
Extend Telegram/interactive memory access without widening the action boundary.

**Primary touch surfaces**
- `src/kaval/notifications/telegram*`
- `src/kaval/memory/`
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- `/note`, `/notes`, `/journal`, and `/recurrence` work as defined.
- Commands remain read-only or note-entry only, not administrative mutation beyond note management.

**Validation focus**
- integration tests for command handling
- security tests if command content feeds prompts later

**Stop conditions**
- stop if Telegram memory commands start to require settings/admin actions that belong in later UI/admin work

### P3B-16 — Memory browser UI: journal tab
**Goal**
Add the journal tab with provenance indicators and trust display.

**Primary touch surfaces**
- `src/web/src/`
- API read helpers/schemas if needed
- `tests/integration/`

**Acceptance criteria**
- Journal entries are viewable with provenance/trust context.
- UI clearly distinguishes source and confidence where available.

**Validation focus**
- frontend integration/build
- API/UI tests if present

**Stop conditions**
- stop if the required provenance fields are not yet exposed by the backend/API

### P3B-17 — Memory browser UI: notes tab
**Goal**
Add the notes tab with trust indicators (`safe_for_model`, stale, source).

**Primary touch surfaces**
- same as P3B-16

**Acceptance criteria**
- Notes tab shows the required trust/safety indicators.
- CRUD paths wired in P3B-14 are consumable from the UI where intended.

**Validation focus**
- frontend integration/build
- API/UI tests if present

**Stop conditions**
- stop if the API does not yet expose the required trust metadata clearly

### P3B-18 — Memory browser UI: system profile tab
**Goal**
Add the system profile tab with diff/history view where supported.

**Primary touch surfaces**
- same as P3B-16

**Acceptance criteria**
- System profile is visible and understandable.
- Diff/history behavior is bounded to data actually available.

**Validation focus**
- frontend integration/build

**Stop conditions**
- stop if diff/history semantics exceed what the current stored profile history can support

### P3B-19 — Memory browser UI: recurrence tab
**Goal**
Add recurrence visualization with conservative permanent-fix suggestions.

**Primary touch surfaces**
- same as P3B-16
- recurrence/read helpers

**Acceptance criteria**
- Recurrence patterns display with supporting evidence.
- Permanent-fix suggestions remain advisory and bounded.

**Validation focus**
- frontend integration/build
- relevant unit/integration tests for recurrence display data

**Stop conditions**
- stop if the UI would overstate speculative recurrence as confirmed fact

### P3B-20 — Memory browser UI: facts tab
**Goal**
Display adapter-imported facts per service with provenance and freshness.

**Primary touch surfaces**
- same as P3B-16
- adapter fact API/read surfaces from Phase 3A

**Acceptance criteria**
- Adapter facts are visible per service.
- Freshness, source, and trust/provenance context are shown.

**Validation focus**
- frontend integration/build
- API/UI tests if present

**Stop conditions**
- stop if Phase 3A has not yet exposed adapter facts in a stable API shape

### P3B-21 — Alerting: severity routing implementation
**Goal**
Implement the operational alerting model for immediate, deduped, digested, and dashboard-only notification paths.

**Primary touch surfaces**
- `src/kaval/notifications/`
- incident/finding routing logic
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- Severity routing works per requirement.
- The model remains incident-centered and avoids raw-finding spam.

**Validation focus**
- integration tests for routing and dedup behavior

**Stop conditions**
- stop if routing requires a broader notification-policy model than the current phase is meant to introduce

### P3B-22 — Alerting: quiet hours and maintenance interaction
**Goal**
Add quiet-hours and maintenance interaction rules without suppressing critical self-health guardrails.

**Primary touch surfaces**
- same as P3B-21
- settings/config surfaces if needed

**Acceptance criteria**
- Quiet hours suppress only the intended notification classes.
- Maintenance interaction matches the requirement model.
- Critical self-health remains protected.

**Validation focus**
- integration tests for routing under quiet-hours/maintenance scenarios

**Stop conditions**
- stop if implementation would suppress critical Kaval self-health in contradiction to the requirement model

### P3B-23 — Alerting: multi-issue summary notifications
**Goal**
Add multi-issue incident summaries so simultaneous unrelated issues do not produce confusing alert storms.

**Primary touch surfaces**
- same as P3B-21
- tests/integration/scenario

**Acceptance criteria**
- Simultaneous issues can be summarized without collapsing unrelated incidents incorrectly.

**Validation focus**
- integration/scenario tests for multi-issue summaries

**Stop conditions**
- stop if multi-issue summarization would undermine incident separation or root-cause clarity

### P3B-24 — Alerting: Kaval self-health notifications
**Goal**
Surface Kaval’s own degraded capability states through the notification system.

**Primary touch surfaces**
- `src/kaval/notifications/`
- Phase 3A capability-health surfaces
- `tests/integration/`
- `tests/security/` if relevant

**Acceptance criteria**
- Opt-in self-health notifications exist.
- Critical self-health paths are not lost under global maintenance.

**Validation focus**
- integration tests for self-health routing/guardrails

**Stop conditions**
- stop if the implementation cannot distinguish Kaval self-health from ordinary service incidents cleanly

### P3B-25 — Cloudflare facts into evidence
**Goal**
Wire Cloudflare adapter facts into investigation evidence gathering.

**Primary touch surfaces**
- `src/kaval/investigation/`
- adapter evidence plumbing
- `tests/unit/`
- `tests/integration/`

**Acceptance criteria**
- When configured, Cloudflare facts appear in evidence gathering for relevant incidents.
- The path remains read-only and respects redaction rules.

**Validation focus**
- unit/integration tests for evidence inclusion and redaction path

**Stop conditions**
- stop if the Phase 3A Cloudflare adapter or adapter-fact API shape is not stable enough yet

### P3B-26 — Authentik facts into evidence
**Goal**
Wire Authentik adapter facts into investigation evidence gathering.

**Primary touch surfaces**
- same as P3B-25

**Acceptance criteria**
- When configured, Authentik facts appear in evidence gathering for relevant incidents.
- The path remains read-only and respects redaction rules.

**Validation focus**
- unit/integration tests for evidence inclusion and redaction path

**Stop conditions**
- stop if the Phase 3A Authentik adapter or adapter-fact API shape is not stable enough yet

### P3B-27 — Homepage/Homarr widget API
**Goal**
Expose a compact summary endpoint consumable by Homepage/Homarr.

**Primary touch surfaces**
- `src/kaval/api/`
- tests/integration

**Acceptance criteria**
- Widget endpoint returns a stable compact JSON summary.
- Auth/config behavior is explicit and documented.

**Validation focus**
- integration tests for payload shape and auth

**Stop conditions**
- stop if the widget contract depends on unfinished Phase 3C admin UX rather than existing summary data

### P3B-28 — Scenario tests: webhook-driven investigation
**Goal**
Prove the end-to-end path from external webhook alert to Kaval investigation and notification.

**Primary touch surfaces**
- `tests/scenario/`
- supporting fixtures

**Acceptance criteria**
- Scenario reliably covers: webhook receipt → normalization → matching → finding → incident → investigation → notification.

**Validation focus**
- deterministic scenario tests

**Stop conditions**
- stop if earlier webhook tasks do not yet expose a stable enough end-to-end path to test deterministically

### P3B-29 — Scenario tests: multi-service Prometheus alert
**Goal**
Prove grouped/multi-service external alerts are handled without forcing incorrect single-service mapping.

**Primary touch surfaces**
- `tests/scenario/`
- fixtures

**Acceptance criteria**
- Scenario shows multi-service/group alert behavior matching the requirements.

**Validation focus**
- deterministic scenario tests

**Stop conditions**
- stop if the matching/grouping semantics are still ambiguous after P3B-10..11

### P3B-30 — Integration tests: memory browser provenance, alerting routing, self-health notification
**Goal**
Lock down the user-facing behavior introduced by 3B’s memory/alerting/self-health work.

**Primary touch surfaces**
- `tests/integration/`
- UI/API test surfaces where present

**Acceptance criteria**
- Provenance indicators, routing behavior, and self-health-notification guardrails are all covered.

**Validation focus**
- integration tests
- frontend build

**Stop conditions**
- stop if those surfaces are still changing and need another earlier task to stabilize first

