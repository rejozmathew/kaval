# Phase 3B — Integration + User-Facing Capability

## Objective

Make Kaval the investigation brain sitting on top of existing monitoring tools via webhook ingestion. Complete the user-facing operational memory experience. Formalize the alerting operational model. Add Prometheus metrics and Homepage widget.

## Requirements Reference

Phase 3/4 Requirements Expansion v2: Sections 8 (Webhooks), 9 (Metrics), 10 (Operational Memory UX), 15 (Alerting Model), 17 (External Integrations — Cloudflare/Authentik wiring into investigation), 20 (Widget)

## Deliverables

- Webhook receiver with per-source API key auth
- Normalized webhook event schema and ingestion pipeline
- Source normalizers: Uptime Kuma, Grafana, Prometheus Alertmanager, Netdata, generic JSON
- Webhook security: payload redaction, rate limiting, retention policy, replay protection
- Webhook → finding → incident pipeline wiring
- Prometheus /metrics endpoint with cardinality-controlled labels
- User notes CRUD API + Telegram memory commands
- Memory browser UI (journal, notes, system profile, recurrence, adapter facts tabs)
- Memory provenance indicators and trust display
- Alerting operational model: severity routing, digest behavior, quiet hours, multi-issue handling
- Kaval self-health notifications
- Cloudflare + Authentik integration wiring into investigation evidence path
- Homepage/Homarr widget API

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
- P3B-10 Webhook → finding creation → incident grouping pipeline wiring
- P3B-11 Webhook service matching (exact, tag, fuzzy, multi-service, unmatched)
- P3B-12 Prometheus /metrics endpoint (service, investigation, adapter, action, webhook, system metrics)
- P3B-13 Metrics cardinality controls (category-level labels only, no unbounded instance IDs)
- P3B-14 User notes full CRUD API (create, edit, version history, archive, delete)
- P3B-15 Telegram memory commands (/note, /notes, /journal, /recurrence)
- P3B-16 Memory browser UI: journal tab with provenance indicators
- P3B-17 Memory browser UI: notes tab with trust indicators (safe_for_model, stale, source)
- P3B-18 Memory browser UI: system profile tab with diff view
- P3B-19 Memory browser UI: recurrence tab with permanent-fix suggestions
- P3B-20 Memory browser UI: facts tab (adapter-imported facts, per service)
- P3B-21 Alerting: severity routing implementation (immediate/dedup/digest/dashboard-only)
- P3B-22 Alerting: quiet hours and maintenance mode interaction (with self-health guardrail)
- P3B-23 Alerting: multi-issue summary notifications
- P3B-24 Alerting: Kaval self-health notifications (opt-in, critical self-health always fires through maintenance)
- P3B-25 Cloudflare integration: adapter facts → investigation evidence path (DNS records, SSL mode, tunnel routes)
- P3B-26 Authentik integration: adapter facts → investigation evidence path (apps, providers, outpost health)
- P3B-27 Homepage/Homarr widget API (/api/v1/widget with configurable auth)
- P3B-28 Scenario tests: webhook-driven investigation (Uptime Kuma alert → finding → investigation → notification)
- P3B-29 Scenario tests: multi-service Prometheus alert → grouped incident
- P3B-30 Integration tests: memory browser provenance, alerting routing, self-health notification

## Dependency notes

- P3B-01..04 are independent of Phase 3A (can start in parallel if needed, but best after P3A-12 for health model consistency)
- P3B-05..09 depend on P3B-01 and P3B-02
- P3B-10..11 depend on P3B-01 and existing incident manager from Phase 1
- P3B-12..13 are independent (expose existing data via /metrics)
- P3B-14..15 depend on existing memory backend from Phase 2B
- P3B-16..20 depend on P3B-14 and existing React UI; P3B-20 also depends on P3A-21 (adapter facts)
- P3B-21..24 depend on existing notification bus from P2A-05..08
- P3B-25..26 depend on P3A-06 (Authentik adapter) and P3A-07 (Cloudflare adapter) from Phase 3A
- P3B-27 is independent (lightweight JSON endpoint)
- P3B-28..30 depend on multiple tasks above

## Exit criteria

- External monitoring tool (Uptime Kuma) sends webhook → Kaval creates finding → groups into incident → investigates → notifies
- Multi-service Prometheus alert → properly matched and grouped
- Webhook endpoints enforce auth, rate limits, and payload redaction
- /metrics returns valid Prometheus exposition format with all defined metrics
- User can create/edit/archive notes via UI and Telegram
- Memory browser shows all 5 tabs with provenance indicators
- Severity routing works: critical = immediate, medium = digest, low = dashboard-only
- Quiet hours hold non-critical notifications; critical pushes through
- Global maintenance does NOT suppress Kaval self-health failures
- Widget API returns valid JSON summary consumable by Homepage/Homarr
- Cloudflare and Authentik adapter facts appear in investigation evidence when configured

## Review gates

- Webhook auth: no unauthenticated webhook acceptance
- Raw payload redaction: secret patterns removed before storage
- Query-string auth documented as compatibility fallback only
- All integrations remain read-only per action boundary
- /metrics does not expose sensitive data (no secrets, no internal IPs in labels)
- Self-health notification guardrail: critical self-health fires through global maintenance

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `cd src/web && npm run build`
- `ruff check .`
- `mypy src`

## Notes

- Query-string webhook auth (?key=) is a fallback for tools that can't set headers. Header auth is preferred.
- Raw webhook payloads are retained for 30 days by default, then purged.
- Metrics avoid high-cardinality labels — no raw incident IDs or arbitrary service names.
- Telegram memory commands extend the existing interactive handler from P2A-08.
