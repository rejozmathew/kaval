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

## Tasks

- P3A-01 Service insight level model and per-service tracking
- P3A-02 Descriptor schema extension: inspection surfaces, auth mode, facts, version range
- P3A-03 ServiceAdapter protocol, AdapterResult model, adapter registry
- P3A-04 Adapter: Nginx Proxy Manager (REST API — proxy hosts, certs, upstreams)
- P3A-05 Adapter: Radarr (REST API — download clients, indexers, queue health)
- P3A-06 Adapter: Authentik (REST API — apps, providers, outposts, health)
- P3A-07 Adapter: Cloudflare (Public API — DNS records, SSL mode, tunnel routes)
- P3A-08 Adapter: Pi-hole (REST API — upstream DNS, blocklist status, DHCP)
- P3A-09 Adapter credential integration (vault/UAC flow for adapter auth)
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
- P3A-21 Evidence gathering integration: invoke adapters during Tier 1 evidence collection when credentials available
- P3A-22 Confidence upgrade: adapter-confirmed edges upgrade from inferred to runtime_observed
- P3A-23 Two-level redaction for adapter facts (redact_for_local vs redact_for_cloud)
- P3A-24 Contract tests: adapter interface, adapter result schema, insight level transitions
- P3A-25 Scenario tests: adapter degradation (break each adapter → verify fallback), lifecycle events (container added/removed)

## Dependency notes

- P3A-01 depends on existing models.py and service/discovery code from Phase 1
- P3A-02 depends on P3A-01 and existing descriptor schema from P1-03
- P3A-03 depends on P3A-01 and P3A-02
- P3A-04..08 depend on P3A-03 and P3A-09
- P3A-09 depends on existing vault/UAC from Phase 2B
- P3A-10..11 depend on P3A-03
- P3A-12 is independent (cross-cutting capability health, not adapter-specific)
- P3A-13..14 depend on existing scheduler from P1-06
- P3A-15 depends on existing change tracker and incident manager
- P3A-16 depends on P3A-03 and P3A-13
- P3A-17..20 depend on P3A-01, P3A-12, and existing React UI from P1-21
- P3A-21 depends on P3A-03..08 and existing investigation workflow from P2A-03
- P3A-22 depends on P3A-21 and existing dependency mapper from P1-05
- P3A-23 depends on existing redaction module from P2B-10
- P3A-24..25 depend on all above

## Exit criteria

- Every service has a visible insight level (0-5) in the service map and detail panel
- At least 5 priority adapters operational with fixture-based tests
- Adapter degradation produces visible status change and fallback to base inference
- Kaval health dashboard shows status of all 10 capability layers
- New container added → appears in service map within one reconciliation cycle
- Container removed → handled per lifecycle model (map updated, history preserved, intent prompt sent)
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

- Adapters prefer stable structured APIs over UI scraping. No headless browser automation.
- Adapter refresh cadence is separate from core check cadence (default: 30-60 min background, immediate on investigation trigger).
- The effectiveness score uses equal weighting in v1; future versions may weight by centrality.
- Service lifecycle "intentional removal" requires user confirmation — Kaval does not guess intent.
