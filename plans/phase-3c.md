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

## Tasks

- P3C-01 Guided setup: Step 1 — Discovery summary (what was found, unknown containers, identify/skip)
- P3C-02 Guided setup: Step 2 — Dependency review (confirm/correct inferred edges, confidence display)
- P3C-03 Guided setup: Step 3 — Effectiveness assessment (per-service insight level, "improve" suggestions)
- P3C-04 Guided setup: Step 4 — Notification setup (channel config, test notification, severity preferences)
- P3C-05 Guided setup: Step 5 — Model configuration (auto-detect local model, cloud config, escalation)
- P3C-06 Interactive graph: edge confidence visualization (solid/dashed/dotted/faint by confidence type)
- P3C-07 Interactive graph: edge hover/click (source of truth, confidence, confirm/edit/remove)
- P3C-08 Interactive graph: node insight depth indicators and "improve" badges
- P3C-09 Interactive graph: add dependency flow, missing information indicators
- P3C-10 Interactive graph: filters (category, health status, insight level, confidence)
- P3C-11 Interactive graph: incident mode (highlight failure path, fade unaffected)
- P3C-12 Service detail panel: full implementation (identity, health, insight, deps, creds, memory, notifications)
- P3C-13 Descriptor editor: view mode (rendered, not raw YAML)
- P3C-14 Descriptor editor: edit mode (form-based common fields + YAML editor for advanced)
- P3C-15 Descriptor editor: validation on save (schema check, policy lint, preview)
- P3C-16 Auto-generated descriptor: trigger (unmatched container + local model → quarantined descriptor)
- P3C-17 Auto-generated descriptor: review queue UI (side-by-side view, promote/edit/dismiss/defer)
- P3C-18 Auto-generated descriptor: community export path (clean YAML for GitHub PR)
- P3C-19 Settings: model configuration (local endpoint, cloud provider, escalation thresholds, cost controls, test connection)
- P3C-20 Settings: notification channels (add/remove/test, per-severity routing, dedup, quiet hours)
- P3C-21 Settings: monitoring configuration (global intervals, per-check enable/disable, per-service overrides)
- P3C-22 Settings: credential vault management (list, test, lock/unlock, master password change)
- P3C-23 Settings: system (database maintenance, log level, backup/export with sensitivity warning, import, about page)
- P3C-24 Noise control: per-service check suppression toggles in service detail
- P3C-25 Noise control: per-check threshold adjustment (cert expiry days, restart storm threshold, probe timeout)
- P3C-26 Noise control: finding feedback loop ("dismiss as false positive" → auto-suggest suppression after N dismissals)
- P3C-27 Noise control: maintenance mode (per-service and global, time-bound, visible indicator, self-health guardrail)
- P3C-28 Proactive suggestions engine ("3 services without descriptors," "API key not tested in 30 days," etc.)
- P3C-29 Audit trail UI (chronological event stream, filters by type/service/date, export, retention config)
- P3C-30 Model usage / cost dashboard (today/week/month, per-incident breakdown, escalation analysis, budget status)
- P3C-31 VM graph representation (distinct node type, hosted service child nodes, guided VM setup prompt)
- P3C-32 Plugin system facets (system profile display, change timeline entries, impact annotations on dependent services)
- P3C-33 Descriptor expansion: 20 additional shipped descriptors (target categories: media, downloads, networking, identity, cloud, monitoring, databases, system, home automation)
- P3C-34 Descriptor contract test expansion for new descriptors
- P3C-35 End-to-end scenario: first-run guided setup flow complete walkthrough
- P3C-36 End-to-end scenario: descriptor auto-generation → quarantine → review → promote → monitoring active

## Dependency notes

- P3C-01..05 (guided setup) depend on P3A-01 (insight levels), P3A-17..20 (insight UI), existing discovery and notification code
- P3C-06..11 (interactive graph) depend on existing React Flow service map from P1-21 and P3A-17 (insight badges)
- P3C-12 (service detail) depends on P3A-18 (insight section) — extends it into full panel
- P3C-13..15 (descriptor editor) depend on existing descriptor schema from P1-03
- P3C-16..18 (auto-generated) depend on existing models and local model integration from P2A-04
- P3C-19..23 (settings) are largely independent of Phase 3A/3B but should follow the same React UI patterns
- P3C-24..27 (noise control) depend on existing check framework from P1-06 and notification system from P2A-05
- P3C-29 (audit trail) depends on existing audit data accumulated since Phase 0
- P3C-30 (cost dashboard) depends on model usage tracking from P2A-04 and P2B-05
- P3C-33..34 (descriptors) are independent — can be parallelized

## Exit criteria

- New user installs Kaval → guided setup walks through 5 steps → sees insight levels, effectiveness score, and improvement suggestions
- User can click an edge in the graph → see confidence source → confirm or remove
- User can suppress a check for a specific service → check stops firing for that service → suppression visible in audit trail
- Auto-generated descriptor created for unknown container → visible in review queue → user promotes → monitoring activates
- Settings UI covers model config, notifications, monitoring intervals, vault, and system
- Maintenance mode: user activates for 2 hours → findings suppressed → critical self-health still fires → mode auto-expires
- Audit trail shows full event history with filters
- Cost dashboard shows model usage with per-incident breakdown
- 35+ total shipped descriptors with contract tests passing
- VMs appear in graph with distinct styling; plugins appear in system profile with impact annotations

## Review gates

- Action boundary reasserted: no new system-modifying actions in this phase
- Settings changes are admin UI operations, never LLM-driven
- Auto-generated descriptor quarantine rules enforced: never used for action recommendations or incident grouping
- Single-admin v1 access model: all admin UIs assume trusted local admin
- Suppression guardrails: no auto-suppression of critical checks without explicit user confirmation

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `cd src/web && npm run build`
- `ruff check .`
- `mypy src`

## Notes

- The guided setup flow is the most important UX deliverable in this phase. It determines whether a new user understands and trusts Kaval within the first 5 minutes.
- Settings persistence model (YAML vs DB vs hybrid) may need an ADR (ADR-018 candidate).
- Descriptor expansion can be parallelized across contributors — each descriptor is independent.
- v1 access model is single trusted local admin. Documentation must state this assumption.
