# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog, and this file is append-only.

## [0.1.0] - 2026-03-31

### Added

- Repository scaffold for the Kaval backend, tests, schemas, docs, and service directories.
- Typed Phase 0 core models and frozen interface contracts implemented with Pydantic.
- SQLite persistence layer with baseline migration and typed CRUD helpers.
- Checked-in JSON schemas plus contract tests for the core entities and Phase 0 interfaces.
- Finding-to-incident grouping logic and lifecycle validation.
- Mock proof-of-life pipeline that produces a finding, creates an incident, and persists both to SQLite.
- GitHub Actions CI for linting, type checking, tests, and schema consistency validation.
- Docker assets for the unprivileged Core container and the isolated Executor sidecar.
- Initial ADR set documenting the major v4.1 architecture decisions.

### Fixed

- Core container bootstrap now passes the packaged `/app/migrations` path explicitly so the SQLite schema is initialized correctly inside Docker.

## [Unreleased]

### Added

- Completed the Phase 3A checkpoint: service insight levels, the deep-inspection adapter foundation, shipped read-only priority adapters for Nginx Proxy Manager, Radarr, Authentik, Cloudflare, and Pi-hole, capability-health visibility, lifecycle handling, the effectiveness score stub, adapter-fact redaction and evidence integration, confidence upgrades, and Phase 3A contract/scenario coverage.
- Completed the Phase 1 checkpoint: Unraid and Docker discovery, shipped service descriptors, dependency graph confidence, deterministic monitoring checks, change tracking, incident management, Operational Memory system profile, FastAPI read APIs, CLI commands, and the React/WebSocket service map UI.
- Completed the Phase 2A checkpoint through `P2A-08`: Tier 1 evidence collection, investigation prompt templates, LangGraph investigation workflow, optional local OpenAI-compatible synthesis, Apprise notification delivery, incident-centered notification formatting, incident-grouped dispatch, and Telegram interactive message delivery.
- Completed `P2A-09`: internal Executor execution over the Unix socket at `/run/kaval/executor.sock` with approval-token validation, restart-only allowlist enforcement, and audit-covered execution flow.
- Completed `P2A-10`: the Core Unix-socket client for signed restart approval tokens and frozen Core↔Executor request/response handling.
- Completed `P2A-11`: the DelugeVPN tunnel-drop scenario covering investigation, approval, executor dispatch, persisted execution results, and deterministic recovery verification.
- Completed `P2A-12`: the cert-expiry scenario covering a bounded no-action investigation path with explicit evidence, inference, recommendation, and recurrence context.
- Completed `P2A-13`: the crash-loop scenario covering restart-storm evidence, approval-gated execution, persisted results, and deterministic recovery verification.
- Completed `P2A-14`: the basic investigation detail UI with incident-centered evidence, inference, recommendation, risk, and action-state visibility.
- Completed the Phase 2B checkpoint through `P2B-14`: Tier 2 public research, workflow enrichment, and optional cloud-safe escalation now sit on top of the Phase 2A investigation path without widening the approved restart-only action boundary.
- Completed `P2B-06`: deterministic remediation risk assessment derived from action scope, target state, reversibility, image-update context, and changelog review status.
- Completed `P2B-07`: credential request flow with typed pending, awaiting-input, skipped, and expired states plus deterministic Telegram and API choice handling.
- Completed `P2B-08`: encrypted-at-rest vault support with explicit lock and unlock state, auto-locking, and separate volatile in-memory credential handling.
- Completed `P2B-09`: Operational Memory journal writing and trust-aware history handling for resolved incidents.
- Completed `P2B-10`: redaction hardening for query strings, cookie/session headers, and cloud-safe memory and prompt handling.
- Completed `P2B-11`: trusted recurrence detection based on matching journal history rather than raw same-service overlap.
- Completed `P2B-12`: the NPM TLS breakage scenario covering Tier 2 changelog and image-context enrichment with bounded no-action synthesis.
- Completed `P2B-13`: the Authentik SSO failure scenario covering dependency-chain context, trusted notes, unsafe-note exclusion, and bounded no-action synthesis.
- Completed `P2B-14`: read-only UI panels for the change timeline, approval queue, and memory browser over the existing realtime incident surface.

### Changed

- Top-level project docs and package metadata now describe the current Phase 1 + Phase 2A-through-`P2A-08` checkpoint instead of only the original Phase 0 scaffold.
- The approved runtime packaging now uses one Docker container with two internal processes: `kaval-core` serves the API/UI on port `9800`, and `kaval-executor` listens on `/run/kaval/executor.sock`; the older sidecar packaging path is no longer the active runtime.
- Top-level docs now reflect Phase 2A as complete under CR-0002 / ADR-014 instead of stopping at the earlier `P2A-08` / "Operate mode in progress" checkpoint.
- Top-level docs now reflect the Phase 3A-complete checkpoint, including the approved one-container/two-process runtime, the implemented insight/adapter/capability-health/lifecycle surfaces, and that Phase 3B has not started yet.
