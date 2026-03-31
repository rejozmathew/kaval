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

- Completed the Phase 1 checkpoint: Unraid and Docker discovery, shipped service descriptors, dependency graph confidence, deterministic monitoring checks, change tracking, incident management, Operational Memory system profile, FastAPI read APIs, CLI commands, and the React/WebSocket service map UI.
- Completed the Phase 2A checkpoint through `P2A-08`: Tier 1 evidence collection, investigation prompt templates, LangGraph investigation workflow, optional local OpenAI-compatible synthesis, Apprise notification delivery, incident-centered notification formatting, incident-grouped dispatch, and Telegram interactive message delivery.

### Changed

- Top-level project docs and package metadata now describe the current Phase 1 + Phase 2A-through-`P2A-08` checkpoint instead of only the original Phase 0 scaffold.
