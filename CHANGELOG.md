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
