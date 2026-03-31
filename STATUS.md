# STATUS.md

## Project
- Name: Kaval
- PRD version: 4.1
- Current phase: Phase 0
- Current task: P0-08
- Overall status: blocked

## Phase gates
- [ ] Phase 0 complete
- [ ] Phase 1 complete
- [ ] Phase 2A complete
- [ ] Phase 2B complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete

## Frozen interfaces (must be stable before parallel work)
- [ ] Core↔Executor API
- [ ] ApprovalToken schema
- [ ] Incident lifecycle state machine
- [ ] Investigation output schema
- [ ] Notification callback payloads
- [ ] Operational Memory query/result schema

## Completed work
- 2026-03-30: Completed P0-01 Repo scaffold.
- Created the Phase 0 repository skeleton under `src/`, `tests/`, `schemas/`, `services/`, and `docs/adr/`.
- Added `pyproject.toml`, Python package init files, frontend placeholder metadata, and scaffold smoke tests.
- Established a repo-local toolchain prefix under `.pkg/local` so the required validation commands can run without modifying the user environment.
- 2026-03-30: Completed P0-02 Core data models.
- Added `src/kaval/models.py` with PRD Section 12 entities plus frozen Phase 0 interface contracts for Core↔Executor, incident lifecycle transitions, notification payloads, and operational memory queries/results.
- Added `tests/unit/test_models.py` covering round-trip serialization and validation for incidents, findings, investigations, services, operational memory, approval tokens, executor requests/results, and notifications.
- 2026-03-30: Completed P0-03 SQLite database.
- Added `src/kaval/database.py` with migration bootstrap, typed JSON-backed persistence, and CRUD helpers for findings, incidents, investigations, services, changes, approval tokens, system profiles, journal entries, and user notes.
- Added `migrations/0001_phase0_baseline.sql` and `tests/unit/test_database.py` to validate baseline schema creation and record round-trips for the proof-of-life path.
- 2026-03-30: Completed P0-04 JSON schemas.
- Added `src/kaval/schema_export.py` and exported checked-in schemas for the core entities and frozen Phase 0 interfaces under `schemas/`.
- Added `tests/contract/test_schemas.py` to verify checked-in schemas stay synchronized with the exporter and accept representative payloads.
- 2026-03-30: Completed P0-05 Incident grouping logic.
- Added `src/kaval/grouping.py` with dependency-graph helpers, finding grouping rules, window-bounded grouping, and incident lifecycle transition helpers.
- Added `tests/unit/test_grouping.py` covering common-upstream grouping, dependency-chain grouping, unrelated-finding separation, and valid versus invalid lifecycle transitions.
- 2026-03-30: Completed P0-06 Mock check + incident pipeline.
- Added `src/kaval/mock_check.py` and `src/kaval/pipeline.py` to create a mock finding, persist it, group it, create an incident, and emit console output from the same proof-of-life path.
- Added `tests/integration/test_mock_pipeline.py` to verify the mock check produces a grouped finding and an incident stored in SQLite.
- 2026-03-30: Completed P0-07 CI pipeline.
- Added `.github/workflows/ci.yml` to install the project, run linting, type checking, schema regeneration checks, and separate unit/contract/integration test phases in GitHub Actions.

## Current focus
- Blocked validating P0-08 Docker setup because the environment does not have a `docker` binary. Draft `Dockerfile`, `Dockerfile.executor`, and `docker-compose.yml` have been added but `docker compose up --build` has not been executed successfully.

## Decisions log
- 2026-03-30: PRD v4.1 accepted as implementation-ready product spec.
- 2026-03-30: Codex + TaskMaster chosen as coding workflow; human review remains at phase boundaries.
- 2026-03-30: Added `pydantic` as the first production dependency because PRD Section 11 and Phase 0 require Pydantic models and JSON schema generation.
- 2026-03-30: Validation commands are executed through a repo-local prefix install at `.pkg/local` because the shell lacks `python`, `ruff`, `mypy`, and `python3 -m venv` support.
- 2026-03-30: Frozen Phase 0 contracts are now represented as strict Pydantic models but remain unchecked until JSON schemas and follow-on persistence logic confirm they are stable.
- 2026-03-30: Implemented the Phase 0 persistence layer at `src/kaval/database.py` per the active phase plan, while treating the PRD's later `store/database.py` path as a future repository-layout concern rather than a frozen interface change.
- 2026-03-30: Schema files are generated from `models.py` through `schema_export.py`; the checked-in JSON artifacts are now the review surface for frozen Phase 0 contracts.
- 2026-03-30: Grouping logic uses a strict five-minute default window plus service-graph relationships (same service, dependency chain, or common upstream) and keeps lifecycle transitions aligned with the PRD state machine.
- 2026-03-30: The Phase 0 proof-of-life path now satisfies the `mock check -> finding -> incident stored in SQLite` exit criterion via an integration-tested pipeline.
- 2026-03-30: CI validates checked-in schemas by regenerating them from `kaval.schema_export` and failing on any diff, keeping the JSON artifacts tied to the model layer.
- 2026-03-30: Draft Docker assets for P0-08 were prepared locally, but Phase 0 cannot proceed past Docker validation until an environment with Docker CLI/Compose is available.

## Open blockers
- 2026-03-30: P0-08 Docker setup is blocked by missing infrastructure.
- Attempted: created `Dockerfile`, `Dockerfile.executor`, and `docker-compose.yml`; ran `docker --version`.
- Result: `/bin/bash: docker: command not found`, so the required `docker compose up --build` validation could not run.
- Smallest unblocking decision needed: provide an environment with Docker CLI + Compose available, or instruct me to continue in an environment where Docker validation can be executed.

## Next 3 tasks
1. P0-08 Docker setup
2. P0-09 ADRs + README
3. Phase 0 exit review

## Validation snapshots
- lint: `ruff check .` passed via `.pkg/local/bin/ruff`
- typecheck: `mypy src` passed via `.pkg/local/bin/mypy`
- tests: `python -m pytest` passed via repo-local Python path and prefix install (`19 passed`)
- contract tests: `tests/contract/test_schemas.py` passed
- scenario tests: not run
- docker: `docker --version` failed (`command not found`); `docker compose up --build` blocked and not completed

## Notes for the coding agent
- Prefer WSL workspace on Windows for Codex.
- Treat the PRD as architecture source of truth.
- Do not begin Phase 1 before Phase 0 exit criteria and frozen interfaces are satisfied.
