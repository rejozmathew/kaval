# Phase 0 — Foundation

## Objective
Repo scaffold, all core models, schemas, CI, Docker setup, ADRs, and proof-of-life pipeline.

## Deliverables
- Repository structure
- All Pydantic models from PRD Section 12
- JSON schemas
- SQLite database with migrations
- CI pipeline
- Dockerfile for Core + Executor
- ADR documents
- Mock check → finding → incident → console output
- README with vision statement

## Tasks

### P0-01 Repo scaffold
Goal:
- Create the initial repository structure, Python packaging, frontend placeholder, docs folders, and config files.
Allowed files:
- repo-wide structural files only
Acceptance:
- project root contains backend/frontend/docs/tests structure
- `pyproject.toml` exists
- empty package init files exist where needed
Validation:
- repo tree matches documented structure
- Python tooling can discover the package

### P0-02 Core data models
Goal:
- Implement all core models from the PRD, including Incident, Finding, Service, Investigation, Change, DependencyEdge, EvidenceStep, ResearchStep, RemediationProposal, RiskAssessment, SystemProfile, JournalEntry, UserNote, and ApprovalToken.
Allowed files:
- `src/kaval/models.py`
- `tests/unit/test_models.py`
Acceptance:
- models validate, serialize, and round-trip cleanly
- frozen Phase 0 interfaces are represented in model/schema form
Validation:
- unit tests for model creation, validation, serialization

### P0-03 SQLite database
Goal:
- Add SQLite persistence with table creation, CRUD, and migrations baseline.
Allowed files:
- `src/kaval/database.py`
- migration/bootstrap files
- `tests/unit/test_database.py`
Acceptance:
- can create/read/update key records
- incident/finding persistence works
Validation:
- unit tests pass

### P0-04 JSON schemas
Goal:
- Generate JSON schemas for the frozen contracts and key entities.
Allowed files:
- `schemas/*.json`
- related schema export helpers
- `tests/contract/test_schemas.py`
Acceptance:
- schemas exist for frozen interfaces and core entities
- sample payloads validate
Validation:
- contract tests pass

### P0-05 Incident grouping logic
Goal:
- Implement finding→incident grouping rules and lifecycle transitions.
Allowed files:
- `src/kaval/grouping.py`
- `tests/unit/test_grouping.py`
Acceptance:
- related findings group into incidents
- lifecycle transitions follow the PRD state machine
Validation:
- unit tests for grouping and status transitions

### P0-06 Mock check + incident pipeline
Goal:
- Implement proof-of-life pipeline from mock check → finding → incident → console or API output.
Allowed files:
- mock check / pipeline modules
- integration tests
Acceptance:
- mock check produces a finding
- finding is persisted
- incident is created and retrievable
Validation:
- integration test passes

### P0-07 CI pipeline
Goal:
- Add GitHub Actions for lint, type check, tests, and schema validation.
Allowed files:
- `.github/workflows/ci.yml`
- supporting config files
Acceptance:
- CI runs lint, mypy/pyright equivalent, unit tests, contract tests
Validation:
- workflow validates locally or in GitHub

### P0-08 Docker setup
Goal:
- Create Core and Executor Dockerfiles and local compose for proof-of-life.
Allowed files:
- `Dockerfile`
- `Dockerfile.executor`
- `docker-compose.yml` or `docker-compose.dev.yml`
Acceptance:
- compose starts Core and Executor
- proof-of-life pipeline can run in dev environment
Validation:
- `docker compose up` starts services

### P0-09 ADRs + README
Goal:
- Write the initial ADR set and bootstrap README.
Allowed files:
- `docs/adr/*.md`
- `README.md`
- `CHANGELOG.md`
Acceptance:
- ADRs reflect the major v4.1 decisions
- README explains vision and local startup
Validation:
- docs reviewed for consistency with PRD

## Exit criteria
- `pytest` passes with at least one test per data-model area
- `docker compose up` starts Core and Executor containers
- mock check produces a finding → incident stored in SQLite
- all ADRs written and reviewed

## Frozen interface contracts (must be reviewed and stable before Phase 1)
1. Core↔Executor API
2. ApprovalToken schema
3. Incident lifecycle state machine
4. Investigation output schema
5. Notification callback payloads
6. Operational Memory query/result schema

## Validation commands
- `python -m pytest`
- `ruff check .`
- `mypy src`
- `docker compose up --build`

## Execution notes
- Phase 0 executes sequentially.
- No parallel feature work before frozen interfaces are reviewed.
- Any contract change requires ADR + status update.
