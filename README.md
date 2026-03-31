# Kaval

Kaval (കാവൽ, Malayalam for "guard / watchkeeper") is a self-hosted, auto-discovering, AI-powered observability and investigation platform for Unraid-based homelab infrastructure.

Kaval is not another monitoring dashboard. Tools like Uptime Kuma tell you that something is broken. Kaval is designed to explain the most likely cause, show the evidence trail, and propose the safest next action with explicit risk framing.

## Product Shape

Kaval is built around three operating profiles:

- `Monitor`: one unprivileged Core container for discovery, deterministic checks, findings, and incidents.
- `Assist`: Monitor plus a local OpenAI-compatible model endpoint for investigation and root-cause analysis.
- `Operate`: Assist plus a minimal Executor sidecar for bounded, approval-gated remediation actions.

The security boundary is foundational:

- Core is unprivileged, non-root, and does not receive `docker.sock`.
- Executor is the only container allowed to mount `docker.sock`.
- Core handles discovery, monitoring, investigation, notifications, and state.
- Executor handles only allowlisted, approved system-modifying actions.

## Phase 0 Status

The repository currently contains the completed Phase 0 foundation:

- typed Pydantic models for the core entities and frozen interface contracts
- SQLite persistence plus a baseline migration
- checked-in JSON schemas and contract tests
- finding-to-incident grouping logic
- a proof-of-life mock pipeline that stores a finding and incident in SQLite
- GitHub Actions for lint, type checking, tests, and schema consistency
- Docker assets for the Core and Executor development setup
- the initial ADR set captured under [`docs/adr/`](docs/adr/)

The current proof-of-life path is intentionally narrow: a mock check produces a finding, the finding is grouped into an incident, both artifacts are persisted, and the Core container prints a console summary.

## Quick Start

Requirements:

- Python `3.12+`
- Docker with Compose support

Local development install:

```bash
python -m pip install -e ".[dev]"
```

Validation commands:

```bash
python -m pytest
ruff check .
mypy src
```

Start the Phase 0 proof-of-life stack:

```bash
docker compose up --build
```

Expected behavior:

- `kaval-core` starts, bootstraps SQLite under `/data/kaval.db`, and runs the mock finding -> incident pipeline.
- `kaval-executor` starts as an isolated placeholder sidecar with `docker.sock`.
- Core logs include a proof-of-life summary showing the stored finding and incident.

## Documentation

- Product and architecture contract: [`docs/prd.md`](docs/prd.md)
- Phase execution contract: [`plans/phase-0.md`](plans/phase-0.md)
- Running project state: [`STATUS.md`](STATUS.md)
- Architecture decisions: [`docs/adr/`](docs/adr/)
