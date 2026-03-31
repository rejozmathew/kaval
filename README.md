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

## Current Status

The repository is no longer Phase 0-only.

The current local checkpoint includes:

- completed Phase 0 foundations: typed Pydantic models, SQLite persistence, checked-in schemas, ADRs, and Docker/dev scaffolding
- completed Phase 1 monitoring surfaces: Unraid + Docker discovery, shipped service descriptors, dependency graph construction, deterministic checks, incident management, system profile generation, FastAPI endpoints, CLI commands, and the React/WebSocket service map UI
- completed Phase 2A work through `P2A-08`: Tier 1 evidence collection, investigation prompt templates, LangGraph investigation workflow, optional local OpenAI-compatible synthesis, Apprise delivery, incident-centered notification formatting, incident-grouped dispatch, and Telegram interactive delivery

`Operate` mode is not complete yet. `P2A-09 Executor sidecar` remains blocked by the current contradiction between the frozen PRD localhost-only Core-to-Executor transport contract and the isolated Executor runtime in `docker-compose.yml`. Treat [`STATUS.md`](STATUS.md) as the authoritative project state and blocker log.

## Quick Start

Requirements:

- Python `3.12+`
- Docker with Compose support

Local development install:

```bash
python -m pip install -e ".[dev]"
```

Common validation commands:

```bash
python -m pytest tests/unit tests/integration
python -m pytest tests/contract
python -m pytest tests/unit/test_investigation tests/scenario
python -m pytest tests/security
ruff check .
mypy src
```

Start the current local stack:

```bash
docker compose up --build
```

Expected behavior:

- `kaval-core` starts with SQLite state under `/data/kaval.db` and the current monitoring/investigation codebase.
- `kaval-executor` starts as the isolated sidecar placeholder, but the approval-gated restart path is not wired yet because `P2A-09` remains blocked.
- The repository includes the completed Phase 1 monitoring stack and the completed Phase 2A investigation/notification work through `P2A-08`.

## Documentation

- Product and architecture contract: [`docs/prd.md`](docs/prd.md)
- Active phase execution contract: [`plans/phase-2a.md`](plans/phase-2a.md)
- Completed monitoring phase plan: [`plans/phase-1.md`](plans/phase-1.md)
- Running project state: [`STATUS.md`](STATUS.md)
- Architecture decisions: [`docs/adr/`](docs/adr/)
