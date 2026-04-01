# Kaval

Kaval (കാവൽ, Malayalam for "guard / watchkeeper") is a self-hosted, auto-discovering, AI-powered observability and investigation platform for Unraid-based homelab infrastructure.

Kaval is not another monitoring dashboard. Tools like Uptime Kuma tell you that something is broken. Kaval is designed to explain the most likely cause, show the evidence trail, and propose the safest next action with explicit risk framing.

## Product Shape

Kaval is built around three operating profiles within one Docker container:

- `Monitor`: `kaval-core` handles discovery, deterministic checks, findings, and incidents.
- `Assist`: Monitor plus a local OpenAI-compatible model endpoint for investigation and root-cause analysis.
- `Operate`: Assist plus the internal `kaval-executor` process for bounded, approval-gated remediation actions.

The security boundary is foundational:

- Core is unprivileged, non-root, and does not receive `docker.sock`.
- Executor is the only process that uses the mounted `docker.sock`.
- Core handles discovery, monitoring, investigation, notifications, API/UI, and state.
- Executor handles only allowlisted, approved system-modifying actions over a Unix domain socket.

## Current Status

The repository is no longer Phase 0-only.

The current local checkpoint includes:

- completed Phase 0 foundations: typed Pydantic models, SQLite persistence, checked-in schemas, ADRs, and Docker/dev scaffolding
- completed Phase 1 monitoring surfaces: Unraid + Docker discovery, shipped service descriptors, dependency graph construction, deterministic checks, incident management, system profile generation, FastAPI endpoints, CLI commands, and the React/WebSocket service map UI
- completed Phase 2A: Tier 1 evidence collection, investigation prompt templates, LangGraph investigation workflow, optional local OpenAI-compatible synthesis, Apprise delivery, incident-centered notification formatting, incident-grouped dispatch, Telegram interactive delivery, the internal Executor over `/run/kaval/executor.sock`, the Core Unix-socket action client, DelugeVPN/cert-expiry/crash-loop scenarios, and the basic investigation detail UI

Phase 2A is complete under the approved CR-0002 / ADR-014 runtime: one Docker container with two internal processes, where `kaval-core` serves the API/UI on port `9800` and `kaval-executor` listens on `/run/kaval/executor.sock`. Treat [`STATUS.md`](STATUS.md) as the authoritative current-state source while the repo waits at the phase boundary for review.

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

- `kaval` starts one container with two internal processes: `kaval-core` serves the FastAPI/API + UI on port `9800`, and `kaval-executor` listens on `/run/kaval/executor.sock`.
- `/var/run/docker.sock` is mounted once and is intended for the executor process only; Core still communicates over the internal Unix socket.
- The repository includes the completed Phase 1 monitoring stack and the completed Phase 2A investigation, approval-gated restart, scenario, and investigation-detail UI surfaces.

## Documentation

- Product and architecture contract: [`docs/prd.md`](docs/prd.md)
- Active phase execution contract: [`plans/phase-2a.md`](plans/phase-2a.md)
- Completed monitoring phase plan: [`plans/phase-1.md`](plans/phase-1.md)
- Running project state: [`STATUS.md`](STATUS.md)
- Architecture decisions: [`docs/adr/`](docs/adr/)
