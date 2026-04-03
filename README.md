# Kaval

Kaval (കാവൽ, Malayalam for "guard / watchkeeper") is a self-hosted, auto-discovering, AI-powered observability and investigation platform for Unraid-based homelab infrastructure.

Kaval is not another monitoring dashboard. Tools like Uptime Kuma tell you that something is broken. Kaval is designed to explain the most likely cause, show the evidence trail, and propose the safest next action with explicit risk framing.

## Product Shape

Kaval is built around three operating profiles within one approved Docker container runtime:

- `Monitor`: `kaval-core` handles discovery, deterministic checks, findings, incidents, notifications, and the API/UI surface.
- `Assist`: Monitor plus Tier 1 and Tier 2 investigation, local OpenAI-compatible synthesis, optional cloud escalation policy, and deterministic risk assessment.
- `Operate`: Assist plus the internal `kaval-executor` process for bounded, approval-gated restart actions over `/run/kaval/executor.sock`.

The security boundary is foundational:

- Core is unprivileged, non-root, and does not receive `docker.sock`.
- Executor is the only process that uses the mounted `docker.sock`.
- Core handles discovery, monitoring, investigation, notifications, API/UI, and state.
- Executor handles only allowlisted, approved system-modifying actions over a Unix domain socket.

## Current Status

The repository is at a Phase 3A-complete checkpoint. Phase 3 overall is not complete yet, and no Phase 3B work has started from the current repo state.

The current local checkpoint includes:

- completed Phase 0 and Phase 1 foundations: typed Pydantic models, SQLite persistence, checked-in schemas, ADRs, Unraid + Docker discovery, shipped service descriptors, dependency graph construction, deterministic checks, incident management, system profile generation, FastAPI endpoints, CLI commands, and the React/WebSocket service map UI
- completed investigation and notification surfaces through Phase 2B: Tier 1 evidence collection, Tier 2 public research, optional local and cloud-safe model synthesis paths, incident-centered notifications, Telegram interactive delivery, approval-gated restart execution, deterministic risk assessment, and representative DelugeVPN, cert-expiry, crash-loop, NPM TLS breakage, and Authentik SSO scenarios
- completed credentials, memory, and UI surfaces through Phase 2B: credential request flow, encrypted vault support, Operational Memory journal and trust model, redaction hardening, recurrence detection, investigation detail, change timeline, approval queue, and memory browser views
- completed Phase 3A service insight and adapter surfaces: per-service insight levels, the deep-inspection adapter foundation, and shipped read-only priority adapters for Nginx Proxy Manager, Radarr, Authentik, Cloudflare, and Pi-hole
- completed Phase 3A runtime and UI visibility: capability-health reporting and dashboard visibility, lifecycle-aware service handling, topology refresh/cadence foundations, service-detail insight status, and the equal-weighted effectiveness score stub
- completed Phase 3A evidence and trust-path work: adapter fact redaction, investigation evidence integration, dependency-confidence upgrades from adapter confirmation, and contract/scenario coverage for the new capability surfaces

The current checkpoint still runs under the approved CR-0002 / ADR-014 runtime: one Docker container with two internal processes, where `kaval-core` serves the API/UI on port `9800` and `kaval-executor` listens on `/run/kaval/executor.sock`. Treat [`STATUS.md`](STATUS.md) as the authoritative running state and detailed execution history; it currently records Phase 3A as complete and Phase 3B as not yet started.

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
python -m pytest tests/scenario tests/security
python -m pytest tests/unit/test_memory tests/unit/test_research
cd src/web && npm run build
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
- The repository includes the completed Phase 1 and Phase 2B foundations plus the completed Phase 3A insight, adapter, capability-health, lifecycle, and evidence-integration surfaces.

## Documentation

- Product and architecture contract: [`docs/prd.md`](docs/prd.md)
- Phase 3/4 requirements source: [`docs/phase3_4_requirements_expansion.md`](docs/phase3_4_requirements_expansion.md)
- Completed Phase 3A execution contract: [`plans/phase-3a.md`](plans/phase-3a.md)
- Next planned execution contract: [`plans/phase-3b.md`](plans/phase-3b.md)
- Completed Phase 2B execution contract: [`plans/phase-2b.md`](plans/phase-2b.md)
- Completed monitoring phase plan: [`plans/phase-1.md`](plans/phase-1.md)
- Running project state: [`STATUS.md`](STATUS.md)
- Approved runtime change: [`docs/change_requests/CR-0002-single-container-process-isolation.md`](docs/change_requests/CR-0002-single-container-process-isolation.md)
- Accepted runtime ADR: [`docs/adr/014-single-container-with-internal-process.md`](docs/adr/014-single-container-with-internal-process.md)
- Architecture decisions: [`docs/adr/`](docs/adr/)
