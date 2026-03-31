# Phase 1 — Auto-Discovery + Deterministic Monitoring

## Objective
Kaval discovers everything and monitors it with zero additional configuration.

## Deliverables
- Auto-discovery engine (Unraid + Docker)
- Service descriptor matching + 15 shipped descriptors
- Dependency graph with edge confidence
- 12 deterministic checks
- Incident manager
- Change detection + timeline
- System profile (Operational Memory layer 1)
- FastAPI core endpoints
- CLI
- Basic web UI with service map + incident feed

## Task order

### Sequential foundation inside Phase 1
- P1-01 Unraid API discovery
- P1-02 Docker API discovery
- P1-03 Service descriptor schema + loader
- P1-04 Write 15 shipped service descriptors
- P1-05 Dependency graph with edge confidence
- P1-06 Check framework + scheduler

Matcher note: service matcher behavior belongs to the service descriptor subsystem and may be completed within P1-03 and P1-04 without introducing a separate task ID.

### Parallelizable checks after P1-06
- P1-07 Container health check
- P1-08 Restart storm detection
- P1-09 Endpoint probe check
- P1-10 TLS certificate check
- P1-11 DNS resolution check
- P1-12 Unraid system checks
- P1-13 VM health check
- P1-14 Log pattern check
- P1-15 Change detection + tracker
- P1-16 Dependency chain check

DNS target note: per approved `CR-0001`, authoritative DNS targets for `P1-11` come from optional DNS metadata declared on shipped service descriptors and materialized onto `Service` records during Phase 1 discovery/matching. `P1-18 System profile` / `NetworkingProfile` is not a prerequisite for `P1-11`.

### Integration layer
- P1-17 Incident manager
- P1-18 System profile (Operational Memory)
- P1-19 FastAPI application
- P1-20 CLI
- P1-21 React service map UI
- P1-22 WebSocket real-time updates

## Dependency notes
- P1-04 depends on P1-03
- P1-05 depends on P1-03
- P1-06 depends on P0-06
- P1-07 depends on P1-06
- P1-08 depends on P1-07
- P1-09 depends on P1-06
- P1-10 depends on P1-06
- P1-11 depends on P1-06 and uses optional descriptor/service DNS metadata as its authoritative target source; it does not depend on P1-18
- P1-12 depends on P1-06 and P1-01
- P1-13 depends on P1-06 and P1-01
- P1-14 depends on P1-06 and P1-03
- P1-15 depends on P1-02
- P1-16 depends on P1-05
- P1-17 depends on P0-05 and P1-05
- P1-18 depends on P1-01 and P1-02
- P1-19 depends on P1-17
- P1-20 depends on P1-17
- P1-21 depends on P1-19
- P1-22 depends on P1-19

## Exit criteria
- Fresh install auto-discovers 20+ containers on a real Unraid server
- Service map shows services with dependency edges and confidence labels
- Checks run on schedule and findings group into incidents
- System profile is written to Operational Memory
- Change timeline tracks image updates and restarts
- Results are visible in web UI and CLI

## Review gates
- Schema review before parallel checks begin
- Security review if any task attempts privilege expansion
- Descriptor contract tests required for shipped descriptors

## Validation commands
- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `ruff check .`
- `mypy src`

## Suggested batching for Codex + TaskMaster
- Batch A: P1-01 through P1-06
- Batch B: P1-07 through P1-16 in parallel once schema review passes
- Batch C: P1-17 through P1-22
