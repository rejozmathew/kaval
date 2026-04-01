# Phase 2B — Research + Credentials + Memory + Polish

## Objective
Enrich investigations with Tier 2 research, credential-gated API access, and Operational Memory learning/trust features.

## Deliverables
- GitHub releases/changelog research
- Docker Hub metadata research
- LangGraph workflow extended with Tier 2
- Cloud-model escalation policy
- Risk assessment engine
- Credential request flow (UAC)
- Credential vault
- Operational Memory journal + trust model
- Memory secret redaction
- Recurrence detection
- Scenario tests including NPM TLS breakage
- UI for change timeline, approval queue, and memory browser

## Tasks
- P2B-01 GitHub releases API client
- P2B-02 Docker Hub API client
- P2B-03 Research module (Tier 2)
- P2B-04 Extend LangGraph workflow with Tier 2
- P2B-05 Cloud LLM integration + escalation policy
- P2B-06 Risk assessment engine
- P2B-07 Credential request flow (UAC)
- P2B-08 Credential vault
- P2B-09 Operational Memory journal + trust model
- P2B-10 Memory secret redaction module
- P2B-11 Recurrence detection
- P2B-12 Scenario: NPM TLS breakage
- P2B-13 Scenario: Authentik SSO failure
- P2B-14 UI: Change timeline, approval queue, memory browser

## Dependency notes
- P2B-03 depends on P2B-01 and P2B-02
- P2B-04 depends on P2A-03 and P2B-03
- P2B-05 depends on P2A-04
- P2B-05 must establish a minimum compliant cloud-safe redaction path before any cloud-bound prompt is sent
- P2B-05 may pull forward only the minimum subset of `src/kaval/memory/redaction.py` required to enforce PRD Section 6.5 for cloud-bound prompt handling
- P2B-06 depends on P2B-03
- P2B-07 depends on P2A-08
- P2B-08 depends on P2B-07
- P2B-09 depends on P1-18 and P2A-03
- P2B-10 depends on P2B-09
- P2B-10 remains responsible for broader redaction-module expansion, memory-flow integration, and hardening beyond the minimum cloud-safe path required by P2B-05
- P2B-11 depends on P2B-09
- P2B-12 depends on P2B-04
- P2B-13 depends on P2A-03
- P2B-14 depends on P2B-09 and P1-21

## Exit criteria
- Investigations can fetch changelogs and identify breaking changes
- Cloud model is invoked when local confidence is low, if configured
- Credential request via Telegram works for volatile and vault modes
- Resolved incidents auto-write journal entries
- Recurrence detection can say: this has happened N times, consider a permanent fix
- Journal entries include trust fields and staleness data
- Secret redaction passes security tests
- Scenario tests pass

## Offline/degraded-mode requirements
- Tier 2 research must be explicitly skipped when offline
- Investigations must state when confidence is lower because research was unavailable
- Risk assessment must call out unverifiable changelog/migration risk when offline

## Review gates
- Security review for credentials, redaction, prompts, cloud escalation, and memory handling
- Ensure local-safe vs cloud-safe redaction levels are enforced
- No cloud-bound prompt may be sent unless the minimum compliant cloud-safe redaction path required by PRD Section 6.5 is active

## Validation commands
- `python -m pytest tests/scenario tests/security`
- `python -m pytest tests/unit/test_memory tests/unit/test_research`
- `ruff check .`
- `mypy src`
