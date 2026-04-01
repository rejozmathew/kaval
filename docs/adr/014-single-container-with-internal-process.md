# ADR-014: Single container with internal process isolation

## Status: Accepted
## Date: 2026-03-31
## Supersedes: ADR-008 (Core/Executor split as separate containers)

## Context
P2A-09 (Executor sidecar) is blocked because the PRD's frozen 
contract specifies localhost-only Core→Executor transport, but 
docker-compose runs them as separate containers that don't share 
localhost. 

More importantly, Unraid's Docker UI is container-centric. Two 
containers means two tiles on the dashboard, like Authentik's 
worker/server split — which is exactly the UX we want to avoid. 
Kaval must appear as one application to the user.

## Decision
Merge Core and Executor into a single Docker container with two 
internal processes:
- kaval-core: runs as unprivileged user, handles all monitoring, 
  investigation, UI, and notifications
- kaval-executor: runs as separate user, listens on Unix domain 
  socket /run/kaval/executor.sock, validates HMAC approval tokens, 
  executes allowlisted actions via docker.sock

Process supervisor (s6-overlay or supervisord) manages both.

## Rationale
- One container = one CA template = one Docker tile on Unraid dashboard
- Unix socket satisfies the "localhost only" transport contract exactly
- Approval token validation, allowlist, and audit trail are unchanged
- The LLM confinement model is unaffected (LLM proposes, code validates, 
  human approves, Executor executes)
- Process-level separation with Unix socket permissions is adequate for 
  the homelab threat model (preventing accidental damage, not surviving 
  targeted attacks)

## What changes
- Dockerfile: merged, adds process supervisor
- docker-compose.yml: one service instead of two
- Section 3.1 of PRD: architecture diagram updated
- Install profiles: all profiles are one container, config determines mode

## What does NOT change
- ApprovalToken schema and HMAC validation
- Executor allowlist (restart_container in v1)
- Audit trail
- LLM tool confinement (no action tools available to LLM)
- Investigation workflow
- All data models
- All frozen Phase 0 interface contracts (except transport changes 
  from TCP to Unix socket)

## Consequences
- Lost: container-level blast radius isolation between Core and Executor
- Lost: network-level isolation for Executor process
- Gained: clean single-app UX on Unraid
- Gained: resolves P2A-09 transport blocker
- Gained: simpler deployment, simpler updates, simpler debugging
- Risk accepted: if the container itself is compromised, attacker has 
  access to both processes. Mitigated by: process user separation, 
  socket permissions, approval token cryptography, action allowlist.