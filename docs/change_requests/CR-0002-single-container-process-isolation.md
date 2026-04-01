# Change Request: CR-0002 Single container with internal process isolation

## Metadata
- CR ID: CR-0002
- Title: Single container with two internal processes (replaces two-container Core/Executor split)
- Status: Approved
- PRD Baseline: v4.1
- Phase Impacted: Phase 2A (unblocks P2A-09, affects P2A-10)
- Raised On: 2026-03-31
- Raised By: Rejo Z. Mathew
- Approved By: pending
- Implemented By: pending
- Related Tasks: P2A-09, P2A-10
- Related Files:
  - docs/prd.md (Sections 3.1, 2.5, 7.1, 7.4, 13, Appendix B)
  - docs/adr/008-core-executor-split.md
  - docs/adr/014-single-container-process-isolation.md (new)
  - plans/phase-2a.md
  - STATUS.md
  - Dockerfile
  - Dockerfile.executor (remove)
  - docker-compose.yml

## Problem Statement
P2A-09 (Executor sidecar) is blocked by a contradiction between the frozen PRD transport contract and the runtime architecture:

1. **Transport contradiction.** The PRD specifies Core↔Executor communication as "localhost only" via Unix socket or local HTTP. The docker-compose.yml runs Core and Executor as separate containers. Separate containers do not share localhost. Workarounds (shared network namespace, compose service networking) add fragility without solving the underlying design tension.

2. **Unraid UX problem.** Unraid's Docker UI is container-centric: one container = one tile on the dashboard. Two containers produce two dashboard tiles, mirroring the Authentik worker/server split that is widely regarded as confusing by Unraid users. Kaval's product requirement is to appear as one application: one CA template, one install, one Docker object.

## Baseline PRD Position
PRD v4.1 Section 3.1 defines two containers with distinct trust boundaries:
- **Core** (unprivileged, no docker.sock): discovery, monitoring, investigation, UI, notifications, credentials, operational memory, API.
- **Executor** (optional sidecar, docker.sock mount): tiny container with strict action allowlist, localhost-only API from Core, HMAC token validation.

PRD v4.1 Section 7.4 defines the ApprovalToken contract: single-use, HMAC-signed, time-limited, incident-bound tokens verified by the Executor before any action executes.

ADR-008 records the original two-container split decision.

## Observed Implementation Gap
The two-container design cannot satisfy both the PRD's "localhost only" transport contract and Docker's container isolation model without workarounds. More critically, it produces two visible Docker objects on the Unraid dashboard, violating the product's core UX requirement of appearing as a single application.

The LLM safety model — which is the primary security concern — is enforced at the code level (LLM has no action tools, proposals are data only, execution requires a human-approved cryptographic token), not at the container boundary. Container-level isolation between Core and Executor addresses a different threat model (lateral movement after container compromise) that is not proportionate to the homelab use case.

## Decision
Merge Core and Executor into **one Docker container** with **two internal processes** managed by a process supervisor:

- **Process 1 (kaval-core):** runs as unprivileged user `kaval`. Handles all monitoring, investigation, UI, notifications, LLM integration, and network I/O. Not in the `docker` group.
- **Process 2 (kaval-executor):** runs as user `kaval-exec` (member of `docker` group). Listens on Unix domain socket `/run/kaval/executor.sock`. Validates HMAC approval tokens. Executes allowlisted actions via `/var/run/docker.sock`. Has no UI, no LLM access, no notification capability.
- **Process supervisor:** s6-overlay (recommended) or supervisord.
- **Container mounts:** `/var/run/docker.sock` (used by Executor process only via docker group membership), `/data` (SQLite, config, operational memory).

The ApprovalToken contract, the action allowlist, the audit trail, the LLM tool confinement, and all other security controls remain exactly as defined in PRD v4.1.

## Rationale
This is the smallest change that resolves both the transport blocker and the UX problem:

1. **Preserves the security architecture that matters.** The LLM confinement model is unaffected: the LLM produces a `RemediationProposal` (data), not an action. The execution path is pure deterministic code requiring a human-approved HMAC token. This is enforced by the tool interface and the approval token architecture, not by container boundaries.
2. **Process isolation is adequate for the threat model.** Separate Unix users, Unix socket permissions, docker group membership restricted to the Executor user, and HMAC token validation provide defense-in-depth against accidental damage — which is the homelab threat model. Container-level isolation protects against lateral movement after arbitrary code execution, which is disproportionate for a homelab product.
3. **One container = one Unraid Docker tile.** This is the product UX requirement. It cannot be achieved with two containers in Unraid's native Docker UI.
4. **Resolves the transport contradiction directly.** Two processes in one container genuinely share localhost. The Unix socket is literally local to the same filesystem namespace. The frozen PRD transport contract works as written.
5. **v1 Executor scope is trivially small.** The Executor does one thing (`restart_container`): ~50-80 lines of Python. A separate container for this is over-engineered packaging.

**Alternatives rejected:**
- **Keep two containers, use compose stack:** Does not produce one Docker tile in Unraid's native UI. Compose Manager Plus can group stacks, but the native Docker tab remains container-centric.
- **AIO mastercontainer pattern (Nextcloud-style):** Requires the master container to have docker.sock to spawn child containers, collapsing the trust boundary anyway. Child containers still visible in Docker UI.
- **Shared network namespace (`network_mode: "service:kaval-core"`):** Fragile, Docker-version-dependent, and still produces two tiles on the Unraid dashboard.

## Scope of Change
This CR changes:
- **PRD Section 3.1:** Rewrite Core/Executor architecture diagram and description. Two processes, one container, Unix socket, process supervisor.
- **PRD Section 2.5:** Install profiles wording. "Executor sidecar" → "Executor process enabled." All profiles are one container; the difference is configuration.
- **PRD Section 7.1:** Hard rules. Adjust "Executor sidecar has no network access" to "Executor process has no network role; network I/O is handled exclusively by Core process."
- **PRD Section 7.4:** ApprovalToken contract text unchanged. Add note that transport is Unix domain socket.
- **PRD Section 13:** Repository structure. Remove `Dockerfile.executor`. Add `src/kaval/executor/` as internal module (not separate `src/executor/`). Add process supervisor config.
- **PRD Appendix B:** `executor.url` changes from `http://kaval-executor:9801` to `unix:///run/kaval/executor.sock`.
- **ADR-008:** Status changed to "Superseded by ADR-014."
- **ADR-014:** New ADR recording this decision.
- **Phase 2A plan:** P2A-09 description updated from "Executor sidecar container" to "Executor internal process with Unix socket." P2A-10 updated from "HTTP client" to "Unix socket client."
- **Dockerfile:** Merge Core and Executor into one image. Add s6-overlay or supervisord. Define two process services.
- **Dockerfile.executor:** Remove.
- **docker-compose.yml:** Single service instead of two.

This CR does **not** change:
- Frozen Phase 0 interface contracts (ApprovalToken schema, incident lifecycle, investigation output schema, notification payloads, memory query schema) — except transport changes from TCP to Unix socket on the Core↔Executor API
- Data models in `src/kaval/models.py`
- Investigation workflow
- Three-tier action model
- Monitoring checks
- Service descriptors
- Operational Memory
- Notification system
- Success metrics
- Any Phase 1 completed work
- Any Phase 2A work completed through P2A-08

## Implementation Instructions
1. Create `docs/adr/014-single-container-process-isolation.md` with the decision record.
2. Update `docs/adr/008-core-executor-split.md` status line to "Superseded by ADR-014."
3. Update `plans/phase-2a.md` for P2A-09 and P2A-10 to reflect internal process + Unix socket.
4. Merge `Dockerfile.executor` logic into `Dockerfile`. Add process supervisor (s6-overlay recommended). Define two process services: `kaval-core` (user `kaval`) and `kaval-executor` (user `kaval-exec` in docker group).
5. Update `docker-compose.yml` to a single `kaval` service. Mount docker.sock and /data.
6. Move `src/executor/` contents into `src/kaval/executor/` as an internal package.
7. Implement Executor as a Unix domain socket listener at `/run/kaval/executor.sock` with socket permissions restricting write access to the `kaval` group.
8. Implement Core→Executor client using Unix socket transport instead of HTTP.
9. Validate HMAC token verification, allowlist enforcement, and audit logging work over Unix socket.
10. Update `STATUS.md` to resolve the P2A-09 blocker and record CR-002.
11. Add/update tests: Executor socket listener, token validation over socket, allowlist rejection, audit trail.
12. Run all validation commands before marking P2A-09 complete.
13. Stop if a new contradiction appears.

## Impact Assessment
- Frozen interface impact: **limited** — Core↔Executor API transport changes from TCP to Unix socket. Payload schema (action, target, approval_token) and response schema are unchanged. ApprovalToken schema is unchanged.
- Security impact: **accepted tradeoff** — loses container-level blast radius isolation between Core and Executor. Gains process-level isolation with separate users, socket permissions, docker group restriction, and HMAC token validation. LLM confinement model is completely unaffected. Adequate for homelab threat model.
- Test impact: update Executor tests from HTTP to Unix socket transport. Add process isolation tests (socket permissions, user separation). Existing approval token and allowlist tests adapt to new transport.
- Documentation impact: update PRD sections listed above, ADRs, phase plan, STATUS.md. No change to monitoring, investigation, or notification documentation.

## Acceptance Criteria
- [ ] ADR-014 created and ADR-008 status updated
- [ ] `plans/phase-2a.md` updated for P2A-09 and P2A-10
- [ ] `STATUS.md` updated, P2A-09 blocker resolved
- [ ] Single Dockerfile with process supervisor managing both processes
- [ ] `Dockerfile.executor` removed
- [ ] `docker-compose.yml` defines one service
- [ ] Executor listens on Unix domain socket, validates HMAC tokens, enforces allowlist
- [ ] Core communicates with Executor over Unix socket
- [ ] `docker compose up --build` produces one running container with both processes healthy
- [ ] Approval token round-trip works: propose → approve → token → socket → execute → verify
- [ ] All existing tests continue to pass
- [ ] New transport/isolation tests pass
- [ ] Validation commands pass: pytest, ruff, mypy

## Supersession / Roll-up
- Superseded By: none
- Roll into future PRD version: yes
- Notes: Roll into consolidated v5 PRD at end of Phase 3/4 alongside CR-0001 and any other accumulated CRs. ADR-014 is the authoritative decision record until then.
