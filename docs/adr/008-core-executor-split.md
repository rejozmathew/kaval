# ADR-008: Split Core and Executor by Trust Boundary

- Status: Superseded by ADR-014
- Date: 2026-03-31
- Superseded On: 2026-03-31
- Superseded By: ADR-014 Single container with internal process isolation

## Context

Kaval's main container needs network access, UI exposure, model integration, persistence, and notification capability. Those same properties make it the wrong place to grant system-modifying privileges. The product requires a hard boundary between reasoning and execution.

## Original Decision

Kaval would run privileged actions through a separate optional Executor sidecar. Core would remain unprivileged, non-root, and free of `docker.sock`. Executor would be the only container allowed to hold `docker.sock`, and it would accept only localhost requests that pass allowlist and approval-token verification.

## Why this ADR was superseded

During Phase 2A, the sidecar design created a product and runtime contradiction:

- the frozen transport contract was localhost-only
- the runtime packaging used separate containers
- Unraid UX strongly favored one visible application rather than separate Core and Executor container objects

ADR-014 preserves the approval-token model, action allowlist, and Core/Executor separation of responsibilities, but moves the boundary from separate containers to separate internal processes within one container using a Unix domain socket.

## Consequences of supersession

- The original trust-boundary intent remains valid.
- Container-level isolation is replaced by process-level isolation.
- The authoritative architecture decision is now ADR-014.
- Any new implementation work should follow ADR-014, not this ADR.