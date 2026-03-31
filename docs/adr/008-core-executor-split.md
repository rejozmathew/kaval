# ADR-008: Split Core and Executor by Trust Boundary

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval's main container needs network access, UI exposure, model integration, persistence, and notification capability. Those same properties make it the wrong place to grant system-modifying privileges. The product requires a hard boundary between reasoning and execution.

## Decision

Kaval will run privileged actions through a separate optional Executor sidecar. Core remains unprivileged, non-root, and free of `docker.sock`. Executor is the only container allowed to hold `docker.sock`, and it accepts only localhost requests that pass allowlist and approval-token verification.

## Consequences

- The Core↔Executor API becomes a frozen foundational contract.
- Operate mode requires an additional sidecar, while Monitor and Assist do not.
- Security review focuses on a smaller privileged surface.
- Executor cannot gain network, UI, LLM, or general host-management responsibilities without a new ADR.
