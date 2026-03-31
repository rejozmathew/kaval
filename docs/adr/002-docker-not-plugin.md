# ADR-002: Docker Deployment, Not an Unraid Plugin

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval must be deployable from the homelab workflow users already understand while preserving clear privilege boundaries. The product needs an unprivileged Core runtime, an optional privileged sidecar for bounded actions, and predictable packaging for local development and Community Applications distribution.

## Decision

Kaval will ship as Docker containers rather than as a native Unraid plugin. The default deployment shape is one Core container, with an optional Executor sidecar for Operate mode.

## Consequences

- Deployment aligns with Unraid Community Applications expectations.
- Security boundaries are easier to express and audit as container boundaries.
- Core can remain non-root and free of `docker.sock`.
- Deep host-coupled plugin behavior is out of scope for v1.
