# ADR-005: UAC-Style Credential Model

- Status: Accepted
- Date: 2026-03-31

## Context

Homelab users do not want to preload a large secret inventory before the product is useful, and most investigations can proceed without service-specific credentials. When deeper access is needed, Kaval must request it explicitly and minimize retention.

## Decision

Kaval will use a just-in-time credential model with three modes:

- volatile session-only credentials by default
- optional encrypted vault storage
- explicit skip to continue investigation with reduced confidence

## Consequences

- Initial setup requires only the Unraid API key.
- Credentials are treated as an event in the workflow, not as mandatory baseline state.
- The vault remains optional and bounded behind explicit user choice.
- Investigations must tolerate missing credentials and report lower confidence rather than failing closed.
