# ADR-003: Two-Layer Monitoring Architecture

- Status: Accepted
- Date: 2026-03-31

## Context

Most monitoring value comes from deterministic checks that do not require an LLM, while root-cause analysis benefits from on-demand AI reasoning. Kaval must work offline for core monitoring and must not turn every health check into a model call.

## Decision

Kaval will use a two-layer architecture:

- Layer 1 is deterministic, always-on monitoring that produces findings and incidents.
- Layer 2 is an on-demand investigation engine that runs only when an incident needs deeper analysis.

## Consequences

- Health monitoring remains cheap, testable, and available offline.
- LLM usage is reserved for investigation and explanation, not basic detection.
- Incident creation becomes the handoff point between detection and investigation.
- The product can degrade gracefully when model or internet access is unavailable.
