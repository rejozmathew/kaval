# ADR-012: Evidence, Inference, Recommendation Framing

- Status: Accepted
- Date: 2026-03-31

## Context

Users must be able to understand why Kaval believes something is broken and why it recommends a given action. Opaque model output would weaken trust, make approval unsafe, and blur the line between facts and conclusions.

## Decision

Kaval investigations will be structured around three explicit outputs:

- evidence: what was observed
- inference: what Kaval concludes from that evidence, with confidence
- recommendation: what action is proposed, with risk framing

## Consequences

- Notification formatting, investigation schemas, and UI views align around the same structure.
- Degraded or skipped research must be called out explicitly inside the investigation result.
- Approval requests are tied to transparent evidence trails rather than hidden chain-of-thought.
- The product remains explainable even when model-driven reasoning is involved.
