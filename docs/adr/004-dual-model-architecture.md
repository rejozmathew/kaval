# ADR-004: Dual-Model Investigation Architecture

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval needs private, low-cost local reasoning for routine investigation but also a path to stronger remote reasoning for complex multi-service failures and changelog research. The system must still function offline with only a local model.

## Decision

Kaval will use a dual-model strategy:

- a local OpenAI-compatible small model endpoint is the default investigation runtime
- an optional cloud state-of-the-art model may be used for escalation when complexity or confidence thresholds require it

## Consequences

- The product remains usable offline with a local model only.
- Cloud usage becomes an opt-in escalation path rather than a baseline dependency.
- Prompt construction and redaction must distinguish local-safe and cloud-safe data handling.
- Investigation results must explain degraded behavior when cloud research is unavailable.
