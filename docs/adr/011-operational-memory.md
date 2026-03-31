# ADR-011: Operational Memory as a Core Product Primitive

- Status: Accepted
- Date: 2026-03-31

## Context

Homelab diagnosis depends heavily on server-specific quirks, recurring incidents, and user knowledge that generic monitoring products do not retain. Kaval's investigation quality improves materially if it can learn from prior incidents and local context.

## Decision

Kaval will treat Operational Memory as a first-class subsystem with three layers:

- system profile
- operational journal
- user notes

Investigations read from this memory, and resolved incidents write back to it.

## Consequences

- Investigation prompts can incorporate recurrence, prior fixes, and environment-specific facts.
- The data model must preserve both machine-generated and user-authored knowledge.
- Memory query and result schemas become frozen interface contracts before parallel feature work.
- Memory handling requires explicit trust and redaction rules, captured separately in ADR-013.
