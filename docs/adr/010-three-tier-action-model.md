# ADR-010: Three-Tier Action Safety Model

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval performs a mix of safe reads, external research, and potentially disruptive system changes. Treating all of those as the same kind of "action" would either over-constrain investigation or under-protect remediation.

## Decision

Kaval will classify actions into three tiers:

- Tier 1: evidence gathering, autonomous and read-only
- Tier 2: research, autonomous and read-only
- Tier 3: remediation, system-modifying and approval-gated

## Consequences

- The approval boundary is attached only to state-changing operations.
- Tier 3 execution must route through the Executor and an ApprovalToken.
- Audit logging, post-action verification, and journal writing are required for remediation flows.
- The v1 allowlist remains intentionally narrow: `restart_container` only.
