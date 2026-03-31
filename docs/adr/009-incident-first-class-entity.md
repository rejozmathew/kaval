# ADR-009: Incident as a First-Class Entity

- Status: Accepted
- Date: 2026-03-31

## Context

Atomic findings are useful for detection, but users reason about outages as shared-root-cause incidents. Notification spam, duplicate investigations, and incoherent approval flows follow if each finding is treated as the primary operational unit.

## Decision

Kaval will treat Incident as a first-class domain entity. Findings are grouped into incidents, and incidents become the unit of investigation, notification, approval, remediation tracking, and lifecycle management.

## Consequences

- Grouping logic and incident lifecycle rules become foundational contracts early in the project.
- Notifications are emitted per incident rather than per raw finding where possible.
- Approval tokens and remediation proposals bind to incidents instead of isolated symptoms.
- Operational Memory can track recurrence and lessons at the level users actually care about.
