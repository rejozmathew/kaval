# ADR-006: Service Descriptors Instead of Service-Specific Code

- Status: Accepted
- Date: 2026-03-31

## Context

Kaval needs service-specific health knowledge, dependencies, and heuristics for dozens of common homelab applications. Encoding that knowledge directly in Python would slow contribution, raise review cost, and blur product logic with catalog content.

## Decision

Kaval will represent service knowledge as schema-validated descriptors rather than as service-specific Python modules wherever possible. Auto-generated descriptors may exist, but they remain quarantined and low-trust until reviewed.

## Consequences

- New services can be added through descriptor authoring instead of backend code changes.
- Descriptor schemas and policy linting become part of the contract surface.
- Auto-generated descriptors are constrained to low-risk use and cannot drive actions or incident grouping.
- The core runtime can stay smaller and more generic.
