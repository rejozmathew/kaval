# Change Request: CR-0001 DNS target source for P1-11

## Metadata
- CR ID: CR-0001
- Title: DNS target source for Phase 1 DNS resolution check
- Status: Approved
- PRD Baseline: v4.1
- Phase Impacted: Phase 1
- Raised On: 2026-03-31
- Raised By: Rejo Z. Mathew / Coding run
- Approved By: Rejo Z. Mathew
- Implemented By: Pending
- Related Tasks: P1-11
- Related Files:
  - docs/prd.md
  - plans/phase-1.md
  - STATUS.md

## Problem Statement
Phase 1 task P1-11 requires a deterministic DNS resolution check, but the currently implemented Phase 1 service and descriptor surfaces do not expose authoritative DNS targets or expected DNS answers. The only nearby baseline concept is `NetworkingProfile`, which belongs to a later system-profile layer and is not yet materialized during P1-11.

## Baseline PRD Position
The baseline PRD places P1-11 inside Phase 1 deterministic monitoring and does not make it depend on the later system-profile task. Therefore P1-11 must be implementable using Phase 1 data surfaces.

## Observed Implementation Gap
Current `Service` records and descriptor metadata expose endpoints, ports, and dependency hints, but not authoritative DNS targets or expected record values needed for a deterministic DNS resolution check.

## Decision
For Phase 1, the authoritative source of DNS targets for P1-11 is:
- optional DNS metadata declared on shipped service descriptors
- materialized onto `Service` records during descriptor matching/materialization

`SystemProfile` / `NetworkingProfile` remains a later system-summary layer and is **not** a prerequisite for P1-11.

## Rationale
This is the smallest change that preserves PRD intent and Phase 1 ordering:
- keeps P1-11 deterministic and Phase-appropriate
- avoids incorrectly reordering work to depend on P1-18
- keeps DNS checks scoped only to explicitly declared DNS targets
- avoids introducing a broad new configuration system

## Scope of Change
This CR changes:
- Phase 1 implementation guidance for P1-11
- `plans/phase-1.md` clarification for DNS target source
- `STATUS.md` blocker resolution
- minimal descriptor/service schema extension for optional DNS metadata
- optionally a narrow clarification note in `docs/prd.md` if you want repo docs to reflect approved CRs

This CR does **not** change frozen Phase 0 interfaces.

## Implementation Instructions
1. Update `plans/phase-1.md` to state that P1-11 DNS targets come from optional descriptor/service DNS metadata.
2. Update `STATUS.md` to resolve the blocker and record this CR as the authoritative decision.
3. Add minimal optional DNS metadata to the descriptor schema and materialized `Service` records.
4. Implement P1-11 using only explicitly declared DNS targets.
5. Support a minimal deterministic record set only (for example `A`, `AAAA`, `CNAME`) unless the task plan requires more.
6. Skip services with no DNS metadata.
7. Add or update tests, fixtures, and contract coverage.
8. Run validations before marking P1-11 complete.
9. Stop if a new contradiction appears.

## Impact Assessment
- Frozen interface impact: none
- Security impact: none beyond normal read-only DNS probing
- Test impact: add/update descriptor schema tests, service materialization tests, and DNS check tests
- Documentation impact: update `plans/phase-1.md`, `STATUS.md`, and optionally annotate `docs/prd.md` later during a consolidated PRD roll-up

## Acceptance Criteria
- [ ] `plans/phase-1.md` updated with the DNS target source decision
- [ ] `STATUS.md` updated and blocker resolved
- [ ] Descriptor schema supports optional DNS metadata
- [ ] `Service` materialization carries DNS targets needed by P1-11
- [ ] P1-11 implemented deterministically against declared DNS metadata
- [ ] Tests and validations pass

## Supersession / Roll-up
- Superseded By: none
- Roll into future PRD version: yes
- Notes: roll into next consolidated PRD refresh rather than mutating the frozen baseline immediately