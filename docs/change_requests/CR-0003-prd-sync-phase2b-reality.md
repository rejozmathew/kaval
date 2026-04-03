# Change Request: CR-0003 PRD sync to Phase 2B reality and Phase 3/4 document authority

## Metadata
- CR ID: CR-0003
- Title: Sync PRD to Phase 2B-complete reality and establish Phase 3/4 document authority
- Status: Proposed
- PRD Baseline: v4.1
- Phase Impacted: Phase 3A pre-work
- Raised On: 2026-04-02
- Raised By: Rejo Z. Mathew
- Approved By: pending
- Implemented By: pending
- Related Tasks: none (governance / housekeeping only)
- Related Files:
  - `docs/prd.md`
  - `docs/phase3_4_requirements_expansion.md`
  - `plans/phase-3a.md`
  - `plans/phase-3b.md`
  - `plans/phase-3c.md`
  - `plans/phase-4.md`
  - `STATUS.md`

## Problem Statement
PRD v4.1 was written before Phase 2A and Phase 2B were completed. Since then:

- CR-0002 / ADR-014 changed the runtime model from a sidecar-oriented design to one Docker container with two internal processes.
- Phase 2A and Phase 2B have been implemented and validated.
- A dedicated Phase 3/4 requirements expansion document now defines Phase 3 and Phase 4 in much greater detail than the thin Phase 3/4 sections in PRD v4.1.
- Detailed phase plans now exist for `phase-3a`, `phase-3b`, `phase-3c`, and `phase-4`.

Without this CR, Phase 3/4 implementation prompts have ambiguous document authority:
- does `docs/prd.md` control,
- does `docs/phase3_4_requirements_expansion.md` control,
- or do the phase plans control?

This CR resolves that ambiguity and aligns the baseline PRD to the current Phase 2B-complete state.

## Baseline PRD Position
PRD v4.1 remains the baseline architectural and product reference for:
- global product goals
- runtime and trust model
- core terminology
- frozen interfaces
- completed-phase context
- Sections 1–16 generally

However, PRD v4.1 Phase 3 and Phase 4 delivery sections are thin and no longer sufficient as implementation authority. They contain high-level deliverables only and do not provide the detailed requirements, execution sequencing, or validation structure now needed.

## Observed Documentation Gap
The repository now has three distinct document layers for post-Phase-2B work:

1. `docs/prd.md`  
   Baseline architectural and product reference.

2. `docs/phase3_4_requirements_expansion.md`  
   Detailed Phase 3/4 requirements source.

3. `plans/phase-3a.md` through `plans/phase-4.md`  
   Execution plans with sequencing, dependencies, validations, and exit criteria.

This layering is valid, but not yet explicitly documented. The result is unnecessary ambiguity for coding agents and future maintainers.

## Decision
1. `docs/prd.md` remains the baseline product and architectural reference.
2. For Phase 3 and Phase 4 requirements, `docs/phase3_4_requirements_expansion.md` becomes the authoritative requirements source.
3. For Phase 3A, Phase 3B, Phase 3C, and Phase 4 execution sequencing, dependencies, validations, and exit criteria, `plans/phase-3a.md` through `plans/phase-4.md` become the authoritative execution contracts.
4. Where the PRD’s Phase 3/4 delivery sections conflict with the requirements expansion document, the requirements expansion document governs until consolidation into PRD v5.
5. `docs/prd.md` is updated to:
   - reflect the Phase 2B-complete project state where needed,
   - remove any residual stale architecture/runtime language inconsistent with CR-0002 / ADR-014,
   - and point readers to the Phase 3/4 requirements expansion and phase plans.
6. This CR does **not** materially rewrite future roadmap scope. Phase 5+ may receive minimal consistency cleanup only if necessary.

## Rationale
This is the smallest change that:
- resolves authority ambiguity,
- keeps PRD v4.1 as the baseline instead of replacing it,
- avoids a premature full PRD v5 rewrite,
- and gives coding agents a clear document hierarchy before Phase 3A implementation begins.

A full PRD v5 consolidation can happen after Phase 4, folding in:
- CR-0001
- CR-0002
- CR-0003
- approved later CRs/ADRs
- the Phase 3/4 requirements expansion

## Scope of Change

### PRD changes
Update `docs/prd.md` to:

- replace the thin Phase 3 delivery section with:
  - a short objective summary,
  - a pointer to `docs/phase3_4_requirements_expansion.md`,
  - and pointers to `plans/phase-3a.md`, `plans/phase-3b.md`, and `plans/phase-3c.md`
- replace the thin Phase 4 delivery section with:
  - a short objective summary,
  - a pointer to `docs/phase3_4_requirements_expansion.md`,
  - and a pointer to `plans/phase-4.md`
- add a governance note clarifying document authority for Phase 3/4
- scan the PRD body for residual language inconsistent with CR-0002 / ADR-014 and Phase 2B-complete reality, including:
  - sidecar-only or two-container-only assumptions
  - obsolete file/runtime references
  - overly provider-specific local-model wording where the implemented product now supports generic OpenAI-compatible local endpoints

### New / committed document
- `docs/phase3_4_requirements_expansion.md`

### STATUS changes
Update `STATUS.md` to reflect:
- Phase 2B complete
- Phase 3A as the next phase
- current task as either:
  - `Phase 3A planning complete; ready to begin P3A-01`, or
  - `P3A-01` only if implementation actually starts in the same run

### Out of scope
This CR does **not**:
- change code
- change models or schemas
- change tests
- change frozen Phase 0 interfaces
- change the approved runtime architecture
- introduce new system-modifying actions
- substantially rewrite Phase 5+ roadmap scope

## Document Authority Note to Add
Add a short governance note to `docs/prd.md` along these lines:

> For Phase 3 and Phase 4 detailed requirements, see `docs/phase3_4_requirements_expansion.md`.  
> For Phase 3A, 3B, 3C, and Phase 4 execution sequencing, dependencies, validation, and exit criteria, see `plans/phase-3a.md` through `plans/phase-4.md`.  
> These documents govern Phase 3/4 implementation until consolidation into PRD v5.  
> `docs/prd.md` remains the baseline architectural and product reference.

## Implementation Instructions
1. Commit `docs/phase3_4_requirements_expansion.md` to the repo.
2. Commit `plans/phase-3a.md`, `plans/phase-3b.md`, `plans/phase-3c.md`, and `plans/phase-4.md`.
3. Edit `docs/prd.md`:
   - update Phase 3 section with summary + pointers
   - update Phase 4 section with summary + pointers
   - add the document-governance note
   - scan the rest of the PRD for residual stale language inconsistent with CR-0002 / ADR-014 and Phase 2B-complete reality
4. Update `STATUS.md` to reflect the current project state accurately.
5. Run documentation/control consistency validation only.
6. Stop and raise a blocker if any contradiction is found between:
   - the baseline PRD body,
   - the requirements expansion document,
   - approved CRs/ADRs,
   - and the new phase plans.

## Validation Expectations
Because this is a governance/documentation CR, validation should be limited to documentation/control consistency, for example:

- path/reference consistency
- stale language scan
- `git diff --check`
- any lightweight structured-file validation if needed

This CR does not require a full repo test/lint/typecheck pass unless another changed file independently requires it.

## Impact Assessment
- Frozen interface impact: none
- Security impact: none
- Runtime impact: none
- Code impact: none
- Test impact: none
- Documentation impact:
  - Phase 3/4 authority clarified
  - PRD Phase 3/4 delivery sections updated
  - requirements expansion and phase plans committed
  - STATUS aligned to current project state

## Acceptance Criteria
- [ ] `docs/phase3_4_requirements_expansion.md` committed to repo
- [ ] `plans/phase-3a.md`, `plans/phase-3b.md`, `plans/phase-3c.md`, and `plans/phase-4.md` committed
- [ ] `docs/prd.md` Phase 3 section updated with summary + pointers
- [ ] `docs/prd.md` Phase 4 section updated with summary + pointer
- [ ] document-governance note added to `docs/prd.md`
- [ ] PRD body scanned for stale language inconsistent with CR-0002 / ADR-014 and current Phase 2B-complete reality; any found issues fixed
- [ ] `STATUS.md` updated to reflect Phase 2B complete and Phase 3A ready/current
- [ ] no contradictions remain among PRD baseline, approved CRs/ADRs, requirements expansion, and phase plans
- [ ] documentation/control consistency validations pass

## Supersession / Roll-up
- Superseded By: none
- Roll into future PRD version: yes
- Notes: This is a governance/housekeeping CR. It does not introduce product functionality; it establishes clear document authority for Phase 3/4 implementation.