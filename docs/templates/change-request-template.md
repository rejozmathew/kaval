# Change Request: CR-XXXX <short-title>

## Metadata
- CR ID: CR-XXXX
- Title: <short title>
- Status: Proposed
- PRD Baseline: v4.1
- Phase Impacted: <Phase 1 / Phase 2A / etc.>
- Raised On: YYYY-MM-DD
- Raised By: <name>
- Approved By: <name or pending>
- Implemented By: <name or pending>
- Related Tasks: <e.g. P1-11>
- Related Files:
  - docs/prd.md
  - plans/phase-X.md
  - STATUS.md

## Problem Statement
Describe the ambiguity, contradiction, gap, or design issue encountered during implementation.

## Baseline PRD Position
Quote or summarize the relevant baseline PRD behavior, sequencing, or dependency.

## Observed Implementation Gap
Describe what the coding agent found missing, contradictory, or not implementable as written.

## Decision
State the approved decision clearly and normatively.

## Rationale
Explain why this is the smallest correct fix and why alternatives were rejected.

## Scope of Change
List exactly what this CR changes:
- PRD clarification only?
- Phase plan clarification?
- STATUS update?
- Schema/model change?
- No change to frozen Phase 0 contracts?

## Implementation Instructions
Concrete instructions for the coding agent:
1. Update relevant control documents.
2. Apply the minimal schema/model/code changes required.
3. Add/update tests and fixtures.
4. Update STATUS.md.
5. Stop on new contradictions.

## Impact Assessment
- Frozen interface impact: <none / limited / requires review>
- Security impact: <none / describe>
- Test impact: <describe>
- Documentation impact: <describe>

## Acceptance Criteria
- [ ] Relevant phase plan updated
- [ ] STATUS updated
- [ ] Code/schema updated if required
- [ ] Tests added/updated
- [ ] Validation commands pass
- [ ] Blocker resolved

## Supersession / Roll-up
- Superseded By: <CR-XXXX or none>
- Roll into future PRD version: <yes/no>
- Notes: <optional>