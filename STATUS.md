# STATUS.md

## Project
- Name: Kaval
- PRD version: 4.1
- Current phase: Phase 0
- Current task: P0-01
- Overall status: not started

## Phase gates
- [ ] Phase 0 complete
- [ ] Phase 1 complete
- [ ] Phase 2A complete
- [ ] Phase 2B complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete

## Frozen interfaces (must be stable before parallel work)
- [ ] Core↔Executor API
- [ ] ApprovalToken schema
- [ ] Incident lifecycle state machine
- [ ] Investigation output schema
- [ ] Notification callback payloads
- [ ] Operational Memory query/result schema

## Completed work
- None yet.

## Current focus
- Bootstrapping repository structure and Phase 0 foundations.

## Decisions log
- 2026-03-30: PRD v4.1 accepted as implementation-ready product spec.
- 2026-03-30: Codex + TaskMaster chosen as coding workflow; human review remains at phase boundaries.

## Open blockers
- None yet.

## Next 3 tasks
1. P0-01 Repo scaffold
2. P0-02 Core data models
3. P0-03 SQLite database

## Validation snapshots
- lint: not run
- typecheck: not run
- tests: not run
- contract tests: not run
- scenario tests: not run

## Notes for the coding agent
- Prefer WSL workspace on Windows for Codex.
- Treat the PRD as architecture source of truth.
- Do not begin Phase 1 before Phase 0 exit criteria and frozen interfaces are satisfied.
