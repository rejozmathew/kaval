# AGENTS.md

## Source of truth

Use these files in this order when they conflict:
1. `docs/prd.md`
2. `plans/phase-*.md`
3. `STATUS.md`
4. file-local comments and tests

The PRD is the product contract. The phase plan files are the execution contract.

## Execution model

- Work phase by phase.
- Do not start a later phase until the active phase exit criteria pass.
- Phase 0 is strictly sequential.
- Before any parallel work, freeze the interfaces called out in the PRD.
- If a required contract must change, stop and record the issue in `STATUS.md` before proceeding.

## Task discipline

For each task:
- restate the goal in 2-5 lines
- touch only files allowed by the current plan when the plan restricts scope
- run the listed validation commands
- update `STATUS.md`
- stop on failed validation instead of pushing forward

Do not silently skip tests, lint, type checks, schema validation, or scenario tests.

## Coding standards

- Python: typed code, Pydantic models, small modules, docstrings on public functions.
- Prefer explicit data contracts over implicit dicts.
- Keep FastAPI request/response models aligned with frozen schemas.
- Favor small commits and reviewable diffs.
- Do not add new production dependencies without recording the reason in `STATUS.md`.

## Security rules

- Core must never get docker.sock or host-level privileges.
- Executor is the only component allowed to use docker.sock.
- No privilege expansion without explicit review.
- Treat credentials, vault logic, approval tokens, redaction, prompts, and executor code as security-sensitive.
- Never log secrets, approval tokens, raw credentials, or unredacted memory exports.
- Preserve the Core↔Executor trust boundary.

## Definition of done (per feature)

A task is not done until all applicable items pass:
- lint
- type check
- unit tests
- contract tests if schemas/descriptors changed
- scenario test if the feature affects incident/investigation flow
- docs/config updated
- failure modes documented
- audit trail verified if actions are involved

## Repo operations

- Keep `docs/prd.md` current if architecture changes.
- ADRs are append-only/immutable except for status lines.
- `CHANGELOG.md` is append-only.
- If TaskMaster is present, follow task order from TaskMaster unless it conflicts with the current phase plan or frozen interfaces.

## When blocked

If blocked by ambiguity, missing secrets, missing infra, or contract conflicts:
- write a concise blocker entry to `STATUS.md`
- list what was attempted
- identify the smallest unblocking decision needed
- stop rather than improvising across trust boundaries
