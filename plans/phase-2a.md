# Phase 2A — Investigation Engine + Notifications + Restart

## Objective
When something breaks, Kaval investigates using Tier 1 evidence gathering, sends structured evidence/inference/recommendation notifications, and can restart containers with approval through an internal Executor process.

## Deliverables
- LangGraph investigation workflow (Tier 1)
- Local model integration via OpenAI-compatible endpoint
- Investigation prompt templates
- Notification bus (apprise)
- Telegram interactive handler
- Incident-grouped notifications
- Executor internal process (restart-container only)
- Core→Executor Unix socket client
- Basic investigation detail UI
- Scenario tests: DelugeVPN, cert expiry, crash loop

## Tasks
- P2A-01 Evidence collection module (Tier 1)
- P2A-02 Investigation prompt templates
- P2A-03 LangGraph investigation workflow (Tier 1)
- P2A-04 Local model integration (OpenAI-compatible)
- P2A-05 Notification bus (apprise)
- P2A-06 Notification formatter
- P2A-07 Incident-grouped notifications
- P2A-08 Telegram interactive handler
- P2A-09 Executor internal process (Unix socket, restart-container only)
- P2A-10 Core→Executor Unix socket client
- P2A-11 Scenario: DelugeVPN tunnel drop
- P2A-12 Scenario: Cert expiry
- P2A-13 Scenario: Container crash loop
- P2A-14 UI: Basic investigation detail

## Dependency notes
- P2A-01 depends on P1-02, P1-14, P1-15
- P2A-02 depends on P2A-01
- P2A-03 depends on P2A-01 and P2A-02
- P2A-04 depends on P2A-03
- P2A-05 depends on P1-17
- P2A-06 depends on P2A-05
- P2A-07 depends on P2A-05 and P1-17
- P2A-08 depends on P2A-05
- P2A-09 depends on P0-08 and ADR-014
- P2A-10 depends on P2A-09
- P2A-11..13 depend on P2A-03 and P2A-10 for approval/execution coverage where applicable
- P2A-14 depends on P2A-03 and P1-21

## Exit criteria
- Container failure → incident → investigation → Telegram message with evidence + inference + recommendation
- Investigation includes log analysis, dependency check, and change correlation
- User approves restart via Telegram → internal Executor process validates approval token → container restart executes → verification runs
- DelugeVPN, cert expiry, and crash loop scenario tests pass

## Review gates
- Security review for prompts, Executor, approvals, and action boundaries
- Executor must preserve: no UI, no LLM, no notification capability, no independent external API surface
- All network I/O remains the responsibility of the Core process
- Restart-container remains the only v1 system-modifying action

## Validation commands
- `python -m pytest tests/unit/test_investigation tests/scenario`
- `python -m pytest tests/security`
- `ruff check .`
- `mypy src`

## Notes
- Executor transport is Unix domain socket: `/run/kaval/executor.sock`
- Restart-container is the only v1 system-modifying action.
- Output must remain structured as evidence, inference, recommendation.
- Approval remains mandatory for every system-modifying action.