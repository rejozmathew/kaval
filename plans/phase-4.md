# Phase 4 — Distribution, Documentation, Release Quality

## Objective

Package Kaval for distribution via Unraid Community Apps. Produce complete user and contributor documentation. Pass security audit and performance validation. Meet release quality gates.

## Requirements Reference

Phase 3/4 Requirements Expansion v2: Sections 23 (Distribution), 24 (Documentation), 25 (Security Audit), 26 (Performance Targets), 27 (Release Checklist)

## Deliverables

- Unraid Community Apps template (one container, one install, one dashboard tile)
- Install/upgrade flow tested and documented
- Backup/restore API
- User documentation: install guide, getting started, operator guide, investigation guide, troubleshooting, FAQ
- Contributor documentation: descriptor authoring, adapter development, webhook normalizer, architecture guide, development setup
- In-product documentation: tooltips, contextual help, "learn more" links
- Security audit pass across all 10 areas defined in requirements
- Performance profiling against defined targets
- 50+ shipped descriptor target (15+ additional beyond Phase 3C)
- Release quality gates verified
- README with screenshots, demo walkthrough, feature list

## Global execution guardrails

- Phase 4 is release-focused. Do not introduce new monitoring, investigation, remediation, or deep-inspection capabilities unless explicitly required by an approved CR/ADR.
- Preserve the approved action boundary:
  - LLM remains proposal-only
  - Executor remains bounded
  - no new state-changing actions
- Treat backup/restore and admin/export surfaces as security-sensitive.
- Prefer tightening, documenting, validating, packaging, and hardening existing behavior over refactoring large working subsystems.
- Where a task is documentation-only, avoid code churn.
- Where a task is audit-focused, prefer additive tests and review artifacts over broad rewrites.
- For execution runs, the active-task prompt must still restate:
  - task ID and name
  - files expected to touch
  - exact validation commands
  - acceptance criteria
  - blockers or contradictions before coding begins

## Suggested repository touch surfaces

Validate against the live repo before editing and keep scope narrow for the active task.

- `docs/`
- `README.md`
- `CHANGELOG.md`
- `.env.example`
- deployment/install artifacts already present in the repo (for example CA template / compose / example config locations chosen by the project)
- `src/kaval/api/`
- `src/kaval/database.py`
- `src/kaval/models.py`
- `src/web/`
- `services/`
- `schemas/`
- `.github/workflows/`
- `tests/unit/`
- `tests/integration/`
- `tests/contract/`
- `tests/scenario/`
- `tests/security/`

## Tasks

### Workstream 1: Packaging and Distribution

- P4-01 Unraid CA template (port mapping, volume mapping, docker.sock, env vars, description, icon)
- P4-02 Install flow smoke test: CA template install → API key → guided setup → service map in < 2 minutes
- P4-03 Upgrade flow smoke test: image pull → restart → data preserved → no regressions → migrations run
- P4-04 Backup API: GET /api/v1/admin/backup (ZIP: database, settings, user descriptors, notes, memory — with sensitivity warning)
- P4-05 Restore API: POST /api/v1/admin/restore (upload and restore from backup)
- P4-06 Release-ready environment/config examples (docker-compose.yml, .env.example, kaval.yaml reference)

### Workstream 2: User Documentation

- P4-07 Install guide (CA template install, first-run, notification configuration)
- P4-08 Getting started guide (first-hour walkthrough: service map, insight levels, deep inspection setup, dependency review)
- P4-09 Operator guide (all UI features, settings, credential management, maintenance mode, noise control)
- P4-10 Investigation guide (how evidence/inference/recommendation works, approving actions, providing feedback)
- P4-11 Troubleshooting guide ("Why isn't Kaval detecting my service?", "Why are investigations generic?", "How do I reduce false positives?")
- P4-12 FAQ (model costs, security model, what Kaval can/cannot do, data storage, privacy, single-admin assumption)

### Workstream 3: Contributor Documentation

- P4-13 Descriptor authoring guide (field reference, testing, quality standards, submitting PRs)
- P4-14 Adapter development guide (ServiceAdapter interface, testing, version compatibility, degradation)
- P4-15 Webhook normalizer guide (normalizer interface, field mapping, testing)
- P4-16 Architecture guide (system architecture, data flow, security model, investigation workflow, adapter model)
- P4-17 Development setup guide (local dev environment, running tests, CI pipeline, coding standards)

### Workstream 4: In-Product Documentation

- P4-18 Tooltips on complex UI elements (insight levels, confidence types, adapter status, effectiveness score)
- P4-19 "Learn more" links from UI sections to relevant docs
- P4-20 Contextual help in guided setup flow (step-by-step explanations)
- P4-21 Error messages: explain what happened and what to do about it (not just "error occurred")

### Workstream 5: Security Audit

- P4-22 LLM confinement audit: verify LLM has no action tools, proposals are data only, execution path is deterministic
- P4-23 Approval token integrity: HMAC validation, single-use, time-limited, incident-bound, replay protection
- P4-24 Credential handling audit: secrets never in logs/prompts/UI, vault encryption, volatile mode, two-level redaction
- P4-25 Executor isolation: socket-only, token validation, allowlist enforcement
- P4-26 Webhook auth audit: per-source keys, rate limiting, payload redaction, no unauthenticated acceptance
- P4-27 Admin API audit: settings/config/backup endpoints accessible only from local network (single-admin model)
- P4-28 Adapter safety audit: all adapters read-only, no state mutations
- P4-29 Input validation audit: user notes, descriptor edits, config changes — validated and sanitized
- P4-30 Dependency audit: third-party Python packages checked for known CVEs
- P4-31 Prompt injection assessment: malicious content in logs/notes tested for investigation behavior impact

### Workstream 6: Performance and Quality

- P4-32 Performance profiling on representative hardware (Intel i3-12100T, 32GB RAM, NVMe)
- P4-33 Responsiveness targets: UI load < 3s, API < 200ms, investigation (local) < 30s, check cycle < 30s
- P4-34 Resource targets: idle memory < 256MB, active < 512MB, CPU idle < 2%
- P4-35 Scale validation: 25 services (primary), 50 services (stretch)
- P4-36 15+ additional shipped descriptors (target: 50+ total with contract tests)
- P4-37 False positive assessment: run for 48 hours on real server, evaluate noise level

### Workstream 7: Release Finalization

- P4-38 README refresh: screenshots, demo walkthrough, feature list, quick start
- P4-39 CHANGELOG update: comprehensive entry for v1.0 release
- P4-40 Release quality gate checklist: verify all hard gates pass (Section 27.1 of requirements)
- P4-41 Quality target review: assess quality targets (Section 27.2), document any justified exceptions
- P4-42 License and attribution review

## Dependency notes

- P4-01 is the packaging anchor for distribution work.
- P4-02 depends on P4-01 and on a Phase 3C-complete product build.
- P4-03 depends on P4-01 and an upgradeable image/build pipeline already existing in the repo.
- P4-04 and P4-05 are paired; P4-05 depends on P4-04.
- P4-06 should follow P4-01 and align to the final install/runtime shape.
- P4-07..12 depend on Phase 3C-complete product behavior and should be written against the real built system, not aspirational behavior.
- P4-13..17 depend on the corresponding implemented extension points from Phases 3A/3B/3C.
- P4-18..21 depend on:
  - Phase 3C UI being complete
  - the relevant docs pages from P4-07..17 existing
- P4-22..31 should begin only after all code-affecting Phase 3 work is complete and after P4-04/P4-05 if those endpoints are part of the audited admin surface.
- P4-32..35 depend on all feature and release-admin surfaces being implemented and stable enough to profile.
- P4-36 can run in parallel with late documentation/audit work, but must complete before final release gates if the 50+ descriptor target is still in scope.
- P4-37 depends on a stable near-release deployment on a real server.
- P4-38..42 depend on the outputs of Workstreams 1–6.

## Exit criteria

### Hard release gates (must all pass)

- [ ] All shipped descriptors pass contract tests
- [ ] Security audit items all verified with passing tests
- [ ] Secrets audit: no secrets in logs, prompts, UI, git-tracked files, exported data
- [ ] Install flow: CA template install → API key → service map in < 2 minutes
- [ ] Upgrade flow: image pull → restart → data preserved → no regressions
- [ ] Guided setup flow complete and functional
- [ ] Core documentation written: install guide, getting started, operator guide
- [ ] Notification tested on at least 2 channels (Telegram + one other)
- [ ] Adapter degradation tested: break each priority adapter → verify graceful fallback
- [ ] Action boundary verified: LLM cannot trigger actions, token validation works, allowlist enforced

### Quality targets (should pass, investigate if not)

- [ ] All priority adapters tested across at least 2 service versions
- [ ] Performance targets met on representative hardware
- [ ] Contributor guides tested: follow guide → produce working descriptor/adapter/normalizer
- [ ] Screenshot/demo content produced
- [ ] Browser compatibility: Chrome and Firefox (primary), Safari (best effort)
- [ ] False positive assessment: 48-hour run, acceptable noise level
- [ ] Notification tested across 3+ channels

### Stretch goals (aspirational, not release-blocking)

- [ ] False positive rate below 5/day sustained over 1 week
- [ ] Full mobile responsiveness
- [ ] 50+ descriptors shipped (35+ is hard target from Phase 3C)
- [ ] Contributor docs tested with external contributors
- [ ] Performance validated at 50-service scale

## Review gates

- Documentation accuracy: docs match actual product behavior
- Security audit: no open critical or high findings
- Single-admin assumption documented in install guide and FAQ
- All Phase 3/4 read-only action boundary commitments verified

## Validation commands

- `python -m pytest tests/unit tests/integration`
- `python -m pytest tests/contract`
- `python -m pytest tests/scenario`
- `python -m pytest tests/security`
- `cd src/web && npm run build`
- `ruff check .`
- `mypy src`

## Notes

- Phase 4 is release-focused, not feature-focused. No new monitoring/investigation/remediation capabilities are added; bounded release/admin surfaces like backup/restore and documentation are allowed.
- Documentation is the largest workstream by volume — plan accordingly.
- Security audit items should produce tests that become part of the permanent CI suite where possible.
- The CA template is what makes Kaval installable by non-technical Unraid users — it is the single most important distribution artifact.
- After Phase 4, the repo should be ready for initial community release. Phase 5+ features (image rollback, VM actions, MCP, multi-server) come after community feedback.

## Task execution packets

### P4-01 — Unraid CA template
**Goal**
Define the canonical Community Apps installation artifact for the current one-container/two-process runtime.

**Primary touch surfaces**
- deployment/install artifact location chosen by the repo
- `README.md`
- `docs/`
- `.env.example`

**Acceptance criteria**
- Template describes one install / one dashboard tile
- Runtime mappings match the implemented product shape
- Required env vars and volumes are documented
- No sidecar-era packaging assumptions remain

**Validation focus**
- artifact reference/path consistency
- install docs consistency
- `git diff --check`

**Stop conditions**
- If the runtime shape in docs/code is still ambiguous
- If CA template requirements conflict with the implemented container model

### P4-02 — Install flow smoke test
**Goal**
Validate the first-time install path from CA template to guided setup and service map availability.

**Primary touch surfaces**
- install/test docs under `docs/`
- scenario/integration test surfaces
- release notes if needed

**Acceptance criteria**
- Reproducible install flow documented and tested
- Fresh install reaches API key entry, guided setup, and service map
- Timing/result evidence recorded against the hard gate

**Validation focus**
- install smoke scenario
- docs accuracy check
- relevant integration/scenario validation

**Stop conditions**
- If install requires undocumented manual fixes
- If guided setup or service map availability depends on unfinished Phase 3 behavior

### P4-03 — Upgrade flow smoke test
**Goal**
Validate upgrade safety for an existing deployment.

**Primary touch surfaces**
- migration/integration test surfaces
- upgrade docs
- release notes

**Acceptance criteria**
- Upgrade path documented
- Data is preserved
- Migrations run successfully
- No regressions in core startup or UI availability

**Validation focus**
- upgrade scenario
- migration validation
- docs/update notes consistency

**Stop conditions**
- If migrations are not deterministic
- If upgrade depends on manual DB surgery or undocumented recovery

### P4-04 — Backup API
**Goal**
Add a bounded admin export path for backup/portability.

**Primary touch surfaces**
- `src/kaval/api/`
- `src/kaval/database.py`
- backup/export code path selected by repo
- tests/integration/security
- docs

**Acceptance criteria**
- Export endpoint exists and is documented
- Sensitivity warning is explicit
- Backup contains the intended bounded dataset only
- Export does not leak secrets unexpectedly

**Validation focus**
- integration tests for export
- security tests for redaction/secrets handling
- docs consistency

**Stop conditions**
- If backup content scope is unclear
- If vault/secret material cannot be safely excluded or clearly handled

### P4-05 — Restore API
**Goal**
Provide the paired bounded restore flow for supported backup artifacts.

**Primary touch surfaces**
- `src/kaval/api/`
- DB/import/restore code path selected by repo
- tests/integration/security
- docs

**Acceptance criteria**
- Restore endpoint accepts only supported backup format
- Restore behavior is documented and testable
- Safety checks prevent malformed or dangerous imports
- Restored state is usable after restart

**Validation focus**
- restore integration tests
- import validation tests
- security tests for malformed input

**Stop conditions**
- If restore semantics are unclear (merge vs replace)
- If restore can corrupt existing state without a bounded rollback/recovery path

### P4-06 — Release-ready environment/config examples
**Goal**
Ship accurate examples for installation and reference configuration.

**Primary touch surfaces**
- `.env.example`
- compose/example config artifacts
- docs

**Acceptance criteria**
- Examples match the implemented runtime
- No stale variable names or sidecar-era examples remain
- Reference config is internally consistent with docs and CA template

**Validation focus**
- config parse/reference consistency
- `git diff --check`

**Stop conditions**
- If examples depend on unsupported paths
- If config semantics are still shifting

### P4-07 — Install guide
**Goal**
Document the installation path for real users.

**Primary touch surfaces**
- `docs/`
- `README.md` if linked

**Acceptance criteria**
- Covers install prerequisites, CA install, first-run path, API key, notifications
- Matches actual product behavior
- Includes troubleshooting pointers for the most likely setup failures

**Validation focus**
- docs accuracy review
- link/reference consistency

**Stop conditions**
- If install flow is not yet stable enough to document confidently

### P4-08 — Getting started guide
**Goal**
Provide a concise first-hour guide that teaches the product’s mental model.

**Primary touch surfaces**
- `docs/`
- screenshots/demo assets if already available

**Acceptance criteria**
- Covers service map, insight levels, deep inspection, dependency review, recommendations
- Written from actual product behavior, not aspiration
- Makes the first-hour value proposition clear

**Validation focus**
- docs accuracy review
- screenshot/reference consistency

**Stop conditions**
- If key first-hour UX is still unstable

### P4-09 — Operator guide
**Goal**
Document day-to-day operation of Kaval.

**Primary touch surfaces**
- `docs/`

**Acceptance criteria**
- Covers service detail, settings, credentials, maintenance mode, noise control, health, audit surfaces
- Matches implemented UI and behavior

**Validation focus**
- docs accuracy review

**Stop conditions**
- If admin/settings surfaces are still moving

### P4-10 — Investigation guide
**Goal**
Explain how Kaval investigates and how operators should interpret and approve actions.

**Primary touch surfaces**
- `docs/`

**Acceptance criteria**
- Evidence/inference/recommendation model explained
- Approval-gated action boundary clearly documented
- Confidence, redaction, and escalation behavior described accurately

**Validation focus**
- docs accuracy review
- action-boundary consistency

**Stop conditions**
- If docs would misrepresent actual investigation behavior

### P4-11 — Troubleshooting guide
**Goal**
Provide practical help for the most common failure modes in Kaval itself.

**Primary touch surfaces**
- `docs/`

**Acceptance criteria**
- Includes detection/matching/investigation/generic-output/noise/setup failure cases
- Uses real troubleshooting paths from implemented behavior

**Validation focus**
- docs accuracy review

**Stop conditions**
- If guide would rely on unsupported behaviors

### P4-12 — FAQ
**Goal**
Document recurring user questions clearly and honestly.

**Primary touch surfaces**
- `docs/`

**Acceptance criteria**
- Covers cost, privacy, security model, capability boundaries, storage, single-admin assumption
- No claims beyond implemented behavior

**Validation focus**
- docs accuracy review

**Stop conditions**
- If answers depend on unsettled policy or roadmap assumptions

### P4-13 — Descriptor authoring guide
**Goal**
Enable contributors to add descriptors safely and consistently.

**Primary touch surfaces**
- `docs/`
- `services/`
- `schemas/`

**Acceptance criteria**
- Includes field reference, examples, validation/testing flow, quality bar
- Matches actual descriptor schema and contract tests

**Validation focus**
- schema/doc consistency
- contract test references

**Stop conditions**
- If descriptor schema is still shifting

### P4-14 — Adapter development guide
**Goal**
Document how to add or maintain deep inspection adapters.

**Primary touch surfaces**
- `docs/`
- adapter code locations under `src/kaval/`

**Acceptance criteria**
- Explains adapter interface, testing, version compatibility, degradation expectations, read-only rule
- Matches implemented adapter model

**Validation focus**
- code/doc consistency

**Stop conditions**
- If adapter interface is not stable

### P4-15 — Webhook normalizer guide
**Goal**
Document how to add new webhook sources safely.

**Primary touch surfaces**
- `docs/`
- webhook/normalizer code locations

**Acceptance criteria**
- Covers normalized schema, auth, mapping, testing, security expectations
- Matches implemented webhook model

**Validation focus**
- code/doc consistency

**Stop conditions**
- If webhook schema or auth model is still unstable

### P4-16 — Architecture guide
**Goal**
Provide a maintainable technical overview of the system.

**Primary touch surfaces**
- `docs/`

**Acceptance criteria**
- Covers runtime model, data flow, action boundary, investigation path, adapter model, major storage surfaces
- Does not reintroduce stale sidecar-era architecture language

**Validation focus**
- doc consistency with current PRD/CRs
- stale-language scan

**Stop conditions**
- If architecture docs conflict with current approved CRs/ADRs

### P4-17 — Development setup guide
**Goal**
Make contributor onboarding practical and repeatable.

**Primary touch surfaces**
- `docs/`
- `.github/workflows/`
- local dev config references

**Acceptance criteria**
- A contributor can set up the repo, run tests, and understand the toolchain
- Matches actual CI/runtime expectations

**Validation focus**
- doc accuracy review
- command/path consistency

**Stop conditions**
- If setup still requires undocumented tribal knowledge

### P4-18 — Tooltips on complex UI elements
**Goal**
Add concise in-product explanations for high-friction concepts.

**Primary touch surfaces**
- `src/web/`
- doc-link surfaces if present

**Acceptance criteria**
- Tooltips exist for insight levels, confidence, adapter status, effectiveness score, and similarly complex concepts
- Language matches docs and product behavior

**Validation focus**
- frontend build
- UI text consistency

**Stop conditions**
- If tooltip text would misstate behavior

### P4-19 — “Learn more” links
**Goal**
Bridge the UI to the written docs.

**Primary touch surfaces**
- `src/web/`
- docs routes/anchors if present

**Acceptance criteria**
- Relevant UI areas link to the correct docs
- No broken or placeholder links

**Validation focus**
- frontend build
- link consistency review

**Stop conditions**
- If docs information architecture is not yet stable

### P4-20 — Contextual help in guided setup
**Goal**
Make the first-run flow self-explanatory.

**Primary touch surfaces**
- `src/web/`
- guided setup UI surfaces
- docs references if linked

**Acceptance criteria**
- Each setup step has useful contextual help
- Help text matches current guided setup behavior

**Validation focus**
- frontend build
- UI copy review

**Stop conditions**
- If guided setup behavior is still shifting

### P4-21 — Better error messages
**Goal**
Replace vague user-facing errors with actionable explanations.

**Primary touch surfaces**
- `src/kaval/api/`
- `src/web/`
- notification/error surfaces as needed

**Acceptance criteria**
- Common install/setup/admin/investigation errors tell users what happened and what to do next
- Sensitive data is not leaked in messages

**Validation focus**
- integration/UI tests where relevant
- security review of error content

**Stop conditions**
- If errors would expose secrets or internal-only details

### P4-22 — LLM confinement audit
**Goal**
Verify the LLM remains bounded to proposal/reasoning only.

**Primary touch surfaces**
- prompt/investigation code paths
- security tests
- docs/audit artifacts

**Acceptance criteria**
- Audit evidence exists
- tests prove no direct action tools are exposed to the LLM
- docs capture the verified boundary

**Validation focus**
- `tests/security`
- targeted prompt/investigation tests

**Stop conditions**
- If any path allows the model to bypass deterministic action flow

### P4-23 — Approval token integrity audit
**Goal**
Verify the approval token model remains correct and enforced.

**Primary touch surfaces**
- approval/executor code paths
- tests/security

**Acceptance criteria**
- HMAC, single-use, expiry, replay, and incident-binding all validated
- audit evidence and tests exist

**Validation focus**
- security tests
- targeted executor/approval tests

**Stop conditions**
- If any approval path can be replayed or bypassed

### P4-24 — Credential handling audit
**Goal**
Verify secrets remain protected across prompts, logs, UI, and storage.

**Primary touch surfaces**
- credential/vault/redaction code paths
- export/import surfaces
- tests/security

**Acceptance criteria**
- evidence exists that secrets are not exposed improperly
- redaction and vault behavior are validated

**Validation focus**
- security tests
- export/import and prompt-redaction tests

**Stop conditions**
- If any secret leakage is found

### P4-25 — Executor isolation audit
**Goal**
Verify the bounded executor model still holds.

**Primary touch surfaces**
- executor/runtime code paths
- tests/security/runtime

**Acceptance criteria**
- socket-only model, token validation, and allowlist enforcement verified
- no scope drift beyond approved actions

**Validation focus**
- security/runtime tests

**Stop conditions**
- If executor scope or isolation assumptions have drifted

### P4-26 — Webhook auth audit
**Goal**
Verify webhook ingress remains authenticated and bounded.

**Primary touch surfaces**
- webhook receiver code
- tests/security

**Acceptance criteria**
- auth, rate limits, payload redaction, and rejection behavior all verified
- no unauthenticated acceptance path remains

**Validation focus**
- security tests
- webhook integration tests

**Stop conditions**
- If any webhook source can inject unauthenticated data

### P4-27 — Admin API audit
**Goal**
Verify sensitive admin surfaces are appropriately constrained for the single-admin model.

**Primary touch surfaces**
- admin API surfaces
- tests/security/integration
- docs

**Acceptance criteria**
- backup/restore/settings/config endpoints reviewed and tested
- local-network / deployment assumptions clearly documented
- no accidental broad exposure remains

**Validation focus**
- security/integration tests
- docs consistency

**Stop conditions**
- If sensitive admin endpoints are exposed contrary to the documented model

### P4-28 — Adapter safety audit
**Goal**
Verify adapters remain read-only and bounded.

**Primary touch surfaces**
- adapter code under `src/kaval/`
- tests/security/integration

**Acceptance criteria**
- all shipped adapters reviewed as read-only
- no state-mutating calls exist
- safety assumptions documented

**Validation focus**
- code review
- adapter tests
- security tests

**Stop conditions**
- If any adapter performs writes or portal-driving behavior

### P4-29 — Input validation audit
**Goal**
Verify editable/admin-provided inputs are validated and sanitized.

**Primary touch surfaces**
- note/descriptor/config/admin input surfaces
- tests/security

**Acceptance criteria**
- validation/sanitization expectations documented and tested
- malformed inputs rejected safely

**Validation focus**
- security tests
- integration tests for edited/admin surfaces

**Stop conditions**
- If malformed input can corrupt state or bypass intended validation

### P4-30 — Dependency audit
**Goal**
Check third-party dependencies for known vulnerabilities and stale risk.

**Primary touch surfaces**
- package manifests
- CI/review artifacts

**Acceptance criteria**
- audit performed
- findings documented and remediated or accepted explicitly

**Validation focus**
- dependency audit tooling/results

**Stop conditions**
- If unresolved critical/high dependency risk remains

### P4-31 — Prompt injection assessment
**Goal**
Assess how hostile content in logs/notes/webhooks affects investigation behavior.

**Primary touch surfaces**
- prompt assembly paths
- tests/security

**Acceptance criteria**
- malicious-content tests exist
- findings documented
- no action-boundary bypass or severe trust break remains

**Validation focus**
- security tests
- targeted prompt/investigation tests

**Stop conditions**
- If hostile content can materially subvert bounded behavior

### P4-32 — Performance profiling
**Goal**
Profile the system on representative hardware and capture the baseline.

**Primary touch surfaces**
- profiling scripts/artifacts if added
- docs/release artifacts

**Acceptance criteria**
- representative profiling run performed
- results captured and compared to target values

**Validation focus**
- profiling results
- reproducibility of measurement method

**Stop conditions**
- If measurement method is not reproducible or hardware assumptions are unclear

### P4-33 — Responsiveness targets
**Goal**
Verify responsiveness targets against measured behavior.

**Primary touch surfaces**
- performance test artifacts
- docs/release artifacts

**Acceptance criteria**
- UI/API/investigation/check-cycle timings evaluated against targets
- failures documented with justification or remediation

**Validation focus**
- performance measurement artifacts

**Stop conditions**
- If results are not attributable to a stable build

### P4-34 — Resource targets
**Goal**
Verify memory/CPU targets against measured behavior.

**Primary touch surfaces**
- performance measurement artifacts
- docs/release artifacts

**Acceptance criteria**
- idle/active memory and CPU measured
- variances documented and justified if necessary

**Validation focus**
- performance measurement artifacts

**Stop conditions**
- If resource measurement is not based on representative workload

### P4-35 — Scale validation
**Goal**
Verify behavior at representative and stretch scale.

**Primary touch surfaces**
- scenario/perf test artifacts
- docs/release artifacts

**Acceptance criteria**
- scale behavior evaluated at 25 services and, where feasible, 50-service stretch
- bottlenecks documented

**Validation focus**
- scale test artifacts

**Stop conditions**
- If synthetic scale setup is too unrealistic to support conclusions

### P4-36 — Additional shipped descriptors
**Goal**
Reach the final descriptor coverage target for release.

**Primary touch surfaces**
- `services/`
- `tests/contract/`
- docs if needed

**Acceptance criteria**
- additional descriptors added
- all pass contract tests
- target coverage justified in release notes

**Validation focus**
- contract tests
- descriptor review

**Stop conditions**
- If descriptor quality drops below the existing contract/quality bar

### P4-37 — False positive assessment
**Goal**
Validate operational noise on a real server before release.

**Primary touch surfaces**
- release/test notes
- docs/release artifacts

**Acceptance criteria**
- 48-hour run completed
- noise reviewed and documented
- obvious issues fed back into tuning or documented as known limitations

**Validation focus**
- real-run assessment artifact
- related scenario/security tests if tuning changes are made

**Stop conditions**
- If the run environment is not representative enough to support release conclusions

### P4-38 — README refresh
**Goal**
Refresh the public-facing repo landing page for release.

**Primary touch surfaces**
- `README.md`
- screenshots/demo assets

**Acceptance criteria**
- screenshots, quick start, demo narrative, and feature list are current
- no stale phase-era language remains

**Validation focus**
- docs review
- asset/link consistency

**Stop conditions**
- If screenshots/demo artifacts are not ready

### P4-39 — CHANGELOG update
**Goal**
Prepare a coherent v1.0 release entry.

**Primary touch surfaces**
- `CHANGELOG.md`

**Acceptance criteria**
- release entry is accurate, scoped, and consistent with actual shipped functionality

**Validation focus**
- changelog review

**Stop conditions**
- If release scope is still moving materially

### P4-40 — Hard release gate checklist
**Goal**
Verify all hard gates explicitly.

**Primary touch surfaces**
- release checklist artifact
- docs/release artifacts

**Acceptance criteria**
- every hard gate is checked with evidence
- any blocker is explicit and unresolved release is prevented

**Validation focus**
- full release evidence review
- required validation commands

**Stop conditions**
- If any hard gate fails

### P4-41 — Quality target review
**Goal**
Assess non-blocking quality targets and record justified exceptions.

**Primary touch surfaces**
- release notes/checklist artifacts

**Acceptance criteria**
- quality targets assessed
- exceptions documented with rationale

**Validation focus**
- release review artifacts

**Stop conditions**
- If “non-blocking” targets are being used to hide actual release blockers

### P4-42 — License and attribution review
**Goal**
Finalize legal/repository hygiene for release.

**Primary touch surfaces**
- license/attribution files in repo
- docs as needed

**Acceptance criteria**
- license and attribution are present, accurate, and consistent with shipped dependencies/assets

**Validation focus**
- repo/legal artifact review

**Stop conditions**
- If unresolved licensing or attribution issues remain
