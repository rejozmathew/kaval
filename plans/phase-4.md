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

- Workstream 1 (packaging) can start as soon as Phase 3C is feature-complete
- Workstream 2-3 (docs) can begin in parallel with late Phase 3C — document features as they stabilize
- Workstream 4 (in-product docs) depends on Phase 3C UI being complete
- Workstream 5 (security) can begin after Phase 3A/3B complete the adapter and webhook surfaces
- Workstream 6 (performance) depends on all features being implemented
- Workstream 7 (release) depends on all other workstreams

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

- Phase 4 is release-focused, not feature-focused. No new capabilities are added.
- Documentation is the largest workstream by volume — plan accordingly.
- Security audit items should produce tests that become part of the permanent CI suite.
- The CA template is what makes Kaval installable by non-technical Unraid users — it's the single most important distribution artifact.
- After Phase 4, the repo should be ready for initial community release. Phase 5+ features (image rollback, VM actions, MCP, multi-server) come after community feedback.
