# Change Request: CR-0004 Security audit hardening

## Metadata
- CR ID: CR-0004
- Title: Baseline the security model as an audited contract; add backup/restore with sensitivity controls; make the admin-exposure model explicit and tested
- Status: Approved
- PRD Baseline: v4.1
- Phase Impacted: Phase 4 (Workstream 5 security audit P4-22…P4-31; Workstream 1 P4-04/P4-05)
- Raised On: 2026-05-31
- Raised By: Rejo Z. Mathew
- Approved By: Rejo Z. Mathew
- Implemented By: pending
- Related Tasks: P4-04, P4-05, P4-22, P4-23, P4-24, P4-25, P4-26, P4-27, P4-28, P4-29, P4-30, P4-31
- Related Files:
  - docs/prd.md
  - docs/security_requirements.md (new)
  - docs/adr/019-admin-api-exposure-model.md (new)
  - docs/security/dependency-audit.md (new)
  - plans/phase-4.md
  - STATUS.md
  - src/kaval/api/app.py
  - src/kaval/api/admin_backup.py (new)
  - tests/security/
  - tests/integration/

## Problem Statement
Phase 4 Workstream 5 enumerates ten security-audit areas (P4-22…P4-31) anchored to the
Phase 3/4 Requirements Expansion v2, Section 25. Those areas describe controls that are
mostly already implemented in code, but they are **not baselined as a single audited
contract**, and three concrete gaps remain:

1. **No consolidated security reference.** The required controls and their acceptance
   evidence are scattered across README, CRs, ADRs, and tests. There is no single normative
   document a reviewer can audit against.
2. **Backup/restore endpoints absent.** P4-04/P4-05 require `GET /api/v1/admin/backup` and
   `POST /api/v1/admin/restore`. Neither exists yet, and backup is security-sensitive
   (the archive can contain secret material).
3. **Admin-exposure model implicit.** The admin/config surface relies on an undocumented
   "local-network single-admin" assumption. Webhook and widget endpoints have explicit auth;
   the broader admin surface does not, and the assumption is not recorded as a decision or
   exercised by a test.

## Baseline PRD Position
PRD v4.1 plus CR-0002/ADR-014 establish the trust boundary: unprivileged Core with no
`docker.sock`, an Executor-only `docker.sock`, HMAC-signed single-use approval tokens, an
encrypted credential vault with two-level redaction, authenticated webhook ingestion, and
read-only adapters. Phase 4 requires this boundary to be **verified by audit** and to pass
"no open critical or high findings" before release.

## Observed Implementation Gap
The controls exist, but the audit cannot be completed because there is no contract document
to audit against, the security-sensitive backup/restore surface is missing, and the
admin-exposure assumption is neither documented nor tested. Without these, P4-22…P4-31
cannot be marked complete with reviewable evidence.

## Decision
1. Adopt [`docs/security_requirements.md`](../security_requirements.md) as the normative,
   audited security contract. It maps each area (P4-22…P4-31) to a threat, a required
   control, and acceptance/evidence.
2. Implement `GET /api/v1/admin/backup` and `POST /api/v1/admin/restore`. The backup
   response carries an explicit sensitivity warning; restore validates the archive shape
   before applying it.
3. Make the admin-exposure model explicit and enforceable: record it in
   [ADR-019](../adr/019-admin-api-exposure-model.md), and add an **optional**
   `KAVAL_ADMIN_API_KEY` control (constant-time comparison, `X-Kaval-Admin-Key` or bearer
   token) that, when configured, guards the admin/backup/restore surface. This mirrors the
   existing widget-auth pattern so default behavior is preserved when no key is set.
4. Record the dependency audit (P4-30) in
   [`docs/security/dependency-audit.md`](../security/dependency-audit.md).
5. Add additive security tests that lock in the boundary areas (LLM confinement, approval
   tokens, executor isolation, adapter read-only, prompt injection) so the audit evidence
   becomes part of the permanent CI suite.

## Rationale
This is the smallest change that lets Phase 4's security audit be completed with reviewable
evidence. It documents and verifies existing controls rather than redesigning them, adds the
one missing security-sensitive surface (backup/restore) required by P4-04/P4-05, and makes
the admin-exposure assumption explicit without changing default behavior for existing
deployments. Making the admin key optional (enforced only when configured) follows the
established widget-auth convention and avoids breaking the single-admin LAN default.

## Scope of Change
This CR changes:
- **Docs:** new `docs/security_requirements.md`, new ADR-019, new
  `docs/security/dependency-audit.md`; cross-links from README, plans/phase-4.md, STATUS.md.
- **Code:** new `src/kaval/api/admin_backup.py` (backup/restore + admin-key guard) wired
  into the existing `/api/v1` router with minimal edits to `src/kaval/api/app.py`.
- **Tests:** additive `tests/security/` audit-boundary coverage and admin-surface tests;
  `tests/integration/` backup/restore round-trip.

This CR does **not** change:
- The trust boundary, the approval-token contract, the LLM confinement model, the executor
  allowlist, the vault/redaction model, or webhook auth.
- Default behavior when `KAVAL_ADMIN_API_KEY` is unset (admin endpoints remain reachable as
  today, consistent with the documented single-admin LAN model).
- Any frozen Phase 0 interface contract or data model.

## Implementation Instructions
1. Add `docs/security_requirements.md` baselining the ten audit areas.
2. Add `docs/adr/019-admin-api-exposure-model.md` recording the single-admin/local-network
   decision and the backup-sensitivity stance.
3. Add `docs/security/dependency-audit.md` capturing the P4-30 review.
4. Implement `src/kaval/api/admin_backup.py`: an optional admin-key authorizer plus
   `GET /api/v1/admin/backup` (archive + sensitivity warning) and
   `POST /api/v1/admin/restore` (validated archive apply). Wire it into the API.
5. Add security/integration tests for the boundary areas, the admin-key guard, and the
   backup/restore round-trip.
6. Cross-link the new docs from README, plans/phase-4.md, and STATUS.md.
7. Run all validation commands. Stop on a new contradiction.

## Impact Assessment
- Frozen interface impact: **none** — new endpoints are additive; existing schemas and the
  approval-token contract are unchanged.
- Security impact: **net positive** — adds the missing security-sensitive backup/restore
  surface with a sensitivity warning and an optional admin-key control; documents and
  verifies existing boundaries. No control is weakened.
- Test impact: additive security and integration tests become part of CI.
- Documentation impact: new security contract, ADR, and dependency-audit artifact;
  cross-links updated.

## Acceptance Criteria
- [ ] `docs/security_requirements.md` added and cross-linked
- [ ] ADR-019 added
- [ ] `docs/security/dependency-audit.md` added
- [ ] Backup/restore endpoints implemented with sensitivity warning
- [ ] Optional `KAVAL_ADMIN_API_KEY` guard enforced when configured (constant-time compare)
- [ ] Additive security audit tests pass
- [ ] Backup/restore round-trip integration test passes
- [ ] Validation commands pass: pytest, ruff, mypy, web build
- [ ] STATUS.md and plans/phase-4.md updated

## Supersession / Roll-up
- Superseded By: none
- Roll into future PRD version: yes
- Notes: Roll into the consolidated v5 PRD alongside CR-0001 and CR-0002.
  `docs/security_requirements.md` is the authoritative security contract until then.
