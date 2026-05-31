# Change Request: CR-0005 Security remediation (admin surface, egress, approval secret)

## Metadata
- CR ID: CR-0005
- Title: Remediate the critical/high findings from the post-CR-0004 security re-assessment
- Status: Approved
- PRD Baseline: v4.1
- Phase Impacted: Phase 4 (Workstream 5 security audit P4-22…P4-31; Workstream 1 P4-04/P4-05)
- Raised On: 2026-05-31
- Raised By: Rejo Z. Mathew
- Approved By: Rejo Z. Mathew
- Implemented By: pending
- Related Tasks: P4-04, P4-05, P4-23, P4-24, P4-27, P4-30
- Related Files:
  - docs/prd.md
  - docs/security_requirements.md
  - docs/adr/019-admin-api-exposure-model.md (partially superseded)
  - docs/adr/020-backup-restore-default-deny.md (new)
  - docs/adr/021-outbound-egress-policy.md (new)
  - docs/adr/022-approval-secret-strength.md (new)
  - docs/security/dependency-audit.md
  - plans/phase-4.md
  - STATUS.md
  - src/kaval/api/app.py
  - src/kaval/api/admin_backup.py
  - src/kaval/api/egress.py (new)
  - src/kaval/actions/approvals.py
  - src/kaval/investigation/local_model.py
  - src/kaval/investigation/cloud_model.py
  - docker-compose.yml
  - .env.example
  - pyproject.toml
  - tests/security/
  - tests/integration/

## Problem Statement
The post-CR-0004 security re-assessment confirmed that CR-0004 delivered governance and a
backup/restore surface, but it did not close the highest-severity runtime findings, and the
new backup/restore surface introduced fresh critical/high exposure under its documented
default configuration. Specifically:

1. **N1 (Critical) — `POST /api/v1/admin/restore` is a default-open remote-takeover
   primitive.** With `KAVAL_ADMIN_API_KEY` unset (the documented default),
   `authorize_admin_request` returns immediately, and `restore_backup_archive` overwrites the
   live `kaval.db` and `kaval.yaml` with attacker-supplied bytes, gated only by a public
   manifest marker. An attacker who can reach port `9800` can replace the entire datastore
   (including a vault config whose passphrase they chose) in a single HTTP POST.
2. **N2 (High) — `GET /api/v1/admin/backup` is a default-open bulk export** of the encrypted
   vault and all secrets-at-rest, downloadable anonymously on the LAN default.
3. **N3 (Medium) — restore performs no integrity validation** of the supplied database, no
   size cap on archive members, and no rollback of the prior datastore before overwrite.
4. **A2 (Critical, pre-existing) — SSRF + cloud-key exfiltration via `/settings/models` →
   `/settings/models/test`.** A caller-controlled `base_url` plus a vault-decrypted API key
   sent to that URL allows exfiltration of stored model credentials and probing of internal
   addresses.
5. **A3 (Critical, pre-existing) — the approval-token HMAC secret has a well-known default**
   (`local-dev-approval-secret`) shipped in `docker-compose.yml`, and startup performs no
   strength validation. Forged approval tokens enable unauthenticated executor actions.
6. **N4 (Medium) — the dependency-audit artifact marks `cryptography >=44,<47` "clean"**
   despite a published advisory affecting versions in that range (fixed in 46.0.7; PYSEC-2026-35/36, CVE-2026-26007).

## Baseline PRD Position
PRD v4.1 plus CR-0002/ADR-014 establish an unprivileged Core, an Executor-only `docker.sock`,
HMAC-signed single-use approval tokens, an encrypted vault with two-level redaction, and
authenticated webhook ingestion. CR-0004/ADR-019 added an optional admin-key control and the
backup/restore surface, recording a "single-admin / trusted LAN" assumption. Phase 4 requires
the audit to pass with **no open critical or high findings** before release.

## Observed Implementation Gap
ADR-019's "default behavior unchanged when `KAVAL_ADMIN_API_KEY` is unset" is acceptable for
reads and for routes an operator at a keyboard would also issue, but it is **not** acceptable
for whole-datastore replacement (`/admin/restore`) or anonymous bulk secret export
(`/admin/backup`). Separately, the model connectivity test still sends stored secrets to a
caller-controlled URL, and the approval secret accepts the shipped default with no guard.
These leave critical/high findings open, so P4-23/P4-24/P4-27 cannot be marked complete.

## Decision
1. **Backup/restore default-deny (ADR-020).** `GET /api/v1/admin/backup` and
   `POST /api/v1/admin/restore` are refused unless an explicit operator authorization is
   present: either `KAVAL_ADMIN_API_KEY` is configured and correctly presented, **or** the
   credential vault is currently unlocked. When neither holds, both endpoints return `403`
   with a clear remediation message. This partially supersedes ADR-019 for these two routes
   only; all other admin routes retain the ADR-019 model.
2. **Restore safety (ADR-020).** Restore validates the supplied database with a SQLite
   `PRAGMA integrity_check` in a staging location, caps the decompressed size of every
   archive member, snapshots the prior `kaval.db`/`kaval.yaml` to timestamped siblings, and
   only then atomically swaps them into place. Malformed input is rejected without destroying
   existing state.
3. **Outbound egress policy (ADR-021).** A shared egress guard rejects outbound model
   connectivity tests whose resolved destination is loopback, link-local, private, or
   cloud-metadata, unless the operator has explicitly opted in. A connectivity test that
   would reuse a stored (vault-backed) secret against a `base_url` different from the
   currently-active one is rejected; the operator must re-enter the key for a new endpoint.
4. **Approval-secret strength (ADR-022).** `get_approval_hmac_secret` rejects the well-known
   default value and any secret shorter than 32 bytes. The shipped `docker-compose.yml`
   no longer provides a default value; `.env.example` documents the requirement.
5. **Dependency floor (CR-0005).** Raise the `cryptography` floor to `>=46.0.7,<47` and
   correct `docs/security/dependency-audit.md` to reflect the advisory and the new floor.

## Rationale
This is the smallest set of changes that closes the open critical/high findings without
redesigning the trust boundary. Default-deny on exactly the two whole-datastore routes keeps
the zero-config first-run experience for everything else while removing the takeover/export
primitives. Reusing the existing vault-unlocked state as an authorization signal avoids adding
a new auth system and matches the operator's existing mental model (the vault must be unlocked
to do sensitive work). The egress guard and approval-secret guard are localized, additive, and
follow patterns already in the code (`secrets.compare_digest`, env-driven config). A floor
bump is the standard remediation for a dependency advisory.

## Scope of Change
This CR changes:
- **Docs:** new ADR-020, ADR-021, ADR-022; updates to `docs/security_requirements.md`
  (Area 6 control text + Area 9 floor), `docs/security/dependency-audit.md`, ADR-019
  (supersession note), `plans/phase-4.md`, `STATUS.md`, README cross-links.
- **Code:** default-deny + restore safety in `src/kaval/api/admin_backup.py` and the
  admin routes in `src/kaval/api/app.py`; a new `src/kaval/api/egress.py` guard wired into
  the model-test route and the local/cloud probe paths; approval-secret validation in
  `src/kaval/actions/approvals.py`; removal of the compose default; `cryptography` floor in
  `pyproject.toml`.
- **Tests:** additive `tests/security/` and `tests/integration/` coverage.

This CR does **not** change:
- The Core/Executor trust boundary, the approval-token canonical payload, the LLM-confinement
  model, the executor allowlist, the vault encryption scheme, or webhook auth.
- The ADR-019 model for admin routes other than `/admin/backup` and `/admin/restore`.
- Any frozen Phase 0 interface contract or data model.

## Implementation Instructions
1. Add ADR-020, ADR-021, ADR-022; add the supersession note to ADR-019.
2. Implement default-deny + restore safety in `admin_backup.py`; wire the new authorization
   signal (admin key OR unlocked vault) into the two admin routes in `app.py`.
3. Implement `src/kaval/api/egress.py` and apply it in the model-test route and the
   local/cloud probe helpers; reject stored-secret reuse against a changed `base_url`.
4. Implement approval-secret strength validation; remove the compose default; update
   `.env.example`.
5. Bump the `cryptography` floor and correct the dependency-audit artifact.
6. Add security/integration tests for each control.
7. Cross-link docs; update `plans/phase-4.md` and `STATUS.md`.
8. Run all validation commands. Stop on a new contradiction.

## Impact Assessment
- Frozen interface impact: **none** — changes are additive guards on existing additive
  endpoints; no schema or approval-token-payload change.
- Security impact: **net positive** — closes N1, N2, N3, A2, A3, N4; weakens no control.
- Test impact: additive security and integration tests become part of CI.
- Documentation impact: three new ADRs; security contract and dependency artifact updated.
- Behavioral change: `/admin/backup` and `/admin/restore` now require admin key or an
  unlocked vault; deployments relying on anonymous backup/restore must unlock the vault or
  set `KAVAL_ADMIN_API_KEY`. The approval secret must now be a real 32+ byte secret.

## Acceptance Criteria
- [ ] ADR-020, ADR-021, ADR-022 added; ADR-019 supersession note added
- [ ] `/admin/backup` and `/admin/restore` refuse without admin key or unlocked vault
- [ ] Restore validates DB integrity, caps member size, and snapshots prior state before swap
- [ ] Model-test egress guard rejects internal destinations and stored-key reuse on a changed base URL
- [ ] Approval secret rejects the well-known default and secrets shorter than 32 bytes
- [ ] Compose no longer ships a default approval secret; `.env.example` updated
- [ ] `cryptography` floor raised to `>=46.0.7,<47`; dependency-audit artifact corrected
- [ ] Additive security and integration tests pass
- [ ] Validation commands pass: pytest, ruff, mypy, web build
- [ ] STATUS.md and plans/phase-4.md updated

## Supersession / Roll-up
- Superseded By: none
- Roll into future PRD version: yes
- Notes: Partially supersedes ADR-019 for the backup/restore routes only. Roll into the
  consolidated v5 PRD alongside CR-0001, CR-0002, and CR-0004.
