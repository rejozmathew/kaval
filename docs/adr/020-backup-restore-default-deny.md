# ADR-020: Backup/restore default-deny and restore safety

## Status: Accepted
## Date: 2026-05-31
## Related: CR-0005 (Security remediation), ADR-019 (partially superseded), docs/security_requirements.md

## Context
ADR-019 introduced an optional admin-API key (`KAVAL_ADMIN_API_KEY`) and recorded a
"single-admin / trusted LAN" model in which the admin surface stays reachable when no key is
configured. CR-0004 added `GET /api/v1/admin/backup` and `POST /api/v1/admin/restore` under
that model.

The post-CR-0004 re-assessment found that the "default-open" stance is unsafe for these two
specific routes:

- `POST /api/v1/admin/restore` overwrites the live `kaval.db` and `kaval.yaml` with
  attacker-supplied bytes, gated only by a public manifest marker. This is a single-request
  whole-datastore takeover: an attacker can install a database carrying a vault config whose
  passphrase they chose, then unlock it and pivot.
- `GET /api/v1/admin/backup` returns the live database (encrypted vault rows, the Argon2id
  verifier ciphertext, all descriptors/notes/memory) to any anonymous caller on the LAN.

Restore additionally performed no integrity validation, no member-size cap, and no rollback,
so a malformed upload could destroy a working datastore with no recovery path.

The "trusted LAN" assumption is a reasonable baseline for reads and for routine mutating
routes an operator would also issue, but it is not proportionate for whole-datastore
replacement or anonymous bulk secret export.

## Decision
1. **Default-deny for backup and restore.** `GET /api/v1/admin/backup` and
   `POST /api/v1/admin/restore` are served only when an explicit operator authorization is
   present:
   - `KAVAL_ADMIN_API_KEY` is configured and correctly presented
     (`X-Kaval-Admin-Key` or `Authorization: Bearer`, constant-time comparison); **or**
   - the credential vault is currently unlocked (proof the operator has performed a
     deliberate, authenticated unlock in this session).

   When neither holds, both endpoints return `403` with a remediation message instructing the
   operator to unlock the vault or configure `KAVAL_ADMIN_API_KEY`. The admin-key check, when
   a key is configured, still takes precedence and yields `401`/`403` exactly as today.
2. **Restore safety.** Restore:
   - caps the decompressed size of every archive member (rejecting oversized/zip-bomb
     members) before reading it;
   - writes the candidate database to a staging path and runs SQLite
     `PRAGMA integrity_check`, rejecting the upload on failure;
   - snapshots the current `kaval.db` and `kaval.yaml` to timestamped sibling files;
   - atomically swaps the validated files into place via `os.replace`.
   Only the two known member names are ever written (unchanged path-traversal protection).
3. **Backup** continues to emit the explicit sensitivity warning header and body field.

## Rationale
- Reusing "vault unlocked" as an authorization signal avoids inventing a new auth system,
  matches the operator's existing mental model, and means a fresh attacker who has not
  unlocked the vault cannot export or replace the datastore.
- Keeping `KAVAL_ADMIN_API_KEY` as an alternative preserves the reverse-proxy/automation path
  for operators who run with a configured key and a locked vault.
- Staging + integrity-check + snapshot is the smallest correct way to make restore safe
  against malformed or hostile archives without a full transactional import layer.

## What changes
- `src/kaval/api/admin_backup.py`: a default-deny authorization helper and restore-safety
  logic (size cap, integrity check, snapshot, atomic swap).
- `src/kaval/api/app.py`: the two admin routes pass the unlocked-vault signal into the
  authorizer.
- `docs/security_requirements.md` Area 6 updated to describe default-deny.

## What does NOT change
- The ADR-019 model for all admin routes other than `/admin/backup` and `/admin/restore`.
- The backup archive format, manifest marker, or path-traversal protection.
- The trust boundary, approval-token contract, vault scheme, or webhook auth.

## Consequences
- Gained: the takeover (restore) and anonymous-export (backup) primitives are closed by
  default; restore can no longer destroy a working datastore on malformed input.
- Accepted: operators who relied on anonymous backup/restore must now unlock the vault or set
  `KAVAL_ADMIN_API_KEY`. This is an intentional, documented behavioral change.

## Supersession
- Partially supersedes ADR-019 for the `/admin/backup` and `/admin/restore` routes only.
