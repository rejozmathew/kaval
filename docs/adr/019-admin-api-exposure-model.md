# ADR-019: Admin API exposure model (single-admin / local network)

## Status: Accepted (partially superseded by ADR-020 for backup/restore)
## Date: 2026-05-31
## Related: CR-0004 (Security audit hardening), CR-0005 (Security remediation), ADR-020 (partially supersedes), docs/security_requirements.md

> **Supersession note (CR-0005 / ADR-020):** The "default behavior unchanged when
> `KAVAL_ADMIN_API_KEY` is unset" stance below is **no longer in effect for the
> `GET /api/v1/admin/backup` and `POST /api/v1/admin/restore` routes**. Those two routes are
> now default-deny (admin key OR unlocked vault required) per
> [ADR-020](020-backup-restore-default-deny.md). The single-admin / local-network model
> below still governs all other admin routes.

## Context
Phase 4 Workstream 5 (P4-27) requires the admin/config surface — settings, configuration,
and the new backup/restore endpoints (P4-04/P4-05) — to be appropriately constrained.

Kaval targets a **single trusted administrator** running on a **trusted home/lab LAN**. The
API/UI on port `9800` is meant to be reached from the local network (or via the operator's
own reverse proxy / VPN), not exposed directly to the public internet. Today the webhook and
widget endpoints carry explicit auth, but the broader admin surface relies on this
deployment assumption without recording it or enforcing it in code, and there is no test
that exercises an admin-key control.

Backup is additionally sensitive: a backup archive can contain secret material (vault
contents, settings, credentials), so exporting it must carry an explicit warning, and both
backup and restore should be guardable.

## Decision
1. Record the single-admin / local-network deployment model as the baseline trust
   assumption for the admin surface. Operators are responsible for not exposing port `9800`
   directly to untrusted networks.
2. Add an **optional** admin API key control, configured via `KAVAL_ADMIN_API_KEY`. When
   set, the admin/backup/restore endpoints require the key, presented as `X-Kaval-Admin-Key`
   or a bearer token, compared with a constant-time comparison. When unset,
   behavior is unchanged (consistent with the documented LAN default).
3. The backup endpoint returns an explicit **sensitivity warning** alongside the archive.
   The restore endpoint validates the archive shape before applying it.

This mirrors the existing widget-auth convention (`_authorize_widget_request`), keeping the
codebase consistent and avoiding a breaking change for existing single-admin deployments.

## Rationale
- The homelab threat model is "single trusted admin on a trusted LAN," not a multi-tenant
  public service. A mandatory auth system would be disproportionate and would break the
  zero-config first-run experience.
- Making the key optional but enforced-when-set gives security-conscious operators (and
  reverse-proxy/VPN setups) a real control without changing the default.
- Constant-time comparison avoids timing side channels, matching the widget/Telegram
  patterns already in the code.
- A sensitivity warning on backup is the smallest correct control for a security-sensitive
  export.

## What changes
- New optional env var `KAVAL_ADMIN_API_KEY`.
- New `src/kaval/api/admin_backup.py` with the authorizer and backup/restore endpoints.
- `docs/security_requirements.md` Area 6 documents the model.

## What does NOT change
- Default behavior when `KAVAL_ADMIN_API_KEY` is unset.
- The trust boundary, approval-token contract, vault/redaction model, or webhook auth.
- Any frozen Phase 0 interface contract or data model.

## Consequences
- Gained: explicit, documented, testable admin-exposure model; a security-sensitive
  backup/restore surface with a sensitivity warning and an optional guard.
- Accepted: with no admin key configured, the admin surface remains reachable from the LAN,
  which is the intended single-admin model. Operators must keep port `9800` off untrusted
  networks.
