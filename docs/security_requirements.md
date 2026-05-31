# Kaval Security Model & Audit Requirements

## Status

- Document type: Normative security reference (audited contract)
- PRD Baseline: v4.1 (+ CR-0002 / ADR-014 runtime, CR-0004 hardening)
- Requirements source: Phase 3/4 Requirements Expansion v2, Section 25 (Security Audit)
- Phase: Phase 4, Workstream 5 (P4-22…P4-31) plus admin/backup surfaces (P4-04, P4-05, P4-27)
- Owner: Rejo Z. Mathew

This document is the single normative reference for Kaval's security model and for the
Phase 4 security audit. It does **not** redefine the architecture; it captures the trust
boundary already established in [`README.md`](../README.md),
[CR-0002](change_requests/CR-0002-single-container-process-isolation.md), and
[ADR-014](adr/014-single-container-with-internal-process.md) as the baseline being
hardened and verified.

Each audit area below states the **threat**, the **required control**, and the
**acceptance/evidence** expectation. "Evidence" means an artifact a reviewer can point to:
a passing test in `tests/security/`, a code path, or a documented decision.

## 1. Trust boundary (baseline)

Kaval ships as **one Docker container with two internal processes** under a process
supervisor:

- **`kaval-core`** — unprivileged user `kaval`, not in the `docker` group. Handles
  discovery, monitoring, investigation, LLM integration, notifications, credentials,
  operational memory, and the API/UI surface on port `9800`. It never receives
  `docker.sock`.
- **`kaval-executor`** — user `kaval-exec` (member of the `docker` group). Listens only on
  the Unix domain socket `/run/kaval/executor.sock`. Validates HMAC approval tokens and
  executes allowlisted, approval-gated actions over `/var/run/docker.sock`. It has no UI,
  no LLM access, and no network role.

The mounted `docker.sock` is used by the executor process only. Core↔Executor transport is
a local Unix socket; the two processes genuinely share localhost.

### Deployment trust assumption (single-admin / local network)

Kaval targets a **single trusted administrator** on a **trusted home/lab LAN**. The API/UI
surface is intended to be reachable only from the local network (or via the operator's own
reverse proxy / VPN), not exposed directly to the public internet. This assumption is the
basis for the admin-surface controls in Area 6 and is recorded in
[ADR-019](adr/019-admin-api-exposure-model.md).

## 2. Audit areas

### Area 1 — LLM confinement (P4-22)

- **Threat:** A model (local or cloud) directly triggers a state-changing action, escaping
  the deterministic, human-approved execution path.
- **Required control:** The LLM is proposal-only. It produces a `RemediationProposal`
  (data) and reasoning text. It is never given action tools, and execution is performed by
  deterministic code that requires a human-approved cryptographic token.
- **Acceptance / evidence:** Tests prove the investigation/synthesis paths expose no action
  tools to the model and that proposals are inert data. See
  `tests/security/test_investigation_prompt_security.py` and the consolidated audit
  evidence in `tests/security/test_security_audit_boundaries.py`.

### Area 2 — Approval-token integrity (P4-23)

- **Threat:** An action is executed with a forged, replayed, expired, or
  wrong-incident token.
- **Required control:** Approval tokens are HMAC-SHA256 signed over a canonical payload,
  single-use, time-limited (`expires_at`), and incident-bound (`incident_id`). The executor
  re-verifies signature, expiry, single-use, and incident binding before acting. The signing
  secret (`KAVAL_APPROVAL_HMAC_SECRET`) is **strength-validated** per
  [ADR-022](adr/022-approval-secret-strength.md): `get_approval_hmac_secret` rejects the
  well-known default value and any secret shorter than 32 bytes, and `docker-compose.yml`
  ships no default value.
- **Acceptance / evidence:** Tests cover signature verification, tamper rejection, expiry,
  single-use/replay rejection, incident binding, and secret-strength validation. See
  `src/kaval/actions/approvals.py`, `src/kaval/executor/server.py`,
  `tests/security/test_executor_security.py`, and
  `tests/security/test_security_audit_boundaries.py`.

### Area 3 — Credential handling (P4-24)

- **Threat:** Secrets leak into logs, prompts, the UI, exported data, or persisted state.
- **Required control:** Credentials live in an encrypted vault. A volatile mode keeps
  secrets memory-only with a TTL. Two-level redaction (memory/journal and cloud-prompt)
  removes secret material before it can reach a log, a model prompt, or the UI.
- **Acceptance / evidence:** `src/kaval/credentials/vault.py`,
  `src/kaval/memory/redaction.py`, `tests/security/test_cloud_prompt_redaction.py`,
  `tests/security/test_credential_request_security.py`,
  `tests/security/test_vault_management_security.py`, and the backup-export sensitivity
  warning in Area 6.
- **Outbound egress control:** the model connectivity test
  (`POST /api/v1/settings/models/test`) must not become a credential-exfiltration or SSRF
  primitive. Per [ADR-021](adr/021-outbound-egress-policy.md), a shared egress guard
  (`src/kaval/api/egress.py`) rejects test destinations that resolve to loopback,
  link-local, private, unique-local, or cloud-metadata addresses unless the operator opts in
  via `KAVAL_ALLOW_PRIVATE_MODEL_EGRESS=true`, and a stored (vault-backed) secret is replayed
  only when the test `base_url` matches the currently-active endpoint.

### Area 4 — Executor isolation (P4-25)

- **Threat:** The executor accepts work over an unintended channel, runs an action outside
  the allowlist, or drifts in scope.
- **Required control:** The executor is reachable only over the Unix socket, validates the
  approval token on every request, and enforces a fixed action allowlist
  (`ALLOWED_EXECUTOR_ACTIONS`). It has no network role and no LLM access.
- **Acceptance / evidence:** `src/kaval/executor/server.py`,
  `tests/security/test_executor_security.py`, and
  `tests/security/test_security_audit_boundaries.py`.

### Area 5 — Webhook authentication (P4-26)

- **Threat:** An unauthenticated or hostile source injects findings/incidents, floods the
  receiver, or smuggles secrets through a payload.
- **Required control:** Each webhook source carries its own key, requests are rate-limited
  and size-limited, payloads are redacted before persistence, and there is no
  unauthenticated acceptance path.
- **Acceptance / evidence:** `tests/security/test_webhook_receiver_security.py`,
  `tests/security/test_telegram_ingress_security.py`, and the webhook config in
  `src/kaval/api/app.py`.

### Area 6 — Admin API exposure (P4-27, P4-04, P4-05)

- **Threat:** Sensitive admin/config/backup endpoints are reachable by an untrusted party,
  a backup export silently exfiltrates secrets, or a restore replaces the whole datastore.
- **Required control:**
  - The general admin surface (settings/config) is governed by the single-admin /
    local-network model in [ADR-019](adr/019-admin-api-exposure-model.md).
  - **Backup and restore are default-deny** per
    [ADR-020](adr/020-backup-restore-default-deny.md): `GET /api/v1/admin/backup` and
    `POST /api/v1/admin/restore` are served only when `KAVAL_ADMIN_API_KEY` is configured and
    correctly presented (`X-Kaval-Admin-Key` or `Authorization: Bearer`, constant-time
    comparison) **or** the credential vault is currently unlocked. Otherwise both return
    `403` with a remediation message.
  - `GET /api/v1/admin/backup` returns the data archive together with an explicit
    **sensitivity warning** stating the archive may contain secret material and must be
    stored securely.
  - `POST /api/v1/admin/restore` accepts only a Kaval-produced archive, caps each archive
    member's decompressed size, validates the candidate database with a SQLite
    `PRAGMA integrity_check` in a staging location, snapshots the prior `kaval.db`/`kaval.yaml`,
    and atomically swaps the validated files into place.
- **Acceptance / evidence:** `src/kaval/api/admin_backup.py`,
  `tests/security/test_admin_api_security.py`,
  `tests/integration/test_admin_backup_restore.py`,
  [ADR-019](adr/019-admin-api-exposure-model.md), and
  [ADR-020](adr/020-backup-restore-default-deny.md).

### Area 7 — Adapter safety (P4-28)

- **Threat:** A deep-inspection adapter mutates a target service's state.
- **Required control:** All shipped adapters are read-only. They issue no
  state-changing/portal-driving calls.
- **Acceptance / evidence:** Adapter modules under `src/kaval/integrations/`,
  `tests/security/test_adapter_facts_api.py`, and the read-only assertion in
  `tests/security/test_security_audit_boundaries.py`.

### Area 8 — Input validation / sanitization (P4-29)

- **Threat:** Admin-supplied input (user notes, descriptor edits, config changes) corrupts
  state, breaks rendering, or bypasses validation.
- **Required control:** Editable/admin inputs are validated by typed Pydantic models and
  sanitized for storage and display; malformed input is rejected safely.
- **Acceptance / evidence:** `src/kaval/api/schemas.py`, note/descriptor/config endpoints in
  `src/kaval/api/app.py`, and `tests/security/` input-validation coverage.

### Area 9 — Dependency audit (P4-30)

- **Threat:** A third-party Python dependency carries a known CVE.
- **Required control:** Direct dependencies are reviewed against known-vulnerability data;
  findings are remediated or explicitly accepted, and the review is recorded. Per CR-0005,
  the `cryptography` floor is `>=46.0.7,<47` to exclude `CVE-2026-26007` / `PYSEC-2026-35` /
  `PYSEC-2026-36`.
- **Acceptance / evidence:** [`docs/security/dependency-audit.md`](security/dependency-audit.md),
  refreshed at each release.

### Area 10 — Prompt-injection assessment (P4-31)

- **Threat:** Hostile content in logs/notes/webhooks subverts investigation behavior or the
  action boundary.
- **Required control:** Hostile content is treated as untrusted data. It cannot grant the
  model action tools or bypass the deterministic, token-gated execution path; redaction and
  framing limit trust breaks.
- **Acceptance / evidence:** `tests/security/test_investigation_prompt_security.py`,
  `tests/security/test_investigation_evidence_security.py`, and the prompt-injection cases
  in `tests/security/test_security_audit_boundaries.py`.

## 3. Verification commands

```bash
python -m pytest tests/unit tests/integration
python -m pytest tests/contract
python -m pytest tests/scenario tests/security
ruff check .
mypy src
cd src/web && npm run build
```

## 4. Change history

- CR-0004 — Security audit hardening: baseline this document as the audited contract; add
  backup/restore with sensitivity controls; make the admin-exposure model explicit and
  tested. See
  [`change_requests/CR-0004-security-audit-hardening.md`](change_requests/CR-0004-security-audit-hardening.md).
