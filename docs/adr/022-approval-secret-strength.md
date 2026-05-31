# ADR-022: Approval-token secret strength validation

## Status: Accepted
## Date: 2026-05-31
## Related: CR-0005 (Security remediation), ADR-010 (three-tier action model), docs/security_requirements.md

## Context
Approval tokens authorize the executor to perform allowlisted, state-changing actions. They
are HMAC-SHA256 signed over a canonical payload using `KAVAL_APPROVAL_HMAC_SECRET`
(`src/kaval/actions/approvals.py`). The integrity of every executor action therefore depends
entirely on the secrecy and strength of this secret.

The re-assessment found two weaknesses:

1. `docker-compose.yml` shipped a **well-known default** value,
   `local-dev-approval-secret`, substituted whenever the operator did not supply one. Anyone
   who knows this public string can forge valid approval tokens and drive the executor.
2. `get_approval_hmac_secret` validated only that the secret was **non-empty**. A short or
   default secret passed silently.

## Decision
1. **Reject the well-known default and weak secrets at the point of use.**
   `get_approval_hmac_secret` raises a clear `RuntimeError` when the configured secret:
   - equals the known-bad default `local-dev-approval-secret`, or
   - is shorter than 32 bytes (UTF-8 encoded).

   The error message instructs the operator to set a strong random
   `KAVAL_APPROVAL_HMAC_SECRET` (e.g. `openssl rand -hex 32`).
2. **Remove the default from `docker-compose.yml`.** The variable is referenced without a
   `:-default` fallback so a missing secret fails fast rather than silently using a public
   value. `.env.example` documents the requirement and a generation command.

## Rationale
- The secret is a single point of trust for the entire action boundary; a guessable default
  defeats the approval-token model entirely.
- Validating at the existing single accessor (`get_approval_hmac_secret`) is the smallest
  correct enforcement point and covers every signing/verification path.
- A 32-byte floor matches the HMAC-SHA256 block/key sizing and is trivial to satisfy with
  standard tooling.

## What changes
- `src/kaval/actions/approvals.py`: strength validation in `get_approval_hmac_secret`.
- `docker-compose.yml`: remove the default value.
- `.env.example`: document the requirement and a generation command.

## What does NOT change
- The approval-token canonical payload, signing algorithm, single-use/expiry/incident-binding
  semantics, or the executor allowlist.

## Consequences
- Gained: forged-token attacks via the shipped default are closed; weak secrets are rejected.
- Accepted: deployments that relied on the default secret must now set a real one before the
  approval/execution path will function. This is an intentional, documented breaking change
  for the `Operate` profile.
