# ADR-021: Outbound HTTP egress policy for model connectivity tests

## Status: Accepted
## Date: 2026-05-31
## Related: CR-0005 (Security remediation), docs/security_requirements.md

## Context
The model-settings surface lets an operator configure a local or cloud model `base_url` and an
API key, and offers an explicit connectivity test (`POST /api/v1/settings/models/test`). The
test builds a model config and performs an outbound HTTP request to the configured `base_url`,
sending the (vault-decrypted, when vault-backed) API key in the request headers
(`Authorization: ****** or `x-api-key`).

The re-assessment found two problems with this flow:

1. **Credential exfiltration.** Because `base_url` is operator-supplied and the stored key is
   sent to it, a request that changes `base_url` to an attacker host and then triggers a test
   exfiltrates the stored model key to that host.
2. **SSRF.** A `base_url` pointing at `http://127.0.0.1:…`, a private RFC-1918 address, a
   link-local address, or the cloud metadata endpoint (`169.254.169.254`) turns the test into
   a server-side request forgery probe against internal infrastructure.

Both are reachable on the API surface. Even once the admin surface is otherwise constrained,
the connectivity test should not be an egress/exfiltration primitive.

## Decision
1. **Egress destination guard.** Introduce a shared `src/kaval/api/egress.py` helper that
   classifies a target URL's resolved host and rejects connectivity tests whose destination
   is loopback, link-local, private, unique-local, or a cloud-metadata address, unless the
   operator has explicitly opted in via `KAVAL_ALLOW_PRIVATE_MODEL_EGRESS=true`.
   - The opt-in exists because a self-hosted local model (e.g. Ollama on
     `http://localhost:11434`) is a legitimate private destination. The opt-in is scoped to
     the connectivity-test egress decision and defaults to disabled for cloud targets.
   - Local-model tests against the configured local base URL remain allowed; the guard
     applies the private-destination rule with the local opt-in in mind so the default
     local-model workflow is preserved.
2. **No stored-secret reuse on a changed endpoint.** A connectivity test that would reuse a
   stored (vault-backed) secret is permitted only when the test target's `base_url` matches
   the currently-active `base_url` for that scope. When the operator is testing a new or
   changed endpoint, they must provide the API key in the test request rather than have the
   server replay the stored secret to an unverified host.

## Rationale
- Blocking private/metadata destinations is the standard SSRF mitigation and is the smallest
  correct control for an outbound test path.
- Pinning stored-secret reuse to the active endpoint prevents the "change URL, then test"
  exfiltration sequence while keeping the legitimate "test my already-configured endpoint"
  workflow working with zero extra operator steps.
- A single shared egress helper keeps the policy consistent and testable, and gives future
  outbound paths (adapters, external APIs) one place to adopt the same rule.

## What changes
- New `src/kaval/api/egress.py` with the destination classifier and decision function.
- `src/kaval/api/app.py` model-test route applies the guard and the stored-secret-reuse rule.
- `src/kaval/investigation/local_model.py` / `cloud_model.py` probe helpers accept the guard
  decision (the route remains the enforcement point).
- New `KAVAL_ALLOW_PRIVATE_MODEL_EGRESS` env flag, documented in `.env.example`.

## What does NOT change
- The model-config schema, the staged/apply settings contract (ADR-018), or the vault scheme.
- The investigation runtime paths that call configured models during real incidents (those
  use operator-configured, already-active endpoints; this ADR governs the explicit test
  surface). A follow-up may extend the same guard to all outbound paths.

## Consequences
- Gained: the connectivity test is no longer an SSRF or key-exfiltration primitive.
- Accepted: operators testing a brand-new private endpoint must either set
  `KAVAL_ALLOW_PRIVATE_MODEL_EGRESS=true` or supply the key inline for the test.
