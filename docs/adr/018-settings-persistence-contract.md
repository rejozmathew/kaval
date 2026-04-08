# ADR-018: Settings persistence contract for admin-editable configuration

## Status: Accepted
## Date: 2026-04-08

## Context

P3C-14 (Settings: model configuration) is blocked because the current repo
still loads model and cloud-escalation settings directly from environment
variables, but does not yet define an approved persistence and apply contract
for admin-editable settings.

The repo already has:
- env-based local/cloud model configuration loaders
- an encrypted vault for secret material
- DB-backed runtime, audit, and operational state

What it does not yet have is a stable contract for:
- where non-secret admin settings live
- where secret settings live
- which settings belong in the DB instead of a config file
- how settings changes are validated and applied at runtime

Without that contract, each Phase 3C settings task would invent its own
storage and reload behavior.

## Decision

Adopt a hybrid settings persistence model.

### Canonical persistence locations

- Global non-secret admin settings are stored in a YAML file at `/data/kaval.yaml`.
- Secret values are never stored in `kaval.yaml`; they remain in the existing
  encrypted vault.
- DB-backed persistence remains authoritative for stateful runtime records,
  audit history, and entity-scoped operational overrides.
- Environment variables remain bootstrap/default inputs and path overrides,
  not the primary operator-editable settings surface once persisted settings
  exist.

### Configuration precedence

For global non-secret settings, configuration resolves in this order:

1. built-in code defaults
2. environment bootstrap / path overrides
3. persisted `/data/kaval.yaml`

For entity-scoped operational controls, DB-backed overrides apply on top of the
global settings model where the feature explicitly supports them.

Environment variables are authoritative only for:
- startup bootstrap before persisted settings exist
- explicit config-path selection
- deploy-time overrides intentionally chosen by the operator

They are not the normal save target for Phase 3C admin UI/API settings changes.

### YAML scope

`/data/kaval.yaml` is the canonical persisted store for global non-secret admin
configuration, including examples such as:
- local model enablement, endpoint, model name, timeout
- cloud provider selection, endpoint, model name, timeout
- escalation thresholds and non-secret cost controls
- notification channel metadata and routing policy excluding secret tokens
- global monitoring defaults and other system-wide feature settings
- non-secret vault/system settings metadata

### Vault scope

The vault remains the canonical store for secret material, including examples
such as:
- cloud API keys
- Telegram bot token
- notification channel credentials
- webhook shared secrets
- future provider credentials

`kaval.yaml` may store only stable secret references such as:
- `api_key_ref`
- `bot_token_ref`
- `secret_ref`

The settings layer resolves those references through the vault at runtime.

### DB scope

The DB remains the canonical store for stateful and entity-scoped operational
records, including examples such as:
- per-service suppressions
- maintenance windows
- per-service or per-check operational overrides
- audit trail entries
- pending queues and other mutable runtime state

The DB is not the canonical store for global model/provider/admin settings.

### Apply and reload semantics

Settings changes must use explicit deterministic apply semantics:

- Save validates and persists settings to the correct backend (`kaval.yaml`,
  vault, or DB).
- Core applies settings only through an explicit reload/apply path.
- No background file watcher or implicit hot reload is introduced.
- Reload-safe changes take effect in-process at the next safe boundary.
- In-flight work may continue under the previous configuration until that
  boundary is reached.
- Changes that are not reload-safe must be surfaced explicitly as requiring
  restart or deferred apply support.
- Secret values are never returned in API/UI responses; only reference and
  status metadata may be surfaced.

## Rationale

- A file-backed non-secret config gives operators one readable, exportable,
  reviewable admin configuration surface.
- Keeping secrets in the vault preserves the current Phase 2B security model
  and avoids leaking credentials into YAML, logs, backups, or git-managed files.
- Keeping entity-scoped mutable operational controls in the DB fits the
  existing audited runtime model and avoids overloading one global config file
  with transient operational state.
- Explicit apply semantics are safer and easier to debug than silent live
  mutation or file-watch reload behavior.
- This unblocks the Phase 3C settings tranche on one shared contract instead
  of forcing each task to invent storage rules independently.

## What changes

- ADR-018 becomes the authoritative settings persistence contract.
- Kaval gains a canonical persisted config path at `/data/kaval.yaml`.
- Future Phase 3C settings APIs/UI must write through this contract instead of
  inventing task-local persistence.
- A typed settings loader/service should merge defaults, env bootstrap,
  persisted YAML, vault references, and DB-backed operational overrides using
  the approved precedence rules.

## What does NOT change

- Core↔Executor trust boundary
- Executor allowlist and action scope
- Vault encryption-at-rest model
- Existing DB-backed incident, finding, investigation, memory, approval,
  webhook, and audit records
- The single-admin v1 assumption
- The rule that settings/admin flows are deterministic UI/API operations and
  never LLM-driven

## Consequences

- Gained: one clear operator-editable config surface for global non-secret settings
- Gained: secret handling stays consistent with the existing vault model
- Gained: later Phase 3C settings tasks can build on one shared contract
- Gained: settings behavior becomes more explicit, auditable, and explainable
- Accepted tradeoff: persistence is now intentionally split across YAML, vault,
  and DB, so those boundaries must stay explicit in code and docs
- Accepted tradeoff: explicit apply/reload is slightly more work than silent
  hot reload, but safer for a homelab admin product
- Risk accepted: manual edits to `kaval.yaml` outside the UI/API can create
  invalid state; mitigated by schema validation on load and explicit reload/apply
  error reporting