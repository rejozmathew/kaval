# ADR-013: Memory Trust Model and Prompt Redaction

- Status: Accepted
- Date: 2026-03-31

## Context

Operational Memory can contain stale advice, speculative conclusions, internal host details, and accidentally pasted secrets. Kaval must treat memory as useful but not automatically trustworthy, and it must prevent sensitive content from leaking into prompts, logs, or outputs.

## Decision

Kaval will apply both trust filtering and mandatory redaction before Operational Memory content reaches any model prompt. The redaction policy has two levels:

- local-safe redaction for local OpenAI-compatible model endpoints
- cloud-safe redaction for remote model APIs, which removes additional operational intelligence

Entries marked unsafe for model use are excluded entirely.

## Consequences

- Memory queries must preserve metadata needed for trust filtering and stale-entry handling.
- Prompt construction depends on a required redaction component rather than best-effort caller behavior.
- Cloud prompts are more aggressively sanitized than local prompts.
- Memory exports and logs must be treated as security-sensitive artifacts.
