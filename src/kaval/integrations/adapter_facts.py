"""Prompt-safe serialization helpers for adapter-derived facts."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from pydantic import Field

from kaval.integrations.service_adapters import AdapterResult, AdapterStatus
from kaval.memory.redaction import (
    CloudRedactionReplacement,
    StructuredRedactionPolicy,
    redact_json_value,
)
from kaval.models import JsonValue, KavalModel, RedactionLevel

_DEFAULT_EXCLUDED_ADAPTER_FACT_KEYS = (
    "access_token",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "passwd",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "session",
    "set_cookie",
    "token",
)


class PromptSafeAdapterFact(KavalModel):
    """One adapter result serialized safely for model-facing prompt sections."""

    adapter_id: str = Field(min_length=1)
    status: AdapterStatus
    timestamp: datetime
    applied_redaction_level: RedactionLevel
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    excluded_paths: list[str] = Field(default_factory=list)
    reason: str | None = None


def default_adapter_fact_redaction_policy() -> StructuredRedactionPolicy:
    """Return the baseline exclusion policy for adapter-derived prompt facts."""
    return StructuredRedactionPolicy(
        excluded_keys=_DEFAULT_EXCLUDED_ADAPTER_FACT_KEYS,
    )


def redact_adapter_result_for_prompt(
    result: AdapterResult,
    *,
    redaction_level: RedactionLevel,
    cloud_replacements: Sequence[CloudRedactionReplacement] = (),
    policy: StructuredRedactionPolicy | None = None,
) -> PromptSafeAdapterFact:
    """Redact one adapter result into a prompt-safe structured payload."""
    effective_policy = policy or default_adapter_fact_redaction_policy()
    redacted = redact_json_value(
        result.facts,
        redaction_level=redaction_level,
        cloud_replacements=cloud_replacements,
        policy=effective_policy,
    )
    return PromptSafeAdapterFact(
        adapter_id=result.adapter_id,
        status=result.status,
        timestamp=result.timestamp,
        applied_redaction_level=redacted.applied_redaction_level,
        facts=redacted.redacted_value if isinstance(redacted.redacted_value, dict) else {},
        excluded_paths=redacted.excluded_paths,
        reason=result.reason,
    )


def redact_adapter_results_for_prompt(
    results: Sequence[AdapterResult],
    *,
    redaction_level: RedactionLevel,
    cloud_replacements: Sequence[CloudRedactionReplacement] = (),
    policy: StructuredRedactionPolicy | None = None,
) -> list[PromptSafeAdapterFact]:
    """Redact a stable ordered list of adapter results for prompt assembly."""
    return [
        redact_adapter_result_for_prompt(
            result,
            redaction_level=redaction_level,
            cloud_replacements=cloud_replacements,
            policy=policy,
        )
        for result in results
    ]
