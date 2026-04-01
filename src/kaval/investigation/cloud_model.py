"""Optional cloud-model investigation synthesis with explicit escalation policy."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Literal, cast
from urllib import error, request

from pydantic import BaseModel, ConfigDict, ValidationError

from kaval.investigation.prompts import InvestigationPromptBundle, InvestigationSynthesis
from kaval.memory.redaction import build_cloud_redaction_replacements, redact_for_cloud
from kaval.models import (
    Finding,
    Incident,
    Investigation,
    InvestigationTrigger,
    JsonValue,
    KavalModel,
    ModelUsed,
    Service,
)

type CloudTransport = Callable[[request.Request, float], bytes]
type CloudProvider = Literal["anthropic", "openai", "openai_compatible"]

_CLOUD_REDACTION_NOTE = (
    "Privacy note: some internal identifiers, internal URLs, and secrets were redacted "
    "before this cloud-model call. Placeholder consistency still reflects the same entity."
)


class CloudModelError(RuntimeError):
    """Raised when the cloud model integration cannot produce a usable result."""


class CloudModelTransportError(CloudModelError):
    """Raised when the HTTP transport to the cloud model endpoint fails."""


class CloudModelResponseError(CloudModelError):
    """Raised when the cloud model response cannot be parsed or validated."""


class CloudPromptRedactionError(CloudModelError):
    """Raised when a prompt cannot be converted into a cloud-safe bundle."""


@dataclass(frozen=True, slots=True)
class CloudModelConfig:
    """Runtime configuration for the optional cloud model endpoint."""

    provider: CloudProvider
    model: str
    api_key: str
    base_url: str
    timeout_seconds: float = 45.0
    max_output_tokens: int = 1600

    def __post_init__(self) -> None:
        """Normalize cloud endpoints and numeric controls."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if not self.api_key.strip():
            msg = "api_key must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if self.max_output_tokens <= 0:
            msg = "max_output_tokens must be positive"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)
        object.__setattr__(self, "api_key", self.api_key.strip())


@dataclass(frozen=True, slots=True)
class CloudEscalationPolicy:
    """Explicit cloud-escalation thresholds and safety caps."""

    finding_count_gt: int = 3
    local_confidence_lt: float = 0.6
    escalate_on_multiple_domains: bool = True
    escalate_on_changelog_research: bool = True
    escalate_on_user_request: bool = False
    max_cloud_calls_per_day: int = 20
    max_cloud_calls_per_incident: int = 3

    def __post_init__(self) -> None:
        """Validate policy thresholds."""
        if self.finding_count_gt < 0:
            msg = "finding_count_gt must be non-negative"
            raise ValueError(msg)
        if not 0.0 <= self.local_confidence_lt <= 1.0:
            msg = "local_confidence_lt must be between 0.0 and 1.0"
            raise ValueError(msg)
        if self.max_cloud_calls_per_day < 1:
            msg = "max_cloud_calls_per_day must be positive"
            raise ValueError(msg)
        if self.max_cloud_calls_per_incident < 1:
            msg = "max_cloud_calls_per_incident must be positive"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class CloudEscalationDecision:
    """Outcome of evaluating the explicit cloud escalation policy."""

    should_use_cloud: bool
    trigger_reasons: tuple[str, ...] = ()
    blocked_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CloudSafePromptBundle:
    """A prompt bundle that has been explicitly transformed for cloud safety."""

    system_prompt: str
    user_prompt: str
    response_schema_name: str
    response_schema: dict[str, JsonValue]


class _ProviderModel(BaseModel):
    """Lenient parser for third-party provider payloads."""

    model_config = ConfigDict(extra="ignore")


class ChatCompletionMessage(KavalModel):
    """One message in an OpenAI-compatible chat completion request."""

    role: str
    content: str


class ChatCompletionRequest(KavalModel):
    """The OpenAI-compatible chat completion payload used for cloud synthesis."""

    model: str
    messages: list[ChatCompletionMessage]
    temperature: float = 0.0


class ChatCompletionContentPart(_ProviderModel):
    """One structured content part returned by some OpenAI-compatible servers."""

    text: str | None = None
    type: str | None = None


class ChatCompletionChoiceMessage(_ProviderModel):
    """The message payload returned by the provider."""

    content: str | list[ChatCompletionContentPart] | None = None


class ChatCompletionChoice(_ProviderModel):
    """One completion choice returned by the provider."""

    message: ChatCompletionChoiceMessage


class ChatCompletionResponse(_ProviderModel):
    """The subset of an OpenAI-compatible response used by the synthesizer."""

    choices: list[ChatCompletionChoice]


class AnthropicMessagePart(_ProviderModel):
    """One content block returned by Anthropic's messages API."""

    text: str | None = None
    type: str | None = None


class AnthropicMessageResponse(_ProviderModel):
    """The subset of Anthropic's response used by the synthesizer."""

    content: list[AnthropicMessagePart]


@dataclass(frozen=True, slots=True)
class CloudInvestigationSynthesizer:
    """Call the configured cloud model endpoint using a cloud-safe prompt bundle."""

    config: CloudModelConfig
    transport: CloudTransport | None = None

    def synthesize(self, *, prompt_bundle: CloudSafePromptBundle) -> InvestigationSynthesis:
        """Request structured investigation output from the configured cloud model."""
        http_request = self._build_request(prompt_bundle)
        response_body = self._transport()(http_request, self.config.timeout_seconds)
        content = self._extract_response_content(response_body)
        structured_payload = _extract_json_object(content)
        structured_payload["model_used"] = ModelUsed.CLOUD.value
        structured_payload["cloud_model_calls"] = 1
        return InvestigationSynthesis.model_validate(structured_payload)

    def _build_request(self, prompt_bundle: CloudSafePromptBundle) -> request.Request:
        """Build the provider-specific cloud request."""
        if self.config.provider in {"openai", "openai_compatible"}:
            payload = ChatCompletionRequest(
                model=self.config.model,
                messages=[
                    ChatCompletionMessage(role="system", content=prompt_bundle.system_prompt),
                    ChatCompletionMessage(role="user", content=prompt_bundle.user_prompt),
                ],
                temperature=0.0,
            ).model_dump(mode="json")
            return request.Request(
                f"{self.config.base_url}/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )

        payload = {
            "model": self.config.model,
            "system": prompt_bundle.system_prompt,
            "messages": [{"role": "user", "content": prompt_bundle.user_prompt}],
            "temperature": 0.0,
            "max_tokens": self.config.max_output_tokens,
        }
        return request.Request(
            f"{self.config.base_url}/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

    def _transport(self) -> CloudTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport

    def _extract_response_content(self, response_body: bytes) -> str:
        """Decode and normalize provider responses into text content."""
        try:
            raw_payload = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CloudModelResponseError("cloud model returned non-JSON content") from exc

        if self.config.provider in {"openai", "openai_compatible"}:
            try:
                openai_response = ChatCompletionResponse.model_validate(raw_payload)
            except ValidationError as exc:
                raise CloudModelResponseError(
                    "cloud model response shape was invalid"
                ) from exc
            return _extract_openai_content(openai_response)

        try:
            anthropic_response = AnthropicMessageResponse.model_validate(raw_payload)
        except ValidationError as exc:
            raise CloudModelResponseError("cloud model response shape was invalid") from exc
        return _extract_anthropic_content(anthropic_response)


def build_cloud_safe_prompt_bundle(
    *,
    prompt_bundle: InvestigationPromptBundle,
    incident: Incident,
    services: Sequence[Service],
) -> CloudSafePromptBundle:
    """Transform a rendered prompt bundle into a cloud-safe equivalent."""
    if not prompt_bundle.system_prompt.strip() or not prompt_bundle.user_prompt.strip():
        msg = "prompt bundle must contain both system and user prompt content"
        raise CloudPromptRedactionError(msg)

    replacements = build_cloud_redaction_replacements(incident=incident, services=services)
    system_prompt = redact_for_cloud(prompt_bundle.system_prompt)
    user_prompt = redact_for_cloud(
        prompt_bundle.user_prompt,
        cloud_replacements=replacements,
    ).replace(
        '"applied_redaction_level": "redact_for_local"',
        '"applied_redaction_level": "redact_for_cloud"',
    )

    return CloudSafePromptBundle(
        system_prompt="\n\n".join([system_prompt, _CLOUD_REDACTION_NOTE]).strip(),
        user_prompt=user_prompt,
        response_schema_name=prompt_bundle.response_schema_name,
        response_schema=prompt_bundle.response_schema,
    )


def evaluate_cloud_escalation_policy(
    *,
    incident: Incident,
    findings: Sequence[Finding],
    investigations: Sequence[Investigation],
    local_synthesis: InvestigationSynthesis,
    changelog_research_available: bool,
    trigger: InvestigationTrigger,
    now: datetime,
    policy: CloudEscalationPolicy,
    offline: bool,
) -> CloudEscalationDecision:
    """Evaluate the explicit cloud-escalation policy for one investigation run."""
    trigger_reasons: list[str] = []
    relevant_findings = _relevant_findings(incident=incident, findings=findings)
    if len(relevant_findings) > policy.finding_count_gt:
        trigger_reasons.append(
            f"finding_count>{policy.finding_count_gt}"
        )
    if local_synthesis.inference.confidence < policy.local_confidence_lt:
        trigger_reasons.append(
            f"local_confidence<{policy.local_confidence_lt:.2f}"
        )
    if policy.escalate_on_multiple_domains and _has_multiple_domains(relevant_findings):
        trigger_reasons.append("multiple_domains_affected")
    if policy.escalate_on_changelog_research and changelog_research_available:
        trigger_reasons.append("changelog_research_needed")
    if policy.escalate_on_user_request and trigger == InvestigationTrigger.USER_REQUEST:
        trigger_reasons.append("user_requested_deep_analysis")

    if not trigger_reasons:
        return CloudEscalationDecision(should_use_cloud=False)

    if offline:
        return CloudEscalationDecision(
            should_use_cloud=False,
            trigger_reasons=tuple(trigger_reasons),
            blocked_reason="Cloud escalation unavailable while offline; local synthesis retained.",
        )

    incident_call_count = sum(
        investigation.cloud_model_calls
        for investigation in investigations
        if investigation.incident_id == incident.id
    )
    if incident_call_count >= policy.max_cloud_calls_per_incident:
        return CloudEscalationDecision(
            should_use_cloud=False,
            trigger_reasons=tuple(trigger_reasons),
            blocked_reason=(
                "Cloud escalation criteria matched but the per-incident cloud call cap "
                "was reached; local synthesis retained."
            ),
        )

    start_of_day = now.astimezone(UTC).date()
    daily_call_count = sum(
        investigation.cloud_model_calls
        for investigation in investigations
        if investigation.started_at.astimezone(UTC).date() == start_of_day
    )
    if daily_call_count >= policy.max_cloud_calls_per_day:
        return CloudEscalationDecision(
            should_use_cloud=False,
            trigger_reasons=tuple(trigger_reasons),
            blocked_reason=(
                "Cloud escalation criteria matched but the daily cloud call cap was "
                "reached; local synthesis retained."
            ),
        )

    return CloudEscalationDecision(
        should_use_cloud=True,
        trigger_reasons=tuple(trigger_reasons),
    )


def load_cloud_model_config_from_env(
    env: Mapping[str, str] | None = None,
) -> CloudModelConfig | None:
    """Load optional cloud-model configuration from the environment."""
    source = env or os.environ
    enabled = source.get("KAVAL_CLOUD_MODEL_ENABLED", "").strip().casefold()
    if enabled in {"0", "false", "no"}:
        return None

    model = source.get("KAVAL_CLOUD_MODEL_NAME", "").strip()
    if not model:
        return None

    provider = cast(
        CloudProvider,
        source.get("KAVAL_CLOUD_MODEL_PROVIDER", "anthropic").strip().casefold(),
    )
    if provider not in {"anthropic", "openai", "openai_compatible"}:
        msg = f"unsupported cloud model provider: {provider}"
        raise ValueError(msg)

    api_key = _resolve_cloud_api_key(source, provider=provider)
    if api_key is None:
        msg = "cloud model api key is required when KAVAL_CLOUD_MODEL_NAME is set"
        raise ValueError(msg)

    timeout_value = source.get("KAVAL_CLOUD_MODEL_TIMEOUT_SECONDS", "45").strip()
    max_tokens_value = source.get("KAVAL_CLOUD_MODEL_MAX_OUTPUT_TOKENS", "1600").strip()
    try:
        timeout_seconds = float(timeout_value)
    except ValueError as exc:
        raise ValueError("KAVAL_CLOUD_MODEL_TIMEOUT_SECONDS must be numeric") from exc
    try:
        max_output_tokens = int(max_tokens_value)
    except ValueError as exc:
        raise ValueError("KAVAL_CLOUD_MODEL_MAX_OUTPUT_TOKENS must be an integer") from exc

    base_url = source.get("KAVAL_CLOUD_MODEL_BASE_URL", "").strip()
    if not base_url:
        if provider == "anthropic":
            base_url = "https://api.anthropic.com"
        elif provider == "openai":
            base_url = "https://api.openai.com"
        else:
            msg = "KAVAL_CLOUD_MODEL_BASE_URL is required for openai_compatible providers"
            raise ValueError(msg)

    return CloudModelConfig(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        max_output_tokens=max_output_tokens,
    )


def load_cloud_escalation_policy_from_env(
    env: Mapping[str, str] | None = None,
) -> CloudEscalationPolicy:
    """Load explicit cloud escalation thresholds from the environment."""
    source = env or os.environ
    try:
        return CloudEscalationPolicy(
            finding_count_gt=int(
                source.get("KAVAL_CLOUD_ESCALATION_FINDING_COUNT_GT", "3").strip()
            ),
            local_confidence_lt=float(
                source.get("KAVAL_CLOUD_ESCALATION_LOCAL_CONFIDENCE_LT", "0.6").strip()
            ),
            escalate_on_multiple_domains=_env_flag(
                source.get("KAVAL_CLOUD_ESCALATION_ON_MULTIPLE_DOMAINS"),
                default=True,
            ),
            escalate_on_changelog_research=_env_flag(
                source.get("KAVAL_CLOUD_ESCALATION_ON_CHANGELOG_RESEARCH"),
                default=True,
            ),
            escalate_on_user_request=_env_flag(
                source.get("KAVAL_CLOUD_ESCALATION_ON_USER_REQUEST"),
                default=False,
            ),
            max_cloud_calls_per_day=int(
                source.get("KAVAL_CLOUD_MODEL_MAX_CALLS_PER_DAY", "20").strip()
            ),
            max_cloud_calls_per_incident=int(
                source.get("KAVAL_CLOUD_MODEL_MAX_CALLS_PER_INCIDENT", "3").strip()
            ),
        )
    except ValueError as exc:
        raise ValueError("cloud escalation policy environment values were invalid") from exc


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the configured cloud endpoint."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except (TimeoutError, OSError, error.HTTPError, error.URLError) as exc:
        raise CloudModelTransportError("cloud model request failed") from exc


def _extract_openai_content(response_payload: ChatCompletionResponse) -> str:
    """Extract plain-text content from the first OpenAI-compatible choice."""
    if not response_payload.choices:
        raise CloudModelResponseError("cloud model returned no completion choices")
    content = response_payload.choices[0].message.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = [part.text for part in content if part.text]
        if text_parts:
            return "\n".join(text_parts)
    raise CloudModelResponseError("cloud model returned no usable message content")


def _extract_anthropic_content(response_payload: AnthropicMessageResponse) -> str:
    """Extract plain-text content from Anthropic's message blocks."""
    text_parts = [part.text for part in response_payload.content if part.text]
    if text_parts:
        return "\n".join(text_parts)
    raise CloudModelResponseError("cloud model returned no usable message content")


def _extract_json_object(content: str) -> dict[str, JsonValue]:
    """Parse the first JSON object from model text content."""
    cleaned = _strip_markdown_fences(content).strip()
    decoder = json.JSONDecoder()
    for index, character in enumerate(cleaned):
        if character != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(cleaned[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return cast(dict[str, JsonValue], parsed)
    raise CloudModelResponseError("cloud model content did not contain a JSON object")


def _strip_markdown_fences(content: str) -> str:
    """Remove a single surrounding markdown code fence when present."""
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1])
    return stripped


def _resolve_cloud_api_key(
    source: Mapping[str, str],
    *,
    provider: CloudProvider,
) -> str | None:
    """Resolve the cloud API key from the configured env var or provider defaults."""
    configured_env = source.get("KAVAL_CLOUD_MODEL_API_KEY_ENV", "").strip()
    if configured_env:
        api_key = source.get(configured_env, "").strip()
        return api_key or None

    configured_key = source.get("KAVAL_CLOUD_MODEL_API_KEY", "").strip()
    if configured_key:
        return configured_key

    if provider == "anthropic":
        api_key = source.get("ANTHROPIC_API_KEY", "").strip()
    else:
        api_key = source.get("OPENAI_API_KEY", "").strip()
    return api_key or None


def _env_flag(raw_value: str | None, *, default: bool) -> bool:
    """Parse one boolean-ish env flag with a default."""
    if raw_value is None or not raw_value.strip():
        return default
    normalized = raw_value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    msg = f"invalid boolean value: {raw_value}"
    raise ValueError(msg)


def _relevant_findings(*, incident: Incident, findings: Sequence[Finding]) -> list[Finding]:
    """Return findings directly attached to the incident."""
    incident_finding_ids = set(incident.all_findings) | set(incident.trigger_findings)
    return [
        finding
        for finding in findings
        if finding.id in incident_finding_ids or finding.incident_id == incident.id
    ]


def _has_multiple_domains(findings: Sequence[Finding]) -> bool:
    """Return whether the investigation spans more than one logical domain."""
    domains = {finding.domain for finding in findings if finding.domain}
    return len(domains) > 1
