"""OpenAI-compatible local model integration for Phase 2A investigations."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, cast
from urllib import error, request

from pydantic import BaseModel, ConfigDict, ValidationError

from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.prompts import InvestigationPromptBundle, InvestigationSynthesis
from kaval.models import Incident, JsonValue, KavalModel, ModelUsed

type RequestTransport = Callable[[request.Request, float], bytes]


class LocalModelError(RuntimeError):
    """Raised when the local model integration cannot produce a usable result."""


class LocalModelTransportError(LocalModelError):
    """Raised when the HTTP transport to the local model endpoint fails."""


class LocalModelResponseError(LocalModelError):
    """Raised when the local model response cannot be parsed or validated."""


@dataclass(frozen=True, slots=True)
class LocalModelConfig:
    """Runtime configuration for the local OpenAI-compatible model endpoint."""

    base_url: str
    model: str
    api_key: str | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Normalize base URL and validate timeout values."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)


class ChatCompletionMessage(KavalModel):
    """One message in an OpenAI-compatible chat completion request."""

    role: str
    content: str


class ChatCompletionRequest(KavalModel):
    """The OpenAI-compatible chat completion payload used for local synthesis."""

    model: str
    messages: list[ChatCompletionMessage]
    temperature: float = 0.0


class _ProviderModel(BaseModel):
    """Lenient parser for third-party provider payloads."""

    model_config = ConfigDict(extra="ignore")


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
    """The subset of the provider response used by the synthesizer."""

    choices: list[ChatCompletionChoice]
    usage: "_OpenAICompatibleUsage | None" = None


class _OpenAICompatibleUsage(_ProviderModel):
    """Optional token-usage details returned by OpenAI-compatible providers."""

    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class OpenAICompatibleInvestigationSynthesizer:
    """Call a local OpenAI-compatible endpoint and validate structured output."""

    config: LocalModelConfig
    transport: RequestTransport | None = None

    def synthesize(
        self,
        *,
        incident: Incident,
        evidence: InvestigationEvidenceResult,
        prompt_bundle: InvestigationPromptBundle,
    ) -> InvestigationSynthesis:
        """Request structured investigation output from the configured local model."""
        del incident, evidence
        response_payload = request_openai_compatible_completion(
            config=self.config,
            system_prompt=prompt_bundle.system_prompt,
            user_prompt=prompt_bundle.user_prompt,
            transport=self.transport,
        )
        structured_payload = _extract_json_object(
            _extract_response_content(response_payload)
        )
        prompt_tokens, completion_tokens = _extract_usage_token_counts(response_payload)
        structured_payload["model_used"] = ModelUsed.LOCAL.value
        structured_payload["cloud_model_calls"] = 0
        structured_payload["local_input_tokens"] = prompt_tokens
        structured_payload["local_output_tokens"] = completion_tokens
        structured_payload["cloud_input_tokens"] = 0
        structured_payload["cloud_output_tokens"] = 0
        structured_payload["estimated_cloud_cost_usd"] = 0.0
        structured_payload["estimated_total_cost_usd"] = 0.0
        structured_payload["cloud_escalation_reason"] = None
        return InvestigationSynthesis.model_validate(structured_payload)

    def _build_request(self, prompt_bundle: InvestigationPromptBundle) -> request.Request:
        """Build the HTTP request sent to the local model endpoint."""
        payload = ChatCompletionRequest(
            model=self.config.model,
            messages=[
                ChatCompletionMessage(role="system", content=prompt_bundle.system_prompt),
                ChatCompletionMessage(role="user", content=prompt_bundle.user_prompt),
            ],
            temperature=0.0,
        ).model_dump(mode="json")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        body = json.dumps(payload).encode("utf-8")
        return request.Request(
            f"{self.config.base_url}/v1/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


def load_local_model_config_from_env(
    env: Mapping[str, str] | None = None,
) -> LocalModelConfig | None:
    """Load optional local-model configuration from the environment."""
    source = env or os.environ
    enabled = source.get("KAVAL_LOCAL_MODEL_ENABLED", "").strip().casefold()
    if enabled in {"0", "false", "no"}:
        return None

    model = source.get("KAVAL_LOCAL_MODEL_NAME", "").strip()
    if not model:
        return None

    base_url = source.get("KAVAL_LOCAL_MODEL_BASE_URL", "http://localhost:11434").strip()
    api_key = source.get("KAVAL_LOCAL_MODEL_API_KEY") or source.get("OLLAMA_API_KEY")
    timeout_value = source.get("KAVAL_LOCAL_MODEL_TIMEOUT_SECONDS", "30").strip()

    try:
        timeout_seconds = float(timeout_value)
    except ValueError as exc:
        raise ValueError("KAVAL_LOCAL_MODEL_TIMEOUT_SECONDS must be numeric") from exc

    return LocalModelConfig(
        base_url=base_url,
        model=model,
        api_key=api_key.strip() if api_key else None,
        timeout_seconds=timeout_seconds,
    )


def request_openai_compatible_json(
    *,
    config: LocalModelConfig,
    system_prompt: str,
    user_prompt: str,
    transport: RequestTransport | None = None,
) -> dict[str, JsonValue]:
    """Request one JSON object from the configured local model endpoint."""
    response_payload = request_openai_compatible_completion(
        config=config,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        transport=transport,
    )
    return _extract_json_object(_extract_response_content(response_payload))


def request_openai_compatible_completion(
    *,
    config: LocalModelConfig,
    system_prompt: str,
    user_prompt: str,
    transport: RequestTransport | None = None,
) -> ChatCompletionResponse:
    """Request one OpenAI-compatible completion and retain optional usage metadata."""
    payload = ChatCompletionRequest(
        model=config.model,
        messages=[
            ChatCompletionMessage(role="system", content=system_prompt),
            ChatCompletionMessage(role="user", content=user_prompt),
        ],
        temperature=0.0,
    ).model_dump(mode="json")
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    http_request = request.Request(
        f"{config.base_url}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    response_body = (transport or _default_transport)(http_request, config.timeout_seconds)
    return _decode_response_payload(response_body)


def probe_local_model_connection(
    *,
    config: LocalModelConfig,
    transport: RequestTransport | None = None,
) -> None:
    """Run one small explicit connectivity check against the local model endpoint."""
    response_payload = request_openai_compatible_json(
        config=config,
        system_prompt="Return JSON only.",
        user_prompt='{"connection_ok": true}',
        transport=transport,
    )
    if response_payload.get("connection_ok") is not True:
        raise LocalModelResponseError(
            "local model test did not return the expected JSON acknowledgement"
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the local model endpoint."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except (TimeoutError, OSError, error.HTTPError, error.URLError) as exc:
        raise LocalModelTransportError("local model request failed") from exc


def _extract_response_content(response_payload: ChatCompletionResponse) -> str:
    """Extract plain-text content from the first model choice."""
    if not response_payload.choices:
        raise LocalModelResponseError("local model returned no completion choices")

    content = response_payload.choices[0].message.content
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = [part.text for part in content if part.text]
        if text_parts:
            return "\n".join(text_parts)
    raise LocalModelResponseError("local model returned no usable message content")


def _extract_usage_token_counts(
    response_payload: ChatCompletionResponse,
) -> tuple[int, int]:
    """Return provider-reported prompt and completion token counts when present."""
    usage = response_payload.usage
    if usage is None:
        return 0, 0
    return max(int(usage.prompt_tokens or 0), 0), max(int(usage.completion_tokens or 0), 0)


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
    raise LocalModelResponseError("local model content did not contain a JSON object")


def _decode_response_payload(response_body: bytes) -> ChatCompletionResponse:
    """Decode and validate the provider response payload."""
    try:
        raw_payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalModelResponseError("local model returned non-JSON content") from exc
    try:
        return ChatCompletionResponse.model_validate(raw_payload)
    except ValidationError as exc:
        raise LocalModelResponseError("local model response shape was invalid") from exc


def _strip_markdown_fences(content: str) -> str:
    """Remove a single surrounding markdown code fence when present."""
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1])
    return stripped
