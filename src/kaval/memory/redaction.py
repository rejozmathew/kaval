"""Operational Memory redaction helpers for local-safe and cloud-safe prompt use."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Self, Sequence
from urllib.parse import SplitResult, parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import Field, model_validator

from kaval.models import Incident, JsonValue, KavalModel, RedactionLevel, Service

_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"token|secret|secret[_-]?key|client[_-]?secret"
    r")\b(\s*[:=]\s*)([^\s&;,]+)"
)
_CLI_SECRET_FLAG_RE = re.compile(
    r"(?i)(?<!\S)(--?(?:password|passwd|token|api[_-]?key|secret|client[_-]?secret)\s+)(\S+)"
)
_AUTH_HEADER_RE = re.compile(r"(?i)(\bAuthorization\s*:\s*)(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_AUTH_TOKEN_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_COOKIE_HEADER_RE = re.compile(r"(?im)^((?:Set-Cookie|Cookie)\s*:\s*)(.+)$")
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"`]+")
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PRIVATE_IPV4_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
_PRIVATE_IPV6_RE = re.compile(r"(?i)\b(?:::1|fe80:[0-9a-f:]+|f[cd][0-9a-f:]+)\b")
_SHARE_PATH_RE = re.compile(r"/mnt/(?:user|cache)/[^\s'\"`]+")
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:localhost|"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:internal|local|lan|home|localdomain|home\.arpa))\b"
)
_GENERIC_RECORD_ID_RE = re.compile(r"\b(?:inc|find|chg|jrnl|note|svc)-[A-Za-z0-9_.-]+\b")
_GENERIC_CONTAINER_ID_RE = re.compile(r"\b(?:container-[A-Za-z0-9_.-]+|[0-9a-f]{12,64})\b")


@dataclass(frozen=True, slots=True)
class CloudRedactionReplacement:
    """One stable placeholder replacement applied before cloud-model calls."""

    original: str
    placeholder: str


class StructuredRedactionPolicy(KavalModel):
    """Field-level exclusion policy for structured prompt-safe payloads."""

    excluded_keys: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        """Reject blank exclusion entries so policies stay deterministic."""
        if any(not entry.strip() for entry in self.excluded_keys):
            msg = "excluded_keys cannot contain blank values"
            raise ValueError(msg)
        if any(not entry.strip() for entry in self.excluded_paths):
            msg = "excluded_paths cannot contain blank values"
            raise ValueError(msg)
        return self


class StructuredRedactionResult(KavalModel):
    """Redacted structured payload plus any fields withheld entirely."""

    redacted_value: JsonValue
    applied_redaction_level: RedactionLevel
    excluded_paths: list[str] = Field(default_factory=list)


def redact_text(
    text: str,
    *,
    redaction_level: RedactionLevel,
    cloud_replacements: Sequence[CloudRedactionReplacement] = (),
) -> str:
    """Redact secret-like and internal patterns for the requested safety level."""
    redacted = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    redacted = _KEY_VALUE_SECRET_RE.sub(r"\1\2[REDACTED]", redacted)
    redacted = _CLI_SECRET_FLAG_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _AUTH_HEADER_RE.sub(r"\1\2 [REDACTED]", redacted)
    redacted = _AUTH_TOKEN_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _COOKIE_HEADER_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _JWT_RE.sub("[REDACTED_JWT]", redacted)
    redacted = _URL_RE.sub(lambda match: _redact_url(match.group(0), redaction_level), redacted)

    if redaction_level == RedactionLevel.REDACT_FOR_CLOUD:
        redacted = _PRIVATE_IPV4_RE.sub("[REDACTED_IP]", redacted)
        redacted = _PRIVATE_IPV6_RE.sub("[REDACTED_IP]", redacted)
        redacted = _SHARE_PATH_RE.sub("[REDACTED_PATH]", redacted)
        redacted = _INTERNAL_HOST_RE.sub("[REDACTED_HOST]", redacted)
        redacted = _apply_cloud_replacements(redacted, cloud_replacements)
        redacted = _GENERIC_RECORD_ID_RE.sub("[REDACTED_ID]", redacted)
        redacted = _GENERIC_CONTAINER_ID_RE.sub("[REDACTED_CONTAINER]", redacted)

    return redacted


def redact_for_local(text: str) -> str:
    """Apply the local-safe redaction level."""
    return redact_text(text, redaction_level=RedactionLevel.REDACT_FOR_LOCAL)


def redact_for_cloud(
    text: str,
    *,
    cloud_replacements: Sequence[CloudRedactionReplacement] = (),
) -> str:
    """Apply the cloud-safe redaction level."""
    return redact_text(
        text,
        redaction_level=RedactionLevel.REDACT_FOR_CLOUD,
        cloud_replacements=cloud_replacements,
    )


def build_cloud_redaction_replacements(
    *,
    incident: Incident,
    services: Sequence[Service],
) -> tuple[CloudRedactionReplacement, ...]:
    """Build stable prompt replacements for service and incident identifiers."""
    replacements: list[CloudRedactionReplacement] = [
        CloudRedactionReplacement(original=incident.id, placeholder="[INCIDENT_ID]")
    ]
    for index, service in enumerate(services, start=1):
        replacements.append(
            CloudRedactionReplacement(
                original=service.id,
                placeholder=f"[SERVICE_ID_{index}]",
            )
        )
        replacements.append(
            CloudRedactionReplacement(
                original=service.name,
                placeholder=f"[SERVICE_{index}]",
            )
        )
        if service.container_id:
            replacements.append(
                CloudRedactionReplacement(
                    original=service.container_id,
                    placeholder=f"[CONTAINER_{index}]",
                )
            )
        if service.descriptor_id:
            replacements.append(
                CloudRedactionReplacement(
                    original=service.descriptor_id,
                    placeholder=f"[DESCRIPTOR_{index}]",
                )
            )
    return tuple(replacements)


def redact_json_value(
    value: JsonValue,
    *,
    redaction_level: RedactionLevel,
    cloud_replacements: Sequence[CloudRedactionReplacement] = (),
    policy: StructuredRedactionPolicy | None = None,
) -> StructuredRedactionResult:
    """Redact one structured JSON-like payload for prompt-safe use."""
    effective_policy = policy or StructuredRedactionPolicy()
    redacted_value, excluded_paths = _redact_json_node(
        value,
        path="",
        field_name=None,
        redaction_level=redaction_level,
        cloud_replacements=cloud_replacements,
        policy=effective_policy,
    )
    return StructuredRedactionResult(
        redacted_value=redacted_value,
        applied_redaction_level=redaction_level,
        excluded_paths=excluded_paths,
    )


def _apply_cloud_replacements(
    text: str,
    replacements: Sequence[CloudRedactionReplacement],
) -> str:
    """Apply explicit cloud placeholders in a stable longest-first order."""
    redacted = text
    ordered = sorted(
        (replacement for replacement in replacements if replacement.original),
        key=lambda item: len(item.original),
        reverse=True,
    )
    for replacement in ordered:
        redacted = redacted.replace(replacement.original, replacement.placeholder)
    return redacted


def _redact_url(url: str, redaction_level: RedactionLevel) -> str:
    """Redact credentials and internal URL targets while preserving outer structure."""
    core_url, suffix = _split_trailing_punctuation(url)
    parsed = urlsplit(core_url)
    hostname = parsed.hostname or ""
    username = parsed.username
    password = parsed.password
    if not hostname:
        return url

    if redaction_level == RedactionLevel.REDACT_FOR_CLOUD and _is_internal_host(hostname):
        return f"{parsed.scheme}://[REDACTED_URL]{suffix}"

    netloc = parsed.netloc
    if username is not None or password is not None:
        host_port = hostname
        if parsed.port is not None:
            host_port = f"{host_port}:{parsed.port}"
        netloc = f"[REDACTED]@{host_port}"
    query = _redact_url_query(parsed.query)
    rebuilt = urlunsplit(
        SplitResult(
            scheme=parsed.scheme,
            netloc=netloc,
            path=parsed.path,
            query=query,
            fragment=parsed.fragment,
        )
    )
    return rebuilt + suffix


def _split_trailing_punctuation(url: str) -> tuple[str, str]:
    """Split off common trailing punctuation that should survive redaction."""
    suffix = ""
    core = url
    while core and core[-1] in {".", ",", ")", "]"}:
        suffix = core[-1] + suffix
        core = core[:-1]
    return core, suffix


def _is_internal_host(hostname: str) -> bool:
    """Return whether a hostname or IP address should be treated as internal."""
    normalized = hostname.strip().strip("[]").rstrip(".").casefold()
    if not normalized:
        return False
    if normalized == "localhost" or "." not in normalized:
        return True
    try:
        address = ip_address(normalized)
    except ValueError:
        return normalized.endswith(
            (".internal", ".local", ".lan", ".home", ".localdomain", ".home.arpa")
        )
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
    )


def _redact_url_query(query: str) -> str:
    """Redact secret-like query parameter values while preserving non-sensitive keys."""
    if not query:
        return query
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:
        return query
    redacted_pairs = [
        (key, "[REDACTED]" if _is_sensitive_query_key(key) else value)
        for key, value in pairs
    ]
    return urlencode(redacted_pairs, doseq=True)


def _is_sensitive_query_key(key: str) -> bool:
    """Return whether a URL query key likely carries secret material."""
    normalized = key.casefold()
    return bool(
        re.search(
            r"(token|api[_-]?key|secret|password|passwd|auth|session|cookie|jwt|code)",
            normalized,
        )
    )


def _redact_json_node(
    value: JsonValue,
    *,
    path: str,
    field_name: str | None,
    redaction_level: RedactionLevel,
    cloud_replacements: Sequence[CloudRedactionReplacement],
    policy: StructuredRedactionPolicy,
) -> tuple[JsonValue, list[str]]:
    """Recursively redact a structured JSON-like payload."""
    if value is None or isinstance(value, bool | int | float):
        return value, []
    if isinstance(value, str):
        if field_name is not None and _is_sensitive_structured_key(field_name):
            return "[REDACTED]", []
        return (
            redact_text(
                value,
                redaction_level=redaction_level,
                cloud_replacements=cloud_replacements,
            ),
            [],
        )
    if isinstance(value, list):
        redacted_items: list[JsonValue] = []
        list_excluded_paths: list[str] = []
        for index, item in enumerate(value):
            child_value, child_excluded = _redact_json_node(
                item,
                path=f"{path}[{index}]" if path else f"[{index}]",
                field_name=field_name,
                redaction_level=redaction_level,
                cloud_replacements=cloud_replacements,
                policy=policy,
            )
            redacted_items.append(child_value)
            list_excluded_paths.extend(child_excluded)
        return redacted_items, list_excluded_paths

    redacted_mapping: dict[str, JsonValue] = {}
    mapping_excluded_paths: list[str] = []
    for key, item in value.items():
        child_path = f"{path}.{key}" if path else key
        if _should_exclude_structured_field(
            key=key,
            path=child_path,
            policy=policy,
        ):
            mapping_excluded_paths.append(child_path)
            continue
        child_value, child_excluded = _redact_json_node(
            item,
            path=child_path,
            field_name=key,
            redaction_level=redaction_level,
            cloud_replacements=cloud_replacements,
            policy=policy,
        )
        redacted_mapping[key] = child_value
        mapping_excluded_paths.extend(child_excluded)
    return redacted_mapping, mapping_excluded_paths


def _should_exclude_structured_field(
    *,
    key: str,
    path: str,
    policy: StructuredRedactionPolicy,
) -> bool:
    """Return whether one structured field should be omitted entirely."""
    normalized_key = _normalize_redaction_token(key)
    normalized_path = _normalize_redaction_path(path)
    return normalized_key in {
        _normalize_redaction_token(entry) for entry in policy.excluded_keys
    } or normalized_path in {
        _normalize_redaction_path(entry) for entry in policy.excluded_paths
    }


def _normalize_redaction_token(value: str) -> str:
    """Normalize one field token for tolerant exclusion matching."""
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _normalize_redaction_path(value: str) -> str:
    """Normalize one dotted field path for tolerant exclusion matching."""
    return ".".join(_normalize_redaction_token(part) for part in value.split("."))


def _is_sensitive_structured_key(key: str) -> bool:
    """Return whether one structured field name likely contains secret material."""
    return _is_sensitive_query_key(key)
