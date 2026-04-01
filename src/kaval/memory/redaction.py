"""Operational Memory redaction helpers for local-safe and cloud-safe prompt use."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Sequence
from urllib.parse import SplitResult, parse_qsl, urlencode, urlsplit, urlunsplit

from kaval.models import Incident, RedactionLevel, Service

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
