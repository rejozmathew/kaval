"""Outbound egress guard for explicit API connectivity tests."""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit

_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class EgressNotAllowedError(ValueError):
    """Raised when an outbound connectivity-test destination is not allowed."""


def private_model_egress_allowed(env: dict[str, str] | None = None) -> bool:
    """Return whether private model-test destinations are explicitly enabled."""
    source = os.environ if env is None else env
    return source.get("KAVAL_ALLOW_PRIVATE_MODEL_EGRESS", "").strip().casefold() in _TRUE_VALUES


def ensure_model_test_egress_allowed(
    target_url: str,
    *,
    allow_private: bool | None = None,
) -> None:
    """Validate that a model connectivity-test URL is safe to contact.

    The guard resolves the URL host and fails closed when DNS resolution fails or any
    resolved address is loopback, link-local, private/unique-local, unspecified,
    reserved, or cloud metadata. The private/loopback classes may be explicitly
    allowed with ``KAVAL_ALLOW_PRIVATE_MODEL_EGRESS=true``; cloud metadata stays
    blocked even when that opt-in is enabled.
    """
    host, port = _parse_target(target_url)
    resolved_ips = _resolve_host(host=host, port=port)
    effective_allow_private = (
        private_model_egress_allowed() if allow_private is None else allow_private
    )
    for address in resolved_ips:
        reason = _blocked_reason(address, allow_private=effective_allow_private)
        if reason is not None:
            msg = (
                f"Model connectivity test target {target_url!r} is not allowed: "
                f"resolved address {address} is {reason}."
            )
            raise EgressNotAllowedError(msg)


def _parse_target(target_url: str) -> tuple[str, int | None]:
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"}:
        msg = "Model connectivity test target must be an http or https URL."
        raise EgressNotAllowedError(msg)
    if parsed.hostname is None:
        msg = "Model connectivity test target must include a host."
        raise EgressNotAllowedError(msg)
    try:
        port = parsed.port
    except ValueError as exc:
        msg = "Model connectivity test target has an invalid port."
        raise EgressNotAllowedError(msg) from exc
    return parsed.hostname, port


def _resolve_host(
    *, host: str, port: int | None
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        msg = f"Model connectivity test target host {host!r} could not be resolved."
        raise EgressNotAllowedError(msg) from exc

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for result in addrinfo:
        sockaddr = result[4]
        if not sockaddr:
            continue
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            msg = f"Model connectivity test target host {host!r} resolved to an invalid address."
            raise EgressNotAllowedError(msg) from exc
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        msg = f"Model connectivity test target host {host!r} did not resolve to an IP address."
        raise EgressNotAllowedError(msg)
    return tuple(addresses)


def _blocked_reason(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool,
) -> str | None:
    if address in _METADATA_ADDRESSES:
        return "a cloud metadata address"
    if allow_private:
        return None
    if address.is_loopback:
        return "a loopback address"
    if address.is_link_local:
        return "a link-local address"
    if address.is_private:
        return "a private address"
    if address.is_unspecified:
        return "an unspecified address"
    if address.is_reserved:
        return "a reserved address"
    return None
