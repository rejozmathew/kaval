"""Read-only Pi-hole deep-inspection adapter."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, cast
from urllib import error, request

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kaval.integrations.service_adapters import (
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.models import KavalModel, Service

type RequestTransport = Callable[[request.Request, float], bytes]


class PiHoleError(RuntimeError):
    """Base error for Pi-hole adapter failures."""


class PiHoleTransportError(PiHoleError):
    """Raised when the Pi-hole HTTP transport fails."""


class PiHoleAuthError(PiHoleError):
    """Raised when the Pi-hole API rejects authentication."""


class PiHoleResponseError(PiHoleError):
    """Raised when the Pi-hole API response shape is invalid."""


@dataclass(frozen=True, slots=True)
class PiHoleClientConfig:
    """Immutable runtime configuration for the Pi-hole API client."""

    base_url: str = "http://pi.hole/api"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"

    def __post_init__(self) -> None:
        """Normalize and validate the configured Pi-hole endpoint."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if not self.user_agent.strip():
            msg = "user_agent must not be empty"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)

    def endpoint(self, path: str) -> str:
        """Build one fully qualified Pi-hole API endpoint URL."""
        trimmed_path = path.lstrip("/")
        return f"{self.base_url}/{trimmed_path}"


class PiHoleUpstreamFact(KavalModel):
    """One normalized upstream DNS server configured in Pi-hole."""

    address: str
    port: int | None = None


class PiHoleBlocklistStatusFact(KavalModel):
    """Aggregated blocklist and blocking-status fact."""

    blocking_enabled: bool
    domains_being_blocked: int | None = None
    last_gravity_update: datetime | None = None
    queries_total: int | None = None
    queries_blocked: int | None = None
    percent_blocked: float | None = None


class PiHoleDhcpConfigFact(KavalModel):
    """Normalized DHCP-related Pi-hole config relevant to investigations."""

    active: bool
    start: str | None = None
    end: str | None = None
    router: str | None = None
    netmask: str | None = None
    lease_time: str | None = None
    ipv6: bool | None = None


class _PiHolePayloadModel(BaseModel):
    """Tolerant parser for Pi-hole API payloads."""

    model_config = ConfigDict(extra="ignore")


class _PiHoleErrorPayload(_PiHolePayloadModel):
    """Subset of Pi-hole error payload fields."""

    key: str | None = None
    message: str | None = None


class _PiHoleSessionPayload(_PiHolePayloadModel):
    """Subset of Pi-hole authentication session fields."""

    valid: bool
    sid: str | None = None
    message: str | None = None


class _PiHoleAuthPayload(_PiHolePayloadModel):
    """Pi-hole authentication response."""

    session: _PiHoleSessionPayload


class _PiHoleDnsConfigPayload(_PiHolePayloadModel):
    """Subset of Pi-hole DNS config fields consumed by the adapter."""

    upstreams: list[str] = Field(default_factory=list)


class _PiHoleDhcpConfigPayload(_PiHolePayloadModel):
    """Subset of Pi-hole DHCP config fields consumed by the adapter."""

    active: bool = False
    start: str | None = None
    end: str | None = None
    router: str | None = None
    netmask: str | None = None
    leaseTime: str | None = None
    ipv6: bool | None = None


class _PiHoleBlockingPayload(_PiHolePayloadModel):
    """Pi-hole DNS blocking status payload."""

    blocking: bool


class _PiHoleSummaryQueriesPayload(_PiHolePayloadModel):
    """Subset of Pi-hole query summary fields consumed by the adapter."""

    total: int | None = None
    blocked: int | None = None
    percent_blocked: float | None = None


class _PiHoleSummaryGravityPayload(_PiHolePayloadModel):
    """Subset of Pi-hole gravity summary fields consumed by the adapter."""

    domains_being_blocked: int | None = None
    last_update: int | None = None


class _PiHoleSummaryPayload(_PiHolePayloadModel):
    """Subset of Pi-hole summary stats consumed by the adapter."""

    queries: _PiHoleSummaryQueriesPayload = Field(
        default_factory=_PiHoleSummaryQueriesPayload
    )
    gravity: _PiHoleSummaryGravityPayload = Field(
        default_factory=_PiHoleSummaryGravityPayload
    )


@dataclass(frozen=True, slots=True)
class PiHoleClient:
    """Minimal read-only client for the Pi-hole HTTP API."""

    config: PiHoleClientConfig = PiHoleClientConfig()
    transport: RequestTransport | None = None

    def authenticate(self, *, password: str) -> str | None:
        """Authenticate and return a session ID when Pi-hole requires one."""
        payload = self._request_json(
            path="auth",
            method="POST",
            payload={"password": password},
            sid=None,
            auth_error_message="Pi-hole authentication failed",
        )
        if not isinstance(payload, Mapping):
            raise PiHoleResponseError("Pi-hole auth response was not an object")
        try:
            parsed = _PiHoleAuthPayload.model_validate(payload)
        except ValidationError as exc:
            raise PiHoleResponseError("Pi-hole auth payload shape was invalid") from exc
        if parsed.session.sid:
            return parsed.session.sid
        if parsed.session.message == "no password set":
            return None
        raise PiHoleAuthError("Pi-hole authentication failed")

    def fetch_dns_upstreams(self, *, sid: str | None) -> list[PiHoleUpstreamFact]:
        """Fetch configured upstream DNS servers from Pi-hole."""
        payload = self._get_json(
            "config/dns",
            sid=sid,
            auth_error_message="Pi-hole password or application password is required",
        )
        section = _extract_config_section(payload, section="dns")
        try:
            parsed = _PiHoleDnsConfigPayload.model_validate(section)
        except ValidationError as exc:
            raise PiHoleResponseError("Pi-hole DNS config payload shape was invalid") from exc
        return [_parse_upstream(value) for value in parsed.upstreams]

    def fetch_blocking_status(self, *, sid: str | None) -> bool:
        """Fetch current Pi-hole DNS blocking status."""
        payload = self._get_json(
            "dns/blocking",
            sid=sid,
            auth_error_message="Pi-hole password or application password is required",
        )
        if not isinstance(payload, Mapping):
            raise PiHoleResponseError("Pi-hole blocking response was not an object")
        try:
            parsed = _PiHoleBlockingPayload.model_validate(payload)
        except ValidationError as exc:
            raise PiHoleResponseError(
                "Pi-hole blocking payload shape was invalid"
            ) from exc
        return parsed.blocking

    def fetch_summary(self, *, sid: str | None) -> PiHoleBlocklistStatusFact:
        """Fetch summary stats used to describe Pi-hole blocklist state."""
        payload = self._get_json(
            "stats/summary",
            sid=sid,
            auth_error_message="Pi-hole password or application password is required",
        )
        if not isinstance(payload, Mapping):
            raise PiHoleResponseError("Pi-hole summary response was not an object")
        try:
            parsed = _PiHoleSummaryPayload.model_validate(payload)
        except ValidationError as exc:
            raise PiHoleResponseError(
                "Pi-hole summary payload shape was invalid"
            ) from exc
        return PiHoleBlocklistStatusFact(
            blocking_enabled=False,
            domains_being_blocked=parsed.gravity.domains_being_blocked,
            last_gravity_update=_unix_timestamp_to_datetime(parsed.gravity.last_update),
            queries_total=parsed.queries.total,
            queries_blocked=parsed.queries.blocked,
            percent_blocked=parsed.queries.percent_blocked,
        )

    def fetch_dhcp_config(self, *, sid: str | None) -> PiHoleDhcpConfigFact:
        """Fetch DHCP-related Pi-hole config relevant to network investigations."""
        payload = self._get_json(
            "config/dhcp",
            sid=sid,
            auth_error_message="Pi-hole password or application password is required",
        )
        section = _extract_config_section(payload, section="dhcp")
        try:
            parsed = _PiHoleDhcpConfigPayload.model_validate(section)
        except ValidationError as exc:
            raise PiHoleResponseError("Pi-hole DHCP payload shape was invalid") from exc
        return PiHoleDhcpConfigFact(
            active=parsed.active,
            start=parsed.start,
            end=parsed.end,
            router=parsed.router,
            netmask=parsed.netmask,
            lease_time=parsed.leaseTime,
            ipv6=parsed.ipv6,
        )

    def _get_json(
        self,
        path: str,
        *,
        sid: str | None,
        auth_error_message: str,
    ) -> object:
        """Send one authenticated GET request to the Pi-hole API."""
        return self._request_json(
            path=path,
            method="GET",
            payload=None,
            sid=sid,
            auth_error_message=auth_error_message,
        )

    def _request_json(
        self,
        *,
        path: str,
        method: str,
        payload: Mapping[str, object] | None,
        sid: str | None,
        auth_error_message: str,
    ) -> object:
        """Send one request to the Pi-hole API and parse the JSON response."""
        headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        data: bytes | None = None
        if sid is not None:
            headers["X-FTL-SID"] = sid
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            self.config.endpoint(path),
            method=method,
            headers=headers,
            data=data,
        )
        try:
            response_body = self._transport()(http_request, self.config.timeout_seconds)
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                detail = _http_error_message(exc)
                if detail is not None:
                    raise PiHoleAuthError(f"{auth_error_message}: {detail}") from exc
                raise PiHoleAuthError(auth_error_message) from exc
            if exc.code == 429:
                raise PiHoleAuthError("Pi-hole API rate limited the request") from exc
            raise PiHoleTransportError("Pi-hole API request failed") from exc
        except (TimeoutError, OSError, error.URLError) as exc:
            raise PiHoleTransportError("Pi-hole API request failed") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PiHoleResponseError("Pi-hole API returned invalid JSON") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


@dataclass(frozen=True, slots=True)
class PiHoleAdapter:
    """Read-only deep-inspection adapter for Pi-hole."""

    client: PiHoleClient = PiHoleClient()

    adapter_id: str = "pihole_api"
    surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
        AdapterSurfaceBinding(
            descriptor_id="networking/pihole",
            surface_id="upstream_dns",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/pihole",
            surface_id="blocklist_status",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/pihole",
            surface_id="dhcp_config",
        ),
    )
    credential_keys: tuple[str, ...] = ("password",)
    supported_versions: str | None = None
    read_only: bool = True

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Collect structured Pi-hole DNS, blocklist, and DHCP facts."""
        del service

        password = credentials.get("password", "")
        now = datetime.now(tz=UTC)

        try:
            sid = self.client.authenticate(password=password) if password else None
            upstream_dns = self.client.fetch_dns_upstreams(sid=sid)
            blocking_enabled = self.client.fetch_blocking_status(sid=sid)
            blocklist_status = self.client.fetch_summary(sid=sid)
            dhcp_config = self.client.fetch_dhcp_config(sid=sid)
        except PiHoleAuthError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except PiHoleTransportError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.CONNECTION_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except PiHoleResponseError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.PARSE_ERROR,
                timestamp=now,
                reason=str(exc),
            )

        blocklist_status = blocklist_status.model_copy(
            update={"blocking_enabled": blocking_enabled}
        )
        return AdapterResult(
            adapter_id=self.adapter_id,
            status=AdapterStatus.SUCCESS,
            facts={
                "upstream_dns_servers": [
                    item.model_dump(mode="json") for item in upstream_dns
                ],
                "blocklist_status": blocklist_status.model_dump(mode="json"),
                "dhcp_config": dhcp_config.model_dump(mode="json"),
            },
            edges_discovered=[],
            timestamp=now,
            reason=None,
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the Pi-hole API."""
    with request.urlopen(http_request, timeout=timeout_seconds) as response:
        return cast(bytes, response.read())


def _extract_config_section(payload: object, *, section: str) -> Mapping[str, object]:
    """Return a named config section from tolerant Pi-hole config payload shapes."""
    if not isinstance(payload, Mapping):
        raise PiHoleResponseError("Pi-hole config response was not an object")
    direct_section = payload.get(section)
    if isinstance(direct_section, Mapping):
        return cast(Mapping[str, object], direct_section)
    config_section = payload.get("config")
    if isinstance(config_section, Mapping):
        nested_section = config_section.get(section)
        if isinstance(nested_section, Mapping):
            return cast(Mapping[str, object], nested_section)
    return cast(Mapping[str, object], payload)


def _parse_upstream(value: str) -> PiHoleUpstreamFact:
    """Parse one Pi-hole upstream entry into stable host/port fields."""
    if "#" not in value:
        return PiHoleUpstreamFact(address=value, port=None)
    address, _, port_text = value.rpartition("#")
    try:
        port = int(port_text)
    except ValueError:
        return PiHoleUpstreamFact(address=value, port=None)
    return PiHoleUpstreamFact(address=address, port=port)


def _unix_timestamp_to_datetime(value: int | None) -> datetime | None:
    """Convert one Unix timestamp into a UTC datetime."""
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=UTC)


def _http_error_message(exc: error.HTTPError) -> str | None:
    """Extract a useful Pi-hole error message from an HTTP error response body."""
    if exc.fp is None:
        return None
    try:
        response_body = exc.read()
    except OSError:
        return None
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    error_payload = payload.get("error")
    if not isinstance(error_payload, Mapping):
        return None
    try:
        parsed = _PiHoleErrorPayload.model_validate(error_payload)
    except ValidationError:
        return None
    return parsed.message
