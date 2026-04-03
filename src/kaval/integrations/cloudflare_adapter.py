"""Read-only Cloudflare deep-inspection adapter."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, cast
from urllib import error, parse, request

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kaval.integrations.service_adapters import (
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.models import KavalModel, Service

type RequestTransport = Callable[[request.Request, float], bytes]

_SUPPORTED_DNS_TYPES = frozenset({"A", "AAAA", "CNAME"})


class CloudflareError(RuntimeError):
    """Base error for Cloudflare adapter failures."""


class CloudflareTransportError(CloudflareError):
    """Raised when the Cloudflare HTTP transport fails."""


class CloudflareAuthError(CloudflareError):
    """Raised when the Cloudflare API rejects authentication or scope."""


class CloudflareResponseError(CloudflareError):
    """Raised when the Cloudflare API response shape is invalid."""


class CloudflareConfigurationError(CloudflareError):
    """Raised when Cloudflare inputs do not map to a usable zone/tunnel."""


@dataclass(frozen=True, slots=True)
class CloudflareClientConfig:
    """Immutable runtime configuration for the Cloudflare API client."""

    base_url: str = "https://api.cloudflare.com/client/v4"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"
    dns_page_size: int = 100
    max_dns_pages: int = 20

    def __post_init__(self) -> None:
        """Normalize and validate the configured Cloudflare API settings."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if self.dns_page_size <= 0:
            msg = "dns_page_size must be positive"
            raise ValueError(msg)
        if self.max_dns_pages <= 0:
            msg = "max_dns_pages must be positive"
            raise ValueError(msg)
        if not self.user_agent.strip():
            msg = "user_agent must not be empty"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)

    def endpoint(
        self,
        path: str,
        query: Mapping[str, str | int] | None = None,
    ) -> str:
        """Build one fully qualified Cloudflare API endpoint URL."""
        trimmed_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


class CloudflareZoneFact(KavalModel):
    """One normalized Cloudflare zone summary."""

    id: str
    name: str
    status: str | None = None
    paused: bool = False
    type: str | None = None


class CloudflareDnsRecordFact(KavalModel):
    """One normalized Cloudflare DNS record."""

    id: str
    type: str
    name: str
    content: str
    ttl: int
    proxied: bool | None = None
    proxiable: bool | None = None
    comment: str | None = None
    created_on: datetime | None = None
    modified_on: datetime | None = None


class CloudflareProxyStatusFact(KavalModel):
    """Aggregated proxy-mode summary for supported DNS records."""

    total_records: int
    proxied_records: int
    dns_only_records: int
    tunnel_routed_records: int


class CloudflareSslModeFact(KavalModel):
    """One normalized SSL/TLS mode fact."""

    id: str
    value: str
    editable: bool | None = None
    modified_on: datetime | None = None


class CloudflareTunnelFact(KavalModel):
    """One normalized Cloudflare tunnel summary."""

    id: str
    name: str
    status: str | None = None
    created_at: datetime | None = None
    deleted_at: datetime | None = None
    tun_type: str | None = None
    config_src: str | None = None
    remote_config: bool | None = None


class CloudflareTunnelConnectionFact(KavalModel):
    """One normalized Cloudflare tunnel connection record."""

    colo_name: str | None = None
    client_id: str | None = None
    client_version: str | None = None
    arch: str | None = None
    opened_at: datetime | None = None
    is_pending_reconnect: bool = False
    origin_ip: str | None = None


class CloudflareTunnelStatusFact(KavalModel):
    """Aggregated tunnel status fact for the local cloudflared context."""

    status: str | None = None
    connection_count: int
    active_connections: int
    pending_reconnects: int
    is_active: bool
    last_connected_at: datetime | None = None


class CloudflareOriginCertificateFact(KavalModel):
    """One normalized Cloudflare Origin CA certificate summary."""

    identifier: str
    hostnames: list[str] = Field(default_factory=list)
    signature: str | None = None
    requested_validity_days: int | None = None
    expires_on: datetime | None = None


class CloudflareOriginCertificateAccessFact(KavalModel):
    """Availability of origin-certificate facts under the supplied token."""

    available: bool
    reason: str | None = None


class _CloudflarePayloadModel(BaseModel):
    """Tolerant parser for Cloudflare API payloads."""

    model_config = ConfigDict(extra="ignore")


class _CloudflareEnvelopeErrorPayload(_CloudflarePayloadModel):
    """Subset of Cloudflare envelope error fields."""

    code: int | None = None
    message: str | None = None


class _CloudflareResultInfoPayload(_CloudflarePayloadModel):
    """Pagination metadata from Cloudflare list responses."""

    page: int | None = None
    per_page: int | None = None
    total_pages: int | None = None


class _CloudflareZonePayload(_CloudflarePayloadModel):
    """Subset of zone fields consumed by the adapter."""

    id: str
    name: str
    status: str | None = None
    paused: bool = False
    type: str | None = None


class _CloudflareDnsRecordPayload(_CloudflarePayloadModel):
    """Subset of DNS record fields consumed by the adapter."""

    id: str
    type: str
    name: str
    content: str
    ttl: int
    proxied: bool | None = None
    proxiable: bool | None = None
    comment: str | None = None
    created_on: datetime | None = None
    modified_on: datetime | None = None


class _CloudflareSslModePayload(_CloudflarePayloadModel):
    """Subset of zone-setting fields consumed by the adapter."""

    id: str
    value: str
    editable: bool | None = None
    modified_on: datetime | None = None


class _CloudflareTunnelPayload(_CloudflarePayloadModel):
    """Subset of tunnel fields consumed by the adapter."""

    id: str
    name: str
    status: str | None = None
    created_at: datetime | None = None
    deleted_at: datetime | None = None
    tun_type: str | None = None
    config_src: str | None = None
    remote_config: bool | None = None


class _CloudflareTunnelConnectionPayload(_CloudflarePayloadModel):
    """Subset of tunnel-connection fields consumed by the adapter."""

    colo_name: str | None = None
    client_id: str | None = None
    client_version: str | None = None
    arch: str | None = None
    opened_at: datetime | None = None
    is_pending_reconnect: bool = False
    origin_ip: str | None = None


class _CloudflareOriginCertificatePayload(_CloudflarePayloadModel):
    """Subset of Origin CA certificate fields consumed by the adapter."""

    id: str | None = None
    serial_number: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    signature: str | None = None
    requested_validity: int | None = None
    expires_on: datetime | None = None


@dataclass(frozen=True, slots=True)
class CloudflareClient:
    """Minimal read-only client for the Cloudflare HTTP API."""

    config: CloudflareClientConfig = CloudflareClientConfig()
    transport: RequestTransport | None = None

    def fetch_zone(self, *, api_token: str, zone_name: str) -> CloudflareZoneFact:
        """Resolve one Cloudflare zone by its configured name."""
        result, _ = self._get_result(
            "/zones",
            api_token=api_token,
            query={"name": zone_name},
            auth_error_message="Cloudflare token requires Zone Read to resolve the zone",
        )
        if not isinstance(result, list):
            raise CloudflareResponseError("Cloudflare zone lookup response was not a list")
        try:
            zones = [_CloudflareZonePayload.model_validate(item) for item in result]
        except ValidationError as exc:
            raise CloudflareResponseError("Cloudflare zone payload shape was invalid") from exc
        if not zones:
            raise CloudflareConfigurationError(
                f"Cloudflare zone {zone_name!r} was not found"
            )
        exact_matches = [zone for zone in zones if zone.name == zone_name]
        if len(exact_matches) != 1:
            raise CloudflareConfigurationError(
                f"Cloudflare zone {zone_name!r} did not resolve to exactly one zone"
            )
        return CloudflareZoneFact.model_validate(exact_matches[0].model_dump(mode="python"))

    def fetch_dns_records(
        self,
        *,
        api_token: str,
        zone_id: str,
    ) -> list[CloudflareDnsRecordFact]:
        """Fetch supported DNS records from one Cloudflare zone."""
        records: list[CloudflareDnsRecordFact] = []
        page = 1
        while page <= self.config.max_dns_pages:
            result, result_info = self._get_result(
                f"/zones/{zone_id}/dns_records",
                api_token=api_token,
                query={
                    "page": page,
                    "per_page": self.config.dns_page_size,
                },
                auth_error_message=(
                    "Cloudflare token requires DNS Read to fetch zone records"
                ),
            )
            if not isinstance(result, list):
                raise CloudflareResponseError(
                    "Cloudflare DNS record response was not a list"
                )
            try:
                payloads = [
                    _CloudflareDnsRecordPayload.model_validate(item)
                    for item in result
                ]
            except ValidationError as exc:
                raise CloudflareResponseError(
                    "Cloudflare DNS record payload shape was invalid"
                ) from exc
            records.extend(
                CloudflareDnsRecordFact.model_validate(item.model_dump(mode="python"))
                for item in payloads
                if item.type in _SUPPORTED_DNS_TYPES
            )
            total_pages = 1 if result_info is None else result_info.total_pages or 1
            if page >= total_pages:
                return records
            page += 1
        raise CloudflareResponseError(
            "Cloudflare DNS pagination exceeded the configured page limit"
        )

    def fetch_ssl_mode(
        self,
        *,
        api_token: str,
        zone_id: str,
    ) -> CloudflareSslModeFact:
        """Fetch the zone SSL/TLS mode setting."""
        result, _ = self._get_result(
            f"/zones/{zone_id}/settings/ssl",
            api_token=api_token,
            auth_error_message=(
                "Cloudflare token requires Zone Settings Read to fetch SSL mode"
            ),
        )
        if not isinstance(result, Mapping):
            raise CloudflareResponseError("Cloudflare SSL mode response was not an object")
        try:
            payload = _CloudflareSslModePayload.model_validate(result)
        except ValidationError as exc:
            raise CloudflareResponseError(
                "Cloudflare SSL mode payload shape was invalid"
            ) from exc
        return CloudflareSslModeFact.model_validate(payload.model_dump(mode="python"))

    def fetch_tunnel(
        self,
        *,
        api_token: str,
        account_id: str,
        tunnel_id: str,
    ) -> CloudflareTunnelFact:
        """Fetch one Cloudflare tunnel bound to the local cloudflared service."""
        result, _ = self._get_result(
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}",
            api_token=api_token,
            auth_error_message=(
                "Cloudflare token requires an account-scoped tunnel-read "
                "permission to fetch tunnel metadata"
            ),
        )
        if not isinstance(result, Mapping):
            raise CloudflareResponseError("Cloudflare tunnel response was not an object")
        try:
            payload = _CloudflareTunnelPayload.model_validate(result)
        except ValidationError as exc:
            raise CloudflareResponseError(
                "Cloudflare tunnel payload shape was invalid"
            ) from exc
        if payload.id != tunnel_id:
            raise CloudflareConfigurationError(
                f"Cloudflare tunnel {tunnel_id!r} did not resolve correctly"
            )
        return CloudflareTunnelFact.model_validate(payload.model_dump(mode="python"))

    def fetch_tunnel_connections(
        self,
        *,
        api_token: str,
        account_id: str,
        tunnel_id: str,
    ) -> list[CloudflareTunnelConnectionFact]:
        """Fetch current connection state for one Cloudflare tunnel."""
        result, _ = self._get_result(
            f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
            api_token=api_token,
            auth_error_message=(
                "Cloudflare token requires an account-scoped tunnel-read "
                "permission to fetch tunnel status"
            ),
        )
        if not isinstance(result, list):
            raise CloudflareResponseError(
                "Cloudflare tunnel-connection response was not a list"
            )
        try:
            payloads = [
                _CloudflareTunnelConnectionPayload.model_validate(item)
                for item in result
            ]
        except ValidationError as exc:
            raise CloudflareResponseError(
                "Cloudflare tunnel-connection payload shape was invalid"
            ) from exc
        return [
            CloudflareTunnelConnectionFact.model_validate(item.model_dump(mode="python"))
            for item in payloads
        ]

    def fetch_origin_certificates(
        self,
        *,
        api_token: str,
        zone_id: str,
    ) -> list[CloudflareOriginCertificateFact]:
        """Fetch Origin CA certificate summaries when the token scope allows it."""
        result, _ = self._get_result(
            "/certificates",
            api_token=api_token,
            query={"zone_id": zone_id},
            auth_error_message=(
                "Cloudflare token lacks permission to fetch origin certificates"
            ),
        )
        if not isinstance(result, list):
            raise CloudflareResponseError(
                "Cloudflare origin-certificate response was not a list"
            )
        try:
            payloads = [
                _CloudflareOriginCertificatePayload.model_validate(item)
                for item in result
            ]
        except ValidationError as exc:
            raise CloudflareResponseError(
                "Cloudflare origin-certificate payload shape was invalid"
            ) from exc
        return [
            CloudflareOriginCertificateFact(
                identifier=item.id or item.serial_number or "unknown",
                hostnames=list(item.hostnames),
                signature=item.signature,
                requested_validity_days=item.requested_validity,
                expires_on=item.expires_on,
            )
            for item in payloads
        ]

    def _get_result(
        self,
        path: str,
        *,
        api_token: str,
        auth_error_message: str,
        query: Mapping[str, str | int] | None = None,
    ) -> tuple[object | None, _CloudflareResultInfoPayload | None]:
        """Fetch one Cloudflare response envelope and return its result payload."""
        payload = self._request_json(
            path=path,
            api_token=api_token,
            auth_error_message=auth_error_message,
            query=query,
        )
        if not isinstance(payload, Mapping):
            raise CloudflareResponseError("Cloudflare API response was not an object")
        success = payload.get("success")
        if success is not True:
            raise CloudflareResponseError(_cloudflare_error_message(payload))
        result_info_payload = payload.get("result_info")
        result_info: _CloudflareResultInfoPayload | None = None
        if result_info_payload is not None:
            if not isinstance(result_info_payload, Mapping):
                raise CloudflareResponseError(
                    "Cloudflare result_info payload was not an object"
                )
            try:
                result_info = _CloudflareResultInfoPayload.model_validate(
                    result_info_payload
                )
            except ValidationError as exc:
                raise CloudflareResponseError(
                    "Cloudflare result_info payload shape was invalid"
                ) from exc
        return payload.get("result"), result_info

    def _request_json(
        self,
        *,
        path: str,
        api_token: str,
        auth_error_message: str,
        query: Mapping[str, str | int] | None = None,
    ) -> object:
        """Send one authenticated GET request to the Cloudflare API."""
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        http_request = request.Request(
            self.config.endpoint(path, query=query),
            method="GET",
            headers=headers,
        )
        try:
            response_body = self._transport()(http_request, self.config.timeout_seconds)
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                detail = _http_error_message(exc)
                if detail is not None:
                    raise CloudflareAuthError(f"{auth_error_message}: {detail}") from exc
                raise CloudflareAuthError(auth_error_message) from exc
            raise CloudflareTransportError("Cloudflare API request failed") from exc
        except (TimeoutError, OSError, error.URLError) as exc:
            raise CloudflareTransportError("Cloudflare API request failed") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CloudflareResponseError("Cloudflare API returned invalid JSON") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


@dataclass(frozen=True, slots=True)
class CloudflareAdapter:
    """Read-only deep-inspection adapter for Cloudflare-backed ingress."""

    client: CloudflareClient = CloudflareClient()

    adapter_id: str = "cloudflare_api"
    surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
        AdapterSurfaceBinding(
            descriptor_id="networking/cloudflared",
            surface_id="dns_records",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/cloudflared",
            surface_id="ssl_mode",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/cloudflared",
            surface_id="tunnel_status",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/cloudflared",
            surface_id="origin_certificates",
        ),
    )
    credential_keys: tuple[str, ...] = (
        "api_token",
        "zone_name",
        "account_id",
        "tunnel_id",
    )
    supported_versions: str | None = None
    read_only: bool = True

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Collect approved-scope Cloudflare facts for the local cloudflared service."""
        del service

        api_token = credentials.get("api_token", "").strip()
        zone_name = credentials.get("zone_name", "").strip()
        account_id = credentials.get("account_id", "").strip()
        tunnel_id = credentials.get("tunnel_id", "").strip()
        now = datetime.now(tz=UTC)
        missing_keys = tuple(
            key
            for key, value in (
                ("api_token", api_token),
                ("zone_name", zone_name),
                ("account_id", account_id),
                ("tunnel_id", tunnel_id),
            )
            if not value
        )
        if missing_keys:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=(
                    "Cloudflare adapter requires configured values for "
                    f"{', '.join(missing_keys)}"
                ),
            )

        try:
            zone = self.client.fetch_zone(api_token=api_token, zone_name=zone_name)
            dns_records = self.client.fetch_dns_records(
                api_token=api_token,
                zone_id=zone.id,
            )
            ssl_mode = self.client.fetch_ssl_mode(
                api_token=api_token,
                zone_id=zone.id,
            )
            tunnel = self.client.fetch_tunnel(
                api_token=api_token,
                account_id=account_id,
                tunnel_id=tunnel_id,
            )
            tunnel_connections = self.client.fetch_tunnel_connections(
                api_token=api_token,
                account_id=account_id,
                tunnel_id=tunnel_id,
            )
        except CloudflareAuthError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except CloudflareTransportError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.CONNECTION_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except CloudflareResponseError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.PARSE_ERROR,
                timestamp=now,
                reason=str(exc),
            )
        except CloudflareConfigurationError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.DEGRADED,
                timestamp=now,
                reason=str(exc),
            )

        origin_certificates: list[CloudflareOriginCertificateFact] = []
        origin_certificate_access = CloudflareOriginCertificateAccessFact(
            available=False,
            reason="Cloudflare origin certificates were not queried",
        )
        try:
            origin_certificates = self.client.fetch_origin_certificates(
                api_token=api_token,
                zone_id=zone.id,
            )
            origin_certificate_access = CloudflareOriginCertificateAccessFact(
                available=True,
                reason=None,
            )
        except (
            CloudflareAuthError,
            CloudflareTransportError,
            CloudflareResponseError,
            CloudflareConfigurationError,
        ) as exc:
            origin_certificate_access = CloudflareOriginCertificateAccessFact(
                available=False,
                reason=str(exc),
            )

        tunnel_dns_records = _tunnel_dns_records(dns_records, tunnel_id=tunnel_id)
        tunnel_status = _tunnel_status(tunnel, tunnel_connections)
        proxy_status = _proxy_status(dns_records, tunnel_dns_records)

        return AdapterResult(
            adapter_id=self.adapter_id,
            status=AdapterStatus.SUCCESS,
            facts={
                "zone": zone.model_dump(mode="json"),
                "dns_records": [item.model_dump(mode="json") for item in dns_records],
                "tunnel_dns_records": [
                    item.model_dump(mode="json") for item in tunnel_dns_records
                ],
                "proxy_status": proxy_status.model_dump(mode="json"),
                "ssl_mode": ssl_mode.model_dump(mode="json"),
                "tunnel": tunnel.model_dump(mode="json"),
                "tunnel_connections": [
                    item.model_dump(mode="json")
                    for item in tunnel_connections
                ],
                "tunnel_status": tunnel_status.model_dump(mode="json"),
                "origin_certificates": [
                    item.model_dump(mode="json")
                    for item in origin_certificates
                ],
                "origin_certificate_access": origin_certificate_access.model_dump(
                    mode="json"
                ),
            },
            edges_discovered=[],
            timestamp=now,
            reason=None,
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the Cloudflare API."""
    with request.urlopen(http_request, timeout=timeout_seconds) as response:
        return cast(bytes, response.read())


def _proxy_status(
    dns_records: list[CloudflareDnsRecordFact],
    tunnel_dns_records: list[CloudflareDnsRecordFact],
) -> CloudflareProxyStatusFact:
    """Build an aggregate proxy summary for supported DNS records."""
    return CloudflareProxyStatusFact(
        total_records=len(dns_records),
        proxied_records=sum(record.proxied is True for record in dns_records),
        dns_only_records=sum(record.proxied is False for record in dns_records),
        tunnel_routed_records=len(tunnel_dns_records),
    )


def _tunnel_dns_records(
    dns_records: list[CloudflareDnsRecordFact],
    *,
    tunnel_id: str,
) -> list[CloudflareDnsRecordFact]:
    """Return zone records that route to the configured cloudflared tunnel."""
    expected_target = f"{tunnel_id}.cfargotunnel.com"
    return [
        record
        for record in dns_records
        if record.content.rstrip(".") == expected_target
    ]


def _tunnel_status(
    tunnel: CloudflareTunnelFact,
    tunnel_connections: list[CloudflareTunnelConnectionFact],
) -> CloudflareTunnelStatusFact:
    """Build an aggregate tunnel-status fact from metadata and live connections."""
    opened_at_values = [
        connection.opened_at
        for connection in tunnel_connections
        if connection.opened_at is not None
    ]
    last_connected_at = max(
        opened_at_values,
        default=None,
    )
    pending_reconnects = sum(
        connection.is_pending_reconnect for connection in tunnel_connections
    )
    active_connections = len(tunnel_connections) - pending_reconnects
    return CloudflareTunnelStatusFact(
        status=tunnel.status,
        connection_count=len(tunnel_connections),
        active_connections=active_connections,
        pending_reconnects=pending_reconnects,
        is_active=active_connections > 0,
        last_connected_at=last_connected_at,
    )


def _cloudflare_error_message(payload: Mapping[str, object]) -> str:
    """Return the first Cloudflare envelope error message when present."""
    errors = payload.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if not isinstance(item, Mapping):
                continue
            try:
                parsed = _CloudflareEnvelopeErrorPayload.model_validate(item)
            except ValidationError:
                continue
            if parsed.message:
                return f"Cloudflare API reported failure: {parsed.message}"
    return "Cloudflare API reported failure"


def _http_error_message(exc: error.HTTPError) -> str | None:
    """Extract a useful error message from an HTTP error response body."""
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
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return None
    for item in errors:
        if not isinstance(item, Mapping):
            continue
        try:
            parsed = _CloudflareEnvelopeErrorPayload.model_validate(item)
        except ValidationError:
            continue
        if parsed.message:
            return parsed.message
    return None
