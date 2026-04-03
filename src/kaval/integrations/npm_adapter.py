"""Read-only Nginx Proxy Manager deep-inspection adapter."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Callable, cast
from urllib import error, parse, request

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kaval.integrations.service_adapters import (
    AdapterDiscoveredEdge,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.models import KavalModel, Service

type RequestTransport = Callable[[request.Request, float], bytes]


class NginxProxyManagerError(RuntimeError):
    """Base error for Nginx Proxy Manager adapter failures."""


class NginxProxyManagerTransportError(NginxProxyManagerError):
    """Raised when the NPM HTTP transport fails."""


class NginxProxyManagerAuthError(NginxProxyManagerError):
    """Raised when the NPM API rejects authentication."""


class NginxProxyManagerResponseError(NginxProxyManagerError):
    """Raised when the NPM API response shape is invalid."""


@dataclass(frozen=True, slots=True)
class NginxProxyManagerClientConfig:
    """Immutable runtime configuration for the NPM API client."""

    base_url: str = "http://localhost:81"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"

    def __post_init__(self) -> None:
        """Normalize and validate the configured NPM endpoint."""
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

    def endpoint(self, path: str, query: Mapping[str, str] | None = None) -> str:
        """Build one fully qualified NPM API endpoint URL."""
        trimmed_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


class NpmVersionFact(KavalModel):
    """One normalized NPM version fact."""

    major: int
    minor: int
    revision: int

    @property
    def version_string(self) -> str:
        """Return the dotted version string."""
        return f"{self.major}.{self.minor}.{self.revision}"


class NpmProxyLocationFact(KavalModel):
    """One custom proxy-host location target."""

    path: str
    forward_scheme: str
    forward_host: str
    forward_port: int
    forward_path: str | None = None


class NpmProxyHostFact(KavalModel):
    """One normalized proxy-host summary fact."""

    id: int
    domain_names: list[str]
    forward_scheme: str
    forward_host: str
    forward_port: int
    enabled: bool
    certificate_id: int | None = None
    nginx_online: bool | None = None
    locations: list[NpmProxyLocationFact] = Field(default_factory=list)


class NpmCertificateFact(KavalModel):
    """One normalized certificate summary fact."""

    id: int
    provider: str
    nice_name: str
    domain_names: list[str]
    expires_on: datetime | None = None


class NpmCertificateBindingFact(KavalModel):
    """A derived certificate binding between one proxy host and one certificate."""

    proxy_host_id: int
    proxy_host_domains: list[str]
    certificate_id: int
    certificate_domains: list[str]
    certificate_expires_on: datetime | None = None


class _NpmPayloadModel(BaseModel):
    """Tolerant parser for NPM API payloads."""

    model_config = ConfigDict(extra="ignore")


class _NpmVersionPayload(_NpmPayloadModel):
    """Version payload from the NPM root API route."""

    major: int
    minor: int
    revision: int


class _NpmStatusPayload(_NpmPayloadModel):
    """Health and version payload from the NPM root API route."""

    status: str
    setup: bool
    version: _NpmVersionPayload


class _NpmTokenPayload(_NpmPayloadModel):
    """Token payload returned by the NPM auth route."""

    token: str


class _NpmProxyMetaPayload(_NpmPayloadModel):
    """Subset of proxy-host runtime metadata used by the adapter."""

    nginx_online: bool | None = None


class _NpmProxyLocationPayload(_NpmPayloadModel):
    """One custom location entry nested under a proxy host."""

    path: str
    forward_scheme: str
    forward_host: str
    forward_port: int
    forward_path: str | None = None


class _NpmProxyHostPayload(_NpmPayloadModel):
    """Subset of proxy-host fields consumed by the adapter."""

    id: int
    domain_names: list[str]
    forward_host: str
    forward_port: int
    forward_scheme: str
    enabled: bool
    certificate_id: int | None = None
    locations: list[_NpmProxyLocationPayload] = Field(default_factory=list)
    meta: _NpmProxyMetaPayload = Field(default_factory=_NpmProxyMetaPayload)


class _NpmCertificatePayload(_NpmPayloadModel):
    """Subset of certificate fields consumed by the adapter."""

    id: int
    provider: str
    nice_name: str
    domain_names: list[str]
    expires_on: datetime | None = None


@dataclass(frozen=True, slots=True)
class NginxProxyManagerClient:
    """Minimal read-only client for the NPM HTTP API."""

    config: NginxProxyManagerClientConfig = NginxProxyManagerClientConfig()
    transport: RequestTransport | None = None

    def fetch_version(self) -> NpmVersionFact:
        """Fetch the current NPM version from the root API status route."""
        payload = self._get_json("/api")
        if not isinstance(payload, Mapping):
            raise NginxProxyManagerResponseError("NPM status response was not an object")
        try:
            parsed_payload = _NpmStatusPayload.model_validate(payload)
        except ValidationError as exc:
            raise NginxProxyManagerResponseError("NPM status payload shape was invalid") from exc
        return NpmVersionFact.model_validate(parsed_payload.version.model_dump(mode="python"))

    def fetch_token(self, *, identity: str, secret: str) -> str:
        """Authenticate against the NPM API and return a bearer token."""
        payload = self._request_json(
            path="/api/tokens",
            method="POST",
            payload={"identity": identity, "secret": secret},
        )
        if not isinstance(payload, Mapping):
            raise NginxProxyManagerResponseError("NPM token response was not an object")
        if payload.get("requires_2fa") is True:
            raise NginxProxyManagerAuthError("NPM 2FA challenge flow is not supported")
        try:
            parsed_payload = _NpmTokenPayload.model_validate(payload)
        except ValidationError as exc:
            raise NginxProxyManagerResponseError("NPM token payload shape was invalid") from exc
        return parsed_payload.token

    def fetch_proxy_hosts(self, *, token: str) -> list[NpmProxyHostFact]:
        """Fetch proxy-host inventory from the NPM API."""
        payload = self._get_json("/api/nginx/proxy-hosts", token=token)
        if not isinstance(payload, list):
            raise NginxProxyManagerResponseError("NPM proxy-host response was not a list")
        try:
            parsed_payload = [_NpmProxyHostPayload.model_validate(item) for item in payload]
        except ValidationError as exc:
            raise NginxProxyManagerResponseError(
                "NPM proxy-host payload shape was invalid"
            ) from exc
        return [
            NpmProxyHostFact(
                id=item.id,
                domain_names=list(item.domain_names),
                forward_scheme=item.forward_scheme,
                forward_host=item.forward_host,
                forward_port=item.forward_port,
                enabled=item.enabled,
                certificate_id=item.certificate_id,
                nginx_online=item.meta.nginx_online,
                locations=[
                    NpmProxyLocationFact.model_validate(location.model_dump(mode="python"))
                    for location in item.locations
                ],
            )
            for item in parsed_payload
        ]

    def fetch_certificates(self, *, token: str) -> list[NpmCertificateFact]:
        """Fetch certificate inventory from the NPM API."""
        payload = self._get_json("/api/nginx/certificates", token=token)
        if not isinstance(payload, list):
            raise NginxProxyManagerResponseError("NPM certificate response was not a list")
        try:
            parsed_payload = [
                _NpmCertificatePayload.model_validate(item)
                for item in payload
            ]
        except ValidationError as exc:
            raise NginxProxyManagerResponseError(
                "NPM certificate payload shape was invalid"
            ) from exc
        return [
            NpmCertificateFact.model_validate(item.model_dump(mode="python"))
            for item in parsed_payload
        ]

    def _get_json(
        self,
        path: str,
        *,
        token: str | None = None,
    ) -> object:
        """Fetch one JSON payload from the NPM API."""
        return self._request_json(path=path, method="GET", token=token)

    def _request_json(
        self,
        *,
        path: str,
        method: str,
        token: str | None = None,
        payload: Mapping[str, str] | None = None,
    ) -> object:
        """Send one JSON request to the NPM API and decode the response body."""
        headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        body: bytes | None = None
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            self.config.endpoint(path),
            data=body,
            headers=headers,
            method=method,
        )
        try:
            response_body = self._transport()(http_request, self.config.timeout_seconds)
        except NginxProxyManagerError:
            raise
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise NginxProxyManagerAuthError("NPM authentication failed") from exc
            raise NginxProxyManagerTransportError("NPM API request failed") from exc
        except (TimeoutError, OSError, error.URLError) as exc:
            raise NginxProxyManagerTransportError("NPM API request failed") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NginxProxyManagerResponseError("NPM API returned invalid JSON") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


@dataclass(frozen=True, slots=True)
class NginxProxyManagerAdapter:
    """Read-only deep-inspection adapter for Nginx Proxy Manager."""

    client: NginxProxyManagerClient = NginxProxyManagerClient()

    adapter_id: str = "nginx_proxy_manager_api"
    surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
        AdapterSurfaceBinding(
            descriptor_id="networking/nginx_proxy_manager",
            surface_id="proxy_hosts",
        ),
        AdapterSurfaceBinding(
            descriptor_id="networking/nginx_proxy_manager",
            surface_id="certificates",
        ),
    )
    credential_keys: tuple[str, ...] = ("identity", "secret")
    supported_versions: str | None = ">=2.0,<3.0"
    read_only: bool = True

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Authenticate to NPM and collect structured proxy/certificate facts."""
        identity = credentials.get("identity", "").strip()
        secret = credentials.get("secret", "")
        now = datetime.now(tz=UTC)
        if not identity or not secret:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason="NPM identity and secret are required",
            )

        try:
            version = self.client.fetch_version()
            if version.major != 2:
                return AdapterResult(
                    adapter_id=self.adapter_id,
                    status=AdapterStatus.VERSION_INCOMPATIBLE,
                    timestamp=now,
                    reason=(
                        f"NPM version {version.version_string} is outside the supported "
                        f"range {self.supported_versions}"
                    ),
                )

            token = self.client.fetch_token(identity=identity, secret=secret)
            proxy_hosts = self.client.fetch_proxy_hosts(token=token)
            certificates = self.client.fetch_certificates(token=token)
        except NginxProxyManagerAuthError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except NginxProxyManagerTransportError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.CONNECTION_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except NginxProxyManagerResponseError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.PARSE_ERROR,
                timestamp=now,
                reason=str(exc),
            )

        certificate_map = {certificate.id: certificate for certificate in certificates}
        certificate_bindings = [
            NpmCertificateBindingFact(
                proxy_host_id=proxy_host.id,
                proxy_host_domains=list(proxy_host.domain_names),
                certificate_id=proxy_host.certificate_id,
                certificate_domains=list(
                    certificate_map[proxy_host.certificate_id].domain_names
                ),
                certificate_expires_on=certificate_map[
                    proxy_host.certificate_id
                ].expires_on,
            )
            for proxy_host in proxy_hosts
            if proxy_host.certificate_id is not None
            and proxy_host.certificate_id in certificate_map
        ]

        return AdapterResult(
            adapter_id=self.adapter_id,
            status=AdapterStatus.SUCCESS,
            facts={
                "version": {
                    **version.model_dump(mode="json"),
                    "version_string": version.version_string,
                },
                "proxy_hosts": [item.model_dump(mode="json") for item in proxy_hosts],
                "certificates": [item.model_dump(mode="json") for item in certificates],
                "certificate_bindings": [
                    item.model_dump(mode="json")
                    for item in certificate_bindings
                ],
            },
            edges_discovered=_build_proxy_host_edges(proxy_hosts),
            timestamp=now,
            reason=None,
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the NPM API."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise NginxProxyManagerAuthError("NPM authentication failed") from exc
        raise NginxProxyManagerTransportError("NPM API request failed") from exc
    except (TimeoutError, OSError, error.URLError) as exc:
        raise NginxProxyManagerTransportError("NPM API request failed") from exc


def _build_proxy_host_edges(
    proxy_hosts: list[NpmProxyHostFact],
) -> list[AdapterDiscoveredEdge]:
    """Build deduplicated upstream dependency edges from proxy-host facts."""
    seen_targets: set[tuple[str, str]] = set()
    edges: list[AdapterDiscoveredEdge] = []
    for proxy_host in proxy_hosts:
        targets = [
            (
                "proxy_hosts",
                proxy_host.forward_host,
                ", ".join(proxy_host.domain_names),
            )
        ]
        targets.extend(
            (
                "proxy_hosts",
                location.forward_host,
                f"{', '.join(proxy_host.domain_names)}{location.path}",
            )
            for location in proxy_host.locations
        )
        for surface_id, target_service_name, target_context in targets:
            if _skip_upstream_target(target_service_name):
                continue
            key = (surface_id, target_service_name.casefold())
            if key in seen_targets:
                continue
            seen_targets.add(key)
            edges.append(
                AdapterDiscoveredEdge(
                    surface_id=surface_id,
                    target_service_name=target_service_name,
                    description=(
                        f"NPM proxy host routing for {target_context} targets "
                        f"{target_service_name}"
                    ),
                )
            )
    return edges


def _skip_upstream_target(target_service_name: str) -> bool:
    """Ignore empty or loopback targets that do not identify another service."""
    candidate = target_service_name.strip()
    if not candidate:
        return True
    if candidate.casefold() == "localhost":
        return True
    try:
        return ip_address(candidate).is_loopback
    except ValueError:
        return False
