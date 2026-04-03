"""Read-only Authentik deep-inspection adapter."""

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


class AuthentikError(RuntimeError):
    """Base error for Authentik adapter failures."""


class AuthentikTransportError(AuthentikError):
    """Raised when the Authentik HTTP transport fails."""


class AuthentikAuthError(AuthentikError):
    """Raised when the Authentik API rejects authentication."""


class AuthentikResponseError(AuthentikError):
    """Raised when the Authentik API response shape is invalid."""


@dataclass(frozen=True, slots=True)
class AuthentikClientConfig:
    """Immutable runtime configuration for the Authentik API client."""

    base_url: str = "http://localhost:9000/api/v3"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"
    page_size: int = 100

    def __post_init__(self) -> None:
        """Normalize and validate the configured Authentik endpoint."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if self.page_size <= 0:
            msg = "page_size must be positive"
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
        """Build one fully qualified Authentik API endpoint URL."""
        trimmed_path = path.lstrip("/")
        url = f"{self.base_url}/{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


class AuthentikProviderRefFact(KavalModel):
    """One safe provider reference embedded in topology facts."""

    pk: int
    name: str
    component: str
    meta_model_name: str
    assigned_application_slug: str | None = None
    assigned_application_name: str | None = None


class AuthentikApplicationFact(KavalModel):
    """One normalized Authentik application summary."""

    pk: str
    name: str
    slug: str
    launch_url: str | None = None
    open_in_new_tab: bool
    meta_launch_url: str | None = None
    meta_description: str | None = None
    meta_publisher: str | None = None
    group: str | None = None
    policy_engine_mode: str | None = None
    provider: AuthentikProviderRefFact | None = None
    backchannel_providers: list[AuthentikProviderRefFact] = Field(default_factory=list)


class AuthentikProviderFact(KavalModel):
    """One normalized Authentik provider summary."""

    pk: int
    name: str
    component: str
    meta_model_name: str
    verbose_name: str
    verbose_name_plural: str
    assigned_application_slug: str | None = None
    assigned_application_name: str | None = None
    assigned_backchannel_application_slug: str | None = None
    assigned_backchannel_application_name: str | None = None


class AuthentikOutpostFact(KavalModel):
    """One normalized Authentik outpost summary."""

    pk: str
    name: str
    type: str
    refresh_interval_s: int
    managed: str | None = None
    providers: list[AuthentikProviderRefFact] = Field(default_factory=list)


class AuthentikOutpostHealthFact(KavalModel):
    """One normalized Authentik outpost health record."""

    outpost_pk: str
    outpost_name: str
    uid: str
    hostname: str
    last_seen: datetime
    version: str
    version_should: str
    version_outdated: bool
    golang_version: str
    openssl_enabled: bool
    openssl_version: str
    fips_enabled: bool | None = None


class AuthentikSystemHealthFact(KavalModel):
    """One normalized Authentik version/health summary."""

    version_current: str
    version_latest: str
    version_latest_valid: bool
    outdated: bool
    outpost_outdated: bool


class _AuthentikPayloadModel(BaseModel):
    """Tolerant parser for Authentik API payloads."""

    model_config = ConfigDict(extra="ignore")


class _AuthentikPaginationPayload(_AuthentikPayloadModel):
    """Pagination metadata returned by Authentik list endpoints."""

    next: int | None = None
    previous: int | None = None
    count: int
    current: int
    total_pages: int
    start_index: int
    end_index: int


class _AuthentikProviderRefPayload(_AuthentikPayloadModel):
    """Subset of provider fields embedded in nested Authentik responses."""

    pk: int
    name: str
    component: str
    meta_model_name: str
    assigned_application_slug: str | None = None
    assigned_application_name: str | None = None


class _AuthentikApplicationPayload(_AuthentikPayloadModel):
    """Subset of application fields consumed by the adapter."""

    pk: str
    name: str
    slug: str
    provider_obj: _AuthentikProviderRefPayload | None = None
    backchannel_providers_obj: list[_AuthentikProviderRefPayload] = Field(default_factory=list)
    launch_url: str | None = None
    open_in_new_tab: bool = False
    meta_launch_url: str | None = None
    meta_description: str | None = None
    meta_publisher: str | None = None
    policy_engine_mode: str | None = None
    group: str | None = None


class _AuthentikProviderPayload(_AuthentikPayloadModel):
    """Subset of provider fields consumed by the adapter."""

    pk: int
    name: str
    component: str
    meta_model_name: str
    verbose_name: str
    verbose_name_plural: str
    assigned_application_slug: str | None = None
    assigned_application_name: str | None = None
    assigned_backchannel_application_slug: str | None = None
    assigned_backchannel_application_name: str | None = None


class _AuthentikOutpostPayload(_AuthentikPayloadModel):
    """Subset of outpost fields consumed by the adapter."""

    pk: str
    name: str
    type: str
    providers_obj: list[_AuthentikProviderRefPayload] = Field(default_factory=list)
    refresh_interval_s: int
    managed: str | None = None


class _AuthentikOutpostHealthPayload(_AuthentikPayloadModel):
    """Subset of outpost health fields consumed by the adapter."""

    uid: str
    last_seen: datetime
    version: str
    golang_version: str
    openssl_enabled: bool
    openssl_version: str
    fips_enabled: bool | None = None
    version_should: str
    version_outdated: bool
    hostname: str


class _AuthentikVersionPayload(_AuthentikPayloadModel):
    """Subset of Authentik system version fields consumed by the adapter."""

    version_current: str
    version_latest: str
    version_latest_valid: bool
    build_hash: str
    outdated: bool
    outpost_outdated: bool


class _AuthentikApplicationListPayload(_AuthentikPayloadModel):
    """Paginated application list response."""

    pagination: _AuthentikPaginationPayload
    results: list[_AuthentikApplicationPayload]


class _AuthentikProviderListPayload(_AuthentikPayloadModel):
    """Paginated provider list response."""

    pagination: _AuthentikPaginationPayload
    results: list[_AuthentikProviderPayload]


class _AuthentikOutpostListPayload(_AuthentikPayloadModel):
    """Paginated outpost list response."""

    pagination: _AuthentikPaginationPayload
    results: list[_AuthentikOutpostPayload]


@dataclass(frozen=True, slots=True)
class AuthentikClient:
    """Minimal read-only client for the Authentik HTTP API."""

    config: AuthentikClientConfig = AuthentikClientConfig()
    transport: RequestTransport | None = None

    def fetch_applications(self, *, api_token: str) -> list[AuthentikApplicationFact]:
        """Fetch Authentik applications from the paginated core endpoint."""
        payloads = self._paginate_applications(api_token=api_token)
        return [
            AuthentikApplicationFact(
                pk=item.pk,
                name=item.name,
                slug=item.slug,
                launch_url=item.launch_url,
                open_in_new_tab=item.open_in_new_tab,
                meta_launch_url=item.meta_launch_url,
                meta_description=item.meta_description,
                meta_publisher=item.meta_publisher,
                group=item.group,
                policy_engine_mode=item.policy_engine_mode,
                provider=(
                    _provider_ref_fact(item.provider_obj)
                    if item.provider_obj is not None
                    else None
                ),
                backchannel_providers=[
                    _provider_ref_fact(provider)
                    for provider in item.backchannel_providers_obj
                ],
            )
            for item in payloads
        ]

    def fetch_providers(self, *, api_token: str) -> list[AuthentikProviderFact]:
        """Fetch Authentik providers from the paginated provider endpoint."""
        payloads = self._paginate_providers(api_token=api_token)
        return [
            AuthentikProviderFact(
                pk=item.pk,
                name=item.name,
                component=item.component,
                meta_model_name=item.meta_model_name,
                verbose_name=item.verbose_name,
                verbose_name_plural=item.verbose_name_plural,
                assigned_application_slug=item.assigned_application_slug,
                assigned_application_name=item.assigned_application_name,
                assigned_backchannel_application_slug=item.assigned_backchannel_application_slug,
                assigned_backchannel_application_name=item.assigned_backchannel_application_name,
            )
            for item in payloads
        ]

    def fetch_outposts(self, *, api_token: str) -> list[AuthentikOutpostFact]:
        """Fetch Authentik outposts from the paginated outpost endpoint."""
        payloads = self._paginate_outposts(api_token=api_token)
        return [
            AuthentikOutpostFact(
                pk=item.pk,
                name=item.name,
                type=item.type,
                refresh_interval_s=item.refresh_interval_s,
                managed=item.managed,
                providers=[
                    _provider_ref_fact(provider) for provider in item.providers_obj
                ],
            )
            for item in payloads
        ]

    def fetch_outpost_health(
        self,
        *,
        api_token: str,
        outpost: AuthentikOutpostFact,
    ) -> list[AuthentikOutpostHealthFact]:
        """Fetch health records for one Authentik outpost."""
        payload = self._get_json(
            f"outposts/instances/{outpost.pk}/health/",
            api_token=api_token,
        )
        if not isinstance(payload, list):
            raise AuthentikResponseError("Authentik outpost health response was not a list")
        try:
            parsed_payload = [
                _AuthentikOutpostHealthPayload.model_validate(item) for item in payload
            ]
        except ValidationError as exc:
            raise AuthentikResponseError(
                "Authentik outpost health payload shape was invalid"
            ) from exc
        return [
            AuthentikOutpostHealthFact(
                outpost_pk=outpost.pk,
                outpost_name=outpost.name,
                uid=item.uid,
                hostname=item.hostname,
                last_seen=item.last_seen,
                version=item.version,
                version_should=item.version_should,
                version_outdated=item.version_outdated,
                golang_version=item.golang_version,
                openssl_enabled=item.openssl_enabled,
                openssl_version=item.openssl_version,
                fips_enabled=item.fips_enabled,
            )
            for item in parsed_payload
        ]

    def fetch_system_health(self, *, api_token: str) -> AuthentikSystemHealthFact:
        """Fetch Authentik's own version and outpost health summary."""
        payload = self._get_json("admin/version/", api_token=api_token)
        if not isinstance(payload, Mapping):
            raise AuthentikResponseError("Authentik version response was not an object")
        try:
            parsed_payload = _AuthentikVersionPayload.model_validate(payload)
        except ValidationError as exc:
            raise AuthentikResponseError(
                "Authentik version payload shape was invalid"
            ) from exc
        return AuthentikSystemHealthFact(
            version_current=parsed_payload.version_current,
            version_latest=parsed_payload.version_latest,
            version_latest_valid=parsed_payload.version_latest_valid,
            outdated=parsed_payload.outdated,
            outpost_outdated=parsed_payload.outpost_outdated,
        )

    def _paginate_applications(
        self,
        *,
        api_token: str,
    ) -> list[_AuthentikApplicationPayload]:
        """Fetch all application pages."""
        page = 1
        results: list[_AuthentikApplicationPayload] = []
        while True:
            payload = self._get_json(
                "core/applications/",
                api_token=api_token,
                query={
                    "page": page,
                    "page_size": self.config.page_size,
                },
            )
            if not isinstance(payload, Mapping):
                raise AuthentikResponseError(
                    "Authentik application list response was not an object"
                )
            try:
                parsed_payload = _AuthentikApplicationListPayload.model_validate(payload)
            except ValidationError as exc:
                raise AuthentikResponseError(
                    "Authentik application list payload shape was invalid"
                ) from exc
            results.extend(parsed_payload.results)
            if parsed_payload.pagination.next is None:
                break
            page = parsed_payload.pagination.next
        return results

    def _paginate_providers(
        self,
        *,
        api_token: str,
    ) -> list[_AuthentikProviderPayload]:
        """Fetch all provider pages."""
        page = 1
        results: list[_AuthentikProviderPayload] = []
        while True:
            payload = self._get_json(
                "providers/all/",
                api_token=api_token,
                query={
                    "page": page,
                    "page_size": self.config.page_size,
                },
            )
            if not isinstance(payload, Mapping):
                raise AuthentikResponseError(
                    "Authentik provider list response was not an object"
                )
            try:
                parsed_payload = _AuthentikProviderListPayload.model_validate(payload)
            except ValidationError as exc:
                raise AuthentikResponseError(
                    "Authentik provider list payload shape was invalid"
                ) from exc
            results.extend(parsed_payload.results)
            if parsed_payload.pagination.next is None:
                break
            page = parsed_payload.pagination.next
        return results

    def _paginate_outposts(
        self,
        *,
        api_token: str,
    ) -> list[_AuthentikOutpostPayload]:
        """Fetch all outpost pages."""
        page = 1
        results: list[_AuthentikOutpostPayload] = []
        while True:
            payload = self._get_json(
                "outposts/instances/",
                api_token=api_token,
                query={
                    "page": page,
                    "page_size": self.config.page_size,
                },
            )
            if not isinstance(payload, Mapping):
                raise AuthentikResponseError(
                    "Authentik outpost list response was not an object"
                )
            try:
                parsed_payload = _AuthentikOutpostListPayload.model_validate(payload)
            except ValidationError as exc:
                raise AuthentikResponseError(
                    "Authentik outpost list payload shape was invalid"
                ) from exc
            results.extend(parsed_payload.results)
            if parsed_payload.pagination.next is None:
                break
            page = parsed_payload.pagination.next
        return results

    def _get_json(
        self,
        path: str,
        *,
        api_token: str,
        query: Mapping[str, str | int] | None = None,
    ) -> object:
        """Fetch one JSON payload from the Authentik API."""
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_token}",
            "User-Agent": self.config.user_agent,
        }
        http_request = request.Request(
            self.config.endpoint(path, query=query),
            headers=headers,
            method="GET",
        )
        try:
            response_body = self._transport()(http_request, self.config.timeout_seconds)
        except AuthentikError:
            raise
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise AuthentikAuthError("Authentik authentication failed") from exc
            raise AuthentikTransportError("Authentik API request failed") from exc
        except (TimeoutError, OSError, error.URLError) as exc:
            raise AuthentikTransportError("Authentik API request failed") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthentikResponseError("Authentik API returned invalid JSON") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


@dataclass(frozen=True, slots=True)
class AuthentikAdapter:
    """Read-only deep-inspection adapter for Authentik."""

    client: AuthentikClient = AuthentikClient()

    adapter_id: str = "authentik_api"
    surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
        AdapterSurfaceBinding(
            descriptor_id="identity/authentik",
            surface_id="applications",
        ),
        AdapterSurfaceBinding(
            descriptor_id="identity/authentik",
            surface_id="providers",
        ),
        AdapterSurfaceBinding(
            descriptor_id="identity/authentik",
            surface_id="outposts",
        ),
        AdapterSurfaceBinding(
            descriptor_id="identity/authentik",
            surface_id="outpost_health",
        ),
        AdapterSurfaceBinding(
            descriptor_id="identity/authentik",
            surface_id="system_health",
        ),
    )
    credential_keys: tuple[str, ...] = ("api_token",)
    supported_versions: str | None = None
    read_only: bool = True

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Authenticate to Authentik and collect structured identity topology facts."""
        del service

        api_token = credentials.get("api_token", "").strip()
        now = datetime.now(tz=UTC)
        if not api_token:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason="Authentik API token is required",
            )

        try:
            applications = self.client.fetch_applications(api_token=api_token)
            providers = self.client.fetch_providers(api_token=api_token)
            outposts = self.client.fetch_outposts(api_token=api_token)
            outpost_health = [
                health_record
                for outpost in outposts
                for health_record in self.client.fetch_outpost_health(
                    api_token=api_token,
                    outpost=outpost,
                )
            ]
            system_health = self.client.fetch_system_health(api_token=api_token)
        except AuthentikAuthError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except AuthentikTransportError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.CONNECTION_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except AuthentikResponseError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.PARSE_ERROR,
                timestamp=now,
                reason=str(exc),
            )

        return AdapterResult(
            adapter_id=self.adapter_id,
            status=AdapterStatus.SUCCESS,
            facts={
                "applications": [
                    item.model_dump(mode="json") for item in applications
                ],
                "providers": [item.model_dump(mode="json") for item in providers],
                "outposts": [item.model_dump(mode="json") for item in outposts],
                "outpost_health": [
                    item.model_dump(mode="json") for item in outpost_health
                ],
                "system_health": system_health.model_dump(mode="json"),
            },
            edges_discovered=[],
            timestamp=now,
            reason=None,
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the Authentik API."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise AuthentikAuthError("Authentik authentication failed") from exc
        raise AuthentikTransportError("Authentik API request failed") from exc
    except (TimeoutError, OSError, error.URLError) as exc:
        raise AuthentikTransportError("Authentik API request failed") from exc


def _provider_ref_fact(
    payload: _AuthentikProviderRefPayload,
) -> AuthentikProviderRefFact:
    """Normalize one safe embedded provider reference."""
    return AuthentikProviderRefFact.model_validate(payload.model_dump(mode="python"))
