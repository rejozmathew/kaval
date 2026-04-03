"""Read-only Radarr deep-inspection adapter."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, cast
from urllib import error, request

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kaval.integrations.service_adapters import (
    AdapterDiscoveredEdge,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.models import KavalModel, Service

type RequestTransport = Callable[[request.Request, float], bytes]

_ATTENTION_QUEUE_STATUSES = frozenset(
    {"failed", "warning", "delay", "downloadClientUnavailable"}
)
_ATTENTION_TRACKED_DOWNLOAD_STATUSES = frozenset({"warning", "error"})
_ATTENTION_TRACKED_DOWNLOAD_STATES = frozenset(
    {"importBlocked", "failedPending", "failed"}
)


class RadarrError(RuntimeError):
    """Base error for Radarr adapter failures."""


class RadarrTransportError(RadarrError):
    """Raised when the Radarr HTTP transport fails."""


class RadarrAuthError(RadarrError):
    """Raised when the Radarr API rejects authentication."""


class RadarrResponseError(RadarrError):
    """Raised when the Radarr API response shape is invalid."""


@dataclass(frozen=True, slots=True)
class RadarrClientConfig:
    """Immutable runtime configuration for the Radarr API client."""

    base_url: str = "http://localhost:7878"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"

    def __post_init__(self) -> None:
        """Normalize and validate the configured Radarr endpoint."""
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
        """Build one fully qualified Radarr API endpoint URL."""
        trimmed_path = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{trimmed_path}"


class RadarrVersionFact(KavalModel):
    """One normalized Radarr version fact."""

    version_string: str
    major: int
    minor: int | None = None
    patch: int | None = None
    build: int | None = None


class RadarrRuntimeInfoFact(KavalModel):
    """One normalized Radarr runtime summary."""

    app_name: str | None = None
    instance_name: str | None = None
    branch: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    mode: str | None = None
    database_type: str | None = None
    is_docker: bool
    is_linux: bool
    is_windows: bool
    is_osx: bool
    is_production: bool


class RadarrProviderMessageFact(KavalModel):
    """One normalized provider-health message."""

    message: str | None = None
    type: str


class RadarrHealthIssueFact(KavalModel):
    """One normalized Radarr health issue."""

    source: str | None = None
    severity: str
    message: str | None = None
    wiki_url: str | None = None


class RadarrDownloadClientFact(KavalModel):
    """One normalized Radarr download-client summary."""

    id: int
    name: str | None = None
    implementation: str | None = None
    implementation_name: str | None = None
    enabled: bool
    protocol: str
    priority: int
    remove_completed_downloads: bool
    remove_failed_downloads: bool
    message: RadarrProviderMessageFact | None = None


class RadarrDownloadClientStatusFact(KavalModel):
    """Aggregated health/status summary for Radarr download clients."""

    configured: int
    enabled: int
    warning_count: int
    error_count: int


class RadarrIndexerFact(KavalModel):
    """One normalized Radarr indexer summary."""

    id: int
    name: str | None = None
    implementation: str | None = None
    implementation_name: str | None = None
    enable_rss: bool
    enable_automatic_search: bool
    enable_interactive_search: bool
    supports_rss: bool
    supports_search: bool
    protocol: str
    priority: int
    download_client_id: int
    message: RadarrProviderMessageFact | None = None


class RadarrIndexerStatusFact(KavalModel):
    """Aggregated health/status summary for Radarr indexers."""

    configured: int
    rss_enabled: int
    automatic_search_enabled: int
    interactive_search_enabled: int
    warning_count: int
    error_count: int


class RadarrQueueStatusFact(KavalModel):
    """One normalized Radarr queue-health summary."""

    total_count: int
    count: int
    unknown_count: int
    errors: bool
    warnings: bool
    unknown_errors: bool
    unknown_warnings: bool


class RadarrQueueStatusMessageFact(KavalModel):
    """One normalized queue item status-message bundle."""

    title: str | None = None
    messages: list[str] = Field(default_factory=list)


class RadarrQueueItemFact(KavalModel):
    """One normalized queue item that requires investigation attention."""

    id: int
    title: str | None = None
    status: str
    tracked_download_status: str
    tracked_download_state: str
    error_message: str | None = None
    download_client: str | None = None
    indexer: str | None = None
    estimated_completion_time: datetime | None = None
    added: datetime | None = None
    status_messages: list[RadarrQueueStatusMessageFact] = Field(default_factory=list)


class _RadarrPayloadModel(BaseModel):
    """Tolerant parser for Radarr API payloads."""

    model_config = ConfigDict(extra="ignore")


class _RadarrProviderMessagePayload(_RadarrPayloadModel):
    """Subset of provider message fields consumed by the adapter."""

    message: str | None = None
    type: str


class _RadarrHealthPayload(_RadarrPayloadModel):
    """Subset of Radarr health-check fields consumed by the adapter."""

    source: str | None = None
    type: str
    message: str | None = None
    wikiUrl: str | None = None


class _RadarrSystemPayload(_RadarrPayloadModel):
    """Subset of Radarr system-status fields consumed by the adapter."""

    appName: str | None = None
    instanceName: str | None = None
    version: str | None = None
    startupPath: str | None = None
    osName: str | None = None
    osVersion: str | None = None
    mode: str | None = None
    branch: str | None = None
    databaseType: str | None = None
    isProduction: bool
    isLinux: bool
    isOsx: bool
    isWindows: bool
    isDocker: bool


class _RadarrDownloadClientPayload(_RadarrPayloadModel):
    """Subset of download-client fields consumed by the adapter."""

    id: int
    name: str | None = None
    implementationName: str | None = None
    implementation: str | None = None
    message: _RadarrProviderMessagePayload | None = None
    enable: bool
    protocol: str
    priority: int
    removeCompletedDownloads: bool
    removeFailedDownloads: bool


class _RadarrIndexerPayload(_RadarrPayloadModel):
    """Subset of indexer fields consumed by the adapter."""

    id: int
    name: str | None = None
    implementationName: str | None = None
    implementation: str | None = None
    message: _RadarrProviderMessagePayload | None = None
    enableRss: bool
    enableAutomaticSearch: bool
    enableInteractiveSearch: bool
    supportsRss: bool
    supportsSearch: bool
    protocol: str
    priority: int
    downloadClientId: int


class _RadarrQueueStatusPayload(_RadarrPayloadModel):
    """Subset of queue status fields consumed by the adapter."""

    totalCount: int
    count: int
    unknownCount: int
    errors: bool
    warnings: bool
    unknownErrors: bool
    unknownWarnings: bool


class _RadarrQueueStatusMessagePayload(_RadarrPayloadModel):
    """Subset of queue status-message fields consumed by the adapter."""

    title: str | None = None
    messages: list[str] = Field(default_factory=list)


class _RadarrQueueItemPayload(_RadarrPayloadModel):
    """Subset of queue item fields consumed by the adapter."""

    id: int
    title: str | None = None
    status: str
    trackedDownloadStatus: str
    trackedDownloadState: str
    statusMessages: list[_RadarrQueueStatusMessagePayload] = Field(default_factory=list)
    errorMessage: str | None = None
    downloadClient: str | None = None
    indexer: str | None = None
    estimatedCompletionTime: datetime | None = None
    added: datetime | None = None


@dataclass(frozen=True, slots=True)
class RadarrClient:
    """Minimal read-only client for the Radarr HTTP API."""

    config: RadarrClientConfig = RadarrClientConfig()
    transport: RequestTransport | None = None

    def fetch_system_status(self, *, api_key: str) -> _RadarrSystemPayload:
        """Fetch Radarr version and runtime metadata."""
        payload = self._get_json("/api/v3/system/status", api_key=api_key)
        if not isinstance(payload, Mapping):
            raise RadarrResponseError("Radarr system status response was not an object")
        try:
            return _RadarrSystemPayload.model_validate(payload)
        except ValidationError as exc:
            raise RadarrResponseError(
                "Radarr system status payload shape was invalid"
            ) from exc

    def fetch_health(self, *, api_key: str) -> list[RadarrHealthIssueFact]:
        """Fetch Radarr health issues."""
        payload = self._get_json("/api/v3/health", api_key=api_key)
        if not isinstance(payload, list):
            raise RadarrResponseError("Radarr health response was not a list")
        try:
            parsed_payload = [_RadarrHealthPayload.model_validate(item) for item in payload]
        except ValidationError as exc:
            raise RadarrResponseError("Radarr health payload shape was invalid") from exc
        return [
            RadarrHealthIssueFact(
                source=item.source,
                severity=item.type,
                message=item.message,
                wiki_url=item.wikiUrl,
            )
            for item in parsed_payload
        ]

    def fetch_download_clients(self, *, api_key: str) -> list[RadarrDownloadClientFact]:
        """Fetch Radarr download-client configuration summaries."""
        payload = self._get_json("/api/v3/downloadclient", api_key=api_key)
        if not isinstance(payload, list):
            raise RadarrResponseError(
                "Radarr download client response was not a list"
            )
        try:
            parsed_payload = [
                _RadarrDownloadClientPayload.model_validate(item) for item in payload
            ]
        except ValidationError as exc:
            raise RadarrResponseError(
                "Radarr download client payload shape was invalid"
            ) from exc
        return [
            RadarrDownloadClientFact(
                id=item.id,
                name=item.name,
                implementation=item.implementation,
                implementation_name=item.implementationName,
                enabled=item.enable,
                protocol=item.protocol,
                priority=item.priority,
                remove_completed_downloads=item.removeCompletedDownloads,
                remove_failed_downloads=item.removeFailedDownloads,
                message=_provider_message_fact(item.message),
            )
            for item in parsed_payload
        ]

    def fetch_indexers(self, *, api_key: str) -> list[RadarrIndexerFact]:
        """Fetch Radarr indexer configuration summaries."""
        payload = self._get_json("/api/v3/indexer", api_key=api_key)
        if not isinstance(payload, list):
            raise RadarrResponseError("Radarr indexer response was not a list")
        try:
            parsed_payload = [_RadarrIndexerPayload.model_validate(item) for item in payload]
        except ValidationError as exc:
            raise RadarrResponseError("Radarr indexer payload shape was invalid") from exc
        return [
            RadarrIndexerFact(
                id=item.id,
                name=item.name,
                implementation=item.implementation,
                implementation_name=item.implementationName,
                enable_rss=item.enableRss,
                enable_automatic_search=item.enableAutomaticSearch,
                enable_interactive_search=item.enableInteractiveSearch,
                supports_rss=item.supportsRss,
                supports_search=item.supportsSearch,
                protocol=item.protocol,
                priority=item.priority,
                download_client_id=item.downloadClientId,
                message=_provider_message_fact(item.message),
            )
            for item in parsed_payload
        ]

    def fetch_queue_status(self, *, api_key: str) -> RadarrQueueStatusFact:
        """Fetch the aggregate Radarr queue status."""
        payload = self._get_json("/api/v3/queue/status", api_key=api_key)
        if not isinstance(payload, Mapping):
            raise RadarrResponseError("Radarr queue status response was not an object")
        try:
            parsed_payload = _RadarrQueueStatusPayload.model_validate(payload)
        except ValidationError as exc:
            raise RadarrResponseError(
                "Radarr queue status payload shape was invalid"
            ) from exc
        return RadarrQueueStatusFact(
            total_count=parsed_payload.totalCount,
            count=parsed_payload.count,
            unknown_count=parsed_payload.unknownCount,
            errors=parsed_payload.errors,
            warnings=parsed_payload.warnings,
            unknown_errors=parsed_payload.unknownErrors,
            unknown_warnings=parsed_payload.unknownWarnings,
        )

    def fetch_queue_details(self, *, api_key: str) -> list[RadarrQueueItemFact]:
        """Fetch queue items that Radarr is actively tracking."""
        payload = self._get_json("/api/v3/queue/details", api_key=api_key)
        if not isinstance(payload, list):
            raise RadarrResponseError("Radarr queue details response was not a list")
        try:
            parsed_payload = [_RadarrQueueItemPayload.model_validate(item) for item in payload]
        except ValidationError as exc:
            raise RadarrResponseError(
                "Radarr queue details payload shape was invalid"
            ) from exc
        return [
            RadarrQueueItemFact(
                id=item.id,
                title=item.title,
                status=item.status,
                tracked_download_status=item.trackedDownloadStatus,
                tracked_download_state=item.trackedDownloadState,
                error_message=item.errorMessage,
                download_client=item.downloadClient,
                indexer=item.indexer,
                estimated_completion_time=item.estimatedCompletionTime,
                added=item.added,
                status_messages=[
                    RadarrQueueStatusMessageFact.model_validate(
                        status_message.model_dump(mode="python")
                    )
                    for status_message in item.statusMessages
                ],
            )
            for item in parsed_payload
        ]

    def _get_json(self, path: str, *, api_key: str) -> object:
        """Fetch one JSON payload from the Radarr API."""
        headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
            "X-Api-Key": api_key,
        }
        http_request = request.Request(
            self.config.endpoint(path),
            headers=headers,
            method="GET",
        )
        try:
            response_body = self._transport()(http_request, self.config.timeout_seconds)
        except RadarrError:
            raise
        except error.HTTPError as exc:
            if exc.code in {401, 403}:
                raise RadarrAuthError("Radarr authentication failed") from exc
            raise RadarrTransportError("Radarr API request failed") from exc
        except (TimeoutError, OSError, error.URLError) as exc:
            raise RadarrTransportError("Radarr API request failed") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RadarrResponseError("Radarr API returned invalid JSON") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


@dataclass(frozen=True, slots=True)
class RadarrAdapter:
    """Read-only deep-inspection adapter for Radarr."""

    client: RadarrClient = RadarrClient()

    adapter_id: str = "radarr_api"
    surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="system_status"),
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="download_clients"),
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="indexers"),
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="queue_status"),
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="queue_details"),
    )
    credential_keys: tuple[str, ...] = ("api_key",)
    supported_versions: str | None = ">=3.0"
    read_only: bool = True

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Authenticate to Radarr and collect structured investigation facts."""
        del service

        api_key = credentials.get("api_key", "").strip()
        now = datetime.now(tz=UTC)
        if not api_key:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason="Radarr API key is required",
            )

        try:
            system_status = self.client.fetch_system_status(api_key=api_key)
            version = _version_fact(system_status.version)
            if version.major < 3:
                return AdapterResult(
                    adapter_id=self.adapter_id,
                    status=AdapterStatus.VERSION_INCOMPATIBLE,
                    timestamp=now,
                    reason=(
                        f"Radarr version {version.version_string} is outside the "
                        f"supported range {self.supported_versions}"
                    ),
                )
            health_issues = self.client.fetch_health(api_key=api_key)
            download_clients = self.client.fetch_download_clients(api_key=api_key)
            indexers = self.client.fetch_indexers(api_key=api_key)
            queue_status = self.client.fetch_queue_status(api_key=api_key)
            queue_items = self.client.fetch_queue_details(api_key=api_key)
        except RadarrAuthError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.AUTH_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except RadarrTransportError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.CONNECTION_FAILED,
                timestamp=now,
                reason=str(exc),
            )
        except RadarrResponseError as exc:
            return AdapterResult(
                adapter_id=self.adapter_id,
                status=AdapterStatus.PARSE_ERROR,
                timestamp=now,
                reason=str(exc),
            )

        runtime_info = RadarrRuntimeInfoFact(
            app_name=system_status.appName,
            instance_name=system_status.instanceName,
            branch=system_status.branch,
            os_name=system_status.osName,
            os_version=system_status.osVersion,
            mode=system_status.mode,
            database_type=system_status.databaseType,
            is_docker=system_status.isDocker,
            is_linux=system_status.isLinux,
            is_windows=system_status.isWindows,
            is_osx=system_status.isOsx,
            is_production=system_status.isProduction,
        )
        attention_queue_items = [
            item for item in queue_items if _queue_item_requires_attention(item)
        ]

        return AdapterResult(
            adapter_id=self.adapter_id,
            status=AdapterStatus.SUCCESS,
            facts={
                "health_issues": [
                    item.model_dump(mode="json") for item in health_issues
                ],
                "download_client_status": _download_client_status(
                    download_clients
                ).model_dump(mode="json"),
                "indexer_status": _indexer_status(indexers).model_dump(mode="json"),
                "version": version.model_dump(mode="json"),
                "runtime_info": runtime_info.model_dump(mode="json"),
                "startup_path": system_status.startupPath,
                "download_clients": [
                    item.model_dump(mode="json") for item in download_clients
                ],
                "indexers": [item.model_dump(mode="json") for item in indexers],
                "queue_status": queue_status.model_dump(mode="json"),
                "queue_items": [
                    item.model_dump(mode="json") for item in attention_queue_items
                ],
            },
            edges_discovered=_build_download_client_edges(download_clients),
            timestamp=now,
            reason=None,
        )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one HTTP request to the Radarr API."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise RadarrAuthError("Radarr authentication failed") from exc
        raise RadarrTransportError("Radarr API request failed") from exc
    except (TimeoutError, OSError, error.URLError) as exc:
        raise RadarrTransportError("Radarr API request failed") from exc


def _provider_message_fact(
    payload: _RadarrProviderMessagePayload | None,
) -> RadarrProviderMessageFact | None:
    """Normalize one optional provider message payload."""
    if payload is None:
        return None
    return RadarrProviderMessageFact.model_validate(payload.model_dump(mode="python"))


def _version_fact(version_string: str | None) -> RadarrVersionFact:
    """Parse the Radarr version string into a stable structured fact."""
    if version_string is None or not version_string.strip():
        raise RadarrResponseError("Radarr system status did not include a version")
    normalized_version = version_string.strip()
    tokens = [int(token) for token in re.findall(r"[0-9]+", normalized_version)]
    if not tokens:
        raise RadarrResponseError("Radarr system status version was not parseable")
    return RadarrVersionFact(
        version_string=normalized_version,
        major=tokens[0],
        minor=tokens[1] if len(tokens) > 1 else None,
        patch=tokens[2] if len(tokens) > 2 else None,
        build=tokens[3] if len(tokens) > 3 else None,
    )


def _download_client_status(
    download_clients: list[RadarrDownloadClientFact],
) -> RadarrDownloadClientStatusFact:
    """Build the aggregate download-client summary fact."""
    return RadarrDownloadClientStatusFact(
        configured=len(download_clients),
        enabled=sum(client.enabled for client in download_clients),
        warning_count=sum(
            client.message is not None and client.message.type == "warning"
            for client in download_clients
        ),
        error_count=sum(
            client.message is not None and client.message.type == "error"
            for client in download_clients
        ),
    )


def _indexer_status(indexers: list[RadarrIndexerFact]) -> RadarrIndexerStatusFact:
    """Build the aggregate indexer summary fact."""
    return RadarrIndexerStatusFact(
        configured=len(indexers),
        rss_enabled=sum(indexer.enable_rss for indexer in indexers),
        automatic_search_enabled=sum(
            indexer.enable_automatic_search for indexer in indexers
        ),
        interactive_search_enabled=sum(
            indexer.enable_interactive_search for indexer in indexers
        ),
        warning_count=sum(
            indexer.message is not None and indexer.message.type == "warning"
            for indexer in indexers
        ),
        error_count=sum(
            indexer.message is not None and indexer.message.type == "error"
            for indexer in indexers
        ),
    )


def _queue_item_requires_attention(item: RadarrQueueItemFact) -> bool:
    """Return whether one queue item is investigation-relevant."""
    return (
        item.error_message is not None
        or item.status in _ATTENTION_QUEUE_STATUSES
        or item.tracked_download_status in _ATTENTION_TRACKED_DOWNLOAD_STATUSES
        or item.tracked_download_state in _ATTENTION_TRACKED_DOWNLOAD_STATES
    )


def _build_download_client_edges(
    download_clients: list[RadarrDownloadClientFact],
) -> list[AdapterDiscoveredEdge]:
    """Build deduplicated runtime-observed download-client edges."""
    seen_targets: set[str] = set()
    edges: list[AdapterDiscoveredEdge] = []
    for client in download_clients:
        if not client.enabled or client.name is None or not client.name.strip():
            continue
        target_service_name = client.name.strip()
        normalized_target = target_service_name.casefold()
        if normalized_target in seen_targets:
            continue
        seen_targets.add(normalized_target)
        edges.append(
            AdapterDiscoveredEdge(
                surface_id="download_clients",
                target_service_name=target_service_name,
                description=(
                    f"Radarr is configured to use download client "
                    f"{target_service_name}"
                ),
            )
        )
    return edges
