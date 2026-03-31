"""Read-only Unraid GraphQL discovery client and snapshot models."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Mapping, TypeVar
from urllib import error, request

from pydantic import BaseModel, ConfigDict, Field


class UnraidDiscoveryModel(BaseModel):
    """Base model for tolerant external API parsing."""

    model_config = ConfigDict(extra="ignore")


class UnraidSystemOS(UnraidDiscoveryModel):
    """Operating system facts returned by the Unraid API."""

    platform: str | None = None
    distro: str | None = None
    release: str | None = None
    uptime: int | None = None


class UnraidCpuInfo(UnraidDiscoveryModel):
    """CPU facts returned by the Unraid API."""

    manufacturer: str | None = None
    brand: str | None = None
    cores: int | None = None
    threads: int | None = None


class UnraidMemoryInfo(UnraidDiscoveryModel):
    """Memory facts returned by the Unraid API."""

    total: int | None = None


class UnraidSystemInfo(UnraidDiscoveryModel):
    """System facts returned by the Unraid API."""

    hostname: str | None = None
    os: UnraidSystemOS = Field(default_factory=UnraidSystemOS)
    cpu: UnraidCpuInfo = Field(default_factory=UnraidCpuInfo)
    memory: UnraidMemoryInfo = Field(default_factory=UnraidMemoryInfo)


class UnraidCapacitySummary(UnraidDiscoveryModel):
    """Storage capacity summary for the Unraid array."""

    free: int | None = None
    used: int | None = None
    total: int | None = None


class UnraidDiskSummary(UnraidDiscoveryModel):
    """Array disk facts exposed through the Unraid API."""

    name: str
    size: int | None = None
    status: str | None = None
    temp: int | None = None


class UnraidArraySnapshot(UnraidDiscoveryModel):
    """Array state and disk inventory from Unraid."""

    state: str | None = None
    capacity: UnraidCapacitySummary | None = None
    disks: list[UnraidDiskSummary] = Field(default_factory=list)


class UnraidContainerSummary(UnraidDiscoveryModel):
    """A read-only container summary discovered from Unraid."""

    id: str
    names: list[str] = Field(default_factory=list)
    image: str | None = None
    state: str | None = None
    status: str | None = None
    auto_start: bool | None = Field(default=None, alias="autoStart")


class UnraidVMSummary(UnraidDiscoveryModel):
    """A read-only VM summary discovered from Unraid."""

    id: str
    name: str
    state: str | None = None
    os: str | None = None
    auto_start: bool | None = Field(default=None, alias="autoStart")


class UnraidShareSummary(UnraidDiscoveryModel):
    """A share summary discovered from Unraid."""

    name: str
    path: str | None = None
    free_bytes: int | None = Field(default=None, alias="free")
    used_bytes: int | None = Field(default=None, alias="used")
    total_bytes: int | None = Field(default=None, alias="total")
    primary_storage: str | None = Field(default=None, alias="primaryStorage")
    secondary_storage: str | None = Field(default=None, alias="secondaryStorage")


class UnraidPluginSummary(UnraidDiscoveryModel):
    """A plugin summary discovered from Unraid."""

    name: str
    version: str | None = None
    enabled: bool | None = None
    update_available: bool | None = Field(default=None, alias="hasUpdate")


class UnraidDiscoverySnapshot(UnraidDiscoveryModel):
    """A single read-only discovery snapshot from Unraid."""

    discovered_at: datetime
    system_info: UnraidSystemInfo = Field(default_factory=UnraidSystemInfo)
    array: UnraidArraySnapshot | None = None
    containers: list[UnraidContainerSummary] = Field(default_factory=list)
    vms: list[UnraidVMSummary] = Field(default_factory=list)
    shares: list[UnraidShareSummary] = Field(default_factory=list)
    plugins: list[UnraidPluginSummary] = Field(default_factory=list)


UNRAID_DISCOVERY_QUERY = """
query KavalDiscovery {
  info {
    hostname
    os {
      platform
      distro
      release
      uptime
    }
    cpu {
      manufacturer
      brand
      cores
      threads
    }
    memory {
      total
    }
  }
  array {
    state
    capacity {
      free
      used
      total
    }
    disks {
      name
      size
      status
      temp
    }
  }
  dockerContainers {
    id
    names
    image
    state
    status
    autoStart
  }
  vms {
    id
    name
    state
    os
    autoStart
  }
  shares {
    name
    path
    free
    used
    total
    primaryStorage
    secondaryStorage
  }
  plugins {
    name
    version
    enabled
    hasUpdate
  }
}
""".strip()

ModelT = TypeVar("ModelT", bound=UnraidDiscoveryModel)


class UnraidDiscoveryError(RuntimeError):
    """Base error for read-only Unraid discovery failures."""


class UnraidTransportError(UnraidDiscoveryError):
    """Raised when an HTTP transport error occurs."""


class UnraidGraphQLError(UnraidDiscoveryError):
    """Raised when the Unraid API returns a GraphQL error payload."""


def decode_graphql_data(payload: Mapping[str, object]) -> Mapping[str, object]:
    """Return the GraphQL data object or raise a typed discovery error."""
    raw_errors = payload.get("errors")
    if isinstance(raw_errors, list) and raw_errors:
        messages: list[str] = []
        for item in raw_errors:
            if isinstance(item, Mapping):
                message = item.get("message")
                if isinstance(message, str):
                    messages.append(message)
        detail = "; ".join(messages) if messages else "unknown GraphQL error"
        raise UnraidGraphQLError(detail)

    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise UnraidGraphQLError("Unraid GraphQL response is missing a data object")
    return data


def build_discovery_snapshot(
    data: Mapping[str, object],
    *,
    discovered_at: datetime | None = None,
) -> UnraidDiscoverySnapshot:
    """Convert a raw GraphQL data payload into a typed discovery snapshot."""
    return UnraidDiscoverySnapshot(
        discovered_at=discovered_at or datetime.now(tz=UTC),
        system_info=_validate_mapping(data.get("info"), UnraidSystemInfo),
        array=_validate_optional_mapping(data.get("array"), UnraidArraySnapshot),
        containers=_validate_model_list(data.get("dockerContainers"), UnraidContainerSummary),
        vms=_validate_model_list(data.get("vms"), UnraidVMSummary),
        shares=_validate_model_list(data.get("shares"), UnraidShareSummary),
        plugins=_validate_model_list(data.get("plugins"), UnraidPluginSummary),
    )


@dataclass(frozen=True, slots=True)
class UnraidClientConfig:
    """Configuration for the read-only Unraid GraphQL client."""

    base_url: str
    api_key: str
    timeout_seconds: float = 10.0
    graphql_path: str = "/graphql"

    def graphql_url(self) -> str:
        """Return the absolute GraphQL endpoint URL."""
        trimmed_base = self.base_url.rstrip("/")
        trimmed_path = (
            self.graphql_path
            if self.graphql_path.startswith("/")
            else f"/{self.graphql_path}"
        )
        return f"{trimmed_base}{trimmed_path}"


class UnraidGraphQLClient:
    """A minimal read-only client for Unraid's GraphQL API."""

    def __init__(self, config: UnraidClientConfig) -> None:
        """Store immutable client configuration."""
        self._config = config

    def fetch_discovery_snapshot(self) -> UnraidDiscoverySnapshot:
        """Fetch a typed discovery snapshot from the configured Unraid server."""
        response_payload = self._post_graphql(UNRAID_DISCOVERY_QUERY)
        data = decode_graphql_data(response_payload)
        return build_discovery_snapshot(data)

    def _post_graphql(self, query: str) -> Mapping[str, object]:
        """Execute a GraphQL query against the Unraid API."""
        request_body = json.dumps({"query": query}).encode("utf-8")
        graphql_request = request.Request(
            self._config.graphql_url(),
            data=request_body,
            method="POST",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "x-api-key": self._config.api_key,
            },
        )

        try:
            with request.urlopen(graphql_request, timeout=self._config.timeout_seconds) as response:
                status = response.getcode()
                if status != HTTPStatus.OK:
                    raise UnraidTransportError(
                        f"unexpected Unraid response status: {status}"
                    )
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise UnraidTransportError(
                f"Unraid GraphQL request failed with HTTP {exc.code}"
            ) from exc
        except error.URLError as exc:
            raise UnraidTransportError(f"failed to reach Unraid GraphQL API: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise UnraidTransportError("Unraid GraphQL response was not valid JSON") from exc

        if not isinstance(payload, Mapping):
            raise UnraidTransportError("Unraid GraphQL response body was not an object")
        return payload


def _validate_optional_mapping(
    raw_value: object,
    model_type: type[ModelT],
) -> ModelT | None:
    """Validate an optional mapping into a discovery model."""
    if raw_value is None:
        return None
    return _validate_mapping(raw_value, model_type)


def _validate_mapping(
    raw_value: object,
    model_type: type[ModelT],
) -> ModelT:
    """Validate a mapping into a discovery model."""
    if not isinstance(raw_value, Mapping):
        return model_type()
    return model_type.model_validate(raw_value)


def _validate_model_list(
    raw_value: object,
    model_type: type[ModelT],
) -> list[ModelT]:
    """Validate a list of objects into discovery models."""
    if not isinstance(raw_value, list):
        return []
    models: list[ModelT] = []
    for item in raw_value:
        if isinstance(item, Mapping):
            models.append(model_type.model_validate(item))
    return models
