"""Typed deep-inspection adapter contracts and registry helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import ConfigDict, Field

from kaval.models import DependencyConfidence, JsonValue, KavalModel, Service


class AdapterStatus(StrEnum):
    """Supported adapter execution outcomes."""

    SUCCESS = "success"
    AUTH_FAILED = "auth_failed"
    CONNECTION_FAILED = "connection_failed"
    VERSION_INCOMPATIBLE = "version_incompatible"
    PARSE_ERROR = "parse_error"
    DEGRADED = "degraded"


class AdapterSurfaceBinding(KavalModel):
    """One descriptor-surface binding owned by an adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    descriptor_id: str = Field(min_length=1)
    surface_id: str = Field(min_length=1)


class AdapterDiscoveredEdge(KavalModel):
    """One dependency hint extracted from a deep-inspection surface."""

    surface_id: str = Field(min_length=1)
    target_service_name: str = Field(min_length=1)
    confidence: DependencyConfidence = DependencyConfidence.RUNTIME_OBSERVED
    description: str | None = None


class AdapterResult(KavalModel):
    """Structured output returned by one deep-inspection adapter execution."""

    adapter_id: str = Field(min_length=1)
    status: AdapterStatus
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    edges_discovered: list[AdapterDiscoveredEdge] = Field(default_factory=list)
    timestamp: datetime
    reason: str | None = None


class ServiceAdapter(Protocol):
    """Common interface implemented by all deep-inspection adapters."""

    adapter_id: str
    surface_bindings: Sequence[AdapterSurfaceBinding]
    credential_keys: Sequence[str]
    supported_versions: str | None
    read_only: bool

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Perform one read-only inspection and return a structured result."""


class AdapterRegistry:
    """Register and resolve deep-inspection adapters by descriptor surface."""

    def __init__(self, adapters: Sequence[ServiceAdapter] = ()) -> None:
        """Initialize the registry with zero or more adapters."""
        self._adapters_by_id: dict[str, ServiceAdapter] = {}
        self._adapters_by_surface: dict[AdapterSurfaceBinding, ServiceAdapter] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ServiceAdapter) -> None:
        """Register one adapter and all of its bound descriptor surfaces."""
        if not adapter.read_only:
            msg = f"service adapters must be read_only: {adapter.adapter_id}"
            raise ValueError(msg)
        if adapter.adapter_id in self._adapters_by_id:
            msg = f"duplicate adapter id: {adapter.adapter_id}"
            raise ValueError(msg)

        bindings = tuple(adapter.surface_bindings)
        if not bindings:
            msg = f"adapter must bind at least one surface: {adapter.adapter_id}"
            raise ValueError(msg)
        if len(set(bindings)) != len(bindings):
            msg = f"adapter surface bindings must be unique: {adapter.adapter_id}"
            raise ValueError(msg)

        duplicate_bindings = [
            binding
            for binding in bindings
            if binding in self._adapters_by_surface
        ]
        if duplicate_bindings:
            duplicate = duplicate_bindings[0]
            msg = (
                "duplicate adapter surface binding: "
                f"{duplicate.descriptor_id}:{duplicate.surface_id}"
            )
            raise ValueError(msg)

        self._adapters_by_id[adapter.adapter_id] = adapter
        for binding in bindings:
            self._adapters_by_surface[binding] = adapter

    def get(self, *, descriptor_id: str, surface_id: str) -> ServiceAdapter | None:
        """Return the adapter bound to one descriptor surface, if any."""
        binding = AdapterSurfaceBinding(
            descriptor_id=descriptor_id,
            surface_id=surface_id,
        )
        return self._adapters_by_surface.get(binding)

    def get_by_id(self, adapter_id: str) -> ServiceAdapter | None:
        """Return one adapter by its stable identifier."""
        return self._adapters_by_id.get(adapter_id)

    def list_adapters(self) -> list[ServiceAdapter]:
        """Return adapters in registration order."""
        return list(self._adapters_by_id.values())


async def execute_service_adapter(
    adapter: ServiceAdapter,
    *,
    service: Service,
    credentials: Mapping[str, str],
    now: datetime | None = None,
) -> AdapterResult:
    """Execute one adapter without allowing exceptions to escape the call site."""
    try:
        return await adapter.inspect(service, credentials)
    except Exception as exc:  # pragma: no cover - exercised via tests
        return AdapterResult(
            adapter_id=adapter.adapter_id,
            status=AdapterStatus.DEGRADED,
            facts={},
            edges_discovered=[],
            timestamp=now or datetime.now(tz=UTC),
            reason=str(exc),
        )
