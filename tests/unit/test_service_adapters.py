"""Unit tests for the deep-inspection adapter foundation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Mapping

import pytest

from kaval.integrations import (
    AdapterDiscoveredEdge,
    AdapterRegistry,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
    execute_service_adapter,
)
from kaval.models import (
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def build_service() -> Service:
    """Create a representative descriptor-backed service."""
    return Service(
        id="svc-radarr",
        name="Radarr",
        type=ServiceType.CONTAINER,
        category="arr",
        status=ServiceStatus.HEALTHY,
        descriptor_id="arr/radarr",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-radarr",
        vm_id=None,
        image="lscr.io/linuxserver/radarr:latest",
        endpoints=[
            Endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTP,
                host="radarr",
                port=7878,
                path="/",
                url=None,
                auth_required=False,
                expected_status=200,
            )
        ],
        dependencies=[],
        dependents=[],
        last_check=ts(9),
        active_findings=0,
        active_incidents=0,
    )


class FakeAdapter:
    """Simple structural adapter double used by the registry tests."""

    def __init__(
        self,
        *,
        adapter_id: str,
        surface_bindings: tuple[AdapterSurfaceBinding, ...],
        result: AdapterResult | None = None,
        error: Exception | None = None,
        read_only: bool = True,
    ) -> None:
        self.adapter_id = adapter_id
        self.surface_bindings = surface_bindings
        self.credential_keys = ("api_key",)
        self.supported_versions = ">=3.0"
        self.read_only = read_only
        self._result = result
        self._error = error

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Return the configured result or raise the configured error."""
        del service, credentials
        if self._error is not None:
            raise self._error
        if self._result is None:
            raise AssertionError("test adapter requires result or error")
        return self._result


def test_adapter_registry_registers_and_resolves_bound_surfaces() -> None:
    """The registry should map descriptor surface bindings back to the adapter."""
    adapter = FakeAdapter(
        adapter_id="radarr_api",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="system_status"),
        ),
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.SUCCESS,
            facts={"version": "5.0.3"},
            edges_discovered=[
                AdapterDiscoveredEdge(
                    surface_id="health_api",
                    target_service_name="DelugeVPN",
                    description="Radarr reports the configured download client.",
                )
            ],
            timestamp=ts(10),
            reason=None,
        ),
    )

    registry = AdapterRegistry([adapter])

    assert registry.get(descriptor_id="arr/radarr", surface_id="health_api") is adapter
    assert registry.get(descriptor_id="arr/radarr", surface_id="system_status") is adapter
    assert registry.get_by_id("radarr_api") is adapter
    assert registry.list_adapters() == [adapter]


def test_adapter_registry_rejects_duplicate_surface_bindings() -> None:
    """Two adapters cannot claim the same descriptor surface binding."""
    first = FakeAdapter(
        adapter_id="radarr_api",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.SUCCESS,
            timestamp=ts(10),
            reason=None,
        ),
    )
    second = FakeAdapter(
        adapter_id="radarr_system_api",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        result=AdapterResult(
            adapter_id="radarr_system_api",
            status=AdapterStatus.SUCCESS,
            timestamp=ts(10, 5),
            reason=None,
        ),
    )

    registry = AdapterRegistry([first])

    with pytest.raises(ValueError, match="duplicate adapter surface binding"):
        registry.register(second)


def test_adapter_registry_rejects_non_read_only_adapters() -> None:
    """Phase 3A adapters must remain read-only."""
    adapter = FakeAdapter(
        adapter_id="mutating_adapter",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        result=AdapterResult(
            adapter_id="mutating_adapter",
            status=AdapterStatus.SUCCESS,
            timestamp=ts(11),
            reason=None,
        ),
        read_only=False,
    )

    with pytest.raises(ValueError, match="read_only"):
        AdapterRegistry([adapter])


def test_execute_service_adapter_returns_successful_results() -> None:
    """The execution wrapper should pass through successful adapter results."""
    service = build_service()
    expected = AdapterResult(
        adapter_id="radarr_api",
        status=AdapterStatus.SUCCESS,
        facts={"health_issues": []},
        edges_discovered=[],
        timestamp=ts(12),
        reason=None,
    )
    adapter = FakeAdapter(
        adapter_id="radarr_api",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        result=expected,
    )

    result = asyncio.run(
        execute_service_adapter(
            adapter,
            service=service,
            credentials={"api_key": "secret"},
        )
    )

    assert result == expected


def test_execute_service_adapter_converts_exceptions_to_degraded_results() -> None:
    """The execution wrapper should degrade cleanly instead of raising."""
    service = build_service()
    adapter = FakeAdapter(
        adapter_id="radarr_api",
        surface_bindings=(
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        error=RuntimeError("request timed out"),
    )

    result = asyncio.run(
        execute_service_adapter(
            adapter,
            service=service,
            credentials={"api_key": "secret"},
            now=ts(13),
        )
    )

    assert result.adapter_id == "radarr_api"
    assert result.status == AdapterStatus.DEGRADED
    assert result.facts == {}
    assert result.edges_discovered == []
    assert result.timestamp == ts(13)
    assert result.reason == "request timed out"
