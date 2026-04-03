"""Contract tests for Phase 3A adapter interfaces and insight progression."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from kaval.discovery.descriptors import load_service_descriptors
from kaval.integrations import (
    AdapterRegistry,
    AuthentikAdapter,
    CloudflareAdapter,
    NginxProxyManagerAdapter,
    PiHoleAdapter,
    RadarrAdapter,
    ServiceAdapter,
)
from kaval.models import (
    DescriptorSource,
    Service,
    ServiceInsightLevel,
    ServiceStatus,
    ServiceType,
    derive_service_insight,
)

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_shipped_adapter_registry_matches_declared_inspection_surfaces() -> None:
    """Every shipped deep-inspection surface should map to exactly one adapter binding."""
    loaded_descriptors = load_service_descriptors([SERVICES_DIR])
    registry = AdapterRegistry(
        cast(
            Sequence[ServiceAdapter],
            (
                NginxProxyManagerAdapter(),
                RadarrAdapter(),
                AuthentikAdapter(),
                CloudflareAdapter(),
                PiHoleAdapter(),
            ),
        )
    )

    declared_surfaces = {
        (f"{item.path.parent.name}/{item.path.stem}", surface.id)
        for item in loaded_descriptors
        for surface in item.descriptor.inspection.surfaces
    }
    bound_surfaces = {
        (binding.descriptor_id, binding.surface_id)
        for adapter in registry.list_adapters()
        for binding in adapter.surface_bindings
    }

    assert bound_surfaces == declared_surfaces


def test_service_insight_progression_matches_phase3a_contract() -> None:
    """The per-service insight ladder should advance only in the approved order."""
    base_service = build_service(descriptor_id=None, last_check=None)

    assert derive_service_insight(base_service).level == ServiceInsightLevel.DISCOVERED
    assert derive_service_insight(
        build_service(descriptor_id="arr/radarr", last_check=None)
    ).level == ServiceInsightLevel.MATCHED
    assert derive_service_insight(
        build_service(descriptor_id="arr/radarr", last_check=ts(14, 0))
    ).level == ServiceInsightLevel.MONITORED
    assert derive_service_insight(
        build_service(descriptor_id="arr/radarr", last_check=ts(14, 0)),
        local_model_configured=True,
    ).level == ServiceInsightLevel.INVESTIGATION_READY
    assert derive_service_insight(
        build_service(descriptor_id="arr/radarr", last_check=ts(14, 0)),
        local_model_configured=True,
        deep_inspection_configured=True,
    ).level == ServiceInsightLevel.DEEP_INSPECTED
    assert derive_service_insight(
        build_service(descriptor_id="arr/radarr", last_check=ts(14, 0)),
        local_model_configured=True,
        deep_inspection_configured=True,
        operator_enriched=True,
    ).level == ServiceInsightLevel.OPERATOR_ENRICHED


def build_service(
    *,
    descriptor_id: str | None,
    last_check: datetime | None,
) -> Service:
    """Build one minimal service sample for insight-level contract assertions."""
    return Service(
        id="svc-radarr",
        name="Radarr",
        type=ServiceType.CONTAINER,
        category="arr",
        status=ServiceStatus.HEALTHY,
        descriptor_id=descriptor_id,
        descriptor_source=(
            DescriptorSource.SHIPPED
            if descriptor_id is not None
            else None
        ),
        container_id="container-radarr",
        vm_id=None,
        image="lscr.io/linuxserver/radarr:latest",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=last_check,
        active_findings=0,
        active_incidents=0,
    )
