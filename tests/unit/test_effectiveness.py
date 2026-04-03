"""Unit tests for the Phase 3A effectiveness score stub."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.descriptors import load_service_descriptors
from kaval.effectiveness import build_effectiveness_report
from kaval.integrations import AdapterRegistry, RadarrAdapter
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
    """Build a deterministic UTC timestamp for effectiveness tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_effectiveness_report_uses_equal_weighted_max_insight_formula() -> None:
    """The v1 score should count services currently at their maximum achievable level."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    adapter_registry = AdapterRegistry((RadarrAdapter(),))

    discovered_service = Service(
        id="svc-share",
        name="downloads",
        type=ServiceType.SHARE,
        category="storage",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
    matched_service = Service(
        id="svc-delugevpn",
        name="DelugeVPN",
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.DEGRADED,
        descriptor_id="downloads/delugevpn",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-delugevpn",
        vm_id=None,
        image="binhex/arch-delugevpn:latest",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=ts(12, 0),
        active_findings=1,
        active_incidents=1,
    )
    deep_inspection_service = Service(
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
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=ts(12, 1),
        active_findings=0,
        active_incidents=0,
        insight=derive_service_insight(
            matched_service.model_copy(
                update={
                    "id": "svc-radarr",
                    "name": "Radarr",
                    "descriptor_id": "arr/radarr",
                    "container_id": "container-radarr",
                }
            ),
            local_model_configured=True,
        ),
    )

    report = build_effectiveness_report(
        services=[discovered_service, matched_service, deep_inspection_service],
        descriptors=descriptors,
        adapter_registry=adapter_registry,
    )

    assert report.score_percent == 33.3
    assert report.services_at_target == 1
    assert report.total_services == 3
    assert report.improvable_services == 2
    assert [
        (
            item.label,
            int(item.target_level),
            item.services_at_target,
            item.service_count,
        )
        for item in report.breakdown
    ] == [
        ("Discovered only", int(ServiceInsightLevel.DISCOVERED), 1, 1),
        ("Investigation-ready", int(ServiceInsightLevel.INVESTIGATION_READY), 0, 1),
        ("Deep-inspection-ready", int(ServiceInsightLevel.DEEP_INSPECTED), 0, 1),
    ]
