"""Equal-weighted v1 effectiveness score for Phase 3A visibility."""

from __future__ import annotations

from collections import defaultdict
from enum import StrEnum
from typing import Sequence

from pydantic import Field

from kaval.discovery.descriptors import LoadedServiceDescriptor
from kaval.integrations import AdapterRegistry
from kaval.models import KavalModel, Service, ServiceInsightLevel


class EffectivenessBucket(StrEnum):
    """The maximum-achievable insight buckets exposed in the v1 dashboard."""

    DISCOVERED_ONLY = "discovered_only"
    INVESTIGATION_READY = "investigation_ready"
    DEEP_INSPECTION_READY = "deep_inspection_ready"
    OPERATOR_ENRICHED = "operator_enriched"


class EffectivenessBreakdownItem(KavalModel):
    """One transparent breakdown row for the effectiveness score."""

    bucket: EffectivenessBucket
    label: str
    target_level: ServiceInsightLevel
    service_count: int = Field(ge=0)
    services_at_target: int = Field(ge=0)
    services_below_target: int = Field(ge=0)


class EffectivenessReport(KavalModel):
    """The minimum equal-weighted effectiveness score contract for Phase 3A."""

    score_percent: float = Field(ge=0.0, le=100.0)
    services_at_target: int = Field(ge=0)
    total_services: int = Field(ge=0)
    improvable_services: int = Field(ge=0)
    formula: str
    breakdown: list[EffectivenessBreakdownItem] = Field(default_factory=list)


def build_effectiveness_report(
    *,
    services: Sequence[Service],
    descriptors: Sequence[LoadedServiceDescriptor],
    adapter_registry: AdapterRegistry,
) -> EffectivenessReport:
    """Build the equal-weighted v1 effectiveness score and simple breakdown."""
    descriptor_ids_with_adapters = {
        descriptor_id
        for descriptor_id, loaded_descriptor in _descriptors_by_id(descriptors).items()
        if _descriptor_has_adapter(
            descriptor_id=descriptor_id,
            loaded_descriptor=loaded_descriptor,
            adapter_registry=adapter_registry,
        )
    }

    breakdown_counts: dict[
        tuple[EffectivenessBucket, ServiceInsightLevel],
        dict[str, int],
    ] = defaultdict(lambda: {"service_count": 0, "services_at_target": 0})
    services_at_target = 0

    for service in services:
        current_level = (
            ServiceInsightLevel.DISCOVERED
            if service.insight is None
            else ServiceInsightLevel(service.insight.level)
        )
        target_level = maximum_achievable_insight_level(
            service=service,
            descriptor_ids_with_adapters=descriptor_ids_with_adapters,
        )
        bucket = _bucket_for_level(target_level)
        counts = breakdown_counts[(bucket, target_level)]
        counts["service_count"] += 1
        if current_level >= target_level:
            counts["services_at_target"] += 1
            services_at_target += 1

    total_services = len(services)
    score_percent = (
        0.0
        if total_services == 0
        else round(services_at_target / total_services * 100, 1)
    )
    ordered_breakdown = sorted(
        breakdown_counts.items(),
        key=lambda item: int(item[0][1]),
    )
    return EffectivenessReport(
        score_percent=score_percent,
        services_at_target=services_at_target,
        total_services=total_services,
        improvable_services=max(0, total_services - services_at_target),
        formula=(
            "services currently at their maximum achievable insight level / total "
            "services, equal-weighted in v1"
        ),
        breakdown=[
            EffectivenessBreakdownItem(
                bucket=bucket,
                label=_bucket_label(bucket),
                target_level=target_level,
                service_count=counts["service_count"],
                services_at_target=counts["services_at_target"],
                services_below_target=(
                    counts["service_count"] - counts["services_at_target"]
                ),
            )
            for (bucket, target_level), counts in ordered_breakdown
        ],
    )


def maximum_achievable_insight_level(
    *,
    service: Service,
    descriptor_ids_with_adapters: set[str],
) -> ServiceInsightLevel:
    """Resolve the v1 maximum-achievable insight level for one service."""
    if service.descriptor_id is None:
        return ServiceInsightLevel.DISCOVERED
    if service.descriptor_id in descriptor_ids_with_adapters:
        # v1 treats shipped adapter coverage as Level 4-ready by default. Level 5
        # remains reserved for already-present operator enrichment until that
        # eligibility is modeled explicitly in a later task.
        if (
            service.insight is not None
            and service.insight.level >= ServiceInsightLevel.OPERATOR_ENRICHED
        ):
            return ServiceInsightLevel.OPERATOR_ENRICHED
        return ServiceInsightLevel.DEEP_INSPECTED
    return ServiceInsightLevel.INVESTIGATION_READY


def _descriptors_by_id(
    descriptors: Sequence[LoadedServiceDescriptor],
) -> dict[str, LoadedServiceDescriptor]:
    """Index loaded descriptors by the persisted service descriptor identifier."""
    return {
        f"{descriptor.path.parent.name}/{descriptor.path.stem}": descriptor
        for descriptor in descriptors
    }


def _descriptor_has_adapter(
    *,
    descriptor_id: str,
    loaded_descriptor: LoadedServiceDescriptor,
    adapter_registry: AdapterRegistry,
) -> bool:
    """Return whether any shipped adapter is bound to the descriptor surfaces."""
    return any(
        adapter_registry.get(
            descriptor_id=descriptor_id,
            surface_id=surface.id,
        )
        is not None
        for surface in loaded_descriptor.descriptor.inspection.surfaces
    )


def _bucket_for_level(level: ServiceInsightLevel) -> EffectivenessBucket:
    """Map a maximum-achievable insight level into the v1 breakdown bucket."""
    if level == ServiceInsightLevel.DISCOVERED:
        return EffectivenessBucket.DISCOVERED_ONLY
    if level == ServiceInsightLevel.INVESTIGATION_READY:
        return EffectivenessBucket.INVESTIGATION_READY
    if level == ServiceInsightLevel.OPERATOR_ENRICHED:
        return EffectivenessBucket.OPERATOR_ENRICHED
    return EffectivenessBucket.DEEP_INSPECTION_READY


def _bucket_label(bucket: EffectivenessBucket) -> str:
    """Return a human-readable label for one effectiveness breakdown bucket."""
    if bucket == EffectivenessBucket.DISCOVERED_ONLY:
        return "Discovered only"
    if bucket == EffectivenessBucket.INVESTIGATION_READY:
        return "Investigation-ready"
    if bucket == EffectivenessBucket.OPERATOR_ENRICHED:
        return "Operator-enriched"
    return "Deep-inspection-ready"
