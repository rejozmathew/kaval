"""Operational Memory Layer 1 system-profile materialization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.discovery.descriptors import LoadedServiceDescriptor, loaded_descriptor_identifier
from kaval.discovery.docker import DockerDiscoverySnapshot
from kaval.discovery.unraid import (
    UnraidDiscoverySnapshot,
    UnraidPluginSummary,
    UnraidVMSummary,
)
from kaval.models import (
    ArrayProfile,
    Change,
    ChangeType,
    HardwareProfile,
    NetworkingProfile,
    PluginImpactService,
    PluginProfile,
    Service,
    ServicesSummary,
    StorageProfile,
    SystemProfile,
    VMProfile,
)
from kaval.runtime.capability_runtime import (
    build_discovery_pipeline_runtime_signal,
)

_BYTES_PER_GIB = 1024**3
_BYTES_PER_TIB = 1024**4


def build_system_profile(
    unraid_snapshot: UnraidDiscoverySnapshot,
    docker_snapshot: DockerDiscoverySnapshot,
    *,
    services: Sequence[Service] | None = None,
    descriptors: Sequence[LoadedServiceDescriptor] = (),
    now: datetime | None = None,
) -> SystemProfile:
    """Build the auto-generated Layer 1 system profile from discovery data."""
    effective_now = now or datetime.now(tz=UTC)
    plugin_impacts = _build_plugin_impacts(
        services=services or [],
        descriptors=descriptors,
    )
    return SystemProfile(
        hostname=unraid_snapshot.system_info.hostname or "unknown",
        unraid_version=unraid_snapshot.system_info.os.release or "unknown",
        hardware=HardwareProfile(
            cpu=unraid_snapshot.system_info.cpu.brand or "unknown",
            memory_gb=_bytes_to_gib(unraid_snapshot.system_info.memory.total),
            gpu=None,
            ups=None,
        ),
        storage=StorageProfile(
            array=ArrayProfile(
                parity_drives=_parity_drive_count(unraid_snapshot),
                data_drives=_data_drive_count(unraid_snapshot),
                cache=None,
                total_tb=_bytes_to_tib(
                    unraid_snapshot.array.capacity.total
                    if unraid_snapshot.array is not None
                    and unraid_snapshot.array.capacity is not None
                    else None
                ),
                used_tb=_bytes_to_tib(
                    unraid_snapshot.array.capacity.used
                    if unraid_snapshot.array is not None
                    and unraid_snapshot.array.capacity is not None
                    else None
                ),
            )
        ),
        networking=_build_networking_profile(services or []),
        services_summary=ServicesSummary(
            total_containers=len(docker_snapshot.containers),
            total_vms=len(unraid_snapshot.vms),
            matched_descriptors=_matched_descriptor_count(services or []),
        ),
        vms=[_build_vm_profile(vm) for vm in sorted(unraid_snapshot.vms, key=lambda vm: vm.name)],
        plugins=[
            _build_plugin_profile(
                plugin=plugin,
                impacted_services=plugin_impacts.get(_plugin_dependency_key(plugin.name), []),
            )
            for plugin in sorted(unraid_snapshot.plugins, key=lambda plugin: plugin.name.casefold())
        ],
        last_updated=effective_now,
    )


def persist_system_profile(database: KavalDatabase, system_profile: SystemProfile) -> None:
    """Persist the singleton system profile into the existing SQLite store."""
    previous_profile = database.get_system_profile()
    database.upsert_system_profile(system_profile)
    for change in _build_plugin_change_events(
        previous_profile=previous_profile,
        current_profile=system_profile,
    ):
        database.upsert_change(change)
    database.upsert_capability_runtime_signal(
        build_discovery_pipeline_runtime_signal(
            recorded_at=system_profile.last_updated,
            last_succeeded_at=system_profile.last_updated,
            unraid_api_reachable=True,
            docker_api_reachable=True,
            trigger="system_profile_persisted",
        )
    )


def _build_networking_profile(services: Sequence[Service]) -> NetworkingProfile:
    """Infer stable networking roles from the matched service catalog when present."""
    descriptor_ids = {service.descriptor_id for service in services}
    return NetworkingProfile(
        domain=None,
        dns_provider=None,
        reverse_proxy=_role_name(
            "networking/nginx_proxy_manager",
            descriptor_ids,
            "nginx_proxy_manager",
        ),
        tunnel=_role_name("networking/cloudflared", descriptor_ids, "cloudflared"),
        vpn=_role_name("downloads/delugevpn", descriptor_ids, "delugevpn"),
        dns_resolver=_role_name("networking/pihole", descriptor_ids, "pihole"),
        ssl_strategy=None,
    )


def _role_name(
    descriptor_id: str,
    descriptor_ids: set[str | None],
    role_name: str,
) -> str | None:
    """Return the stable role name when the matching descriptor is present."""
    return role_name if descriptor_id in descriptor_ids else None


def _matched_descriptor_count(services: Sequence[Service]) -> int:
    """Count services with a shipped or user-provided descriptor match."""
    return sum(1 for service in services if service.descriptor_id is not None)


def _build_vm_profile(vm: UnraidVMSummary) -> VMProfile:
    """Build one VM profile entry from the Unraid discovery surface."""
    return VMProfile(
        name=vm.name,
        purpose="unknown",
        os=vm.os,
        type=None,
        quirks=None,
        gpu_passthrough=False,
    )


def _build_plugin_profile(
    *,
    plugin: UnraidPluginSummary,
    impacted_services: Sequence[PluginImpactService],
) -> PluginProfile:
    """Build one persisted plugin facet from the Unraid discovery surface."""
    return PluginProfile(
        name=plugin.name,
        version=plugin.version,
        enabled=plugin.enabled,
        update_available=plugin.update_available,
        impacted_services=sorted(
            impacted_services,
            key=lambda impacted_service: (
                impacted_service.service_name.casefold(),
                impacted_service.service_id,
            ),
        ),
    )


def _build_plugin_impacts(
    *,
    services: Sequence[Service],
    descriptors: Sequence[LoadedServiceDescriptor],
) -> dict[str, list[PluginImpactService]]:
    """Resolve plugin-to-service impact annotations from explicit descriptor metadata."""
    descriptors_by_id = {
        loaded_descriptor_identifier(descriptor): descriptor.descriptor
        for descriptor in descriptors
    }
    plugin_impacts: dict[str, list[PluginImpactService]] = {}
    for service in services:
        if service.descriptor_id is None:
            continue
        descriptor = descriptors_by_id.get(service.descriptor_id)
        if descriptor is None:
            continue
        for plugin_dependency in descriptor.plugin_dependencies:
            plugin_impacts.setdefault(
                _plugin_dependency_key(plugin_dependency),
                [],
            ).append(
                PluginImpactService(
                    service_id=service.id,
                    service_name=service.name,
                    descriptor_id=service.descriptor_id,
                )
            )
    return plugin_impacts


def _build_plugin_change_events(
    *,
    previous_profile: SystemProfile | None,
    current_profile: SystemProfile,
) -> list[Change]:
    """Return deterministic plugin-update changes between persisted profile revisions."""
    if previous_profile is None:
        return []

    previous_by_name = {
        _plugin_dependency_key(plugin.name): plugin
        for plugin in previous_profile.plugins
    }
    current_by_name = {
        _plugin_dependency_key(plugin.name): plugin
        for plugin in current_profile.plugins
    }
    change_events: list[Change] = []

    for plugin_key in sorted(set(previous_by_name) | set(current_by_name)):
        previous_plugin = previous_by_name.get(plugin_key)
        current_plugin = current_by_name.get(plugin_key)
        if previous_plugin is None and current_plugin is not None:
            change_events.append(
                _plugin_change(
                    plugin=current_plugin,
                    timestamp=current_profile.last_updated,
                    kind="installed",
                    old_value=None,
                    new_value=_plugin_inventory_value(current_plugin),
                )
            )
            continue
        if previous_plugin is not None and current_plugin is None:
            change_events.append(
                _plugin_change(
                    plugin=previous_plugin,
                    timestamp=current_profile.last_updated,
                    kind="removed",
                    old_value=_plugin_inventory_value(previous_plugin),
                    new_value=None,
                )
            )
            continue
        if previous_plugin is None or current_plugin is None:
            continue
        if previous_plugin.version != current_plugin.version:
            change_events.append(
                _plugin_change(
                    plugin=current_plugin,
                    timestamp=current_profile.last_updated,
                    kind="version_changed",
                    old_value=previous_plugin.version,
                    new_value=current_plugin.version,
                )
            )
        if _plugin_state_value(previous_plugin) != _plugin_state_value(current_plugin):
            change_events.append(
                _plugin_change(
                    plugin=current_plugin,
                    timestamp=current_profile.last_updated,
                    kind="state_changed",
                    old_value=_plugin_state_value(previous_plugin),
                    new_value=_plugin_state_value(current_plugin),
                )
            )

    return change_events


def _plugin_change(
    *,
    plugin: PluginProfile,
    timestamp: datetime,
    kind: str,
    old_value: str | None,
    new_value: str | None,
) -> Change:
    """Build one deterministic plugin-update change record."""
    description_by_kind = {
        "installed": f"Plugin {plugin.name} was installed.",
        "removed": f"Plugin {plugin.name} was removed.",
        "version_changed": f"Plugin {plugin.name} changed version.",
        "state_changed": f"Plugin {plugin.name} changed state.",
    }
    impacted_service_names = [item.service_name for item in plugin.impacted_services]
    description = description_by_kind[kind]
    if impacted_service_names:
        description += " Impacted services: " + ", ".join(impacted_service_names) + "."
    return Change(
        id=_plugin_change_id(plugin=plugin, timestamp=timestamp, kind=kind),
        type=ChangeType.PLUGIN_UPDATE,
        service_id=(
            plugin.impacted_services[0].service_id
            if len(plugin.impacted_services) == 1
            else None
        ),
        description=description,
        old_value=old_value,
        new_value=new_value,
        timestamp=timestamp,
        correlated_incidents=[],
    )


def _plugin_change_id(*, plugin: PluginProfile, timestamp: datetime, kind: str) -> str:
    """Build one stable identifier for a plugin-update change record."""
    timestamp_token = timestamp.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return (
        "chg-plugin-update-"
        f"{_slugify_token(plugin.name)}-{kind}-{timestamp_token}"
    )


def _plugin_inventory_value(plugin: PluginProfile) -> str:
    """Render one plugin facet snapshot for change storage."""
    version = plugin.version or "unknown"
    return (
        f"version={version}; state={_plugin_state_value(plugin)}; "
        f"impacts={len(plugin.impacted_services)}"
    )


def _plugin_state_value(plugin: PluginProfile) -> str:
    """Render the plugin status tuple that drives state-change detection."""
    enabled = (
        "enabled"
        if plugin.enabled is True
        else "disabled"
        if plugin.enabled is False
        else "unknown"
    )
    update_state = (
        "update_available"
        if plugin.update_available is True
        else "up_to_date"
        if plugin.update_available is False
        else "update_unknown"
    )
    return f"{enabled}; {update_state}"


def _plugin_dependency_key(value: str) -> str:
    """Normalize one plugin identifier for deterministic matching."""
    return value.strip().casefold()


def _slugify_token(value: str) -> str:
    """Normalize arbitrary plugin names for stable change identifiers."""
    return (
        value.casefold()
        .replace(".", "-")
        .replace("_", "-")
        .replace(" ", "-")
        .strip("-")
    )


def _parity_drive_count(snapshot: UnraidDiscoverySnapshot) -> int:
    """Count parity disks from the Unraid array snapshot."""
    if snapshot.array is None:
        return 0
    return sum(1 for disk in snapshot.array.disks if disk.name.lower().startswith("parity"))


def _data_drive_count(snapshot: UnraidDiscoverySnapshot) -> int:
    """Count non-parity data disks from the Unraid array snapshot."""
    if snapshot.array is None:
        return 0
    return sum(1 for disk in snapshot.array.disks if not disk.name.lower().startswith("parity"))


def _bytes_to_gib(value: int | None) -> float:
    """Convert bytes to GiB with stable rounding."""
    if value is None:
        return 0.0
    return round(value / _BYTES_PER_GIB, 2)


def _bytes_to_tib(value: int | None) -> float:
    """Convert bytes to TiB with stable rounding."""
    if value is None:
        return 0.0
    return round(value / _BYTES_PER_TIB, 2)
