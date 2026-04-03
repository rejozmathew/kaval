"""Operational Memory Layer 1 system-profile materialization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.discovery.docker import DockerDiscoverySnapshot
from kaval.discovery.unraid import UnraidDiscoverySnapshot, UnraidVMSummary
from kaval.models import (
    ArrayProfile,
    HardwareProfile,
    NetworkingProfile,
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
    now: datetime | None = None,
) -> SystemProfile:
    """Build the auto-generated Layer 1 system profile from discovery data."""
    effective_now = now or datetime.now(tz=UTC)
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
        last_updated=effective_now,
    )


def persist_system_profile(database: KavalDatabase, system_profile: SystemProfile) -> None:
    """Persist the singleton system profile into the existing SQLite store."""
    database.upsert_system_profile(system_profile)
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
