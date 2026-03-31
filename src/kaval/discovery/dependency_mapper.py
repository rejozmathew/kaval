"""Dependency graph construction with explicit edge confidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable

from kaval.discovery.descriptors import DescriptorContainerDependency, LoadedServiceDescriptor
from kaval.discovery.docker import DockerContainerSnapshot, DockerDiscoverySnapshot
from kaval.discovery.matcher import build_service, match_service_descriptor, service_name_tokens
from kaval.discovery.unraid import UnraidDiscoverySnapshot, UnraidVMSummary
from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    Service,
    ServiceStatus,
    ServiceType,
)

_DEFAULT_DOCKER_NETWORKS = {"bridge", "host", "none"}


@dataclass(frozen=True, slots=True)
class DependencyGraphResult:
    """The typed services and dependency edges inferred from discovery data."""

    services: list[Service]


@dataclass(frozen=True, slots=True)
class _DiscoveredContainerService:
    """Internal container service state used while building the graph."""

    service: Service
    container: DockerContainerSnapshot
    descriptor: LoadedServiceDescriptor | None


def build_dependency_graph(
    docker_snapshot: DockerDiscoverySnapshot,
    descriptors: Iterable[LoadedServiceDescriptor],
    *,
    unraid_snapshot: UnraidDiscoverySnapshot | None = None,
) -> DependencyGraphResult:
    """Build a service graph with explicit dependency confidence edges."""
    descriptor_list = list(descriptors)
    container_services = [
        _DiscoveredContainerService(
            service=build_service(
                container,
                match_service_descriptor(container, descriptor_list),
            ),
            container=container,
            descriptor=match_service_descriptor(container, descriptor_list),
        )
        for container in docker_snapshot.containers
    ]

    share_services = _build_share_services(container_services, unraid_snapshot)
    vm_services = _build_vm_services(unraid_snapshot)
    dependency_map: dict[str, dict[str, DependencyEdge]] = {
        item.service.id: {}
        for item in container_services
    }
    all_services = [*(item.service for item in container_services), *share_services, *vm_services]

    service_token_index = _service_token_index(container_services)
    share_token_index = _share_token_index(share_services)
    for item in container_services:
        if item.descriptor is None:
            continue
        for target_id, edge in _descriptor_container_edges(
            item,
            service_token_index,
            container_services,
        ).items():
            dependency_map[item.service.id][target_id] = edge
        for target_id, edge in _share_edges(
            item,
            share_token_index,
        ).items():
            dependency_map[item.service.id][target_id] = edge

    dependents_map: dict[str, set[str]] = {service.id: set() for service in all_services}
    finalized_services: list[Service] = []
    for item in container_services:
        dependencies = sorted(
            dependency_map[item.service.id].values(),
            key=lambda edge: edge.target_service_id,
        )
        for edge in dependencies:
            dependents_map.setdefault(edge.target_service_id, set()).add(item.service.id)
        finalized_services.append(
            item.service.model_copy(
                update={"dependencies": dependencies},
            )
        )

    for share_service in share_services:
        finalized_services.append(
            share_service.model_copy(
                update={
                    "dependents": sorted(dependents_map.get(share_service.id, set())),
                }
            )
        )

    finalized_services.extend(vm_services)

    finalized_with_dependents = [
        service.model_copy(
            update={"dependents": sorted(dependents_map.get(service.id, set()))}
        )
        if service.type == ServiceType.CONTAINER
        else service
        for service in finalized_services
    ]
    finalized_with_dependents.sort(
        key=lambda service: (service.type.value, service.name.lower(), service.id)
    )
    return DependencyGraphResult(services=finalized_with_dependents)


def _descriptor_container_edges(
    item: _DiscoveredContainerService,
    service_token_index: dict[str, _DiscoveredContainerService],
    services: Iterable[_DiscoveredContainerService],
) -> dict[str, DependencyEdge]:
    """Resolve descriptor container dependencies against discovered services."""
    resolved: dict[str, DependencyEdge] = {}
    assert item.descriptor is not None
    for raw_dependency in item.descriptor.descriptor.typical_dependencies.containers:
        target = _resolve_container_dependency(raw_dependency, service_token_index)
        if target is None or target.service.id == item.service.id:
            continue

        confidence = DependencyConfidence.INFERRED
        source = DependencySource.DESCRIPTOR
        description = f"Descriptor dependency from {item.service.name} to {target.service.name}."

        shared_networks = _shared_non_default_networks(item.container, target.container)
        if shared_networks:
            confidence = DependencyConfidence.CONFIGURED
            source = DependencySource.DOCKER_NETWORK
            joined_networks = ", ".join(shared_networks)
            description = (
                "Descriptor dependency corroborated by shared Docker "
                f"network(s): {joined_networks}."
            )

        resolved[target.service.id] = DependencyEdge(
            target_service_id=target.service.id,
            confidence=confidence,
            source=source,
            description=description,
        )
    return resolved


def _share_edges(
    item: _DiscoveredContainerService,
    share_token_index: dict[str, Service],
) -> dict[str, DependencyEdge]:
    """Resolve descriptor share dependencies against discovered share services."""
    resolved: dict[str, DependencyEdge] = {}
    assert item.descriptor is not None
    mounted_share_names = {
        share_name
        for share_name in (
            _mounted_share_name(mount.source) for mount in item.container.mounts
        )
        if share_name is not None
    }
    for share_name in item.descriptor.descriptor.typical_dependencies.shares:
        target = share_token_index.get(_normalize_token(share_name))
        if target is None:
            continue

        confidence = DependencyConfidence.INFERRED
        source = DependencySource.DESCRIPTOR
        description = f"Descriptor dependency from {item.service.name} to share {target.name}."
        if _normalize_token(share_name) in mounted_share_names:
            confidence = DependencyConfidence.CONFIGURED
            source = DependencySource.SHARED_VOLUME
            description = (
                f"Descriptor dependency corroborated by mounted share path for {target.name}."
            )

        resolved[target.id] = DependencyEdge(
            target_service_id=target.id,
            confidence=confidence,
            source=source,
            description=description,
        )
    return resolved


def _resolve_container_dependency(
    raw_dependency: str | DescriptorContainerDependency,
    service_token_index: dict[str, _DiscoveredContainerService],
) -> _DiscoveredContainerService | None:
    """Resolve one descriptor dependency entry to a discovered service."""
    candidates: list[str]
    if isinstance(raw_dependency, str):
        candidates = [raw_dependency]
    else:
        candidates = [raw_dependency.name, *raw_dependency.alternatives]

    for candidate in candidates:
        match = service_token_index.get(_normalize_token(candidate))
        if match is not None:
            return match
    return None


def _service_token_index(
    services: Iterable[_DiscoveredContainerService],
) -> dict[str, _DiscoveredContainerService]:
    """Build a name-token index for matched container services."""
    index: dict[str, _DiscoveredContainerService] = {}
    for item in services:
        tokens = service_name_tokens(item.service) | {_normalize_token(item.container.name)}
        if item.descriptor is not None:
            tokens.add(_normalize_token(item.descriptor.descriptor.id))
        for token in tokens:
            index.setdefault(token, item)
    return index


def _share_token_index(services: Iterable[Service]) -> dict[str, Service]:
    """Build a name-token index for share services."""
    index: dict[str, Service] = {}
    for service in services:
        index[_normalize_token(service.name)] = service
    return index


def _build_share_services(
    container_services: Iterable[_DiscoveredContainerService],
    unraid_snapshot: UnraidDiscoverySnapshot | None,
) -> list[Service]:
    """Build deterministic share service nodes from Unraid and mount data."""
    share_names: dict[str, str] = {}
    if unraid_snapshot is not None:
        for share in unraid_snapshot.shares:
            share_names[_normalize_token(share.name)] = share.name
    for item in container_services:
        for mount in item.container.mounts:
            share_name = _mounted_share_name(mount.source)
            if share_name is None:
                continue
            share_names.setdefault(share_name, share_name)

    return [
        Service(
            id=f"svc-share-{share_token}",
            name=share_name,
            type=ServiceType.SHARE,
            category="storage",
            status=ServiceStatus.UNKNOWN,
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=None,
            image=None,
            endpoints=[],
            dependencies=[],
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        )
        for share_token, share_name in sorted(share_names.items())
    ]


def _build_vm_services(unraid_snapshot: UnraidDiscoverySnapshot | None) -> list[Service]:
    """Build deterministic VM service nodes from the Unraid snapshot."""
    if unraid_snapshot is None:
        return []

    return [
        Service(
            id=_vm_service_id(vm),
            name=vm.name,
            type=ServiceType.VM,
            category="virtualization",
            status=_vm_service_status(vm),
            descriptor_id=None,
            descriptor_source=None,
            container_id=None,
            vm_id=vm.id,
            image=None,
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=[],
            last_check=None,
            active_findings=0,
            active_incidents=0,
        )
        for vm in sorted(unraid_snapshot.vms, key=lambda vm: (vm.name.lower(), vm.id))
    ]


def _vm_service_id(vm: UnraidVMSummary) -> str:
    """Return the stable service identifier for one discovered VM."""
    normalized_id = _normalize_token(vm.id)
    if normalized_id.startswith("vm-"):
        normalized_id = normalized_id.removeprefix("vm-")
    return f"svc-vm-{normalized_id}"


def _vm_service_status(vm: UnraidVMSummary) -> ServiceStatus:
    """Map the Unraid VM state to the service health model."""
    state = (vm.state or "").strip().lower()
    if state in {"running", "started"}:
        return ServiceStatus.HEALTHY
    if state in {"paused", "suspended"}:
        return ServiceStatus.DEGRADED
    if state in {"stopped", "shut off", "shutoff", "shutdown"}:
        return ServiceStatus.STOPPED
    return ServiceStatus.UNKNOWN


def _shared_non_default_networks(
    source: DockerContainerSnapshot,
    target: DockerContainerSnapshot,
) -> list[str]:
    """Return shared non-default Docker networks between two containers."""
    source_networks = {
        network.name for network in source.networks if network.name not in _DEFAULT_DOCKER_NETWORKS
    }
    target_networks = {
        network.name for network in target.networks if network.name not in _DEFAULT_DOCKER_NETWORKS
    }
    return sorted(source_networks & target_networks)


def _mounted_share_name(path: str | None) -> str | None:
    """Return a normalized Unraid share name from a mount source path."""
    if path is None:
        return None
    mount_path = PurePosixPath(path)
    parts = mount_path.parts
    if len(parts) >= 4 and parts[:3] == ("/", "mnt", "user"):
        return _normalize_token(parts[3])
    return None


def _normalize_token(value: str) -> str:
    """Normalize names used for dependency resolution."""
    return value.lower().replace("_", "-").strip()
