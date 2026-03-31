"""Service descriptor matching for discovered Docker containers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Iterable

from kaval.discovery.descriptors import LoadedServiceDescriptor
from kaval.discovery.docker import DockerContainerSnapshot
from kaval.models import (
    DnsTarget,
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class DescriptorMatch:
    """A matched descriptor and the score that selected it."""

    descriptor: LoadedServiceDescriptor
    score: int


def match_service_descriptor(
    container: DockerContainerSnapshot,
    descriptors: Iterable[LoadedServiceDescriptor],
) -> LoadedServiceDescriptor | None:
    """Return the best-matching service descriptor for a discovered container."""
    matches: list[DescriptorMatch] = []
    for descriptor in descriptors:
        score = _descriptor_match_score(container, descriptor)
        if score > 0:
            matches.append(DescriptorMatch(descriptor=descriptor, score=score))
    if not matches:
        return None
    matches.sort(
        key=lambda match: (
            -match.score,
            match.descriptor.path.parent.name,
            match.descriptor.path.name,
        )
    )
    return matches[0].descriptor


def build_service(
    container: DockerContainerSnapshot,
    descriptor: LoadedServiceDescriptor | None,
) -> Service:
    """Build a Service model for a discovered Docker container."""
    service_id_slug = descriptor.descriptor.id if descriptor is not None else container.name
    return Service(
        id=f"svc-{_slugify(service_id_slug)}",
        name=descriptor.descriptor.name if descriptor is not None else container.name,
        type=ServiceType.CONTAINER,
        category=descriptor.descriptor.category if descriptor is not None else "container",
        status=_service_status(container),
        descriptor_id=_descriptor_id(descriptor),
        descriptor_source=(
            descriptor.descriptor.source if descriptor is not None else None
        ),
        container_id=container.id,
        vm_id=None,
        image=container.image,
        endpoints=_build_endpoints(container, descriptor),
        dns_targets=_build_dns_targets(descriptor),
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _descriptor_match_score(
    container: DockerContainerSnapshot,
    descriptor: LoadedServiceDescriptor,
) -> int:
    """Return a deterministic specificity score for a descriptor match."""
    scores: list[int] = []
    for pattern in descriptor.descriptor.match.image_patterns:
        if fnmatch(container.image, pattern):
            scores.append(_pattern_score(pattern))
    for pattern in descriptor.descriptor.match.container_name_patterns:
        if fnmatch(container.name, pattern):
            scores.append(_pattern_score(pattern))
    if not scores:
        return 0
    return max(scores)


def _pattern_score(pattern: str) -> int:
    """Return a specificity score for a fnmatch pattern."""
    wildcard_penalty = pattern.count("*") + pattern.count("?")
    return len(pattern) - wildcard_penalty


def _service_status(container: DockerContainerSnapshot) -> ServiceStatus:
    """Map Docker state into the Service health model."""
    health_status = container.state.health.status if container.state.health is not None else None
    if health_status == "unhealthy":
        return ServiceStatus.DEGRADED
    if container.state.restarting:
        return ServiceStatus.DEGRADED
    if container.state.running:
        return ServiceStatus.HEALTHY
    if container.state.status in {"created", "paused"}:
        return ServiceStatus.STOPPED
    if container.state.status in {"dead", "exited"}:
        return ServiceStatus.DOWN
    return ServiceStatus.UNKNOWN


def _descriptor_id(descriptor: LoadedServiceDescriptor | None) -> str | None:
    """Return a stable descriptor identifier for a matched file."""
    if descriptor is None:
        return None
    return f"{descriptor.path.parent.name}/{descriptor.path.stem}"


def _build_endpoints(
    container: DockerContainerSnapshot,
    descriptor: LoadedServiceDescriptor | None,
) -> list[Endpoint]:
    """Build Service endpoints from the descriptor or published ports."""
    if descriptor is not None and descriptor.descriptor.endpoints:
        return [
            Endpoint(
                name=name,
                protocol=EndpointProtocol.HTTP,
                host=container.name,
                port=endpoint.port,
                path=endpoint.path,
                url=None,
                auth_required=endpoint.auth is not None,
                expected_status=200,
            )
            for name, endpoint in descriptor.descriptor.endpoints.items()
        ]

    return [
        Endpoint(
            name=f"port_{binding.container_port}_{binding.protocol}",
            protocol=EndpointProtocol.TCP,
            host=container.name,
            port=binding.container_port,
            path=None,
            url=None,
            auth_required=False,
            expected_status=None,
        )
        for binding in container.ports
    ]


def _build_dns_targets(descriptor: LoadedServiceDescriptor | None) -> list[DnsTarget]:
    """Build Service DNS targets from descriptor metadata."""
    if descriptor is None:
        return []
    return [
        DnsTarget(
            host=target.host,
            record_type=target.record_type,
            expected_values=list(target.expected_values),
        )
        for target in descriptor.descriptor.dns_targets
    ]


def service_name_tokens(service: Service) -> set[str]:
    """Return normalized names used to resolve dependency references."""
    tokens = {
        _slugify(service.id.removeprefix("svc-")),
        _slugify(service.name),
    }
    if service.descriptor_id is not None:
        tokens.add(_slugify(service.descriptor_id.rsplit("/", maxsplit=1)[-1]))
    if service.container_id is not None:
        tokens.add(_slugify(service.container_id))
    return {token for token in tokens if token}


def _slugify(value: str) -> str:
    """Normalize a value for stable identifiers and comparisons."""
    normalized = _NON_ALNUM_RE.sub("-", value.lower()).strip("-")
    return normalized
