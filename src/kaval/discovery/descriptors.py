"""YAML service descriptor schema and loader utilities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Sequence

import yaml  # type: ignore[import-untyped]
from pydantic import Field, ValidationError, model_validator

from kaval.models import DescriptorSource, DnsTarget, KavalModel, PortNumber


class DescriptorLoadError(RuntimeError):
    """Raised when a descriptor file cannot be loaded or validated."""


class DescriptorMatchRule(KavalModel):
    """Patterns used to match a discovered service to a descriptor."""

    image_patterns: list[str] = Field(default_factory=list)
    container_name_patterns: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_patterns(self) -> DescriptorMatchRule:
        """Require at least one image or container name pattern."""
        if not self.image_patterns and not self.container_name_patterns:
            msg = "descriptor match rules require at least one pattern"
            raise ValueError(msg)
        return self


class DescriptorEndpoint(KavalModel):
    """A health or UI endpoint defined by a service descriptor."""

    port: int = PortNumber
    path: str | None = None
    auth: str | None = None
    auth_header: str | None = None
    healthy_when: str | None = None


class DescriptorLogSignals(KavalModel):
    """Log signal patterns associated with a service."""

    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DescriptorContainerDependency(KavalModel):
    """A named container dependency with optional alternatives."""

    name: str
    alternatives: list[str] = Field(default_factory=list)


class DescriptorDependencies(KavalModel):
    """Typical dependencies captured by a service descriptor."""

    containers: list[str | DescriptorContainerDependency] = Field(default_factory=list)
    shares: list[str] = Field(default_factory=list)


class DescriptorFailureMode(KavalModel):
    """A common failure mode captured by a service descriptor."""

    trigger: str
    likely_cause: str
    check_first: list[str] = Field(default_factory=list)


class DescriptorInspectionSurfaceType(StrEnum):
    """Supported deep-inspection surface types."""

    API = "api"
    CONFIG = "config"
    DATABASE = "database"


class DescriptorInspectionAuthMode(StrEnum):
    """Supported auth modes for inspection surfaces."""

    API_KEY = "api_key"
    TOKEN = "token"
    BASIC = "basic"


class DescriptorInspectionConfidenceEffect(StrEnum):
    """Supported dependency-confidence upgrades from inspection surfaces."""

    UPGRADE_TO_RUNTIME_OBSERVED = "upgrade_to_runtime_observed"


class DescriptorInspectionSurface(KavalModel):
    """One declarative deep-inspection surface exposed by a service descriptor."""

    id: str
    type: DescriptorInspectionSurfaceType
    description: str
    endpoint: str | None = None
    auth: DescriptorInspectionAuthMode | None = None
    auth_header: str | None = None
    read_only: bool = True
    facts_provided: list[str] = Field(default_factory=list)
    confidence_effect: DescriptorInspectionConfidenceEffect | None = None
    version_range: str | None = None

    @model_validator(mode="after")
    def validate_surface_contract(self) -> DescriptorInspectionSurface:
        """Enforce the declarative descriptor contract for deep inspection."""
        if self.type == DescriptorInspectionSurfaceType.API:
            if self.endpoint is None or not self.endpoint.startswith("/"):
                msg = "api inspection surfaces require a relative endpoint path"
                raise ValueError(msg)
        if not self.facts_provided:
            msg = "inspection surfaces require at least one declared fact"
            raise ValueError(msg)
        if not self.read_only:
            msg = "inspection surfaces must be read_only in Phase 3A"
            raise ValueError(msg)
        if self.auth is None and self.auth_header is not None:
            msg = "auth_header requires an auth mode"
            raise ValueError(msg)
        return self


class DescriptorInspection(KavalModel):
    """Inspection capability declarations for a service descriptor."""

    surfaces: list[DescriptorInspectionSurface] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_surface_ids(self) -> DescriptorInspection:
        """Require stable, unique surface identifiers per descriptor."""
        surface_ids = [surface.id for surface in self.surfaces]
        duplicate_ids = sorted(
            {surface_id for surface_id in surface_ids if surface_ids.count(surface_id) > 1}
        )
        if duplicate_ids:
            duplicates = ", ".join(duplicate_ids)
            raise ValueError(f"inspection surfaces require unique ids: {duplicates}")
        return self


class DescriptorCredentialHint(KavalModel):
    """Instructions for locating a service credential."""

    description: str
    location: str
    prompt: str | None = None


class ServiceDescriptor(KavalModel):
    """A strict YAML-backed service descriptor."""

    id: str
    name: str
    category: str
    project_url: str | None = None
    icon: str | None = None
    match: DescriptorMatchRule
    endpoints: dict[str, DescriptorEndpoint] = Field(default_factory=dict)
    dns_targets: list[DnsTarget] = Field(default_factory=list)
    log_signals: DescriptorLogSignals = Field(default_factory=DescriptorLogSignals)
    typical_dependencies: DescriptorDependencies = Field(default_factory=DescriptorDependencies)
    common_failure_modes: list[DescriptorFailureMode] = Field(default_factory=list)
    investigation_context: str | None = None
    inspection: DescriptorInspection = Field(default_factory=DescriptorInspection)
    credential_hints: dict[str, DescriptorCredentialHint] = Field(default_factory=dict)
    source: DescriptorSource = DescriptorSource.SHIPPED
    verified: bool = True


@dataclass(frozen=True, slots=True)
class LoadedServiceDescriptor:
    """A descriptor paired with its on-disk source path."""

    path: Path
    descriptor: ServiceDescriptor


def discover_descriptor_files(paths: Sequence[Path | str]) -> list[Path]:
    """Return all YAML descriptor files from the configured descriptor paths."""
    descriptor_files: list[Path] = []
    for raw_path in paths:
        base_path = Path(raw_path)
        if not base_path.exists():
            continue
        for candidate in sorted(base_path.rglob("*.yaml")):
            if candidate.name.startswith("."):
                continue
            descriptor_files.append(candidate)
    return descriptor_files


def load_service_descriptor(path: Path | str) -> LoadedServiceDescriptor:
    """Load and validate one service descriptor file."""
    descriptor_path = Path(path)
    try:
        parsed = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise DescriptorLoadError(f"invalid YAML in {descriptor_path}") from exc
    if not isinstance(parsed, dict):
        raise DescriptorLoadError(f"descriptor {descriptor_path} must contain a YAML mapping")
    try:
        descriptor = ServiceDescriptor.model_validate(parsed)
    except ValidationError as exc:
        raise DescriptorLoadError(f"descriptor validation failed for {descriptor_path}") from exc
    return LoadedServiceDescriptor(path=descriptor_path, descriptor=descriptor)


def load_service_descriptors(paths: Sequence[Path | str]) -> list[LoadedServiceDescriptor]:
    """Load all service descriptors from the configured descriptor paths."""
    loaded_descriptors = [
        load_service_descriptor(path)
        for path in discover_descriptor_files(paths)
    ]
    descriptor_ids = [item.descriptor.id for item in loaded_descriptors]
    duplicate_ids = sorted(
        {
            descriptor_id
            for descriptor_id in descriptor_ids
            if descriptor_ids.count(descriptor_id) > 1
        }
    )
    if duplicate_ids:
        duplicates = ", ".join(duplicate_ids)
        raise DescriptorLoadError(f"duplicate descriptor ids: {duplicates}")
    return loaded_descriptors
