"""YAML service descriptor schema and loader utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Sequence, cast

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
    plugin_dependencies: list[str] = Field(default_factory=list)
    common_failure_modes: list[DescriptorFailureMode] = Field(default_factory=list)
    investigation_context: str | None = None
    inspection: DescriptorInspection = Field(default_factory=DescriptorInspection)
    credential_hints: dict[str, DescriptorCredentialHint] = Field(default_factory=dict)
    source: DescriptorSource = DescriptorSource.SHIPPED
    verified: bool = True
    generated_at: datetime | None = None

    @model_validator(mode="after")
    def validate_plugin_dependencies(self) -> ServiceDescriptor:
        """Keep plugin dependency metadata explicit, normalized, and unique."""
        normalized_dependencies = [dependency.strip() for dependency in self.plugin_dependencies]
        if any(not dependency for dependency in normalized_dependencies):
            msg = "plugin_dependencies must not contain blank values"
            raise ValueError(msg)
        lowered = [dependency.casefold() for dependency in normalized_dependencies]
        duplicates = sorted(
            {
                dependency
                for dependency, lowered_dependency in zip(
                    normalized_dependencies,
                    lowered,
                    strict=False,
                )
                if lowered.count(lowered_dependency) > 1
            }
        )
        if duplicates:
            duplicate_list = ", ".join(duplicates)
            raise ValueError(
                f"plugin_dependencies must be unique case-insensitively: {duplicate_list}"
            )
        self.plugin_dependencies = normalized_dependencies
        return self


@dataclass(frozen=True, slots=True)
class LoadedServiceDescriptor:
    """A descriptor paired with its on-disk source path."""

    path: Path
    descriptor: ServiceDescriptor


@dataclass(frozen=True, slots=True)
class CommunityDescriptorExport:
    """A cleaned descriptor export suitable for community review."""

    target_path: str
    yaml_text: str
    omitted_fields: tuple[str, ...]


_USER_DESCRIPTOR_DIRNAME = "user"
_AUTO_GENERATED_DESCRIPTOR_DIRNAME = "auto_generated"


def descriptor_identifier(descriptor: ServiceDescriptor) -> str:
    """Return the stable identifier stored on service records."""
    return f"{descriptor.category}/{descriptor.id}"


def loaded_descriptor_identifier(loaded_descriptor: LoadedServiceDescriptor) -> str:
    """Return the stable identifier for one loaded descriptor record."""
    return descriptor_identifier(loaded_descriptor.descriptor)


def build_user_descriptor_path(
    services_dir: Path | str,
    descriptor: ServiceDescriptor,
) -> Path:
    """Return the canonical writable path for one user descriptor override."""
    return (
        Path(services_dir)
        / _USER_DESCRIPTOR_DIRNAME
        / descriptor.category
        / f"{descriptor.id}.yaml"
    )


def build_user_descriptor_reference_path(
    services_dir: Path | str,
    *,
    category: str,
    descriptor_id: str,
) -> Path:
    """Return the canonical user-descriptor path for one descriptor identifier."""
    return (
        Path(services_dir)
        / _USER_DESCRIPTOR_DIRNAME
        / category
        / f"{descriptor_id}.yaml"
    )


def build_auto_generated_descriptor_path(
    services_dir: Path | str,
    descriptor: ServiceDescriptor,
) -> Path:
    """Return the canonical quarantine path for one auto-generated descriptor."""
    return (
        Path(services_dir)
        / _AUTO_GENERATED_DESCRIPTOR_DIRNAME
        / descriptor.category
        / f"{descriptor.id}.yaml"
    )


def build_auto_generated_descriptor_reference_path(
    services_dir: Path | str,
    *,
    category: str,
    descriptor_id: str,
) -> Path:
    """Return the canonical quarantine path for one descriptor identifier."""
    return (
        Path(services_dir)
        / _AUTO_GENERATED_DESCRIPTOR_DIRNAME
        / category
        / f"{descriptor_id}.yaml"
    )


def dump_service_descriptor_yaml(descriptor: ServiceDescriptor) -> str:
    """Serialize one descriptor into deterministic YAML for repo-backed storage."""
    payload = descriptor.model_dump(mode="json", exclude_none=True)
    return cast(
        str,
        yaml.safe_dump(payload, allow_unicode=False, sort_keys=False),
    )


def build_service_descriptor_community_export(
    descriptor: ServiceDescriptor,
) -> CommunityDescriptorExport:
    """Serialize one reviewed descriptor into a contributor-safe YAML export."""
    payload: dict[str, object] = {
        "id": descriptor.id,
        "name": descriptor.name,
        "category": descriptor.category,
        "match": descriptor.match.model_dump(mode="json", exclude_none=True),
    }
    if descriptor.project_url is not None:
        payload["project_url"] = descriptor.project_url
    if descriptor.icon is not None:
        payload["icon"] = descriptor.icon
    if descriptor.endpoints:
        payload["endpoints"] = {
            name: endpoint.model_dump(mode="json", exclude_none=True)
            for name, endpoint in descriptor.endpoints.items()
        }
    if descriptor.log_signals.errors or descriptor.log_signals.warnings:
        payload["log_signals"] = descriptor.log_signals.model_dump(
            mode="json",
            exclude_none=True,
        )

    dependencies: dict[str, object] = {}
    if descriptor.typical_dependencies.containers:
        dependencies["containers"] = [
            item.model_dump(mode="json", exclude_none=True)
            if isinstance(item, DescriptorContainerDependency)
            else item
            for item in descriptor.typical_dependencies.containers
        ]
    if descriptor.typical_dependencies.shares:
        dependencies["shares"] = list(descriptor.typical_dependencies.shares)
    if dependencies:
        payload["typical_dependencies"] = dependencies
    if descriptor.plugin_dependencies:
        payload["plugin_dependencies"] = list(descriptor.plugin_dependencies)
    if descriptor.common_failure_modes:
        payload["common_failure_modes"] = [
            item.model_dump(mode="json", exclude_none=True)
            for item in descriptor.common_failure_modes
        ]
    if descriptor.investigation_context is not None:
        payload["investigation_context"] = descriptor.investigation_context

    omitted_fields = ["source", "verified"]
    if descriptor.generated_at is not None:
        omitted_fields.append("generated_at")
    if descriptor.dns_targets:
        omitted_fields.append("dns_targets")
    if descriptor.inspection.surfaces:
        omitted_fields.append("inspection")
    if descriptor.credential_hints:
        omitted_fields.append("credential_hints")

    return CommunityDescriptorExport(
        target_path=f"services/{descriptor.category}/{descriptor.id}.yaml",
        yaml_text=cast(
            str,
            yaml.safe_dump(payload, allow_unicode=False, sort_keys=False),
        ),
        omitted_fields=tuple(omitted_fields),
    )


def write_user_descriptor(
    *,
    services_dir: Path | str,
    descriptor: ServiceDescriptor,
) -> LoadedServiceDescriptor:
    """Persist one reviewed user descriptor override into the canonical tree."""
    descriptor_path = build_user_descriptor_path(services_dir, descriptor)
    descriptor_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor_path.write_text(
        dump_service_descriptor_yaml(descriptor),
        encoding="utf-8",
    )
    return LoadedServiceDescriptor(path=descriptor_path, descriptor=descriptor)


def write_auto_generated_descriptor(
    *,
    services_dir: Path | str,
    descriptor: ServiceDescriptor,
) -> LoadedServiceDescriptor:
    """Persist one quarantined auto-generated descriptor into the canonical tree."""
    descriptor_path = build_auto_generated_descriptor_path(services_dir, descriptor)
    descriptor_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor_path.write_text(
        dump_service_descriptor_yaml(descriptor),
        encoding="utf-8",
    )
    return LoadedServiceDescriptor(path=descriptor_path, descriptor=descriptor)


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
        summary = _descriptor_validation_error_message(exc)
        raise DescriptorLoadError(
            f"descriptor validation failed for {descriptor_path}: {summary}"
        ) from exc
    return LoadedServiceDescriptor(path=descriptor_path, descriptor=descriptor)


def _descriptor_validation_error_message(exc: ValidationError) -> str:
    """Summarize the first validation errors for readable loader failures."""
    parts: list[str] = []
    for error in exc.errors()[:3]:
        location = ".".join(str(part) for part in error["loc"])
        message = str(error["msg"])
        if message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        parts.append(message if not location else f"{location}: {message}")
    return "; ".join(parts) or "unknown validation error"


def load_service_descriptors(paths: Sequence[Path | str]) -> list[LoadedServiceDescriptor]:
    """Load all service descriptors from the configured descriptor paths."""
    active_descriptors: dict[str, LoadedServiceDescriptor] = {}
    for path in discover_descriptor_files(paths):
        priority = _active_descriptor_priority(path)
        if priority is None:
            continue

        loaded_descriptor = load_service_descriptor(path)
        descriptor_id = loaded_descriptor_identifier(loaded_descriptor)
        existing_descriptor = active_descriptors.get(descriptor_id)
        if existing_descriptor is None:
            active_descriptors[descriptor_id] = loaded_descriptor
            continue

        existing_priority = _active_descriptor_priority(existing_descriptor.path)
        if existing_priority == priority:
            raise DescriptorLoadError(f"duplicate descriptor ids: {descriptor_id}")
        if existing_priority is None or priority > existing_priority:
            active_descriptors[descriptor_id] = loaded_descriptor

    return [
        active_descriptors[descriptor_id]
        for descriptor_id in sorted(active_descriptors)
    ]


def load_auto_generated_service_descriptors(
    paths: Sequence[Path | str],
) -> list[LoadedServiceDescriptor]:
    """Load only quarantined auto-generated descriptors from the configured tree."""
    loaded_descriptors: dict[str, LoadedServiceDescriptor] = {}
    for path in discover_descriptor_files(paths):
        if _AUTO_GENERATED_DESCRIPTOR_DIRNAME not in path.parts:
            continue
        loaded_descriptor = load_service_descriptor(path)
        descriptor_id = loaded_descriptor_identifier(loaded_descriptor)
        if descriptor_id in loaded_descriptors:
            raise DescriptorLoadError(f"duplicate descriptor ids: {descriptor_id}")
        loaded_descriptors[descriptor_id] = loaded_descriptor
    return [
        loaded_descriptors[descriptor_id]
        for descriptor_id in sorted(loaded_descriptors)
    ]


def _active_descriptor_priority(path: Path) -> int | None:
    """Return load precedence for active descriptors, skipping quarantine trees."""
    path_parts = path.parts
    if _AUTO_GENERATED_DESCRIPTOR_DIRNAME in path_parts:
        return None
    if _USER_DESCRIPTOR_DIRNAME in path_parts:
        return 2
    return 1
