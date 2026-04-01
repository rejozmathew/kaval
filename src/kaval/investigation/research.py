"""Tier 2 public research for version and changelog enrichment."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from pydantic import Field

from kaval.integrations.external_apis.dockerhub import (
    DockerHubClient,
    DockerHubError,
    DockerHubImageReference,
    DockerHubNotFoundError,
    DockerHubOfflineError,
    DockerHubRepository,
    DockerHubTag,
    parse_dockerhub_reference,
)
from kaval.integrations.external_apis.github_releases import (
    GitHubRelease,
    GitHubReleasesClient,
    GitHubReleasesError,
    GitHubReleasesNotFoundError,
    GitHubReleasesOfflineError,
    GitHubRepositoryReference,
    parse_repository_reference,
)
from kaval.models import Change, ChangeType, Incident, KavalModel, ResearchStep, Service

_OFFLINE_DEGRADED_REASON = (
    "Research steps skipped (no internet access). Root cause analysis based on local "
    "evidence only. Confidence may be lower than usual."
)


class Tier2ResearchStatus(StrEnum):
    """Explicit outcome states for one public research source."""

    SUCCESS = "success"
    PARTIAL = "partial"
    SKIPPED_OFFLINE = "skipped_offline"
    NOT_FOUND = "not_found"
    NO_PUBLIC_SOURCE = "no_public_source"
    INSUFFICIENT_DATA = "insufficient_data"


class PublicResearchHints(KavalModel):
    """Optional public-source hints used to resolve research targets."""

    github_repository: str | None = None
    dockerhub_reference: str | None = None


class Tier2ResearchTarget(KavalModel):
    """One service/version target eligible for Tier 2 public research."""

    service_id: str
    service_name: str
    change_id: str
    current_image: str | None = None
    previous_image: str | None = None
    current_tag: str | None = None
    previous_tag: str | None = None
    github_repository: GitHubRepositoryReference | None = None
    dockerhub_reference: DockerHubImageReference | None = None


class ServiceResearchResult(KavalModel):
    """Public research collected for one service target."""

    target: Tier2ResearchTarget
    github_status: Tier2ResearchStatus
    dockerhub_status: Tier2ResearchStatus
    research_steps: list[ResearchStep] = Field(default_factory=list)
    github_current_release: GitHubRelease | None = None
    github_previous_release: GitHubRelease | None = None
    docker_repository: DockerHubRepository | None = None
    docker_current_tag: DockerHubTag | None = None
    docker_previous_tag: DockerHubTag | None = None
    warnings: list[str] = Field(default_factory=list)


class Tier2ResearchBundle(KavalModel):
    """Aggregated Tier 2 research results ready for workflow integration."""

    research_steps: list[ResearchStep] = Field(default_factory=list)
    service_results: list[ServiceResearchResult] = Field(default_factory=list)
    skipped_offline: bool = False
    degraded_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class GitHubResearchClient(Protocol):
    """The GitHub lookup surface required by Tier 2 research."""

    def fetch_release_by_tag(
        self,
        repository: GitHubRepositoryReference | str,
        *,
        tag_name: str,
    ) -> GitHubRelease:
        """Fetch one GitHub release by tag."""


class DockerHubResearchClient(Protocol):
    """The Docker Hub lookup surface required by Tier 2 research."""

    def fetch_repository(
        self,
        reference: DockerHubImageReference | str,
    ) -> DockerHubRepository:
        """Fetch one Docker Hub repository metadata record."""

    def fetch_tag(
        self,
        reference: DockerHubImageReference | str,
        *,
        tag_name: str | None = None,
    ) -> DockerHubTag:
        """Fetch one Docker Hub tag metadata record."""


def build_tier2_research_targets(
    *,
    incident: Incident,
    services: Sequence[Service],
    changes: Sequence[Change],
    hints_by_service: Mapping[str, PublicResearchHints] | None = None,
) -> list[Tier2ResearchTarget]:
    """Build public research targets from correlated image-update changes."""
    service_by_id = {service.id: service for service in services}
    hints = hints_by_service or {}

    targets: list[Tier2ResearchTarget] = []
    for change in sorted(changes, key=lambda item: (item.timestamp, item.id)):
        if change.type != ChangeType.IMAGE_UPDATE:
            continue
        if change.id not in incident.changes_correlated:
            continue
        if change.service_id is None:
            continue

        service = service_by_id.get(change.service_id)
        hint = hints.get(change.service_id)
        previous_image = _extract_image_reference(change.old_value)
        current_image = _extract_image_reference(change.new_value)
        current_docker_ref = _parse_optional_dockerhub_reference(current_image)
        previous_docker_ref = _parse_optional_dockerhub_reference(previous_image)

        targets.append(
            Tier2ResearchTarget(
                service_id=change.service_id,
                service_name=service.name if service is not None else change.service_id,
                change_id=change.id,
                current_image=current_image,
                previous_image=previous_image,
                current_tag=current_docker_ref.tag if current_docker_ref is not None else None,
                previous_tag=(
                    previous_docker_ref.tag if previous_docker_ref is not None else None
                ),
                github_repository=_parse_optional_github_repository(
                    None if hint is None else hint.github_repository
                ),
                dockerhub_reference=(
                    _parse_optional_dockerhub_reference(
                        None if hint is None else hint.dockerhub_reference
                    )
                    or current_docker_ref
                    or previous_docker_ref
                ),
            )
        )
    return targets


def run_tier2_research(
    *,
    targets: Sequence[Tier2ResearchTarget],
    github_client: GitHubResearchClient | None = None,
    dockerhub_client: DockerHubResearchClient | None = None,
    offline_mode: bool = False,
    now: datetime | None = None,
) -> Tier2ResearchBundle:
    """Collect public Tier 2 research for the supplied service targets."""
    effective_now = now or datetime.now(tz=UTC)
    if not targets:
        return Tier2ResearchBundle()

    if offline_mode:
        return _offline_research_bundle(targets=targets, timestamp=effective_now)

    resolved_github_client = github_client or GitHubReleasesClient()
    resolved_dockerhub_client = dockerhub_client or DockerHubClient()

    next_order = 1
    service_results: list[ServiceResearchResult] = []
    research_steps: list[ResearchStep] = []
    degraded_reasons: list[str] = []
    warnings: list[str] = []

    for target in targets:
        service_result = _collect_service_research(
            target=target,
            github_client=resolved_github_client,
            dockerhub_client=resolved_dockerhub_client,
            start_order=next_order,
            timestamp=effective_now,
        )
        service_results.append(service_result)
        research_steps.extend(service_result.research_steps)
        warnings.extend(service_result.warnings)
        if (
            service_result.github_status == Tier2ResearchStatus.SKIPPED_OFFLINE
            or service_result.dockerhub_status == Tier2ResearchStatus.SKIPPED_OFFLINE
        ):
            _append_unique(degraded_reasons, _OFFLINE_DEGRADED_REASON)
        next_order += len(service_result.research_steps)

    return Tier2ResearchBundle(
        research_steps=research_steps,
        service_results=service_results,
        skipped_offline=bool(degraded_reasons),
        degraded_reasons=degraded_reasons,
        warnings=warnings,
    )


def _offline_research_bundle(
    *,
    targets: Sequence[Tier2ResearchTarget],
    timestamp: datetime,
) -> Tier2ResearchBundle:
    """Return an explicit offline skip bundle for Tier 2 research."""
    research_step = ResearchStep(
        order=1,
        action="skip_tier2_research",
        source="internet",
        result_summary=(
            "Skipped GitHub release and Docker Hub metadata research because internet "
            "access is unavailable."
        ),
        timestamp=timestamp,
    )
    service_results = [
        ServiceResearchResult(
            target=target,
            github_status=Tier2ResearchStatus.SKIPPED_OFFLINE,
            dockerhub_status=Tier2ResearchStatus.SKIPPED_OFFLINE,
            research_steps=[],
            warnings=[],
        )
        for target in targets
    ]
    return Tier2ResearchBundle(
        research_steps=[research_step],
        service_results=service_results,
        skipped_offline=True,
        degraded_reasons=[_OFFLINE_DEGRADED_REASON],
        warnings=[],
    )


def _collect_service_research(
    *,
    target: Tier2ResearchTarget,
    github_client: GitHubResearchClient,
    dockerhub_client: DockerHubResearchClient,
    start_order: int,
    timestamp: datetime,
) -> ServiceResearchResult:
    """Collect public research for one service target."""
    next_order = start_order
    research_steps: list[ResearchStep] = []
    warnings: list[str] = []

    (
        github_status,
        github_current_release,
        github_previous_release,
        github_steps,
        github_warnings,
    ) = _collect_github_research(
        target=target,
        client=github_client,
        start_order=next_order,
        timestamp=timestamp,
    )
    research_steps.extend(github_steps)
    warnings.extend(github_warnings)
    next_order += len(github_steps)

    (
        dockerhub_status,
        docker_repository,
        docker_current_tag,
        docker_previous_tag,
        docker_steps,
        dockerhub_warnings,
    ) = _collect_dockerhub_research(
        target=target,
        client=dockerhub_client,
        start_order=next_order,
        timestamp=timestamp,
    )
    research_steps.extend(docker_steps)
    warnings.extend(dockerhub_warnings)

    return ServiceResearchResult(
        target=target,
        github_status=github_status,
        dockerhub_status=dockerhub_status,
        research_steps=research_steps,
        github_current_release=github_current_release,
        github_previous_release=github_previous_release,
        docker_repository=docker_repository,
        docker_current_tag=docker_current_tag,
        docker_previous_tag=docker_previous_tag,
        warnings=warnings,
    )


def _collect_github_research(
    *,
    target: Tier2ResearchTarget,
    client: GitHubResearchClient,
    start_order: int,
    timestamp: datetime,
) -> tuple[
    Tier2ResearchStatus,
    GitHubRelease | None,
    GitHubRelease | None,
    list[ResearchStep],
    list[str],
]:
    """Collect GitHub release-note research for one target."""
    if target.github_repository is None:
        return (
            Tier2ResearchStatus.NO_PUBLIC_SOURCE,
            None,
            None,
            [],
            [f"No GitHub repository hint is available for service {target.service_id}."],
        )
    if target.current_tag is None and target.previous_tag is None:
        return (
            Tier2ResearchStatus.INSUFFICIENT_DATA,
            None,
            None,
            [],
            [f"No version tags were available for GitHub release lookup on {target.service_id}."],
        )

    steps: list[ResearchStep] = []
    warnings: list[str] = []
    success_count = 0
    offline_hit = False
    not_found_count = 0

    current_release = None
    if target.current_tag is not None:
        current_release, step, status_token = _lookup_github_release(
            repository=target.github_repository,
            requested_tag=target.current_tag,
            client=client,
            order=start_order,
            timestamp=timestamp,
        )
        steps.append(step)
        if current_release is not None:
            success_count += 1
        elif status_token == Tier2ResearchStatus.NOT_FOUND:
            not_found_count += 1
            warnings.append(
                f"GitHub release metadata for {target.service_id} tag {target.current_tag} "
                "was not found."
            )
        elif status_token == Tier2ResearchStatus.SKIPPED_OFFLINE:
            offline_hit = True
    else:
        warnings.append(f"Current version tag is missing for {target.service_id}.")

    previous_release = None
    previous_order = start_order + len(steps)
    if target.previous_tag is not None:
        previous_release, step, status_token = _lookup_github_release(
            repository=target.github_repository,
            requested_tag=target.previous_tag,
            client=client,
            order=previous_order,
            timestamp=timestamp,
        )
        steps.append(step)
        if previous_release is not None:
            success_count += 1
        elif status_token == Tier2ResearchStatus.NOT_FOUND:
            not_found_count += 1
            warnings.append(
                f"GitHub release metadata for {target.service_id} tag {target.previous_tag} "
                "was not found."
            )
        elif status_token == Tier2ResearchStatus.SKIPPED_OFFLINE:
            offline_hit = True
    else:
        warnings.append(f"Previous version tag is missing for {target.service_id}.")

    return (
        _determine_status(
            success_count=success_count,
            attempt_count=len(steps),
            not_found_count=not_found_count,
            offline_hit=offline_hit,
            warnings=warnings,
        ),
        current_release,
        previous_release,
        steps,
        warnings,
    )


def _collect_dockerhub_research(
    *,
    target: Tier2ResearchTarget,
    client: DockerHubResearchClient,
    start_order: int,
    timestamp: datetime,
) -> tuple[
    Tier2ResearchStatus,
    DockerHubRepository | None,
    DockerHubTag | None,
    DockerHubTag | None,
    list[ResearchStep],
    list[str],
]:
    """Collect Docker Hub repository and tag metadata for one target."""
    if target.dockerhub_reference is None:
        return (
            Tier2ResearchStatus.NO_PUBLIC_SOURCE,
            None,
            None,
            None,
            [],
            [f"No Docker Hub image reference is available for service {target.service_id}."],
        )

    steps: list[ResearchStep] = []
    warnings: list[str] = []
    success_count = 0
    offline_hit = False
    not_found_count = 0

    repository, repo_step, repo_status = _lookup_dockerhub_repository(
        reference=target.dockerhub_reference,
        client=client,
        order=start_order,
        timestamp=timestamp,
    )
    steps.append(repo_step)
    if repository is not None:
        success_count += 1
    elif repo_status == Tier2ResearchStatus.NOT_FOUND:
        not_found_count += 1
        warnings.append(
            f"Docker Hub repository metadata for {target.service_id} was not found."
        )
    elif repo_status == Tier2ResearchStatus.SKIPPED_OFFLINE:
        offline_hit = True

    current_tag = None
    if target.current_tag is not None:
        current_tag, step, tag_status = _lookup_dockerhub_tag(
            reference=target.dockerhub_reference,
            requested_tag=target.current_tag,
            client=client,
            order=start_order + len(steps),
            timestamp=timestamp,
        )
        steps.append(step)
        if current_tag is not None:
            success_count += 1
        elif tag_status == Tier2ResearchStatus.NOT_FOUND:
            not_found_count += 1
            warnings.append(
                f"Docker Hub tag metadata for {target.service_id} tag {target.current_tag} "
                "was not found."
            )
        elif tag_status == Tier2ResearchStatus.SKIPPED_OFFLINE:
            offline_hit = True
    else:
        warnings.append(f"Current Docker image tag is missing for {target.service_id}.")

    previous_tag = None
    if target.previous_tag is not None:
        previous_tag, step, tag_status = _lookup_dockerhub_tag(
            reference=target.dockerhub_reference,
            requested_tag=target.previous_tag,
            client=client,
            order=start_order + len(steps),
            timestamp=timestamp,
        )
        steps.append(step)
        if previous_tag is not None:
            success_count += 1
        elif tag_status == Tier2ResearchStatus.NOT_FOUND:
            not_found_count += 1
            warnings.append(
                f"Docker Hub tag metadata for {target.service_id} tag {target.previous_tag} "
                "was not found."
            )
        elif tag_status == Tier2ResearchStatus.SKIPPED_OFFLINE:
            offline_hit = True
    else:
        warnings.append(f"Previous Docker image tag is missing for {target.service_id}.")

    return (
        _determine_status(
            success_count=success_count,
            attempt_count=len(steps),
            not_found_count=not_found_count,
            offline_hit=offline_hit,
            warnings=warnings,
        ),
        repository,
        current_tag,
        previous_tag,
        steps,
        warnings,
    )


def _lookup_github_release(
    *,
    repository: GitHubRepositoryReference,
    requested_tag: str,
    client: GitHubResearchClient,
    order: int,
    timestamp: datetime,
) -> tuple[GitHubRelease | None, ResearchStep, Tier2ResearchStatus]:
    """Look up a GitHub release using exact and v-prefixed tag forms."""
    for candidate_tag in _github_tag_candidates(requested_tag):
        try:
            release = client.fetch_release_by_tag(repository, tag_name=candidate_tag)
            return (
                release,
                ResearchStep(
                    order=order,
                    action="fetch_github_release",
                    source=repository.releases_url,
                    result_summary=(
                        f"Found GitHub release {release.tag_name} for {repository.full_name}."
                    ),
                    timestamp=timestamp,
                ),
                Tier2ResearchStatus.SUCCESS,
            )
        except GitHubReleasesNotFoundError:
            continue
        except GitHubReleasesOfflineError:
            return (
                None,
                ResearchStep(
                    order=order,
                    action="fetch_github_release",
                    source=repository.releases_url,
                    result_summary=(
                        f"Skipped GitHub release lookup for {repository.full_name} "
                        f"tag {requested_tag}: internet access unavailable."
                    ),
                    timestamp=timestamp,
                ),
                Tier2ResearchStatus.SKIPPED_OFFLINE,
            )
        except GitHubReleasesError as exc:
            return (
                None,
                ResearchStep(
                    order=order,
                    action="fetch_github_release",
                    source=repository.releases_url,
                    result_summary=(
                        f"GitHub release lookup for {repository.full_name} tag "
                        f"{requested_tag} failed: {exc}."
                    ),
                    timestamp=timestamp,
                ),
                Tier2ResearchStatus.PARTIAL,
            )

    return (
        None,
        ResearchStep(
            order=order,
            action="fetch_github_release",
            source=repository.releases_url,
            result_summary=(
                "GitHub release metadata was not found for tags "
                f"{', '.join(_github_tag_candidates(requested_tag))} "
                f"in {repository.full_name}."
            ),
            timestamp=timestamp,
        ),
        Tier2ResearchStatus.NOT_FOUND,
    )


def _lookup_dockerhub_repository(
    *,
    reference: DockerHubImageReference,
    client: DockerHubResearchClient,
    order: int,
    timestamp: datetime,
) -> tuple[DockerHubRepository | None, ResearchStep, Tier2ResearchStatus]:
    """Look up Docker Hub repository metadata for one image reference."""
    try:
        repository = client.fetch_repository(reference)
        return (
            repository,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_repository",
                source=reference.html_url,
                result_summary=(
                    f"Found Docker Hub repository metadata for {reference.repository_path}."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.SUCCESS,
        )
    except DockerHubNotFoundError:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_repository",
                source=reference.html_url,
                result_summary=(
                    f"Docker Hub repository metadata for {reference.repository_path} "
                    "was not found."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.NOT_FOUND,
        )
    except DockerHubOfflineError:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_repository",
                source=reference.html_url,
                result_summary=(
                    f"Skipped Docker Hub repository lookup for {reference.repository_path}: "
                    "internet access unavailable."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.SKIPPED_OFFLINE,
        )
    except DockerHubError as exc:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_repository",
                source=reference.html_url,
                result_summary=(
                    f"Docker Hub repository lookup for {reference.repository_path} "
                    f"failed: {exc}."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.PARTIAL,
        )


def _lookup_dockerhub_tag(
    *,
    reference: DockerHubImageReference,
    requested_tag: str,
    client: DockerHubResearchClient,
    order: int,
    timestamp: datetime,
) -> tuple[DockerHubTag | None, ResearchStep, Tier2ResearchStatus]:
    """Look up Docker Hub metadata for one tag."""
    try:
        tag = client.fetch_tag(reference, tag_name=requested_tag)
        return (
            tag,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_tag",
                source=reference.tags_url,
                result_summary=(
                    f"Found Docker Hub tag metadata for {reference.repository_path}:{tag.name}."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.SUCCESS,
        )
    except DockerHubNotFoundError:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_tag",
                source=reference.tags_url,
                result_summary=(
                    f"Docker Hub tag metadata for {reference.repository_path}:{requested_tag} "
                    "was not found."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.NOT_FOUND,
        )
    except DockerHubOfflineError:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_tag",
                source=reference.tags_url,
                result_summary=(
                    "Skipped Docker Hub tag lookup for "
                    f"{reference.repository_path}:{requested_tag} because internet "
                    "access is unavailable."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.SKIPPED_OFFLINE,
        )
    except DockerHubError as exc:
        return (
            None,
            ResearchStep(
                order=order,
                action="fetch_dockerhub_tag",
                source=reference.tags_url,
                result_summary=(
                    f"Docker Hub tag lookup for {reference.repository_path}:{requested_tag} "
                    f"failed: {exc}."
                ),
                timestamp=timestamp,
            ),
            Tier2ResearchStatus.PARTIAL,
        )


def _determine_status(
    *,
    success_count: int,
    attempt_count: int,
    not_found_count: int,
    offline_hit: bool,
    warnings: Sequence[str],
) -> Tier2ResearchStatus:
    """Collapse per-step outcomes into one explicit source status."""
    if offline_hit and success_count == 0:
        return Tier2ResearchStatus.SKIPPED_OFFLINE
    if attempt_count == 0:
        return Tier2ResearchStatus.INSUFFICIENT_DATA
    if success_count == 0 and not_found_count == attempt_count:
        return Tier2ResearchStatus.NOT_FOUND
    if success_count == attempt_count and not warnings:
        return Tier2ResearchStatus.SUCCESS
    if success_count > 0:
        return Tier2ResearchStatus.PARTIAL
    return Tier2ResearchStatus.INSUFFICIENT_DATA


def _github_tag_candidates(tag_name: str) -> list[str]:
    """Return exact and v-prefixed tag candidates for GitHub release lookup."""
    normalized_tag = tag_name.strip()
    if normalized_tag.startswith("v"):
        return [normalized_tag]
    return [normalized_tag, f"v{normalized_tag}"]


def _extract_image_reference(raw_value: str | None) -> str | None:
    """Extract the image reference from the Phase 1 change-tracker value format."""
    if raw_value is None:
        return None
    image_reference, _, _ = raw_value.partition(" [")
    normalized = image_reference.strip()
    return normalized or None


def _parse_optional_github_repository(
    raw_value: str | None,
) -> GitHubRepositoryReference | None:
    """Parse an optional GitHub repository hint when present."""
    if raw_value is None or not raw_value.strip():
        return None
    return parse_repository_reference(raw_value)


def _parse_optional_dockerhub_reference(
    raw_value: str | None,
) -> DockerHubImageReference | None:
    """Parse an optional Docker Hub image hint when present."""
    if raw_value is None or not raw_value.strip():
        return None
    try:
        return parse_dockerhub_reference(raw_value)
    except ValueError:
        return None


def _append_unique(items: list[str], value: str) -> None:
    """Append a string value once while preserving insertion order."""
    if value not in items:
        items.append(value)


__all__ = [
    "PublicResearchHints",
    "ServiceResearchResult",
    "Tier2ResearchBundle",
    "Tier2ResearchStatus",
    "Tier2ResearchTarget",
    "build_tier2_research_targets",
    "run_tier2_research",
]
