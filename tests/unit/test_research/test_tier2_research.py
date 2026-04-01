"""Unit tests for the Phase 2B Tier 2 research module."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.external_apis.dockerhub import (
    DockerHubImageReference,
    DockerHubNotFoundError,
    DockerHubRepository,
    DockerHubTag,
    decode_repository_payload,
    decode_tag_payload,
    parse_dockerhub_reference,
)
from kaval.integrations.external_apis.github_releases import (
    GitHubRelease,
    GitHubReleasesNotFoundError,
    decode_release_payload,
    parse_repository_reference,
)
from kaval.investigation.research import (
    PublicResearchHints,
    Tier2ResearchStatus,
    build_tier2_research_targets,
    run_tier2_research,
)
from kaval.models import (
    Change,
    ChangeType,
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Incident,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)

FIXTURES_ROOT = Path(__file__).resolve().parents[2] / "fixtures"


def load_json_fixture(relative_path: str) -> object:
    """Load a JSON fixture shared with the public research client tests."""
    return json.loads((FIXTURES_ROOT / relative_path).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for research tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_build_tier2_research_targets_extracts_image_versions_and_hints() -> None:
    """Correlated image updates should produce typed Tier 2 research targets."""
    incident, services, changes = build_inputs()

    targets = build_tier2_research_targets(
        incident=incident,
        services=services,
        changes=changes,
        hints_by_service={
            "svc-npm": PublicResearchHints(
                github_repository="NginxProxyManager/nginx-proxy-manager"
            )
        },
    )

    assert len(targets) == 1
    target = targets[0]
    assert target.service_id == "svc-npm"
    assert target.current_image == "jc21/nginx-proxy-manager:2.12.1"
    assert target.previous_image == "jc21/nginx-proxy-manager:2.12.0"
    assert target.current_tag == "2.12.1"
    assert target.previous_tag == "2.12.0"
    assert target.github_repository is not None
    assert target.github_repository.full_name == "NginxProxyManager/nginx-proxy-manager"
    assert target.dockerhub_reference is not None
    assert target.dockerhub_reference.repository_path == "jc21/nginx-proxy-manager"


def test_run_tier2_research_skips_explicitly_when_offline() -> None:
    """Offline mode should return an explicit skip result and degraded reason."""
    incident, services, changes = build_inputs()
    targets = build_tier2_research_targets(
        incident=incident,
        services=services,
        changes=changes,
        hints_by_service={
            "svc-npm": PublicResearchHints(
                github_repository="NginxProxyManager/nginx-proxy-manager"
            )
        },
    )

    result = run_tier2_research(targets=targets, offline_mode=True, now=ts(19, 30))

    assert result.skipped_offline is True
    assert result.research_steps[0].action == "skip_tier2_research"
    assert "no internet access" in result.degraded_reasons[0]
    assert result.service_results[0].github_status == Tier2ResearchStatus.SKIPPED_OFFLINE
    assert result.service_results[0].dockerhub_status == Tier2ResearchStatus.SKIPPED_OFFLINE


def test_run_tier2_research_collects_structured_public_metadata() -> None:
    """GitHub and Docker Hub metadata should be unified into ordered research results."""
    incident, services, changes = build_inputs()
    targets = build_tier2_research_targets(
        incident=incident,
        services=services,
        changes=changes,
        hints_by_service={
            "svc-npm": PublicResearchHints(
                github_repository="NginxProxyManager/nginx-proxy-manager"
            )
        },
    )

    github_client = StubGitHubClient(
        releases_by_repo_and_tag={
            ("NginxProxyManager/nginx-proxy-manager", "v2.12.1"): decode_release_payload(
                load_json_fixture("github/release_npm_v2.12.1.json")
            ),
            ("NginxProxyManager/nginx-proxy-manager", "v2.12.0"): GitHubRelease(
                id=2120,
                tag_name="v2.12.0",
                name="v2.12.0",
                body="No migration changes listed.",
                html_url=(
                    "https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.12.0"
                ),
                draft=False,
                prerelease=False,
                created_at=ts(12, 20),
                published_at=ts(12, 45),
            ),
        }
    )
    dockerhub_client = StubDockerHubClient(
        repository_by_path={
            "jc21/nginx-proxy-manager": decode_repository_payload(
                load_json_fixture("dockerhub/repository_npm.json")
            )
        },
        tags_by_path_and_name={
            ("jc21/nginx-proxy-manager", "2.12.1"): decode_tag_payload(
                load_json_fixture("dockerhub/tag_npm_2.12.1.json")
            ),
            ("jc21/nginx-proxy-manager", "2.12.0"): DockerHubTag(
                name="2.12.0",
                full_size=176543210,
                last_updated=ts(12, 45),
                tag_last_pushed=ts(12, 45),
                tag_last_pulled=ts(17, 0),
                images=[],
            ),
        },
    )

    result = run_tier2_research(
        targets=targets,
        github_client=github_client,
        dockerhub_client=dockerhub_client,
        now=ts(19, 45),
    )

    assert result.skipped_offline is False
    assert len(result.service_results) == 1
    service_result = result.service_results[0]
    assert service_result.github_status == Tier2ResearchStatus.SUCCESS
    assert service_result.dockerhub_status == Tier2ResearchStatus.SUCCESS
    assert [step.action for step in result.research_steps] == [
        "fetch_github_release",
        "fetch_github_release",
        "fetch_dockerhub_repository",
        "fetch_dockerhub_tag",
        "fetch_dockerhub_tag",
    ]
    assert service_result.github_current_release is not None
    assert service_result.github_current_release.body is not None
    assert "OpenSSL 3.5.5" in service_result.github_current_release.body
    assert service_result.docker_repository is not None
    assert service_result.docker_repository.pull_count == 987654
    assert service_result.docker_current_tag is not None
    assert service_result.docker_current_tag.images[0].digest == "sha256:npm-2121-amd64"
    assert service_result.warnings == []


def test_run_tier2_research_reports_missing_public_data_explicitly() -> None:
    """Not-found responses should produce explicit source statuses and warnings."""
    incident, services, changes = build_inputs()
    targets = build_tier2_research_targets(
        incident=incident,
        services=services,
        changes=changes,
        hints_by_service={
            "svc-npm": PublicResearchHints(
                github_repository="NginxProxyManager/nginx-proxy-manager"
            )
        },
    )

    result = run_tier2_research(
        targets=targets,
        github_client=StubGitHubClient(),
        dockerhub_client=StubDockerHubClient(),
        now=ts(20, 0),
    )

    service_result = result.service_results[0]
    assert service_result.github_status == Tier2ResearchStatus.NOT_FOUND
    assert service_result.dockerhub_status == Tier2ResearchStatus.NOT_FOUND
    assert "was not found" in service_result.research_steps[0].result_summary
    assert any("was not found" in warning for warning in service_result.warnings)


def build_inputs() -> tuple[Incident, list[Service], list[Change]]:
    """Build a minimal incident/service/change set for Tier 2 research tests."""
    incident = Incident(
        id="inc-npm",
        title="Nginx Proxy Manager TLS failures",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-npm"],
        all_findings=["find-npm"],
        affected_services=["svc-npm"],
        triggering_symptom="SSL handshake failure",
        suspected_cause="Nginx Proxy Manager image update introduced a TLS regression",
        confirmed_cause=None,
        root_cause_service="svc-npm",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.84,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=["chg-npm-image"],
        grouping_window_start=ts(18, 0),
        grouping_window_end=ts(18, 20),
        created_at=ts(18, 0),
        updated_at=ts(18, 20),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    services = [
        Service(
            id="svc-npm",
            name="Nginx Proxy Manager",
            type=ServiceType.CONTAINER,
            category="networking",
            status=ServiceStatus.DEGRADED,
            descriptor_id="networking/nginx_proxy_manager",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-npm",
            vm_id=None,
            image="jc21/nginx-proxy-manager:2.12.1",
            endpoints=[],
            dns_targets=[],
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-cloudflared",
                    confidence=DependencyConfidence.INFERRED,
                    source=DependencySource.DESCRIPTOR,
                    description="Proxy traffic depends on the tunnel path.",
                )
            ],
            dependents=[],
            last_check=ts(18, 5),
            active_findings=1,
            active_incidents=1,
        )
    ]
    changes = [
        Change(
            id="chg-npm-image",
            type=ChangeType.IMAGE_UPDATE,
            service_id="svc-npm",
            description=(
                "nginx-proxy-manager image changed from jc21/nginx-proxy-manager:2.12.0 "
                "[sha256:old] to jc21/nginx-proxy-manager:2.12.1 [sha256:new]."
            ),
            old_value="jc21/nginx-proxy-manager:2.12.0 [sha256:old]",
            new_value="jc21/nginx-proxy-manager:2.12.1 [sha256:new]",
            timestamp=ts(18, 3),
            correlated_incidents=["inc-npm"],
        )
    ]
    return incident, services, changes


@dataclass(slots=True)
class StubGitHubClient:
    """Minimal stub implementing the research module's GitHub protocol."""

    releases_by_repo_and_tag: dict[tuple[str, str], GitHubRelease] = field(default_factory=dict)

    def fetch_release_by_tag(
        self,
        repository: str,
        *,
        tag_name: str,
    ) -> GitHubRelease:
        """Return the configured release or a typed not-found error."""
        normalized_repository = parse_repository_reference(repository).full_name
        key = (normalized_repository, tag_name)
        if key not in self.releases_by_repo_and_tag:
            raise GitHubReleasesNotFoundError("missing release")
        return self.releases_by_repo_and_tag[key]


@dataclass(slots=True)
class StubDockerHubClient:
    """Minimal stub implementing the research module's Docker Hub protocol."""

    repository_by_path: dict[str, DockerHubRepository] = field(default_factory=dict)
    tags_by_path_and_name: dict[tuple[str, str], DockerHubTag] = field(default_factory=dict)

    def fetch_repository(self, reference: str | DockerHubImageReference) -> DockerHubRepository:
        """Return the configured repository metadata or a typed not-found error."""
        normalized_reference = parse_dockerhub_reference(reference).repository_path
        if normalized_reference not in self.repository_by_path:
            raise DockerHubNotFoundError("missing repository")
        return self.repository_by_path[normalized_reference]

    def fetch_tag(
        self,
        reference: str | DockerHubImageReference,
        *,
        tag_name: str | None = None,
    ) -> DockerHubTag:
        """Return the configured tag metadata or a typed not-found error."""
        normalized_reference = parse_dockerhub_reference(reference)
        resolved_tag = tag_name or normalized_reference.tag
        if resolved_tag is None:
            raise ValueError("tag_name is required for tag lookups")
        key = (normalized_reference.repository_path, resolved_tag)
        if key not in self.tags_by_path_and_name:
            raise DockerHubNotFoundError("missing tag")
        return self.tags_by_path_and_name[key]
