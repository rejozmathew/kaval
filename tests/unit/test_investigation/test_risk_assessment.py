"""Unit tests for deterministic Phase 2B risk assessment."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.investigation.prompts import InvestigationRecommendation
from kaval.investigation.research import (
    PublicResearchHints,
    build_tier2_research_targets,
    run_tier2_research,
)
from kaval.investigation.risk_assessment import (
    apply_deterministic_risk_assessment,
    build_risk_assessment,
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
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from tests.unit.test_research.test_tier2_research import StubDockerHubClient, StubGitHubClient


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for risk tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_build_risk_assessment_returns_low_for_bounded_restart_without_image_update() -> None:
    """A bounded restart without correlated image updates should remain low risk."""
    incident, services = build_incident_and_services()
    recommendation = build_restart_recommendation()

    risk = build_risk_assessment(
        recommendation=recommendation,
        incident=incident,
        services=services,
        changes=[],
        research=run_tier2_research(targets=[]),
    )

    assert risk.overall_risk == RiskLevel.LOW
    assert [check.check for check in risk.checks] == [
        "bounded_action_scope",
        "target_service_state",
        "reversible_restart",
        "recent_image_update_context",
        "changelog_migration_review",
    ]
    assert risk.checks[3].result == RiskCheckResult.PASS
    assert risk.checks[4].result == RiskCheckResult.PASS


def test_build_risk_assessment_marks_changelog_review_unknown_when_offline() -> None:
    """Offline research should explicitly degrade changelog review risk output."""
    incident, services = build_incident_and_services()
    changes = [build_image_update_change()]
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
    research = run_tier2_research(targets=targets, offline_mode=True, now=ts(18, 30))

    risk = build_risk_assessment(
        recommendation=build_restart_recommendation(),
        incident=incident,
        services=services,
        changes=changes,
        research=research,
    )

    assert risk.overall_risk == RiskLevel.MEDIUM
    assert risk.checks[3].result == RiskCheckResult.UNKNOWN
    assert risk.checks[4].result == RiskCheckResult.UNKNOWN
    assert any("Unable to verify changelog/migration risk" in warning for warning in risk.warnings)


def test_build_risk_assessment_flags_release_note_keyword_risk() -> None:
    """Release-note keywords should surface as deterministic medium-risk warnings."""
    incident, services = build_incident_and_services()
    changes = [build_image_update_change()]
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
    research = run_tier2_research(
        targets=targets,
        github_client=StubGitHubClient(
            releases_by_repo_and_tag={
                ("NginxProxyManager/nginx-proxy-manager", "v2.12.1"): build_release(
                    body="- Upgraded Alpine base with OpenSSL 3.5.5\n- Breaking TLS edge case"
                ),
                ("NginxProxyManager/nginx-proxy-manager", "v2.12.0"): build_release(
                    tag_name="v2.12.0",
                    body="- Stable release without migration notes"
                ),
            }
        ),
        dockerhub_client=StubDockerHubClient(),
        now=ts(18, 40),
    )

    risk = build_risk_assessment(
        recommendation=build_restart_recommendation(),
        incident=incident,
        services=services,
        changes=changes,
        research=research,
    )

    assert risk.overall_risk == RiskLevel.MEDIUM
    assert risk.checks[4].result == RiskCheckResult.FAIL
    assert "openssl" in risk.checks[4].detail.casefold()
    assert any("behavioral/runtime changes" in warning for warning in risk.warnings)


def test_apply_deterministic_risk_assessment_overrides_model_risk() -> None:
    """Workflow callers should be able to replace model-authored risk fields deterministically."""
    incident, services = build_incident_and_services()
    recommendation = build_restart_recommendation().model_copy(
        update={
            "risk": RiskAssessment(
                overall_risk=RiskLevel.HIGH,
                checks=[
                    RiskCheck(
                        check="model_guess",
                        result=RiskCheckResult.FAIL,
                        detail="model-authored placeholder",
                    )
                ],
                reversible=False,
                warnings=["placeholder"],
            )
        }
    )

    updated = apply_deterministic_risk_assessment(
        recommendation=recommendation,
        incident=incident,
        services=services,
        changes=[],
        research=run_tier2_research(targets=[]),
    )

    assert updated.risk.overall_risk == RiskLevel.LOW
    assert updated.risk.reversible is True
    assert updated.risk.checks[0].check == "bounded_action_scope"
    assert updated.risk.checks[0].check != "model_guess"


def build_incident_and_services() -> tuple[Incident, list[Service]]:
    """Build a minimal NPM incident and service set for risk tests."""
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
    return incident, services


def build_image_update_change() -> Change:
    """Build a correlated image update for NPM."""
    return Change(
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


def build_restart_recommendation() -> InvestigationRecommendation:
    """Build a minimal restart recommendation for risk tests."""
    return InvestigationRecommendation(
        summary="Restart npm to verify whether the incident clears.",
        action_type="restart_container",
        target="npm",
        rationale="Restart is the current bounded verification step.",
        risk=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            checks=[],
            reversible=True,
            warnings=[],
        ),
    )


def build_release(*, tag_name: str = "v2.12.1", body: str) -> object:
    """Build a minimal GitHub release payload for research-backed risk tests."""
    from kaval.integrations.external_apis.github_releases import GitHubRelease

    return GitHubRelease(
        id=2121 if tag_name == "v2.12.1" else 2120,
        tag_name=tag_name,
        name=tag_name,
        body=body,
        html_url=f"https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/{tag_name}",
        draft=False,
        prerelease=False,
        created_at=ts(18, 10),
        published_at=ts(18, 15),
    )
