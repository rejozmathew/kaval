"""Unit tests for the LangGraph Tier 1 investigation workflow."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

import pytest

from kaval.credentials import (
    CredentialMaterialService,
    CredentialRequestManager,
    CredentialRequestMode,
    CredentialVault,
    VolatileCredentialStore,
)
from kaval.database import KavalDatabase
from kaval.integrations.external_apis.dockerhub import (
    DockerHubImageReference,
    DockerHubNotFoundError,
    DockerHubRepository,
    DockerHubTag,
    parse_dockerhub_reference,
)
from kaval.integrations.external_apis.github_releases import (
    GitHubRelease,
    GitHubReleasesNotFoundError,
    parse_repository_reference,
)
from kaval.integrations.service_adapters import (
    AdapterDiscoveredEdge,
    AdapterRegistry,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.investigation.cloud_model import CloudPromptRedactionError
from kaval.investigation.prompts import InvestigationSynthesis
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.models import (
    Change,
    ChangeType,
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
    ResearchStep,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
    UserNote,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for workflow tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_workflow_single_finding_produces_ordered_evidence_steps(tmp_path: Path) -> None:
    """A one-finding incident should still produce ordered structured evidence."""
    database = seed_database(tmp_path / "single-finding.db", include_downstream=False)
    try:
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert [step.order for step in result.investigation.evidence_steps] == list(
            range(1, len(result.investigation.evidence_steps) + 1)
        )
        assert result.investigation.evidence_steps[0].action == "summarize_incident_findings"
        assert result.investigation.evidence_steps[-1].action == "query_operational_memory"
        assert result.investigation.remediation is not None
        assert result.investigation.remediation.risk_assessment.checks[0].check == (
            "bounded_action_scope"
        )
    finally:
        database.close()


def test_workflow_collects_prompt_safe_adapter_facts_when_credentials_available(
    tmp_path: Path,
) -> None:
    """Available adapter credentials should add prompt-safe deep-inspection evidence."""
    database_path = tmp_path / "adapter-evidence.db"
    database = seed_database(database_path)
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        satisfy_adapter_secret(
            service=credential_service,
            secret_value="radarr-secret-value",
        )
        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="radarr_api",
                status=AdapterStatus.SUCCESS,
                facts={
                    "download_client": "DelugeVPN",
                    "probe_url": "http://radarr:7878/api/v3/system/status?token=abc123",
                    "api_key": "leak-me",
                },
                edges_discovered=[
                    AdapterDiscoveredEdge(
                        surface_id="download_clients",
                        target_service_name="DelugeVPN",
                        description="Radarr uses DelugeVPN as its download client.",
                    )
                ],
                timestamp=ts(14, 25),
                reason=None,
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert adapter.seen_credentials == {"api_key": "radarr-secret-value"}
        assert "Adapter Facts:" in result.prompt_bundle.user_prompt
        assert "\"adapter_id\": \"radarr_api\"" in result.prompt_bundle.user_prompt
        assert "\"download_client\": \"DelugeVPN\"" in result.prompt_bundle.user_prompt
        assert "radarr-secret-value" not in result.prompt_bundle.user_prompt
        assert "leak-me" not in result.prompt_bundle.user_prompt
        persisted_radarr = database.get_service("svc-radarr")
        assert persisted_radarr is not None
        assert persisted_radarr.dependencies[0].confidence == DependencyConfidence.RUNTIME_OBSERVED
        assert "radarr_api" in (persisted_radarr.dependencies[0].description or "")
        assert any(
            step.action == "inspect_service_adapter"
            and step.result_data["status"] == "success"
            and step.result_data["facts_available"] is True
            for step in result.investigation.evidence_steps
        )
    finally:
        database.close()


def test_workflow_skips_adapter_when_credentials_are_unconfigured(
    tmp_path: Path,
) -> None:
    """Missing adapter credentials should not crash the workflow or create adapter facts."""
    database_path = tmp_path / "adapter-unconfigured.db"
    database = seed_database(database_path)
    try:
        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="radarr_api",
                status=AdapterStatus.SUCCESS,
                facts={"download_client": "DelugeVPN"},
                edges_discovered=[],
                timestamp=ts(14, 25),
                reason=None,
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            credential_material_service=build_adapter_credential_service(
                database=database,
                database_path=database_path,
            ),
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        adapter_steps = [
            step
            for step in result.investigation.evidence_steps
            if step.action == "inspect_service_adapter"
        ]
        assert adapter.seen_credentials == {}
        assert "Adapter Facts:" not in result.prompt_bundle.user_prompt
        assert len(adapter_steps) == 1
        assert adapter_steps[0].result_data["credential_state"] == "unconfigured"
        assert adapter_steps[0].result_data["status"] == "skipped"
    finally:
        database.close()


def test_workflow_records_adapter_failures_without_crashing(
    tmp_path: Path,
) -> None:
    """Adapter execution failures should surface as evidence, not workflow exceptions."""
    database_path = tmp_path / "adapter-failure.db"
    database = seed_database(database_path)
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        satisfy_adapter_secret(
            service=credential_service,
            secret_value="radarr-secret-value",
        )
        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="radarr_api",
                status=AdapterStatus.AUTH_FAILED,
                facts={},
                edges_discovered=[],
                timestamp=ts(14, 25),
                reason="invalid api key",
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        adapter_steps = [
            step
            for step in result.investigation.evidence_steps
            if step.action == "inspect_service_adapter"
        ]
        assert "Adapter Facts:" not in result.prompt_bundle.user_prompt
        assert len(adapter_steps) == 1
        assert adapter_steps[0].result_data["status"] == "auth_failed"
        assert adapter_steps[0].result_data["reason"] == "invalid api key"
    finally:
        database.close()


def test_workflow_does_not_create_new_edges_from_unmatched_adapter_targets(
    tmp_path: Path,
) -> None:
    """Only existing dependency edges should upgrade; unmatched targets must be ignored."""
    database_path = tmp_path / "adapter-unmatched-edge.db"
    database = seed_database(database_path)
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        satisfy_adapter_secret(
            service=credential_service,
            secret_value="radarr-secret-value",
        )
        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="radarr_api",
                status=AdapterStatus.SUCCESS,
                facts={"download_client": "GhostDownloader"},
                edges_discovered=[
                    AdapterDiscoveredEdge(
                        surface_id="download_clients",
                        target_service_name="GhostDownloader",
                        description="No matching local service exists.",
                    )
                ],
                timestamp=ts(14, 25),
                reason=None,
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        persisted_radarr = database.get_service("svc-radarr")
        assert persisted_radarr is not None
        assert len(persisted_radarr.dependencies) == 1
        assert persisted_radarr.dependencies[0].confidence == DependencyConfidence.INFERRED
    finally:
        database.close()


def test_workflow_collects_cloudflare_facts_for_connected_ingress_context(
    tmp_path: Path,
) -> None:
    """Connected cloudflared services should contribute prompt-safe Cloudflare facts."""
    database_path = tmp_path / "cloudflare-ingress.db"
    database = seed_cloudflare_ingress_database(database_path)
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        for credential_key, secret_value in {
            "api_token": "cloudflare-token",
            "zone_name": "example.com",
            "account_id": "account-123",
            "tunnel_id": "tunnel-123",
        }.items():
            satisfy_adapter_secret(
                service=credential_service,
                incident_id="inc-npm-ingress",
                service_id="svc-cloudflared",
                credential_key=credential_key,
                secret_value=secret_value,
                reason=f"Need Cloudflare deep inspection ({credential_key}).",
                requested_at=ts(18, 20),
            )

        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="cloudflare_api",
                status=AdapterStatus.SUCCESS,
                facts={
                    "ssl_mode": {"value": "strict"},
                    "tunnel_dns_records": [
                        {
                            "name": "app.example.com",
                            "content": "tunnel-123.cfargotunnel.com",
                        }
                    ],
                    "api_token": "leak-me",
                },
                edges_discovered=[],
                timestamp=ts(18, 25),
                reason=None,
            ),
            adapter_id="cloudflare_api",
            surface_bindings=(
                AdapterSurfaceBinding(
                    descriptor_id="networking/cloudflared",
                    surface_id="dns_records",
                ),
            ),
            credential_keys=("api_token", "zone_name", "account_id", "tunnel_id"),
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause=(
                    "Cloudflare-side ingress is healthy; the TLS breakage is inside "
                    "Nginx Proxy Manager after the image update."
                ),
                confidence=0.88,
                action_type="none",
                target=None,
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-npm-ingress",
            trigger=InvestigationTrigger.AUTO,
            now=ts(18, 30),
        )

        assert adapter.seen_service_id == "svc-cloudflared"
        assert adapter.seen_credentials == {
            "api_token": "cloudflare-token",
            "zone_name": "example.com",
            "account_id": "account-123",
            "tunnel_id": "tunnel-123",
        }
        assert "\"adapter_id\": \"cloudflare_api\"" in result.prompt_bundle.user_prompt
        assert "\"ssl_mode\"" in result.prompt_bundle.user_prompt
        assert "\"strict\"" in result.prompt_bundle.user_prompt
        assert "cloudflare-token" not in result.prompt_bundle.user_prompt
        assert "leak-me" not in result.prompt_bundle.user_prompt
        assert any(
            step.action == "inspect_service_adapter"
            and step.target == "svc-cloudflared"
            and step.result_data["status"] == "success"
            and step.result_data["facts_available"] is True
            for step in result.investigation.evidence_steps
        )
    finally:
        database.close()


def test_workflow_does_not_collect_cloudflare_facts_for_unrelated_services(
    tmp_path: Path,
) -> None:
    """Unrelated incidents should not pull cloudflared into adapter evidence."""
    database_path = tmp_path / "cloudflare-unrelated.db"
    database = seed_database(database_path)
    database.upsert_service(
        Service(
            id="svc-cloudflared",
            name="cloudflared",
            type=ServiceType.CONTAINER,
            category="networking",
            status=ServiceStatus.HEALTHY,
            descriptor_id="networking/cloudflared",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-cloudflared",
            vm_id=None,
            image="cloudflare/cloudflared:2026.4.0",
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=[],
            last_check=ts(14, 24),
            active_findings=0,
            active_incidents=0,
        )
    )
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        for credential_key, secret_value in {
            "api_token": "cloudflare-token",
            "zone_name": "example.com",
            "account_id": "account-123",
            "tunnel_id": "tunnel-123",
        }.items():
            satisfy_adapter_secret(
                service=credential_service,
                incident_id="inc-delugevpn",
                service_id="svc-cloudflared",
                credential_key=credential_key,
                secret_value=secret_value,
                reason=f"Need Cloudflare deep inspection ({credential_key}).",
                requested_at=ts(14, 20),
            )

        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="cloudflare_api",
                status=AdapterStatus.SUCCESS,
                facts={"ssl_mode": {"value": "strict"}},
                edges_discovered=[],
                timestamp=ts(14, 25),
                reason=None,
            ),
            adapter_id="cloudflare_api",
            surface_bindings=(
                AdapterSurfaceBinding(
                    descriptor_id="networking/cloudflared",
                    surface_id="dns_records",
                ),
            ),
            credential_keys=("api_token", "zone_name", "account_id", "tunnel_id"),
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.91,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert adapter.seen_service_id is None
        assert "cloudflare_api" not in result.prompt_bundle.user_prompt
        assert not any(
            step.action == "inspect_service_adapter"
            and step.target == "svc-cloudflared"
            for step in result.investigation.evidence_steps
        )
    finally:
        database.close()


def test_workflow_collects_authentik_facts_for_connected_sso_context(
    tmp_path: Path,
) -> None:
    """Connected Authentik services should contribute prompt-safe identity facts."""
    database_path = tmp_path / "authentik-sso-context.db"
    database = seed_authentik_sso_context_database(database_path)
    try:
        credential_service = build_adapter_credential_service(
            database=database,
            database_path=database_path,
        )
        satisfy_adapter_secret(
            service=credential_service,
            incident_id="inc-nextcloud-sso",
            service_id="svc-authentik",
            credential_key="api_token",
            secret_value="authentik-token",
            reason="Need Authentik deep inspection.",
            requested_at=ts(17, 20),
        )

        adapter = FakeInspectionAdapter(
            result=AdapterResult(
                adapter_id="authentik_api",
                status=AdapterStatus.SUCCESS,
                facts={
                    "applications": [
                        {"slug": "nextcloud", "name": "Nextcloud"},
                    ],
                    "providers": [
                        {"name": "Nextcloud OIDC"},
                    ],
                    "api_token": "leak-me",
                },
                edges_discovered=[],
                timestamp=ts(17, 25),
                reason=None,
            ),
            adapter_id="authentik_api",
            surface_bindings=(
                AdapterSurfaceBinding(
                    descriptor_id="identity/authentik",
                    surface_id="applications",
                ),
            ),
            credential_keys=("api_token",),
        )
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause=(
                    "The downstream app is healthy; the SSO failure is concentrated in "
                    "the connected Authentik identity path."
                ),
                confidence=0.86,
                action_type="none",
                target=None,
            ),
            log_reader=fixture_log_reader,
            credential_material_service=credential_service,
            adapter_registry=AdapterRegistry([adapter]),
        )

        result = workflow.run(
            incident_id="inc-nextcloud-sso",
            trigger=InvestigationTrigger.AUTO,
            now=ts(17, 30),
        )

        assert adapter.seen_service_id == "svc-authentik"
        assert adapter.seen_credentials == {"api_token": "authentik-token"}
        assert "\"adapter_id\": \"authentik_api\"" in result.prompt_bundle.user_prompt
        assert "\"Nextcloud OIDC\"" in result.prompt_bundle.user_prompt
        assert "authentik-token" not in result.prompt_bundle.user_prompt
        assert "leak-me" not in result.prompt_bundle.user_prompt
        assert any(
            step.action == "inspect_service_adapter"
            and step.target == "svc-authentik"
            and step.result_data["status"] == "success"
            and step.result_data["facts_available"] is True
            for step in result.investigation.evidence_steps
        )
    finally:
        database.close()


def test_workflow_persists_investigation_and_updates_incident_for_restart(
    tmp_path: Path,
) -> None:
    """The workflow should persist a completed investigation and open approval for restart."""
    database = seed_database(tmp_path / "restart.db")
    try:
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN lost its VPN tunnel.",
                confidence=0.96,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.status.value == "completed"
        assert result.investigation.root_cause == "DelugeVPN lost its VPN tunnel."
        assert result.investigation.recurrence_count == 2
        assert result.investigation.remediation is not None
        assert result.investigation.remediation.action_type.value == "restart_container"
        assert result.investigation.model_used == ModelUsed.NONE
        assert result.prompt_bundle.response_schema_name == "phase2a_investigation"
        assert any(
            step.action == "inspect_dependency_graph"
            for step in result.investigation.evidence_steps
        )

        persisted_incident = database.get_incident("inc-delugevpn")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.AWAITING_APPROVAL
        assert persisted_incident.investigation_id == result.investigation.id
        assert persisted_incident.suspected_cause == "DelugeVPN lost its VPN tunnel."

        persisted_findings = {
            finding.id: finding
            for finding in database.list_findings()
            if finding.incident_id == "inc-delugevpn"
        }
        assert set(persisted_findings) == {"find-delugevpn", "find-radarr"}
        assert {finding.status for finding in persisted_findings.values()} == {
            FindingStatus.INVESTIGATING
        }
    finally:
        database.close()


def test_workflow_collects_and_persists_tier2_research_steps(
    tmp_path: Path,
) -> None:
    """Correlated image updates should flow through Tier 2 research and persistence."""
    database = seed_database(tmp_path / "tier2-research.db", include_image_update=True)
    try:
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="DelugeVPN image update likely changed VPN behavior.",
                confidence=0.83,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            github_research_client=StaticGitHubResearchClient(
                releases_by_repo_and_tag={
                    ("binhex/arch-delugevpn", "v5.0.1"): GitHubRelease(
                        id=501,
                        tag_name="v5.0.1",
                        name="v5.0.1",
                        body="Updated OpenVPN packaging.",
                        html_url="https://github.com/binhex/arch-delugevpn/releases/tag/v5.0.1",
                        draft=False,
                        prerelease=False,
                        created_at=ts(14, 10),
                        published_at=ts(14, 12),
                    ),
                    ("binhex/arch-delugevpn", "v5.0.0"): GitHubRelease(
                        id=500,
                        tag_name="v5.0.0",
                        name="v5.0.0",
                        body="Previous stable package set.",
                        html_url="https://github.com/binhex/arch-delugevpn/releases/tag/v5.0.0",
                        draft=False,
                        prerelease=False,
                        created_at=ts(12, 0),
                        published_at=ts(12, 5),
                    ),
                }
            ),
            dockerhub_research_client=StaticDockerHubResearchClient(
                repository_by_path={
                    "binhex/arch-delugevpn": DockerHubRepository(
                        namespace="binhex",
                        repository="arch-delugevpn",
                        description="DelugeVPN image",
                        full_description=None,
                        is_private=False,
                        star_count=100,
                        pull_count=5000,
                        last_updated=ts(14, 11),
                        status=1,
                        source_url="https://hub.docker.com/r/binhex/arch-delugevpn",
                    )
                },
                tags_by_path_and_name={
                    ("binhex/arch-delugevpn", "5.0.1"): DockerHubTag(
                        name="5.0.1",
                        full_size=123456789,
                        last_updated=ts(14, 11),
                        tag_last_pushed=ts(14, 11),
                        tag_last_pulled=ts(14, 40),
                        images=[],
                    ),
                    ("binhex/arch-delugevpn", "5.0.0"): DockerHubTag(
                        name="5.0.0",
                        full_size=123000000,
                        last_updated=ts(12, 1),
                        tag_last_pushed=ts(12, 1),
                        tag_last_pulled=ts(13, 50),
                        images=[],
                    ),
                },
            ),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert [step.action for step in result.investigation.research_steps] == [
            "fetch_github_release",
            "fetch_github_release",
            "fetch_dockerhub_repository",
            "fetch_dockerhub_tag",
            "fetch_dockerhub_tag",
        ]
        assert "Research Steps:" in result.prompt_bundle.user_prompt
        assert "fetch_github_release" in result.prompt_bundle.user_prompt
        persisted_investigation = database.get_investigation(result.investigation.id)
        assert persisted_investigation is not None
        assert len(persisted_investigation.research_steps) == 5
    finally:
        database.close()


def test_workflow_applies_deterministic_risk_assessment_to_restart_recommendations(
    tmp_path: Path,
) -> None:
    """Persisted restart recommendations should use deterministic Phase 2B risk checks."""
    database = seed_database(tmp_path / "risk-engine.db", include_image_update=True)
    try:
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="Nginx Proxy Manager image update likely changed TLS behavior.",
                confidence=0.79,
                action_type="restart_container",
                target="delugevpn",
            ),
            log_reader=fixture_log_reader,
            github_research_client=StaticGitHubResearchClient(
                releases_by_repo_and_tag={
                    ("binhex/arch-delugevpn", "v5.0.1"): GitHubRelease(
                        id=501,
                        tag_name="v5.0.1",
                        name="v5.0.1",
                        body="- Updated OpenSSL packaging\n- Breaking TLS edge case handling",
                        html_url="https://github.com/binhex/arch-delugevpn/releases/tag/v5.0.1",
                        draft=False,
                        prerelease=False,
                        created_at=ts(14, 10),
                        published_at=ts(14, 12),
                    ),
                    ("binhex/arch-delugevpn", "v5.0.0"): GitHubRelease(
                        id=500,
                        tag_name="v5.0.0",
                        name="v5.0.0",
                        body="Previous stable package set.",
                        html_url="https://github.com/binhex/arch-delugevpn/releases/tag/v5.0.0",
                        draft=False,
                        prerelease=False,
                        created_at=ts(12, 0),
                        published_at=ts(12, 5),
                    ),
                }
            ),
            dockerhub_research_client=StaticDockerHubResearchClient(
                repository_by_path={},
                tags_by_path_and_name={},
            ),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.remediation is not None
        risk_assessment = result.investigation.remediation.risk_assessment
        assert risk_assessment.overall_risk == RiskLevel.MEDIUM
        assert [check.check for check in risk_assessment.checks] == [
            "bounded_action_scope",
            "target_service_state",
            "reversible_restart",
            "recent_image_update_context",
            "changelog_migration_review",
        ]
        assert risk_assessment.checks[-1].result == RiskCheckResult.FAIL
        assert any(
            "Release notes mention behavioral/runtime changes" in warning
            for warning in risk_assessment.warnings
        )
    finally:
        database.close()


def test_workflow_keeps_incident_investigating_when_no_restart_is_justified(
    tmp_path: Path,
) -> None:
    """A no-action synthesis should persist the investigation without opening approval."""
    database = seed_database(tmp_path / "no-restart.db")
    try:
        workflow = InvestigationWorkflow(
            database=database,
            synthesizer=StaticSynthesizer(
                root_cause="Radarr is degraded but no bounded restart target is justified.",
                confidence=0.64,
                action_type="none",
                target=None,
            ),
            log_reader=fixture_log_reader,
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.USER_REQUEST,
            now=ts(15, 0),
        )

        assert result.investigation.remediation is None
        assert result.investigation.trigger == InvestigationTrigger.USER_REQUEST
        assert result.investigation.journal_entries_referenced == [
            "jrnl-delugevpn-2",
            "jrnl-delugevpn-1",
        ]
        assert result.investigation.user_notes_referenced == ["note-delugevpn"]
        assert result.incident.status == IncidentStatus.INVESTIGATING
        dependency_step = next(
            step
            for step in result.investigation.evidence_steps
            if step.action == "inspect_dependency_graph"
        )
        assert "DelugeVPN upstream of 1 affected service" in dependency_step.result_summary
    finally:
        database.close()


def test_workflow_falls_back_cleanly_when_local_model_is_not_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The workflow should use deterministic synthesis when no local-model config is present."""
    for variable_name in [
        "KAVAL_LOCAL_MODEL_ENABLED",
        "KAVAL_LOCAL_MODEL_NAME",
        "KAVAL_LOCAL_MODEL_BASE_URL",
        "KAVAL_LOCAL_MODEL_API_KEY",
        "KAVAL_LOCAL_MODEL_TIMEOUT_SECONDS",
        "OLLAMA_API_KEY",
    ]:
        monkeypatch.delenv(variable_name, raising=False)

    database = seed_database(tmp_path / "fallback.db")
    try:
        workflow = InvestigationWorkflow(database=database, log_reader=fixture_log_reader)

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 45),
        )

        assert result.investigation.model_used == ModelUsed.NONE
        assert result.synthesis.degraded_mode_note is not None
        assert result.investigation.remediation is not None
        assert result.investigation.remediation.target == "delugevpn"
    finally:
        database.close()


def test_workflow_escalates_to_cloud_with_cloud_safe_prompt_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Low-confidence local synthesis should escalate through a cloud-safe prompt bundle."""
    for key, value in {
        "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
        "KAVAL_LOCAL_MODEL_BASE_URL": "http://local-model.test",
        "KAVAL_CLOUD_MODEL_NAME": "gpt-4o-mini",
        "KAVAL_CLOUD_MODEL_PROVIDER": "openai",
        "OPENAI_API_KEY": "cloud-secret",
        "KAVAL_CLOUD_ESCALATION_LOCAL_CONFIDENCE_LT": "0.6",
        "KAVAL_CLOUD_MODEL_MAX_CALLS_PER_INCIDENT": "3",
        "KAVAL_CLOUD_MODEL_MAX_CALLS_PER_DAY": "20",
    }.items():
        monkeypatch.setenv(key, value)

    database = seed_database(tmp_path / "cloud-escalation.db")
    captured_cloud_payload: dict[str, object] = {}
    try:
        database.upsert_user_note(
            UserNote(
                id="note-cloud-safe",
                service_id="svc-delugevpn",
                note="Probe http://delugevpn:8112/api/status with token=super-secret",
                safe_for_model=True,
                last_verified_at=ts(12, 10),
                stale=False,
                added_at=ts(12, 10),
                updated_at=ts(12, 12),
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            log_reader=fixture_log_reader,
            local_model_transport=build_local_transport(confidence=0.51),
            cloud_model_transport=build_cloud_transport(captured_cloud_payload),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.model_used == ModelUsed.BOTH
        assert result.investigation.cloud_model_calls == 1
        assert result.synthesis.inference.confidence == 0.93
        body = captured_cloud_payload["body"]
        assert isinstance(body, dict)
        messages = body["messages"]
        assert isinstance(messages, list)
        system_prompt = messages[0]["content"]
        user_prompt = messages[1]["content"]
        assert "Privacy note:" in system_prompt
        assert "svc-delugevpn" not in user_prompt
        assert "DelugeVPN" not in user_prompt
        assert "container-delugevpn" not in user_prompt
        assert "inc-delugevpn" not in user_prompt
        assert "http://delugevpn:8112/api/status" not in user_prompt
        assert "super-secret" not in user_prompt
        assert "[SERVICE_ID_1]" in user_prompt
        assert "[SERVICE_1]" in user_prompt
        assert "http://[REDACTED_URL]" in user_prompt
        assert "token=[REDACTED]" in user_prompt
    finally:
        database.close()


def test_workflow_keeps_local_result_when_cloud_redaction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cloud escalation must safely fall back when the redaction step cannot complete."""
    for key, value in {
        "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
        "KAVAL_LOCAL_MODEL_BASE_URL": "http://local-model.test",
        "KAVAL_CLOUD_MODEL_NAME": "gpt-4o-mini",
        "KAVAL_CLOUD_MODEL_PROVIDER": "openai",
        "OPENAI_API_KEY": "cloud-secret",
        "KAVAL_CLOUD_ESCALATION_LOCAL_CONFIDENCE_LT": "0.6",
    }.items():
        monkeypatch.setenv(key, value)

    database = seed_database(tmp_path / "cloud-redaction-fallback.db")
    cloud_called = {"value": False}
    try:
        monkeypatch.setattr(
            "kaval.investigation.workflow.build_cloud_safe_prompt_bundle",
            lambda **_: (_ for _ in ()).throw(CloudPromptRedactionError("redaction failed")),
        )
        workflow = InvestigationWorkflow(
            database=database,
            log_reader=fixture_log_reader,
            local_model_transport=build_local_transport(confidence=0.5),
            cloud_model_transport=lambda *_args, **_kwargs: _mark_cloud_called(cloud_called),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.model_used == ModelUsed.LOCAL
        assert result.investigation.cloud_model_calls == 0
        assert cloud_called["value"] is False
        assert result.synthesis.degraded_mode_note is not None
        assert "Cloud escalation criteria matched" in result.synthesis.degraded_mode_note
        assert "Cloud-safe redaction failed" in result.synthesis.degraded_mode_note
    finally:
        database.close()


def test_workflow_keeps_local_result_when_incident_cloud_cap_is_reached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-incident cloud call caps should block further escalation attempts."""
    for key, value in {
        "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
        "KAVAL_LOCAL_MODEL_BASE_URL": "http://local-model.test",
        "KAVAL_CLOUD_MODEL_NAME": "gpt-4o-mini",
        "KAVAL_CLOUD_MODEL_PROVIDER": "openai",
        "OPENAI_API_KEY": "cloud-secret",
        "KAVAL_CLOUD_ESCALATION_LOCAL_CONFIDENCE_LT": "0.6",
        "KAVAL_CLOUD_MODEL_MAX_CALLS_PER_INCIDENT": "1",
    }.items():
        monkeypatch.setenv(key, value)

    database = seed_database(tmp_path / "cloud-cap.db")
    cloud_called = {"value": False}
    try:
        database.upsert_investigation(
            Investigation(
                id="inv-prior-cloud",
                incident_id="inc-delugevpn",
                trigger=InvestigationTrigger.AUTO,
                status=InvestigationStatus.COMPLETED,
                evidence_steps=[],
                research_steps=[_research_step()],
                root_cause="Prior cloud-assisted run",
                confidence=0.7,
                model_used=ModelUsed.CLOUD,
                cloud_model_calls=1,
                journal_entries_referenced=[],
                user_notes_referenced=[],
                recurrence_count=0,
                remediation=None,
                started_at=ts(9, 0),
                completed_at=ts(9, 5),
            )
        )
        workflow = InvestigationWorkflow(
            database=database,
            log_reader=fixture_log_reader,
            local_model_transport=build_local_transport(confidence=0.5),
            cloud_model_transport=lambda *_args, **_kwargs: _mark_cloud_called(cloud_called),
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.model_used == ModelUsed.LOCAL
        assert result.investigation.cloud_model_calls == 0
        assert cloud_called["value"] is False
        assert result.synthesis.degraded_mode_note is not None
        assert "per-incident cloud call cap" in result.synthesis.degraded_mode_note
    finally:
        database.close()


def build_local_transport(*, confidence: float):
    """Build a deterministic local-model transport for workflow tests."""

    def transport(http_request, _timeout_seconds: float) -> bytes:
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][1]["role"] == "user"
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _synthesis_payload(
                                    confidence=confidence,
                                    model_used="local",
                                    cloud_model_calls=0,
                                )
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    return transport


def build_cloud_transport(captured_payload: dict[str, object]):
    """Build a deterministic cloud-model transport for workflow tests."""

    def transport(http_request, _timeout_seconds: float) -> bytes:
        captured_payload["url"] = http_request.full_url
        captured_payload["headers"] = {
            key.lower(): value for key, value in http_request.header_items()
        }
        captured_payload["body"] = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                _synthesis_payload(
                                    confidence=0.93,
                                    model_used="cloud",
                                    cloud_model_calls=1,
                                )
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    return transport


def _mark_cloud_called(cloud_called: dict[str, bool]) -> bytes:
    """Mark that cloud transport was invoked and fail the test."""
    cloud_called["value"] = True
    raise AssertionError("cloud transport should not have been called")


def _research_step() -> ResearchStep:
    """Build a minimal research step for persisted investigation fixtures."""
    return ResearchStep(
        order=1,
        action="fetch_github_release",
        source="github://binhex/arch-delugevpn/releases/v5.0.1",
        result_summary="Fetched one release.",
        timestamp=ts(9, 0),
    )


def _synthesis_payload(
    *,
    confidence: float,
    model_used: str,
    cloud_model_calls: int,
) -> dict[str, object]:
    """Build one structured synthesis payload."""
    return {
        "evidence_summary": [
            "DelugeVPN logs report tunnel inactivity.",
            "Radarr reports its download client is unavailable.",
        ],
        "inference": {
            "root_cause": "DelugeVPN VPN tunnel dropped",
            "confidence": confidence,
            "reasoning": "Structured synthesis payload for workflow validation.",
        },
        "recommendation": {
            "summary": "Restart the affected container.",
            "action_type": "restart_container",
            "target": "delugevpn",
            "rationale": "Restart is bounded and restart-only.",
            "risk": {
                "overall_risk": "low",
                "checks": [
                    {
                        "check": "bounded_action_scope",
                        "result": "pass",
                        "detail": "Phase 2A keeps remediation scope narrow.",
                    }
                ],
                "reversible": True,
                "warnings": [],
            },
        },
        "degraded_mode_note": None,
        "model_used": model_used,
        "cloud_model_calls": cloud_model_calls,
    }


class StaticSynthesizer:
    """Deterministic synthesis stub for workflow tests."""

    def __init__(
        self,
        *,
        root_cause: str,
        confidence: float,
        action_type: str,
        target: str | None,
    ) -> None:
        """Store the deterministic synthesis output."""
        self._root_cause = root_cause
        self._confidence = confidence
        self._action_type = action_type
        self._target = target

    def synthesize(self, **_: object) -> InvestigationSynthesis:
        """Return one fixed synthesis payload."""
        return InvestigationSynthesis.model_validate(
            {
                "evidence_summary": [
                    "DelugeVPN logs report tunnel inactivity.",
                    "Radarr reports its download client is unavailable.",
                ],
                "inference": {
                    "root_cause": self._root_cause,
                    "confidence": self._confidence,
                    "reasoning": "Structured synthesis stub for workflow validation.",
                },
                "recommendation": {
                    "summary": (
                        "Restart the affected container."
                        if self._action_type == "restart_container"
                        else "No restart recommendation."
                    ),
                    "action_type": self._action_type,
                    "target": self._target,
                    "rationale": (
                        "Restart is bounded and restart-only."
                        if self._action_type == "restart_container"
                        else "The evidence is insufficient for restart-only remediation."
                    ),
                    "risk": RiskAssessment(
                        overall_risk=(
                            RiskLevel.LOW
                            if self._action_type == "restart_container"
                            else RiskLevel.MEDIUM
                        ),
                        checks=[
                            RiskCheck(
                                check="bounded_action_scope",
                                result=(
                                    RiskCheckResult.PASS
                                    if self._action_type == "restart_container"
                                    else RiskCheckResult.UNKNOWN
                                ),
                                detail="Phase 2A keeps remediation scope narrow.",
                            )
                        ],
                        reversible=True,
                        warnings=[],
                    ).model_dump(mode="json"),
                },
                "degraded_mode_note": None,
                "model_used": "none",
                "cloud_model_calls": 0,
            }
        )


class FakeInspectionAdapter:
    """Simple adapter double for workflow evidence-integration tests."""

    adapter_id = "radarr_api"
    surface_bindings = (
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
    )
    credential_keys = ("api_key",)
    supported_versions = ">=3.0"
    read_only = True

    def __init__(
        self,
        *,
        result: AdapterResult,
        adapter_id: str = "radarr_api",
        surface_bindings: tuple[AdapterSurfaceBinding, ...] = (
            AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
        ),
        credential_keys: tuple[str, ...] = ("api_key",),
    ) -> None:
        """Store the deterministic adapter result."""
        self._result = result
        self.adapter_id = adapter_id
        self.surface_bindings = surface_bindings
        self.credential_keys = credential_keys
        self.seen_credentials: dict[str, str] = {}
        self.seen_service_id: str | None = None

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Return the configured result and capture the supplied credential bundle."""
        self.seen_service_id = service.id
        self.seen_credentials = dict(credentials)
        return self._result


def build_adapter_credential_service(
    *,
    database: KavalDatabase,
    database_path: Path,
) -> CredentialMaterialService:
    """Build a credential service wired to the seeded workflow database."""
    return CredentialMaterialService(
        request_manager=CredentialRequestManager(database=database),
        volatile_store=VolatileCredentialStore(default_ttl_seconds=1800),
        vault=CredentialVault(database_path=database_path, auto_lock_minutes=5),
    )


def satisfy_adapter_secret(
    *,
    service: CredentialMaterialService,
    incident_id: str = "inc-delugevpn",
    service_id: str = "svc-radarr",
    credential_key: str = "api_key",
    secret_value: str,
    reason: str = "Need Radarr deep inspection.",
    requested_at: datetime | None = None,
) -> None:
    """Satisfy one seeded adapter credential using volatile storage."""
    requested_timestamp = requested_at or ts(14, 20)
    request_record = service.request_manager.create_request(
        incident_id=incident_id,
        service_id=service_id,
        credential_key=credential_key,
        reason=reason,
        now=requested_timestamp,
    )
    service.request_manager.resolve_choice(
        request_id=request_record.id,
        mode=CredentialRequestMode.VOLATILE,
        decided_by="user_via_telegram",
        now=requested_timestamp.replace(minute=requested_timestamp.minute + 1),
    )
    service.submit_secret(
        request_id=request_record.id,
        secret_value=secret_value,
        submitted_by="user_via_telegram",
        now=requested_timestamp.replace(minute=requested_timestamp.minute + 2),
    )


def fixture_log_reader(container_id: str, _tail_lines: int) -> str:
    """Return deterministic log lines for the seeded services."""
    if container_id == "container-radarr":
        return "2026-03-31T14:24:01Z warn: Download client DelugeVPN not available\n"
    if container_id == "container-authentik":
        return (
            "2026-03-31T17:24:01Z error: OAuth source request failed for provider "
            "google-oauth\n"
        )
    if container_id == "container-nextcloud":
        return "2026-03-31T17:24:02Z warn: OIDC login callback rejected\n"
    if container_id == "container-npm":
        return (
            "2026-03-31T18:24:01Z error: SSL routines: ssl3_read_bytes:sslv3 alert "
            "handshake failure\n"
        )
    if container_id == "container-cloudflared":
        return "2026-03-31T18:24:05Z info: Registered tunnel connection to Cloudflare\n"
    return "2026-03-31T14:23:55Z error: VPN tunnel inactive\n"


def seed_database(
    database_path: Path,
    *,
    include_downstream: bool = True,
    include_image_update: bool = False,
) -> KavalDatabase:
    """Seed a temporary database with one DelugeVPN incident path."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    delugevpn_service = Service(
        id="svc-delugevpn",
        name="DelugeVPN",
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.DEGRADED,
        descriptor_id="downloads/delugevpn",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-delugevpn",
        vm_id=None,
        image="binhex/arch-delugevpn:latest",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=["svc-radarr"],
        last_check=ts(14, 23),
        active_findings=1,
        active_incidents=1,
    )
    database.upsert_service(delugevpn_service)
    if include_downstream:
        database.upsert_service(
            Service(
                id="svc-radarr",
                name="Radarr",
                type=ServiceType.CONTAINER,
                category="arr",
                status=ServiceStatus.DEGRADED,
                descriptor_id="arr/radarr",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-radarr",
                vm_id=None,
                image="lscr.io/linuxserver/radarr:latest",
                endpoints=[],
                dns_targets=[],
                dependencies=[
                    DependencyEdge(
                        target_service_id="svc-delugevpn",
                        confidence=DependencyConfidence.INFERRED,
                        source=DependencySource.DESCRIPTOR,
                        description="Descriptor dependency from Radarr to DelugeVPN.",
                    )
                ],
                dependents=[],
                last_check=ts(14, 24),
                active_findings=1,
                active_incidents=1,
            )
        )

    change = Change(
        id="chg-delugevpn-restart",
        type=ChangeType.CONTAINER_RESTART,
        service_id="svc-delugevpn",
        description="delugevpn restart count increased from 3 to 4.",
        old_value="3",
        new_value="4",
        timestamp=ts(14, 22),
        correlated_incidents=["inc-delugevpn"],
    )
    database.upsert_change(change)
    correlated_change_ids = ["chg-delugevpn-restart"]
    if include_image_update:
        image_change = Change(
            id="chg-delugevpn-image",
            type=ChangeType.IMAGE_UPDATE,
            service_id="svc-delugevpn",
            description=(
                "delugevpn image changed from binhex/arch-delugevpn:5.0.0 [sha256:old] "
                "to binhex/arch-delugevpn:5.0.1 [sha256:new]."
            ),
            old_value="binhex/arch-delugevpn:5.0.0 [sha256:old]",
            new_value="binhex/arch-delugevpn:5.0.1 [sha256:new]",
            timestamp=ts(14, 21),
            correlated_incidents=["inc-delugevpn"],
        )
        database.upsert_change(image_change)
        correlated_change_ids.append(image_change.id)

    database.upsert_finding(
        Finding(
            id="find-delugevpn",
            title="DelugeVPN tunnel inactive",
            severity=Severity.HIGH,
            domain="downloads",
            service_id="svc-delugevpn",
            summary="DelugeVPN reports the VPN tunnel is inactive.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="docker_logs",
                    summary="VPN tunnel inactive",
                    observed_at=ts(14, 23),
                    data={"matched_patterns": ["VPN tunnel inactive"]},
                )
            ],
            impact="Downloads cannot exit through the VPN tunnel.",
            confidence=0.96,
            status=FindingStatus.GROUPED,
            incident_id="inc-delugevpn",
            related_changes=[change],
            created_at=ts(14, 23),
            resolved_at=None,
        )
    )
    if include_downstream:
        database.upsert_finding(
            Finding(
                id="find-radarr",
                title="Radarr cannot reach DelugeVPN",
                severity=Severity.HIGH,
                domain="arr",
                service_id="svc-radarr",
                summary="Radarr reports the download client is unavailable.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.LOG,
                        source="radarr",
                        summary="Download client not available",
                        observed_at=ts(14, 24),
                        data={"message": "Download client DelugeVPN not available"},
                    )
                ],
                impact="The movie download pipeline is blocked.",
                confidence=0.94,
                status=FindingStatus.GROUPED,
                incident_id="inc-delugevpn",
                related_changes=[],
                created_at=ts(14, 24),
                resolved_at=None,
            )
        )

    database.upsert_incident(
        Incident(
            id="inc-delugevpn",
            title="Radarr and DelugeVPN degraded",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            trigger_findings=["find-delugevpn"],
            all_findings=(
                ["find-delugevpn", "find-radarr"]
                if include_downstream
                else ["find-delugevpn"]
            ),
            affected_services=(
                ["svc-radarr", "svc-delugevpn"]
                if include_downstream
                else ["svc-delugevpn"]
            ),
            triggering_symptom=(
                "Radarr download client unavailable"
                if include_downstream
                else "DelugeVPN tunnel inactive"
            ),
            suspected_cause="DelugeVPN VPN tunnel dropped",
            confirmed_cause=None,
            root_cause_service="svc-delugevpn",
            resolution_mechanism=None,
            cause_confirmation_source=None,
            confidence=0.95,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=correlated_change_ids,
            grouping_window_start=ts(14, 23),
            grouping_window_end=ts(14, 28),
            created_at=ts(14, 23),
            updated_at=ts(14, 28),
            resolved_at=None,
            mttr_seconds=None,
            journal_entry_id=None,
        )
    )

    database.upsert_journal_entry(
        JournalEntry(
            id="jrnl-delugevpn-1",
            incident_id="inc-old-1",
            date=date(2026, 3, 12),
            services=["svc-delugevpn", "svc-radarr"],
            summary="DelugeVPN tunnel dropped after provider blip.",
            root_cause="VPN session dropped upstream.",
            resolution="Restarted DelugeVPN and downloads recovered.",
            time_to_resolution_minutes=8.0,
            model_used="local",
            tags=["delugevpn", "vpn", "downloads"],
            lesson="Restarting DelugeVPN restored connectivity quickly.",
            recurrence_count=1,
            confidence=JournalConfidence.CONFIRMED,
            user_confirmed=True,
            last_verified_at=ts(10, 0),
            applies_to_version=None,
            superseded_by=None,
            stale_after_days=None,
        )
    )
    database.upsert_journal_entry(
        JournalEntry(
            id="jrnl-delugevpn-2",
            incident_id="inc-old-2",
            date=date(2026, 3, 20),
            services=["svc-delugevpn"],
            summary="Download failures traced back to DelugeVPN again.",
            root_cause="VPN tunnel inactive.",
            resolution="Restarted DelugeVPN container.",
            time_to_resolution_minutes=6.0,
            model_used="local",
            tags=["delugevpn", "recurrence"],
            lesson="Recurrence points to unstable provider sessions.",
            recurrence_count=2,
            confidence=JournalConfidence.CONFIRMED,
            user_confirmed=True,
            last_verified_at=ts(11, 0),
            applies_to_version=None,
            superseded_by=None,
            stale_after_days=None,
        )
    )
    database.upsert_user_note(
        UserNote(
            id="note-delugevpn",
            service_id="svc-delugevpn",
            note="Provider endpoint rotates often.",
            safe_for_model=True,
            last_verified_at=ts(12, 0),
            stale=False,
            added_at=ts(12, 0),
            updated_at=ts(12, 30),
        )
    )
    return database


def seed_cloudflare_ingress_database(database_path: Path) -> KavalDatabase:
    """Seed a temporary database with one ingress incident linked to cloudflared."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    database.upsert_service(
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
            last_check=ts(18, 24),
            active_findings=1,
            active_incidents=1,
        )
    )
    database.upsert_service(
        Service(
            id="svc-cloudflared",
            name="cloudflared",
            type=ServiceType.CONTAINER,
            category="networking",
            status=ServiceStatus.HEALTHY,
            descriptor_id="networking/cloudflared",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-cloudflared",
            vm_id=None,
            image="cloudflare/cloudflared:2026.4.0",
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=["svc-npm"],
            last_check=ts(18, 24),
            active_findings=0,
            active_incidents=0,
        )
    )
    database.upsert_finding(
        Finding(
            id="find-npm-ingress",
            title="NPM TLS handshakes failing after image update",
            severity=Severity.HIGH,
            domain="networking",
            service_id="svc-npm",
            summary=(
                "NPM logs show repeated TLS handshake failures after the latest "
                "image update."
            ),
            evidence=[
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="docker_logs",
                    summary="SSL handshake failures in NPM logs.",
                    observed_at=ts(18, 23),
                    data={
                        "matched_patterns": ["SSL routines"],
                        "excerpt": (
                            "SSL routines: ssl3_read_bytes:sslv3 alert handshake failure"
                        ),
                    },
                )
            ],
            impact="Reverse-proxied sites fail external TLS handshakes.",
            confidence=0.96,
            status=FindingStatus.GROUPED,
            incident_id="inc-npm-ingress",
            related_changes=[],
            created_at=ts(18, 23),
            resolved_at=None,
        )
    )
    database.upsert_incident(
        Incident(
            id="inc-npm-ingress",
            title="NPM external TLS failures after image update",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            trigger_findings=["find-npm-ingress"],
            all_findings=["find-npm-ingress"],
            affected_services=["svc-npm"],
            triggering_symptom="External TLS handshakes started failing.",
            suspected_cause="Recent NPM image update likely changed TLS behavior.",
            confirmed_cause=None,
            root_cause_service="svc-npm",
            resolution_mechanism=None,
            cause_confirmation_source=None,
            confidence=0.9,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=[],
            grouping_window_start=ts(18, 23),
            grouping_window_end=ts(18, 28),
            created_at=ts(18, 23),
            updated_at=ts(18, 28),
            resolved_at=None,
            mttr_seconds=None,
            journal_entry_id=None,
        )
    )
    return database


def seed_authentik_sso_context_database(database_path: Path) -> KavalDatabase:
    """Seed a temporary database with one downstream SSO incident linked to Authentik."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    database.upsert_service(
        Service(
            id="svc-authentik",
            name="Authentik",
            type=ServiceType.CONTAINER,
            category="identity",
            status=ServiceStatus.DEGRADED,
            descriptor_id="identity/authentik",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-authentik",
            vm_id=None,
            image="ghcr.io/goauthentik/server:2026.3.1",
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=["svc-nextcloud"],
            last_check=ts(17, 24),
            active_findings=0,
            active_incidents=0,
        )
    )
    database.upsert_service(
        Service(
            id="svc-nextcloud",
            name="Nextcloud",
            type=ServiceType.CONTAINER,
            category="cloud",
            status=ServiceStatus.DEGRADED,
            descriptor_id="cloud/nextcloud",
            descriptor_source=DescriptorSource.SHIPPED,
            container_id="container-nextcloud",
            vm_id=None,
            image="linuxserver/nextcloud:31.0.0",
            endpoints=[],
            dns_targets=[],
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-authentik",
                    confidence=DependencyConfidence.INFERRED,
                    source=DependencySource.DESCRIPTOR,
                    description="Nextcloud SSO depends on Authentik.",
                )
            ],
            dependents=[],
            last_check=ts(17, 24),
            active_findings=1,
            active_incidents=1,
        )
    )
    database.upsert_finding(
        Finding(
            id="find-nextcloud-sso",
            title="Nextcloud SSO login failed",
            severity=Severity.HIGH,
            domain="identity",
            service_id="svc-nextcloud",
            summary="Nextcloud OIDC callbacks are failing after Authentik redirects users.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.LOG,
                    source="application_logs",
                    summary="OIDC callback rejected",
                    observed_at=ts(17, 24),
                    data={"message": "OIDC callback rejected"},
                )
            ],
            impact="Protected applications cannot complete SSO logins.",
            confidence=0.93,
            status=FindingStatus.GROUPED,
            incident_id="inc-nextcloud-sso",
            related_changes=[],
            created_at=ts(17, 24),
            resolved_at=None,
        )
    )
    database.upsert_incident(
        Incident(
            id="inc-nextcloud-sso",
            title="Nextcloud SSO degraded",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            trigger_findings=["find-nextcloud-sso"],
            all_findings=["find-nextcloud-sso"],
            affected_services=["svc-nextcloud"],
            triggering_symptom="OIDC callbacks are failing after redirect.",
            suspected_cause="Connected identity-provider redirects are failing.",
            confirmed_cause=None,
            root_cause_service="svc-nextcloud",
            resolution_mechanism=None,
            cause_confirmation_source=None,
            confidence=0.89,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=[],
            grouping_window_start=ts(17, 23),
            grouping_window_end=ts(17, 28),
            created_at=ts(17, 23),
            updated_at=ts(17, 28),
            resolved_at=None,
            mttr_seconds=None,
            journal_entry_id=None,
        )
    )
    return database


class StaticGitHubResearchClient:
    """Deterministic GitHub research stub for workflow tests."""

    def __init__(self, *, releases_by_repo_and_tag: dict[tuple[str, str], GitHubRelease]) -> None:
        """Store the configured release lookups."""
        self._releases_by_repo_and_tag = copy.deepcopy(releases_by_repo_and_tag)

    def fetch_release_by_tag(self, repository: str, *, tag_name: str) -> GitHubRelease:
        """Return one configured GitHub release."""
        key = (parse_repository_reference(repository).full_name, tag_name)
        if key not in self._releases_by_repo_and_tag:
            raise GitHubReleasesNotFoundError("missing release")
        return self._releases_by_repo_and_tag[key]


class StaticDockerHubResearchClient:
    """Deterministic Docker Hub research stub for workflow tests."""

    def __init__(
        self,
        *,
        repository_by_path: dict[str, DockerHubRepository],
        tags_by_path_and_name: dict[tuple[str, str], DockerHubTag],
    ) -> None:
        """Store the configured repository and tag lookups."""
        self._repository_by_path = copy.deepcopy(repository_by_path)
        self._tags_by_path_and_name = copy.deepcopy(tags_by_path_and_name)

    def fetch_repository(self, reference: str | DockerHubImageReference) -> DockerHubRepository:
        """Return one configured Docker Hub repository."""
        key = parse_dockerhub_reference(reference).repository_path
        if key not in self._repository_by_path:
            raise DockerHubNotFoundError("missing repository")
        return self._repository_by_path[key]

    def fetch_tag(
        self,
        reference: str | DockerHubImageReference,
        *,
        tag_name: str | None = None,
    ) -> DockerHubTag:
        """Return one configured Docker Hub tag."""
        parsed_reference = parse_dockerhub_reference(reference)
        resolved_tag = tag_name or parsed_reference.tag
        if resolved_tag is None:
            raise ValueError("tag_name is required")
        key = (parsed_reference.repository_path, resolved_tag)
        if key not in self._tags_by_path_and_name:
            raise DockerHubNotFoundError("missing tag")
        return self._tags_by_path_and_name[key]
