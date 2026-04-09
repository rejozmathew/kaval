"""Scenario test for the representative NPM TLS breakage investigation."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

from kaval.database import KavalDatabase
from kaval.discovery.descriptors import load_service_descriptors
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
    GitHubRepositoryReference,
    decode_release_payload,
    parse_repository_reference,
)
from kaval.investigation.prompts import InvestigationSynthesis
from kaval.investigation.research import PublicResearchHints
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.models import (
    ArrayProfile,
    Change,
    ChangeType,
    DescriptorSource,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
    NetworkingProfile,
    Service,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    UserNote,
    VMProfile,
)

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for scenario assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def load_json_fixture(relative_path: str) -> dict[str, object] | list[object]:
    """Load one shared JSON fixture."""
    return cast(
        dict[str, object] | list[object],
        json.loads((FIXTURES_DIR / relative_path).read_text(encoding="utf-8")),
    )


def test_npm_tls_breakage_workflow_collects_tier2_research_without_restarting(
    tmp_path: Path,
) -> None:
    """The NPM TLS path should surface changelog research and keep remediation bounded."""
    database = seed_database(tmp_path / "npm-tls-breakage.db")

    try:
        workflow = InvestigationWorkflow(
            database=database,
            descriptors=tuple(load_service_descriptors([SERVICES_DIR])),
            log_reader=lambda _container_id, _tail_lines: (
                "2026-03-31T18:24:01Z error: SSL routines: ssl3_read_bytes:sslv3 alert "
                "handshake failure\n"
            ),
            synthesizer=NpmTlsSynthesizer(),
            research_hints_by_service={
                "svc-npm": PublicResearchHints(
                    github_repository="NginxProxyManager/nginx-proxy-manager"
                )
            },
            github_research_client=StaticGitHubResearchClient(),
            dockerhub_research_client=StaticDockerHubResearchClient(),
        )

        result = workflow.run(
            incident_id="inc-npm-tls",
            trigger=InvestigationTrigger.AUTO,
            now=ts(19, 30),
        )

        assert result.investigation.status.value == "completed"
        assert [step.action for step in result.investigation.research_steps] == [
            "fetch_github_release",
            "fetch_github_release",
            "fetch_dockerhub_repository",
            "fetch_dockerhub_tag",
            "fetch_dockerhub_tag",
        ]
        assert "OpenSSL 3.5.5" in result.prompt_bundle.user_prompt
        assert "cloudflare_origin_certs" in result.prompt_bundle.user_prompt
        assert result.synthesis.inference.root_cause == (
            "NPM image update introduced OpenSSL 3.5.5, which likely broke "
            "Cloudflare origin-cert TLS handshakes."
        )
        assert result.synthesis.recommendation.action_type == "none"
        assert result.investigation.remediation is None
        assert result.investigation.recurrence_count == 1
        assert result.investigation.local_input_tokens == 0
        assert result.investigation.local_output_tokens == 0
        assert result.investigation.estimated_total_cost_usd == 0.0

        persisted_incident = database.get_incident("inc-npm-tls")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.INVESTIGATING
        assert persisted_incident.investigation_id == result.investigation.id
    finally:
        database.close()


class NpmTlsSynthesizer:
    """Deterministic scenario synthesizer for the NPM TLS breakage path."""

    def synthesize(self, **_: object) -> InvestigationSynthesis:
        """Return one fixed structured no-action synthesis."""
        return InvestigationSynthesis.model_validate(
            {
                "evidence_summary": [
                    "NPM started failing TLS handshakes after an image update.",
                    "Tier 2 research identified an OpenSSL 3.5.5 base-image change.",
                    "Operational Memory shows this server uses Cloudflare origin certs.",
                ],
                "inference": {
                    "root_cause": (
                        "NPM image update introduced OpenSSL 3.5.5, which likely broke "
                        "Cloudflare origin-cert TLS handshakes."
                    ),
                    "confidence": 0.91,
                    "reasoning": (
                        "Evidence, changelog research, and prior journal history align on "
                        "the same TLS compatibility issue."
                    ),
                },
                "recommendation": {
                    "summary": "No restart-only remediation is justified for this TLS breakage.",
                    "action_type": "none",
                    "target": None,
                    "rationale": (
                        "The likely fix is image rollback or certificate strategy change, "
                        "which is outside the current restart-only remediation scope."
                    ),
                    "risk": {
                        "overall_risk": "medium",
                        "checks": [
                            {
                                "check": "bounded_action_scope",
                                "result": "unknown",
                                "detail": (
                                    "The current phase does not allow image rollback or "
                                    "config mutation."
                                ),
                            }
                        ],
                        "reversible": True,
                        "warnings": [
                            (
                                "Restarting NPM alone is unlikely to clear a version-level "
                                "TLS incompatibility."
                            )
                        ],
                    },
                },
                "degraded_mode_note": None,
                "model_used": ModelUsed.NONE.value,
                "cloud_model_calls": 0,
                "local_input_tokens": 0,
                "local_output_tokens": 0,
                "cloud_input_tokens": 0,
                "cloud_output_tokens": 0,
                "estimated_cloud_cost_usd": 0.0,
                "estimated_total_cost_usd": 0.0,
                "cloud_escalation_reason": None,
            }
        )


class StaticGitHubResearchClient:
    """Deterministic GitHub research client backed by checked-in fixtures."""

    def __init__(self) -> None:
        """Decode the representative NPM release fixtures once."""
        releases_payload = cast(list[object], load_json_fixture("github/releases_npm.json"))
        releases = [
            decode_release_payload(releases_payload[0]),
            decode_release_payload(releases_payload[1]),
        ]
        self._releases_by_repo_and_tag = {
            ("NginxProxyManager/nginx-proxy-manager", release.tag_name): release
            for release in releases
        }

    def fetch_release_by_tag(
        self,
        repository: GitHubRepositoryReference | str,
        *,
        tag_name: str,
    ) -> GitHubRelease:
        """Return one fixture-backed GitHub release."""
        key = (parse_repository_reference(repository).full_name, tag_name)
        if key not in self._releases_by_repo_and_tag:
            raise GitHubReleasesNotFoundError("missing release")
        return self._releases_by_repo_and_tag[key]


class StaticDockerHubResearchClient:
    """Deterministic Docker Hub research client backed by checked-in fixtures."""

    def __init__(self) -> None:
        """Decode the representative NPM Docker Hub fixtures once."""
        tags_payload = cast(dict[str, object], load_json_fixture("dockerhub/tags_npm.json"))
        tag_payloads = cast(list[object], tags_payload["results"])
        self._repository = decode_repository_payload(
            load_json_fixture("dockerhub/repository_npm.json")
        )
        self._tags_by_path_and_name = {
            (
                "jc21/nginx-proxy-manager",
                cast(str, cast(dict[str, object], tag_payload)["name"]),
            ): decode_tag_payload(tag_payload)
            for tag_payload in tag_payloads
        }

    def fetch_repository(self, reference: str | DockerHubImageReference) -> DockerHubRepository:
        """Return the fixture-backed Docker Hub repository."""
        parsed = parse_dockerhub_reference(reference)
        if parsed.repository_path != "jc21/nginx-proxy-manager":
            raise DockerHubNotFoundError("missing repository")
        return self._repository

    def fetch_tag(
        self,
        reference: str | DockerHubImageReference,
        *,
        tag_name: str | None = None,
    ) -> DockerHubTag:
        """Return one fixture-backed Docker Hub tag."""
        parsed = parse_dockerhub_reference(reference)
        resolved_tag = tag_name or parsed.tag
        if resolved_tag is None:
            raise ValueError("tag_name is required")
        key = (parsed.repository_path, resolved_tag)
        if key not in self._tags_by_path_and_name:
            raise DockerHubNotFoundError("missing tag")
        return self._tags_by_path_and_name[key]


def seed_database(database_path: Path) -> KavalDatabase:
    """Seed the SQLite store with the representative NPM TLS breakage path."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    service = Service(
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
        dependencies=[],
        dependents=[],
        last_check=ts(18, 24),
        active_findings=1,
        active_incidents=1,
    )
    finding = Finding(
        id="find-npm-tls",
        title="NPM TLS handshakes failing after image update",
        severity=Severity.HIGH,
        domain="networking",
        service_id=service.id,
        summary="NPM logs show repeated TLS handshake failures after the latest image update.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="docker_logs",
                summary="SSL handshake failures in NPM logs.",
                observed_at=ts(18, 23),
                data={
                    "matched_patterns": ["SSL routines"],
                    "excerpt": "SSL routines: ssl3_read_bytes:sslv3 alert handshake failure",
                },
            )
        ],
        impact="Reverse-proxied sites fail external TLS handshakes.",
        confidence=0.96,
        status=FindingStatus.GROUPED,
        incident_id="inc-npm-tls",
        related_changes=[],
        created_at=ts(18, 23),
        resolved_at=None,
    )
    change = Change(
        id="chg-npm-image",
        type=ChangeType.IMAGE_UPDATE,
        service_id=service.id,
        description="NPM image changed from 2.12.0 to 2.12.1 shortly before TLS failures.",
        old_value="jc21/nginx-proxy-manager:2.12.0 [sha256:npm-2120-amd64]",
        new_value="jc21/nginx-proxy-manager:2.12.1 [sha256:npm-2121-amd64]",
        timestamp=ts(18, 20),
        correlated_incidents=["inc-npm-tls"],
    )
    incident = Incident(
        id="inc-npm-tls",
        title="NPM external TLS failures after image update",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=[finding.id],
        all_findings=[finding.id],
        affected_services=[service.id],
        triggering_symptom=finding.summary,
        suspected_cause="Recent NPM image update likely changed TLS behavior.",
        confirmed_cause=None,
        root_cause_service=service.id,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[change.id],
        grouping_window_start=ts(18, 23),
        grouping_window_end=ts(18, 28),
        created_at=ts(18, 23),
        updated_at=ts(18, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    system_profile = SystemProfile(
        hostname="zactower",
        unraid_version="7.2.1",
        hardware=HardwareProfile(
            cpu="Intel i3-12100T",
            memory_gb=32.0,
            gpu="NVIDIA",
            ups="APC Back-UPS",
        ),
        storage=StorageProfile(
            array=ArrayProfile(
                parity_drives=1,
                data_drives=4,
                cache="2x NVMe RAID 1",
                total_tb=12.0,
                used_tb=4.2,
            )
        ),
        networking=NetworkingProfile(
            domain="zactower.com",
            dns_provider="cloudflare",
            reverse_proxy="nginx_proxy_manager",
            tunnel="cloudflare_zero_trust",
            vpn="wireguard",
            dns_resolver="pihole",
            ssl_strategy="cloudflare_origin_certs",
        ),
        services_summary=ServicesSummary(
            total_containers=25,
            total_vms=3,
            matched_descriptors=22,
        ),
        vms=[
            VMProfile(
                name="Ubuntu Server",
                purpose="Hosts Moodle LMS + MariaDB",
                os="Ubuntu 22.04 LTS",
            )
        ],
        last_updated=ts(18, 10),
    )
    journal_entry = JournalEntry(
        id="jrnl-npm-tls-1",
        incident_id="inc-old-npm-tls",
        date=date(2026, 3, 15),
        services=[service.id],
        summary="NPM TLS failed after an earlier image update.",
        root_cause="OpenSSL base-image change conflicted with Cloudflare origin certs.",
        resolution="Pinned NPM below the affected image version.",
        time_to_resolution_minutes=6.0,
        model_used="cloud",
        tags=["npm", "tls", "cloudflare", "openssl"],
        lesson="Avoid auto-applying NPM image updates before TLS validation.",
        recurrence_count=1,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(11, 0),
        applies_to_version="svc-npm < 2.12.2",
        superseded_by=None,
        stale_after_days=180,
    )
    user_note = UserNote(
        id="note-npm-certs",
        service_id=service.id,
        note="This stack uses Cloudflare origin certs, not Let's Encrypt.",
        safe_for_model=True,
        last_verified_at=ts(12, 0),
        stale=False,
        added_at=ts(12, 0),
        updated_at=ts(12, 5),
    )

    database.upsert_service(service)
    database.upsert_change(change)
    database.upsert_finding(finding)
    database.upsert_incident(incident)
    database.upsert_system_profile(system_profile)
    database.upsert_journal_entry(journal_entry)
    database.upsert_user_note(user_note)
    return database
