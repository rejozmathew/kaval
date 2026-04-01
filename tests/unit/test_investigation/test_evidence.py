"""Unit tests for Tier 1 investigation evidence collection."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.investigation.evidence import collect_incident_evidence, query_operational_memory
from kaval.models import (
    Change,
    ChangeType,
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    RedactionLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
    UserNote,
)
from kaval.system_profile import build_system_profile

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[3] / "services"


def load_docker_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture used by evidence tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load an Unraid JSON fixture used by evidence tests."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_collect_incident_evidence_includes_logs_dependencies_changes_and_memory() -> None:
    """Tier 1 collection should cover the core structured evidence surfaces."""
    state = build_delugevpn_state()

    result = collect_incident_evidence(
        incident=state.incident,
        findings=state.findings,
        services=state.services,
        changes=state.changes,
        docker_snapshot=state.docker_snapshot,
        system_profile=state.system_profile,
        journal_entries=state.journal_entries,
        user_notes=state.user_notes,
        descriptors=state.descriptors,
        log_reader=state.log_reader,
        now=ts(14, 30),
    )

    actions = [step.action for step in result.evidence_steps]
    assert actions == [
        "summarize_incident_findings",
        "inspect_service_state",
        "inspect_service_state",
        "read_container_logs",
        "read_container_logs",
        "inspect_dependency_graph",
        "correlate_change_timeline",
        "query_operational_memory",
    ]

    deluge_state_step = result.evidence_steps[1]
    assert deluge_state_step.target == "svc-delugevpn"
    assert deluge_state_step.result_data["container"]["restart_count"] == 4
    assert "descriptor context available" in deluge_state_step.result_summary

    deluge_logs_step = result.evidence_steps[3]
    assert deluge_logs_step.target == "svc-delugevpn"
    assert "VPN tunnel inactive" in deluge_logs_step.result_data["matched_patterns"]

    dependency_step = result.evidence_steps[5]
    assert dependency_step.result_data["edges"] == [
        {
            "confidence": "inferred",
            "description": "Descriptor dependency from Radarr to DelugeVPN.",
            "source": "descriptor",
            "source_service_id": "svc-radarr",
            "source_service_name": "Radarr",
            "target_service_id": "svc-delugevpn",
            "target_service_name": "DelugeVPN",
            "target_status": "degraded",
        }
    ]
    assert "DelugeVPN upstream" in dependency_step.result_summary

    change_step = result.evidence_steps[6]
    assert change_step.result_data["change_ids"] == ["chg-delugevpn-restart"]

    memory_step = result.evidence_steps[7]
    assert memory_step.result_data["recurrence_count"] == 2
    assert result.operational_memory.recurrence_count == 2
    assert result.operational_memory.user_notes[0].id == "note-delugevpn"


def test_query_operational_memory_excludes_unsafe_notes_and_redacts_safe_context() -> None:
    """Operational Memory context should keep only prompt-safe, redacted note content."""
    state = build_delugevpn_state()
    safe_note, unsafe_note = state.user_notes

    result = query_operational_memory(
        incident=state.incident,
        journal_entries=state.journal_entries,
        user_notes=[
            safe_note.model_copy(update={"note": "VPN token=supersecret"}),
            unsafe_note,
        ],
        system_profile=state.system_profile,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
    )

    assert [note.id for note in result.user_notes] == ["note-delugevpn"]
    assert result.user_notes[0].note == "VPN token=[REDACTED]"
    assert result.recurrence_count == 2
    assert result.warnings == ["Excluded 1 unsafe user note from model context."]


def test_query_operational_memory_applies_trust_staleness_and_version_scope() -> None:
    """Trust filtering should exclude mismatched scope and flag stale/speculative entries."""
    incident = Incident(
        id="inc-npm",
        title="NPM TLS failures",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-npm"],
        all_findings=["find-npm"],
        affected_services=["svc-npm"],
        triggering_symptom="TLS handshake failures",
        suspected_cause="OpenSSL change in the new image",
        confirmed_cause=None,
        root_cause_service="svc-npm",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.88,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(14, 0),
        grouping_window_end=ts(14, 5),
        created_at=ts(14, 0),
        updated_at=ts(14, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
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
        endpoints=[
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTP,
                host="npm",
                port=81,
                path="/",
                url=None,
                auth_required=False,
                expected_status=200,
            )
        ],
        dns_targets=[
            DnsTarget(
                host="proxy.example.test",
                record_type=DnsRecordType.A,
                expected_values=["192.0.2.10"],
            )
        ],
        dependencies=[],
        dependents=[],
        last_check=ts(14, 1),
        active_findings=1,
        active_incidents=1,
    )
    journal_entries = [
        JournalEntry(
            id="jrnl-stale",
            incident_id="inc-old-stale",
            date=date(2025, 9, 1),
            services=["svc-npm"],
            summary="Old TLS breakage pattern.",
            root_cause="Legacy TLS cipher mismatch.",
            resolution="Rolled back to an older image.",
            time_to_resolution_minutes=12.0,
            model_used="cloud",
            tags=["npm", "tls"],
            lesson="Older OpenSSL builds were more tolerant.",
            recurrence_count=1,
            confidence=JournalConfidence.CONFIRMED,
            user_confirmed=True,
            last_verified_at=ts(8, 0).replace(year=2025, month=9, day=1),
            applies_to_version=None,
            superseded_by=None,
            stale_after_days=30,
        ),
        JournalEntry(
            id="jrnl-speculative",
            incident_id="inc-old-speculative",
            date=date(2026, 3, 1),
            services=["svc-npm"],
            summary="Possibly related TLS regression.",
            root_cause="Maybe a proxy config mismatch.",
            resolution="Restarted NPM.",
            time_to_resolution_minutes=5.0,
            model_used="local",
            tags=["npm"],
            lesson="Unclear evidence, keep investigating.",
            recurrence_count=2,
            confidence=JournalConfidence.SPECULATIVE,
            user_confirmed=False,
            last_verified_at=None,
            applies_to_version=None,
            superseded_by=None,
            stale_after_days=180,
        ),
        JournalEntry(
            id="jrnl-version-mismatch",
            incident_id="inc-old-version",
            date=date(2026, 3, 2),
            services=["svc-npm"],
            summary="Applies only to older NPM builds.",
            root_cause="OpenSSL regression in an older image.",
            resolution="Pinned NPM below 2.12.0.",
            time_to_resolution_minutes=4.0,
            model_used="cloud",
            tags=["npm", "version"],
            lesson="Avoid affected builds.",
            recurrence_count=1,
            confidence=JournalConfidence.CONFIRMED,
            user_confirmed=True,
            last_verified_at=ts(9, 0),
            applies_to_version="svc-npm < 2.12.0",
            superseded_by=None,
            stale_after_days=180,
        ),
    ]

    result = query_operational_memory(
        incident=incident,
        services=[service],
        journal_entries=journal_entries,
        user_notes=[],
        system_profile=None,
        redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        now=ts(14, 30),
    )

    assert [entry.id for entry in result.journal_entries] == [
        "jrnl-stale",
        "jrnl-speculative",
    ]
    assert result.journal_entries[0].summary.startswith("[STALE] ")
    assert result.journal_entries[1].summary.startswith("[SPECULATIVE] ")
    assert result.recurrence_count == 1
    assert result.warnings == [
        "Excluded 1 version-scoped journal entry that did not match the current service version.",
        "Flagged 1 stale journal entry as potentially outdated.",
        "Included 1 speculative journal entry with explicit disclaimers.",
        "Excluded 1 speculative journal entry from recurrence count.",
    ]


class DelugeVpnState:
    """Shared deterministic evidence-collection state for tests."""

    def __init__(self) -> None:
        """Build the shared test state once."""
        self.descriptors = load_service_descriptors([SERVICES_DIR])
        self.docker_snapshot = build_discovery_snapshot(
            [
                load_docker_fixture("container_inspect_abc123.json"),
                load_docker_fixture("container_inspect_def456.json"),
            ],
            {
                "sha256:img-radarr": load_docker_fixture("image_inspect_sha256_img-radarr.json"),
                "sha256:img-delugevpn": load_docker_fixture(
                    "image_inspect_sha256_img-delugevpn.json"
                ),
            },
            discovered_at=ts(14, 24),
        )
        self.unraid_snapshot = build_unraid_discovery_snapshot(
            decode_graphql_data(load_unraid_fixture("discovery_response.json"))
        )
        self.services = build_dependency_graph(
            self.docker_snapshot,
            self.descriptors,
            unraid_snapshot=self.unraid_snapshot,
        ).services
        self.system_profile = build_system_profile(
            self.unraid_snapshot,
            self.docker_snapshot,
            services=self.services,
            now=ts(14, 10),
        )
        self.changes = [
            Change(
                id="chg-delugevpn-restart",
                type=ChangeType.CONTAINER_RESTART,
                service_id="svc-delugevpn",
                description="delugevpn restart count increased from 3 to 4.",
                old_value="3",
                new_value="4",
                timestamp=ts(14, 22),
                correlated_incidents=["inc-delugevpn"],
            )
        ]
        self.findings = [
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
                related_changes=self.changes,
                created_at=ts(14, 23),
                resolved_at=None,
            ),
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
            ),
        ]
        self.incident = Incident(
            id="inc-delugevpn",
            title="Radarr and DelugeVPN degraded",
            severity=Severity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            trigger_findings=["find-delugevpn"],
            all_findings=["find-delugevpn", "find-radarr"],
            affected_services=["svc-radarr", "svc-delugevpn"],
            triggering_symptom="Radarr download client unavailable",
            suspected_cause="DelugeVPN VPN tunnel dropped",
            confirmed_cause=None,
            root_cause_service="svc-delugevpn",
            resolution_mechanism=None,
            cause_confirmation_source=None,
            confidence=0.95,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=["chg-delugevpn-restart"],
            grouping_window_start=ts(14, 23),
            grouping_window_end=ts(14, 28),
            created_at=ts(14, 23),
            updated_at=ts(14, 28),
            resolved_at=None,
            mttr_seconds=None,
            journal_entry_id=None,
        )
        self.journal_entries = [
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
            ),
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
            ),
        ]
        self.user_notes = [
            UserNote(
                id="note-delugevpn",
                service_id="svc-delugevpn",
                note="Provider endpoint rotates often; token=provider-secret",
                safe_for_model=True,
                last_verified_at=ts(12, 0),
                stale=False,
                added_at=ts(12, 0),
                updated_at=ts(12, 30),
            ),
            UserNote(
                id="note-unsafe",
                service_id="svc-delugevpn",
                note="Do not expose to model.",
                safe_for_model=False,
                last_verified_at=ts(12, 0),
                stale=False,
                added_at=ts(12, 0),
                updated_at=ts(12, 45),
            ),
        ]
        self._logs_by_container_id = {
            "abc123": (
                "2026-03-31T14:24:01Z warn: Download client DelugeVPN not available\n"
                "2026-03-31T14:24:02Z Authorization: Bearer radarr-secret-token\n"
            ),
            "def456": (
                DOCKER_FIXTURES_DIR / "container_logs_def456.txt"
            ).read_text(encoding="utf-8"),
        }

    def log_reader(self, container_id: str, tail_lines: int) -> str:
        """Return deterministic fixture logs for the requested container."""
        assert tail_lines == 200
        return self._logs_by_container_id[container_id]


def build_delugevpn_state() -> DelugeVpnState:
    """Create the shared deterministic state for evidence tests."""
    return DelugeVpnState()
