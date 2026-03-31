"""Scenario test for DelugeVPN tunnel-drop Tier 1 evidence collection."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.investigation.evidence import collect_incident_evidence
from kaval.models import (
    Change,
    ChangeType,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    Severity,
    UserNote,
)
from kaval.system_profile import build_system_profile

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_docker_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture used by the scenario."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load an Unraid JSON fixture used by the scenario."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_delugevpn_tunnel_drop_collects_structured_tier1_evidence() -> None:
    """The flagship DelugeVPN incident should yield ordered evidence, not a free-form dump."""
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

    assert [step.order for step in result.evidence_steps] == list(
        range(1, len(result.evidence_steps) + 1)
    )
    assert [step.action for step in result.evidence_steps[-3:]] == [
        "inspect_dependency_graph",
        "correlate_change_timeline",
        "query_operational_memory",
    ]
    assert "VPN tunnel inactive" in result.evidence_steps[3].result_data["matched_patterns"]
    assert result.evidence_steps[5].result_summary == (
        "Dependency walk shows DelugeVPN upstream of 1 affected service(s): Radarr."
    )
    assert result.operational_memory.recurrence_count == 2


class DelugeVpnScenarioState:
    """Deterministic DelugeVPN scenario inputs for evidence collection."""

    def __init__(self) -> None:
        """Build the shared scenario state."""
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
            )
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


def build_delugevpn_state() -> DelugeVpnScenarioState:
    """Create the DelugeVPN scenario state for the test."""
    return DelugeVpnScenarioState()
