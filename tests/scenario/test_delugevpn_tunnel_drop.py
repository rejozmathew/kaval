"""Scenario test for the DelugeVPN tunnel-drop investigation workflow."""

from __future__ import annotations

import json
import threading
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast

from kaval.actions import ExecutorClient, ExecutorClientConfig
from kaval.database import KavalDatabase
from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import LoadedServiceDescriptor, load_service_descriptors
from kaval.discovery.docker import DockerDiscoverySnapshot, build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.executor.server import ExecutorServerConfig, create_executor_server
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.memory.journal import OperationalJournalService
from kaval.models import (
    CauseConfirmationSource,
    Change,
    ChangeType,
    Evidence,
    EvidenceKind,
    ExecutorActionStatus,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    Service,
    ServiceStatus,
    Severity,
    UserNote,
)
from kaval.system_profile import build_system_profile

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"
_TEST_SECRET = "test-secret"


def load_docker_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture used by the scenario."""
    return cast(
        dict[str, object],
        json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8")),
    )


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load an Unraid JSON fixture used by the scenario."""
    return cast(
        dict[str, object],
        json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8")),
    )


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for scenario assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class _SequencedClock:
    """Return a fixed sequence of timestamps for deterministic socket tests."""

    def __init__(self, *timestamps: datetime) -> None:
        self._timestamps = iter(timestamps)

    def __call__(self) -> datetime:
        return next(self._timestamps)


class _RestartAwareDockerClient:
    """Fake executor dependency that toggles the scenario into recovery."""

    def __init__(self, state: "DelugeVpnTunnelDropState") -> None:
        self.state = state
        self.calls: list[str] = []

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Record the bounded restart and move the fixture state into recovery."""
        del wait_timeout_seconds
        self.calls.append(container)
        self.state.apply_restart(container)


def test_delugevpn_tunnel_drop_workflow_persists_structured_investigation(
    tmp_path: Path,
) -> None:
    """The DelugeVPN tunnel-drop path should persist structured restart-ready output."""
    state = DelugeVpnTunnelDropState()
    database = seed_database(tmp_path / "delugevpn-workflow.db", state=state)

    try:
        workflow = InvestigationWorkflow(
            database=database,
            descriptors=tuple(state.descriptors),
            log_reader=state.log_reader,
            docker_snapshot_provider=lambda: state.docker_snapshot,
        )

        result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        assert result.investigation.status.value == "completed"
        assert [step.order for step in result.investigation.evidence_steps] == list(
            range(1, len(result.investigation.evidence_steps) + 1)
        )
        assert [step.action for step in result.investigation.evidence_steps[-3:]] == [
            "inspect_dependency_graph",
            "correlate_change_timeline",
            "query_operational_memory",
        ]
        assert result.synthesis.evidence_summary
        assert result.synthesis.inference.root_cause == "DelugeVPN VPN tunnel dropped"
        assert result.synthesis.recommendation.action_type == "restart_container"
        assert result.synthesis.recommendation.target == "delugevpn"
        assert result.synthesis.degraded_mode_note is not None
        assert result.investigation.recurrence_count == 2
        assert result.investigation.remediation is not None
        assert result.investigation.remediation.action_type.value == "restart_container"

        persisted_incident = database.get_incident("inc-delugevpn")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.AWAITING_APPROVAL
        assert persisted_incident.investigation_id == result.investigation.id
    finally:
        database.close()


def test_delugevpn_tunnel_drop_scenario_covers_approval_gated_restart_path(
    tmp_path: Path,
) -> None:
    """The DelugeVPN scenario should cover approval, execution, and recovery verification."""
    state = DelugeVpnTunnelDropState()
    database_path = tmp_path / "delugevpn-remediation.db"
    database = seed_database(database_path, state=state)
    socket_path = tmp_path / "run" / "executor.sock"
    docker_client = _RestartAwareDockerClient(state)
    server = create_executor_server(
        ExecutorServerConfig(
            socket_path=socket_path,
            database_path=database_path,
            approval_hmac_secret=_TEST_SECRET,
        ),
        docker_client=docker_client,
        now_factory=_SequencedClock(ts(14, 36), ts(14, 37)),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        workflow = InvestigationWorkflow(
            database=database,
            descriptors=tuple(state.descriptors),
            log_reader=state.log_reader,
            docker_snapshot_provider=lambda: state.docker_snapshot,
        )
        workflow_result = workflow.run(
            incident_id="inc-delugevpn",
            trigger=InvestigationTrigger.AUTO,
            now=ts(14, 30),
        )

        remediation = workflow_result.investigation.remediation
        assert remediation is not None
        assert remediation.action_type.value == "restart_container"
        persisted_incident = database.get_incident("inc-delugevpn")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.AWAITING_APPROVAL
        assert docker_client.calls == []

        client = ExecutorClient(
            config=ExecutorClientConfig(
                socket_path=socket_path,
                database_path=database_path,
                approval_hmac_secret=_TEST_SECRET,
            ),
            now_factory=lambda: ts(14, 35),
            token_id_factory=lambda: "tok-delugevpn-restart",
            nonce_factory=lambda: "nonce-delugevpn-restart",
        )
        token = client.issue_approval_token(
            incident_id="inc-delugevpn",
            action=remediation.action_type,
            target=remediation.target,
            approved_by="telegram-user",
        )
        stored_token_before = database.get_approval_token(token.token_id)
        assert stored_token_before is not None
        assert stored_token_before.used_at is None

        executor_result = client.execute_approved_action(token)

        assert executor_result.status is ExecutorActionStatus.SUCCESS
        assert docker_client.calls == ["delugevpn"]
        stored_token_after = database.get_approval_token(token.token_id)
        assert stored_token_after is not None
        assert stored_token_after.used_at == ts(14, 36)
        assert stored_token_after.result is not None
        assert stored_token_after.result.startswith("success:")

        verification = state.verification_result()
        assert verification["vpn_tunnel_restored"] is True
        assert verification["delugevpn_status"] == ServiceStatus.HEALTHY.value
        assert verification["radarr_status"] == ServiceStatus.HEALTHY.value
        assert "inactive" not in str(verification["delugevpn_log"]).lower()
        assert "restored" in str(verification["radarr_log"]).lower()

        resolution_result = OperationalJournalService(database=database).resolve_incident(
            incident_id="inc-delugevpn",
            resolution="Restarted delugevpn container.",
            lesson="Recurring issue; restart restored the tunnel quickly.",
            cause_confirmation_source=CauseConfirmationSource.RESOLUTION_INFERRED,
            now=ts(14, 38),
        )

        assert resolution_result.incident.status is IncidentStatus.RESOLVED
        assert resolution_result.journal_entry.recurrence_count == 3
        assert resolution_result.journal_entry.confidence is JournalConfidence.LIKELY
        persisted_resolved_incident = database.get_incident("inc-delugevpn")
        assert persisted_resolved_incident is not None
        assert persisted_resolved_incident.journal_entry_id == resolution_result.journal_entry.id
        persisted_journal_entry = database.get_journal_entry(resolution_result.journal_entry.id)
        assert persisted_journal_entry is not None
        assert persisted_journal_entry.resolution == "Restarted delugevpn container."
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        database.close()


class DelugeVpnTunnelDropState:
    """Deterministic DelugeVPN tunnel-drop scenario inputs."""

    def __init__(self) -> None:
        """Build the shared fixture-backed workflow inputs."""
        self._vpn_tunnel_restored = False
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
        unraid_snapshot = build_unraid_discovery_snapshot(
            decode_graphql_data(load_unraid_fixture("discovery_response.json"))
        )
        self.services = build_dependency_graph(
            self.docker_snapshot,
            self.descriptors,
            unraid_snapshot=unraid_snapshot,
        ).services
        self.recovered_services = [
            service.model_copy(
                update={
                    "status": (
                        ServiceStatus.HEALTHY
                        if service.id in {"svc-delugevpn", "svc-radarr"}
                        else service.status
                    )
                }
            )
            for service in self.services
        ]
        self.system_profile = build_system_profile(
            unraid_snapshot,
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
            status=IncidentStatus.OPEN,
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
        self._recovered_logs_by_container_id = {
            "abc123": "2026-03-31T14:38:01Z info: Download client DelugeVPN connection restored\n",
            "def456": "2026-03-31T14:38:00Z info: VPN tunnel established and healthy\n",
        }

    descriptors: list[LoadedServiceDescriptor]
    docker_snapshot: DockerDiscoverySnapshot
    services: list[Service]
    recovered_services: list[Service]

    def log_reader(self, container_id: str, tail_lines: int) -> str:
        """Return deterministic fixture logs for the requested container."""
        assert tail_lines == 200
        if self._vpn_tunnel_restored:
            return self._recovered_logs_by_container_id[container_id]
        return self._logs_by_container_id[container_id]

    def apply_restart(self, container: str) -> None:
        """Mark the scenario as recovered after the bounded restart executes."""
        assert container == "delugevpn"
        self._vpn_tunnel_restored = True

    def verification_result(self) -> dict[str, bool | str]:
        """Return the deterministic post-restart verification view."""
        services = self.recovered_services if self._vpn_tunnel_restored else self.services
        service_statuses = {service.id: service.status.value for service in services}
        return {
            "vpn_tunnel_restored": self._vpn_tunnel_restored,
            "delugevpn_status": service_statuses["svc-delugevpn"],
            "radarr_status": service_statuses["svc-radarr"],
            "delugevpn_log": self.log_reader("def456", 200),
            "radarr_log": self.log_reader("abc123", 200),
        }


def seed_database(database_path: Path, *, state: DelugeVpnTunnelDropState) -> KavalDatabase:
    """Seed the SQLite store with the DelugeVPN tunnel-drop scenario."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    for service in state.services:
        database.upsert_service(service)
    database.upsert_system_profile(state.system_profile)
    for change in state.changes:
        database.upsert_change(change)
    for finding in state.findings:
        database.upsert_finding(finding)
    database.upsert_incident(state.incident)
    for journal_entry in state.journal_entries:
        database.upsert_journal_entry(journal_entry)
    for user_note in state.user_notes:
        database.upsert_user_note(user_note)

    return database
