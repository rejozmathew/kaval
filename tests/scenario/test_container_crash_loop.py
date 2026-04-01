"""Scenario test for a crash-loop investigation and restart flow."""

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
from kaval.executor.server import ExecutorServerConfig, create_executor_server
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.models import (
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

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"
_TEST_SECRET = "test-secret"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture used by the crash-loop scenario."""
    return cast(
        dict[str, object],
        json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8")),
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
    """Fake executor dependency that flips the crash-loop scenario into recovery."""

    def __init__(self, state: "CrashLoopState") -> None:
        self.state = state
        self.calls: list[str] = []

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Record the bounded restart and mark the crash loop as cleared."""
        del wait_timeout_seconds
        self.calls.append(container)
        self.state.apply_restart(container)


def test_container_crash_loop_scenario_covers_approval_gated_restart_path(
    tmp_path: Path,
) -> None:
    """The crash-loop path should recommend a restart and verify recovery after approval."""
    state = CrashLoopState()
    database_path = tmp_path / "crash-loop.db"
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
        now_factory=_SequencedClock(ts(16, 36), ts(16, 37)),
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
        result = workflow.run(
            incident_id="inc-crash-loop",
            trigger=InvestigationTrigger.AUTO,
            now=ts(16, 30),
        )

        assert (
            result.synthesis.inference.root_cause
            == "DelugeVPN is crash-looping after repeated restarts."
        )
        assert result.synthesis.recommendation.action_type == "restart_container"
        assert result.synthesis.recommendation.target == "delugevpn"
        assert "restart count increased" in result.prompt_bundle.user_prompt
        persisted_incident = database.get_incident("inc-crash-loop")
        assert persisted_incident is not None
        assert persisted_incident.status == IncidentStatus.AWAITING_APPROVAL
        assert docker_client.calls == []

        client = ExecutorClient(
            config=ExecutorClientConfig(
                socket_path=socket_path,
                database_path=database_path,
                approval_hmac_secret=_TEST_SECRET,
            ),
            now_factory=lambda: ts(16, 35),
            token_id_factory=lambda: "tok-crash-loop-restart",
            nonce_factory=lambda: "nonce-crash-loop-restart",
        )
        remediation = result.investigation.remediation
        assert remediation is not None
        token = client.issue_approval_token(
            incident_id="inc-crash-loop",
            action=remediation.action_type,
            target=remediation.target,
            approved_by="telegram-user",
        )

        executor_result = client.execute_approved_action(token)

        assert executor_result.status is ExecutorActionStatus.SUCCESS
        assert docker_client.calls == ["delugevpn"]
        stored_token = database.get_approval_token(token.token_id)
        assert stored_token is not None
        assert stored_token.used_at == ts(16, 36)
        assert stored_token.result is not None
        assert stored_token.result.startswith("success:")

        verification = state.verification_result()
        assert verification["crash_loop_cleared"] is True
        assert verification["delugevpn_status"] == ServiceStatus.HEALTHY.value
        assert verification["radarr_status"] == ServiceStatus.HEALTHY.value
        assert "crash" not in str(verification["delugevpn_log"]).lower()
        assert "ready" in str(verification["delugevpn_log"]).lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
        database.close()


class CrashLoopState:
    """Deterministic crash-loop scenario inputs."""

    def __init__(self) -> None:
        """Build the shared fixture-backed workflow inputs."""
        self._crash_loop_cleared = False
        self.descriptors = load_service_descriptors([SERVICES_DIR])
        self.docker_snapshot = build_discovery_snapshot(
            [
                load_json_fixture("container_inspect_abc123.json"),
                _deluge_inspect_payload(restart_count=7),
            ],
            {
                "sha256:img-radarr": load_json_fixture("image_inspect_sha256_img-radarr.json"),
                "sha256:img-delugevpn": load_json_fixture(
                    "image_inspect_sha256_img-delugevpn.json"
                ),
            },
            discovered_at=ts(16, 24),
        )
        discovered_services = build_dependency_graph(
            self.docker_snapshot,
            self.descriptors,
        ).services
        self.services = [
            service.model_copy(
                update={
                    "status": (
                        ServiceStatus.DEGRADED
                        if service.id in {"svc-delugevpn", "svc-radarr"}
                        else service.status
                    )
                }
            )
            for service in discovered_services
        ]
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
        self.changes = [
            Change(
                id="chg-delugevpn-crash-loop",
                type=ChangeType.CONTAINER_RESTART,
                service_id="svc-delugevpn",
                description="delugevpn restart count increased from 4 to 7.",
                old_value="4",
                new_value="7",
                timestamp=ts(16, 22),
                correlated_incidents=["inc-crash-loop"],
            )
        ]
        self.findings = [
            Finding(
                id="find-delugevpn-crash-loop",
                title="DelugeVPN restart storm detected",
                severity=Severity.HIGH,
                domain="downloads",
                service_id="svc-delugevpn",
                summary=(
                    "DelugeVPN restarted 3 times in 60 seconds according to Docker "
                    "restart counters."
                ),
                evidence=[
                    Evidence(
                        kind=EvidenceKind.API,
                        source="docker_api",
                        summary="Docker restart count increased from 4 to 7 within 60 seconds",
                        observed_at=ts(16, 23),
                        data={
                            "container_id": "def456",
                            "previous_restart_count": 4,
                            "current_restart_count": 7,
                            "restart_delta": 3,
                            "elapsed_seconds": 60,
                            "state": "restarting",
                        },
                    )
                ],
                impact=(
                    "Downloads and dependent arr services may stay unavailable until "
                    "the crash loop is cleared."
                ),
                confidence=0.98,
                status=FindingStatus.GROUPED,
                incident_id="inc-crash-loop",
                related_changes=self.changes,
                created_at=ts(16, 23),
                resolved_at=None,
            )
        ]
        self.incident = Incident(
            id="inc-crash-loop",
            title="DelugeVPN crash loop impacting downloads",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            trigger_findings=["find-delugevpn-crash-loop"],
            all_findings=["find-delugevpn-crash-loop"],
            affected_services=["svc-delugevpn", "svc-radarr"],
            triggering_symptom=(
                "DelugeVPN restarted repeatedly and Radarr lost its download client."
            ),
            suspected_cause="DelugeVPN is crash-looping after repeated restarts.",
            confirmed_cause=None,
            root_cause_service="svc-delugevpn",
            resolution_mechanism=None,
            cause_confirmation_source=None,
            confidence=0.97,
            investigation_id=None,
            approved_actions=[],
            changes_correlated=["chg-delugevpn-crash-loop"],
            grouping_window_start=ts(16, 23),
            grouping_window_end=ts(16, 28),
            created_at=ts(16, 23),
            updated_at=ts(16, 28),
            resolved_at=None,
            mttr_seconds=None,
            journal_entry_id=None,
        )
        self.journal_entries = [
            JournalEntry(
                id="jrnl-crash-loop-1",
                incident_id="inc-old-crash-loop",
                date=date(2026, 3, 10),
                services=["svc-delugevpn"],
                summary="DelugeVPN entered a crash loop after a bad session state.",
                root_cause="The DelugeVPN process exited repeatedly after a stale session file.",
                resolution="Restarted DelugeVPN and the process stabilized.",
                time_to_resolution_minutes=7.0,
                model_used="local",
                tags=["delugevpn", "restart_storm", "crash_loop"],
                lesson="A bounded restart cleared the transient crash loop quickly.",
                recurrence_count=1,
                confidence=JournalConfidence.CONFIRMED,
                user_confirmed=True,
                last_verified_at=ts(10, 0),
                applies_to_version=None,
                superseded_by=None,
                stale_after_days=None,
            )
        ]
        self.user_notes = [
            UserNote(
                id="note-crash-loop",
                service_id="svc-delugevpn",
                note="Crash loops have previously cleared after a clean container restart.",
                safe_for_model=True,
                last_verified_at=ts(12, 0),
                stale=False,
                added_at=ts(12, 0),
                updated_at=ts(12, 30),
            )
        ]
        self._logs_by_container_id = {
            "abc123": "2026-03-31T16:24:01Z warn: Download client DelugeVPN not available\n",
            "def456": (
                "2026-03-31T16:23:50Z fatal: delugevpn process crashed unexpectedly\n"
                "2026-03-31T16:24:05Z fatal: restarting supervised process after crash\n"
            ),
        }
        self._recovered_logs_by_container_id = {
            "abc123": "2026-03-31T16:38:01Z info: Download client DelugeVPN connection restored\n",
            "def456": "2026-03-31T16:38:00Z info: DelugeVPN daemon ready after restart\n",
        }

    descriptors: list[LoadedServiceDescriptor]
    docker_snapshot: DockerDiscoverySnapshot
    services: list[Service]
    recovered_services: list[Service]

    def log_reader(self, container_id: str, tail_lines: int) -> str:
        """Return deterministic fixture logs for the requested container."""
        assert tail_lines == 200
        if self._crash_loop_cleared:
            return self._recovered_logs_by_container_id[container_id]
        return self._logs_by_container_id[container_id]

    def apply_restart(self, container: str) -> None:
        """Mark the scenario as recovered after the bounded restart executes."""
        assert container == "delugevpn"
        self._crash_loop_cleared = True

    def verification_result(self) -> dict[str, bool | str]:
        """Return the deterministic post-restart verification view."""
        services = self.recovered_services if self._crash_loop_cleared else self.services
        service_statuses = {service.id: service.status.value for service in services}
        return {
            "crash_loop_cleared": self._crash_loop_cleared,
            "delugevpn_status": service_statuses["svc-delugevpn"],
            "radarr_status": service_statuses["svc-radarr"],
            "delugevpn_log": self.log_reader("def456", 200),
            "radarr_log": self.log_reader("abc123", 200),
        }


def seed_database(database_path: Path, *, state: CrashLoopState) -> KavalDatabase:
    """Seed the SQLite store with the crash-loop scenario."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()

    for service in state.services:
        database.upsert_service(service)
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


def _deluge_inspect_payload(*, restart_count: int) -> dict[str, object]:
    """Return the DelugeVPN inspect fixture with an overridden restart count."""
    payload = load_json_fixture("container_inspect_def456.json")
    payload["RestartCount"] = restart_count
    return payload
