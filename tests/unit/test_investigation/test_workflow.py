"""Unit tests for the LangGraph Tier 1 investigation workflow."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from kaval.database import KavalDatabase
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
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
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


def fixture_log_reader(container_id: str, _tail_lines: int) -> str:
    """Return deterministic log lines for the seeded services."""
    if container_id == "container-radarr":
        return "2026-03-31T14:24:01Z warn: Download client DelugeVPN not available\n"
    return "2026-03-31T14:23:55Z error: VPN tunnel inactive\n"


def seed_database(database_path: Path, *, include_downstream: bool = True) -> KavalDatabase:
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
            changes_correlated=["chg-delugevpn-restart"],
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
