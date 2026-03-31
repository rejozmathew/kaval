"""LangGraph-backed Tier 1 investigation workflow."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol, TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from kaval.database import KavalDatabase
from kaval.discovery.descriptors import LoadedServiceDescriptor, load_service_descriptors
from kaval.discovery.docker import DockerDiscoverySnapshot
from kaval.grouping import can_transition_incident_status, transition_incident
from kaval.investigation.evidence import (
    InvestigationEvidenceResult,
    LogReader,
    collect_incident_evidence,
)
from kaval.investigation.local_model import (
    LocalModelError,
    OpenAICompatibleInvestigationSynthesizer,
    load_local_model_config_from_env,
)
from kaval.investigation.prompts import (
    InvestigationInference,
    InvestigationPromptBundle,
    InvestigationRecommendation,
    InvestigationSynthesis,
    build_investigation_prompt_bundle,
)
from kaval.models import (
    ActionType,
    Change,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalEntry,
    ModelUsed,
    RemediationProposal,
    RemediationStatus,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServiceType,
    SystemProfile,
    UserNote,
)

type DockerSnapshotProvider = Callable[[], DockerDiscoverySnapshot | None]


def default_services_dir() -> Path:
    """Return the shipped service-descriptor directory."""
    return Path(__file__).resolve().parents[3] / "services"


class InvestigationWorkflowState(TypedDict, total=False):
    """Shared state carried through the LangGraph investigation workflow."""

    incident_id: str
    trigger: InvestigationTrigger
    started_at: datetime
    completed_at: datetime
    incident: Incident
    findings: list[Finding]
    services: list[Service]
    changes: list[Change]
    system_profile: SystemProfile | None
    journal_entries: list[JournalEntry]
    user_notes: list[UserNote]
    docker_snapshot: DockerDiscoverySnapshot | None
    evidence: InvestigationEvidenceResult
    prompt_bundle: InvestigationPromptBundle
    synthesis: InvestigationSynthesis
    investigation: Investigation
    updated_incident: Incident
    updated_findings: list[Finding]


class InvestigationSynthesizer(Protocol):
    """The model-facing synthesis step used by the workflow."""

    def synthesize(
        self,
        *,
        incident: Incident,
        evidence: InvestigationEvidenceResult,
        prompt_bundle: InvestigationPromptBundle,
    ) -> InvestigationSynthesis:
        """Return structured synthesis for one incident investigation."""


@dataclass(frozen=True, slots=True)
class InvestigationWorkflowResult:
    """The persisted outcome of one workflow run."""

    incident: Incident
    findings: list[Finding]
    investigation: Investigation
    prompt_bundle: InvestigationPromptBundle
    synthesis: InvestigationSynthesis


@dataclass(frozen=True, slots=True)
class InvestigationWorkflow:
    """Run the Phase 2A investigation graph against persisted state."""

    database: KavalDatabase
    synthesizer: InvestigationSynthesizer | None = None
    descriptors: tuple[LoadedServiceDescriptor, ...] = ()
    log_reader: LogReader | None = None
    docker_snapshot_provider: DockerSnapshotProvider | None = None
    _graph: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Load default descriptors when the caller does not provide them."""
        if not self.descriptors:
            loaded = tuple(load_service_descriptors([default_services_dir()]))
            object.__setattr__(self, "descriptors", loaded)
        object.__setattr__(self, "_graph", _build_graph(self))

    def run(
        self,
        *,
        incident_id: str,
        trigger: InvestigationTrigger = InvestigationTrigger.AUTO,
        now: datetime | None = None,
    ) -> InvestigationWorkflowResult:
        """Execute the compiled LangGraph workflow for one incident."""
        effective_now = now or datetime.now(tz=UTC)
        output = self._graph.invoke(
            {
                "incident_id": incident_id,
                "trigger": trigger,
                "started_at": effective_now,
            }
        )
        return InvestigationWorkflowResult(
            incident=output["updated_incident"],
            findings=output["updated_findings"],
            investigation=output["investigation"],
            prompt_bundle=output["prompt_bundle"],
            synthesis=output["synthesis"],
        )

    def _load_context(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Load the persisted incident context required for the investigation."""
        incident = self.database.get_incident(state["incident_id"])
        if incident is None:
            msg = f"incident not found: {state['incident_id']}"
            raise ValueError(msg)

        docker_snapshot = (
            self.docker_snapshot_provider()
            if self.docker_snapshot_provider is not None
            else None
        )
        return {
            "incident": incident,
            "findings": self.database.list_findings(),
            "services": self.database.list_services(),
            "changes": self.database.list_changes(),
            "system_profile": self.database.get_system_profile(),
            "journal_entries": _list_journal_entries(self.database),
            "user_notes": _list_user_notes(self.database),
            "docker_snapshot": docker_snapshot,
        }

    def _collect_evidence(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Collect read-only evidence for the incident."""
        return {
            "evidence": collect_incident_evidence(
                incident=state["incident"],
                findings=state["findings"],
                services=state["services"],
                changes=state["changes"],
                docker_snapshot=state.get("docker_snapshot"),
                system_profile=state["system_profile"],
                journal_entries=state["journal_entries"],
                user_notes=state["user_notes"],
                descriptors=self.descriptors,
                log_reader=self.log_reader,
                now=state["started_at"],
            )
        }

    def _build_prompt(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Render the prompt bundle from collected evidence."""
        return {
            "prompt_bundle": build_investigation_prompt_bundle(
                incident=state["incident"],
                evidence=state["evidence"],
                now=state["started_at"],
            )
        }

    def _synthesize(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Produce structured inference and recommendation from the prompt bundle."""
        synthesis = self._run_synthesis(state)
        bounded_synthesis = synthesis.model_copy(
            update={
                "recommendation": _bounded_recommendation(
                    recommendation=synthesis.recommendation,
                    incident=state["incident"],
                    services=state["services"],
                )
            }
        )
        return {
            "synthesis": bounded_synthesis,
            "completed_at": state["started_at"],
        }

    def _run_synthesis(self, state: InvestigationWorkflowState) -> InvestigationSynthesis:
        """Run explicit or environment-configured synthesis with deterministic fallback."""
        if self.synthesizer is not None:
            return self.synthesizer.synthesize(
                incident=state["incident"],
                evidence=state["evidence"],
                prompt_bundle=state["prompt_bundle"],
            )

        try:
            local_model_config = load_local_model_config_from_env()
        except ValueError:
            return _fallback_synthesis(
                state=state,
                degraded_reason="Local model config was invalid; deterministic fallback was used.",
            )

        if local_model_config is None:
            return _fallback_synthesis(state=state)

        try:
            return OpenAICompatibleInvestigationSynthesizer(
                config=local_model_config
            ).synthesize(
                incident=state["incident"],
                evidence=state["evidence"],
                prompt_bundle=state["prompt_bundle"],
            )
        except LocalModelError:
            return _fallback_synthesis(
                state=state,
                degraded_reason="Local model request failed; deterministic fallback was used.",
            )

    def _persist(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Persist the investigation plus aligned incident and finding updates."""
        completed_at = state["completed_at"]
        remediation = _build_remediation(state["synthesis"].recommendation)
        investigation = Investigation(
            id=f"inv-{uuid4()}",
            incident_id=state["incident"].id,
            trigger=state["trigger"],
            status=InvestigationStatus.COMPLETED,
            evidence_steps=state["evidence"].evidence_steps,
            research_steps=[],
            root_cause=state["synthesis"].inference.root_cause,
            confidence=state["synthesis"].inference.confidence,
            model_used=state["synthesis"].model_used,
            cloud_model_calls=state["synthesis"].cloud_model_calls,
            journal_entries_referenced=[
                entry.id for entry in state["evidence"].operational_memory.journal_entries
            ],
            user_notes_referenced=[
                note.id for note in state["evidence"].operational_memory.user_notes
            ],
            recurrence_count=state["evidence"].operational_memory.recurrence_count,
            remediation=remediation,
            started_at=state["started_at"],
            completed_at=completed_at,
        )

        updated_incident = _updated_incident(
            incident=state["incident"],
            investigation=investigation,
            completed_at=completed_at,
            remediation=remediation,
        )
        updated_findings = _updated_findings_for_investigation(
            findings=state["findings"],
            incident_id=state["incident"].id,
        )

        self.database.upsert_investigation(investigation)
        self.database.upsert_incident(updated_incident)
        for finding in updated_findings:
            self.database.upsert_finding(finding)

        return {
            "investigation": investigation,
            "updated_incident": updated_incident,
            "updated_findings": updated_findings,
        }


class HeuristicInvestigationSynthesizer:
    """A deterministic fallback synthesizer used before model integration."""

    def synthesize(
        self,
        *,
        incident: Incident,
        evidence: InvestigationEvidenceResult,
        prompt_bundle: InvestigationPromptBundle,
    ) -> InvestigationSynthesis:
        """Build a bounded structured investigation without calling a model."""
        del prompt_bundle
        evidence_summary = [
            step.result_summary for step in evidence.evidence_steps[:3]
        ] or [f"Incident {incident.id} has no collected evidence steps."]
        root_cause = incident.suspected_cause or incident.triggering_symptom or incident.title
        confidence = max(incident.confidence, 0.7)
        return InvestigationSynthesis(
            evidence_summary=evidence_summary,
            inference=InvestigationInference(
                root_cause=root_cause,
                confidence=confidence,
                reasoning=(
                    "Bounded deterministic synthesis derived from collected Tier 1 evidence. "
                    "Model-backed synthesis is not configured yet."
                ),
            ),
            recommendation=_heuristic_recommendation(incident=incident),
            degraded_mode_note=(
                "Model-backed synthesis is unavailable; a deterministic local fallback was used."
            ),
            model_used=ModelUsed.NONE,
            cloud_model_calls=0,
        )


def _heuristic_recommendation(*, incident: Incident) -> InvestigationRecommendation:
    """Build a restart-only heuristic recommendation when the root cause is container-backed."""
    target = (
        incident.root_cause_service.removeprefix("svc-")
        if incident.root_cause_service is not None
        else None
    )
    if target is None:
        return InvestigationRecommendation(
            summary="No restart recommendation is justified from the current evidence.",
            action_type="none",
            target=None,
            rationale="No container-scoped root cause service was identified.",
            risk=RiskAssessment(
                overall_risk=RiskLevel.MEDIUM,
                checks=[
                    RiskCheck(
                        check="restart_scope_available",
                        result=RiskCheckResult.FAIL,
                        detail="No root-cause container target was available.",
                    )
                ],
                reversible=True,
                warnings=["Investigation should continue with additional evidence."],
            ),
        )

    return InvestigationRecommendation(
        summary=f"Restart {target} to verify whether the incident clears.",
        action_type="restart_container",
        target=target,
        rationale=(
            "The incident has a container-scoped suspected root cause and Phase 2A "
            "allows restart_container as the only remediation path."
        ),
        risk=RiskAssessment(
            overall_risk=RiskLevel.LOW,
            checks=[
                RiskCheck(
                    check="bounded_action_scope",
                    result=RiskCheckResult.PASS,
                    detail="Phase 2A remediation is limited to one container restart.",
                ),
                RiskCheck(
                    check="reversible",
                    result=RiskCheckResult.PASS,
                    detail="A container restart is reversible and does not mutate configuration.",
                ),
            ],
            reversible=True,
            warnings=["Restart may briefly interrupt service availability."],
        ),
    )


def _fallback_synthesis(
    *,
    state: InvestigationWorkflowState,
    degraded_reason: str | None = None,
) -> InvestigationSynthesis:
    """Produce deterministic synthesis and optionally append degraded-mode context."""
    fallback = HeuristicInvestigationSynthesizer().synthesize(
        incident=state["incident"],
        evidence=state["evidence"],
        prompt_bundle=state["prompt_bundle"],
    )
    if degraded_reason is None:
        return fallback
    return fallback.model_copy(
        update={
            "degraded_mode_note": _combine_degraded_notes(
                fallback.degraded_mode_note,
                degraded_reason,
            )
        }
    )


def _build_graph(workflow: InvestigationWorkflow) -> Any:
    """Compile the LangGraph investigation workflow."""
    graph = StateGraph(InvestigationWorkflowState)
    graph.add_node("load_context", workflow._load_context)
    graph.add_node("collect_evidence", workflow._collect_evidence)
    graph.add_node("build_prompt", workflow._build_prompt)
    graph.add_node("synthesize", workflow._synthesize)
    graph.add_node("persist", workflow._persist)
    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "collect_evidence")
    graph.add_edge("collect_evidence", "build_prompt")
    graph.add_edge("build_prompt", "synthesize")
    graph.add_edge("synthesize", "persist")
    graph.add_edge("persist", END)
    return graph.compile(name="phase2a_investigation")


def _build_remediation(
    recommendation: InvestigationRecommendation,
) -> RemediationProposal | None:
    """Convert a structured recommendation into the frozen remediation contract."""
    if recommendation.action_type != "restart_container" or recommendation.target is None:
        return None
    return RemediationProposal(
        action_type=ActionType.RESTART_CONTAINER,
        target=recommendation.target,
        rationale=recommendation.rationale,
        risk_assessment=recommendation.risk,
        status=RemediationStatus.PROPOSED,
    )


def _bounded_recommendation(
    *,
    recommendation: InvestigationRecommendation,
    incident: Incident,
    services: list[Service],
) -> InvestigationRecommendation:
    """Keep restart recommendations inside the incident's affected container scope."""
    if recommendation.action_type != "restart_container" or recommendation.target is None:
        return recommendation

    allowed_targets: dict[str, str] = {}
    for service in services:
        if service.id not in incident.affected_services or service.type != ServiceType.CONTAINER:
            continue
        canonical_target = service.id.removeprefix("svc-")
        for alias in _service_target_aliases(service):
            allowed_targets[alias.casefold()] = canonical_target

    normalized_target = allowed_targets.get(recommendation.target.casefold())
    if normalized_target is None:
        return InvestigationRecommendation(
            summary="No restart recommendation is justified from the current evidence.",
            action_type="none",
            target=None,
            rationale=(
                "The proposed restart target was outside the incident's affected container "
                "scope and was discarded."
            ),
            risk=RiskAssessment(
                overall_risk=RiskLevel.MEDIUM,
                checks=[
                    RiskCheck(
                        check="bounded_action_scope",
                        result=RiskCheckResult.FAIL,
                        detail="The proposed target did not match an affected container service.",
                    )
                ],
                reversible=True,
                warnings=["Discarded an out-of-scope remediation target."],
            ),
        )

    return recommendation.model_copy(update={"target": normalized_target})


def _service_target_aliases(service: Service) -> set[str]:
    """Return acceptable human/model aliases for one container target."""
    normalized_name = service.name.casefold()
    return {
        service.id,
        service.id.removeprefix("svc-"),
        service.name,
        normalized_name,
        normalized_name.replace(" ", "-"),
        normalized_name.replace(" ", ""),
    }


def _combine_degraded_notes(existing_note: str | None, extra_note: str) -> str:
    """Combine degraded-mode notes without dropping earlier context."""
    if existing_note is None:
        return extra_note
    return f"{existing_note} {extra_note}"


def _updated_incident(
    *,
    incident: Incident,
    investigation: Investigation,
    completed_at: datetime,
    remediation: RemediationProposal | None,
) -> Incident:
    """Return the incident aligned to the persisted investigation result."""
    working_incident = incident
    if working_incident.status == IncidentStatus.OPEN:
        working_incident = transition_incident(
            working_incident,
            IncidentStatus.INVESTIGATING,
            changed_at=completed_at,
        )

    if remediation is not None and can_transition_incident_status(
        working_incident.status,
        IncidentStatus.AWAITING_APPROVAL,
    ):
        working_incident = transition_incident(
            working_incident,
            IncidentStatus.AWAITING_APPROVAL,
            changed_at=completed_at,
        )

    return working_incident.model_copy(
        update={
            "suspected_cause": investigation.root_cause,
            "confidence": investigation.confidence,
            "investigation_id": investigation.id,
            "updated_at": completed_at,
        }
    )


def _updated_findings_for_investigation(
    *,
    findings: list[Finding],
    incident_id: str,
) -> list[Finding]:
    """Mark the incident's active findings as under investigation."""
    updated: list[Finding] = []
    for finding in findings:
        if finding.incident_id != incident_id:
            continue
        if finding.status in {
            FindingStatus.RESOLVED,
            FindingStatus.DISMISSED,
            FindingStatus.STALE,
        }:
            updated.append(finding)
            continue
        updated.append(finding.model_copy(update={"status": FindingStatus.INVESTIGATING}))
    return updated


def _list_journal_entries(database: KavalDatabase) -> list[JournalEntry]:
    """Load journal entries directly from persistence for workflow context."""
    rows = database.connection().execute(
        "SELECT payload FROM journal_entries ORDER BY entry_date, id"
    ).fetchall()
    return [JournalEntry.model_validate_json(str(row["payload"])) for row in rows]


def _list_user_notes(database: KavalDatabase) -> list[UserNote]:
    """Load user notes directly from persistence for workflow context."""
    rows = database.connection().execute(
        "SELECT payload FROM user_notes ORDER BY updated_at, id"
    ).fetchall()
    return [UserNote.model_validate_json(str(row["payload"])) for row in rows]
