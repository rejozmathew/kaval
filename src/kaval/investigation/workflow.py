"""LangGraph-backed Tier 1 investigation workflow."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TypedDict, cast
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from kaval.credentials.vault import (
    AdapterCredentialResolution,
    AdapterCredentialState,
    CredentialMaterialService,
)
from kaval.database import KavalDatabase
from kaval.discovery.descriptors import (
    DescriptorInspectionConfidenceEffect,
    LoadedServiceDescriptor,
    load_service_descriptors,
    loaded_descriptor_identifier,
)
from kaval.discovery.docker import DockerDiscoverySnapshot
from kaval.grouping import can_transition_incident_status, transition_incident
from kaval.integrations import (
    AdapterDiscoveredEdge,
    AdapterRegistry,
    AuthentikAdapter,
    CloudflareAdapter,
    NginxProxyManagerAdapter,
    PiHoleAdapter,
    RadarrAdapter,
    ServiceAdapter,
    execute_service_adapter,
)
from kaval.integrations.adapter_facts import (
    PromptSafeAdapterFact,
    redact_adapter_result_for_prompt,
)
from kaval.integrations.service_adapters import AdapterStatus
from kaval.investigation.cloud_model import (
    CloudInvestigationSynthesizer,
    CloudModelError,
    CloudPromptRedactionError,
    CloudTransport,
    build_cloud_safe_prompt_bundle,
    evaluate_cloud_escalation_policy,
    load_cloud_escalation_policy_from_env,
    load_cloud_model_config_from_env,
)
from kaval.investigation.evidence import (
    AdapterEvidenceCollection,
    InvestigationEvidenceResult,
    LogReader,
    collect_incident_evidence,
    merge_adapter_evidence,
)
from kaval.investigation.local_model import (
    LocalModelError,
    OpenAICompatibleInvestigationSynthesizer,
    load_local_model_config_from_env,
)
from kaval.investigation.local_model import (
    RequestTransport as LocalModelTransport,
)
from kaval.investigation.prompts import (
    InvestigationInference,
    InvestigationPromptBundle,
    InvestigationRecommendation,
    InvestigationSynthesis,
    build_investigation_prompt_bundle,
)
from kaval.investigation.research import (
    DockerHubResearchClient,
    GitHubResearchClient,
    PublicResearchHints,
    Tier2ResearchBundle,
    build_tier2_research_targets,
    run_tier2_research,
)
from kaval.investigation.risk_assessment import apply_deterministic_risk_assessment
from kaval.models import (
    ActionType,
    Change,
    DependencyConfidence,
    EvidenceStep,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalEntry,
    JsonValue,
    ModelUsed,
    RedactionLevel,
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


def _build_default_adapter_registry() -> AdapterRegistry:
    """Build the default registry for the Phase 3A shipped deep adapters."""
    return AdapterRegistry(
        cast(
            tuple[ServiceAdapter, ...],
            (
            NginxProxyManagerAdapter(),
            RadarrAdapter(),
            AuthentikAdapter(),
            CloudflareAdapter(),
            PiHoleAdapter(),
            ),
        )
    )


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
    adapter_edge_observations: list[_AdapterEdgeObservation]
    research: Tier2ResearchBundle
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
class _AdapterEdgeObservation:
    """Internal adapter-discovered edge observations from one evidence run."""

    source_service_id: str
    adapter_id: str
    observed_at: datetime
    edges: tuple[AdapterDiscoveredEdge, ...]


@dataclass(frozen=True, slots=True)
class _CollectedAdapterEvidence:
    """Internal adapter evidence bundle plus edge observations for graph updates."""

    evidence: AdapterEvidenceCollection
    edge_observations: list[_AdapterEdgeObservation] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class InvestigationWorkflow:
    """Run the Phase 2A investigation graph against persisted state."""

    database: KavalDatabase
    synthesizer: InvestigationSynthesizer | None = None
    descriptors: tuple[LoadedServiceDescriptor, ...] = ()
    log_reader: LogReader | None = None
    docker_snapshot_provider: DockerSnapshotProvider | None = None
    credential_material_service: CredentialMaterialService | None = None
    adapter_registry: AdapterRegistry = field(default_factory=_build_default_adapter_registry)
    research_hints_by_service: Mapping[str, PublicResearchHints] = field(default_factory=dict)
    github_research_client: GitHubResearchClient | None = None
    dockerhub_research_client: DockerHubResearchClient | None = None
    local_model_transport: LocalModelTransport | None = None
    cloud_model_transport: CloudTransport | None = None
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
        base_evidence = collect_incident_evidence(
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
        collected_adapter_evidence = self._collect_adapter_evidence(
            state=state,
            base_step_count=len(base_evidence.evidence_steps),
        )
        return {
            "evidence": merge_adapter_evidence(
                base_evidence,
                adapter_evidence=collected_adapter_evidence.evidence,
            ),
            "adapter_edge_observations": collected_adapter_evidence.edge_observations,
        }

    def _build_prompt(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Render the prompt bundle from collected evidence."""
        return {
            "prompt_bundle": build_investigation_prompt_bundle(
                incident=state["incident"],
                evidence=state["evidence"],
                research=state["research"],
                degraded_reasons=state["research"].degraded_reasons,
                now=state["started_at"],
            )
        }

    def _collect_research(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Collect Tier 2 public research for correlated image-version changes."""
        targets = build_tier2_research_targets(
            incident=state["incident"],
            services=state["services"],
            changes=state["changes"],
            hints_by_service=self._public_research_hints(state["services"]),
        )
        return {
            "research": run_tier2_research(
                targets=targets,
                github_client=self.github_research_client,
                dockerhub_client=self.dockerhub_research_client,
                now=state["started_at"],
            )
        }

    def _synthesize(self, state: InvestigationWorkflowState) -> InvestigationWorkflowState:
        """Produce structured inference and recommendation from the prompt bundle."""
        synthesis = self._run_synthesis(state)
        degraded_note = synthesis.degraded_mode_note
        for reason in state["research"].degraded_reasons:
            degraded_note = _combine_degraded_notes(degraded_note, reason)
        bounded_recommendation = _bounded_recommendation(
            recommendation=synthesis.recommendation,
            incident=state["incident"],
            services=state["services"],
        )
        deterministic_recommendation = apply_deterministic_risk_assessment(
            recommendation=bounded_recommendation,
            incident=state["incident"],
            services=state["services"],
            changes=state["changes"],
            research=state["research"],
        )
        bounded_synthesis = synthesis.model_copy(
            update={
                "degraded_mode_note": degraded_note,
                "recommendation": deterministic_recommendation,
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
            local_synthesis = OpenAICompatibleInvestigationSynthesizer(
                config=local_model_config,
                transport=self.local_model_transport,
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
        return self._maybe_escalate_cloud(state=state, local_synthesis=local_synthesis)

    def _maybe_escalate_cloud(
        self,
        *,
        state: InvestigationWorkflowState,
        local_synthesis: InvestigationSynthesis,
    ) -> InvestigationSynthesis:
        """Optionally escalate a successful local synthesis to the configured cloud model."""
        try:
            policy = load_cloud_escalation_policy_from_env()
        except ValueError:
            return _with_degraded_reason(
                local_synthesis,
                "Cloud escalation policy config was invalid; local synthesis retained.",
            )

        decision = evaluate_cloud_escalation_policy(
            incident=state["incident"],
            findings=state["findings"],
            investigations=self.database.list_investigations(),
            local_synthesis=local_synthesis,
            changelog_research_available=bool(state["research"].research_steps),
            trigger=state["trigger"],
            now=state["started_at"],
            policy=policy,
            offline=state["research"].skipped_offline,
        )
        if decision.blocked_reason is not None:
            return _with_degraded_reason(local_synthesis, decision.blocked_reason)
        if not decision.should_use_cloud:
            return local_synthesis

        try:
            cloud_model_config = load_cloud_model_config_from_env()
        except ValueError:
            return _with_degraded_reason(
                local_synthesis,
                _cloud_retained_reason(
                    decision.trigger_reasons,
                    "Cloud model config was invalid; local synthesis retained.",
                ),
            )
        if cloud_model_config is None:
            return _with_degraded_reason(
                local_synthesis,
                _cloud_retained_reason(
                    decision.trigger_reasons,
                    "Cloud model was not configured; local synthesis retained.",
                ),
            )

        try:
            cloud_prompt_bundle = build_cloud_safe_prompt_bundle(
                prompt_bundle=state["prompt_bundle"],
                incident=state["incident"],
                services=state["services"],
            )
        except CloudPromptRedactionError:
            return _with_degraded_reason(
                local_synthesis,
                _cloud_retained_reason(
                    decision.trigger_reasons,
                    "Cloud-safe redaction failed; local synthesis retained.",
                ),
            )

        try:
            cloud_synthesis = CloudInvestigationSynthesizer(
                config=cloud_model_config,
                transport=self.cloud_model_transport,
            ).synthesize(prompt_bundle=cloud_prompt_bundle)
        except CloudModelError:
            return _with_degraded_reason(
                local_synthesis,
                _cloud_retained_reason(
                    decision.trigger_reasons,
                    "Cloud model request failed; local synthesis retained.",
                ),
            )

        return cloud_synthesis.model_copy(
            update={
                "model_used": ModelUsed.BOTH,
                "cloud_model_calls": (
                    local_synthesis.cloud_model_calls
                    + cloud_synthesis.cloud_model_calls
                ),
                "degraded_mode_note": (
                    _combine_degraded_notes(
                        local_synthesis.degraded_mode_note,
                        cloud_synthesis.degraded_mode_note,
                    )
                    if cloud_synthesis.degraded_mode_note is not None
                    else local_synthesis.degraded_mode_note
                ),
            }
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
            research_steps=state["research"].research_steps,
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
        updated_services = _apply_runtime_observed_upgrades(
            services=state["services"],
            descriptors=self.descriptors,
            observations=state.get("adapter_edge_observations", []),
        )

        self.database.upsert_investigation(investigation)
        self.database.upsert_incident(updated_incident)
        for finding in updated_findings:
            self.database.upsert_finding(finding)
        for service in updated_services:
            self.database.upsert_service(service)

        return {
            "investigation": investigation,
            "updated_incident": updated_incident,
            "updated_findings": updated_findings,
        }

    def _public_research_hints(
        self,
        services: list[Service],
    ) -> dict[str, PublicResearchHints]:
        """Build per-service public research hints from descriptors and overrides."""
        hints: dict[str, PublicResearchHints] = {
            service_id: hint.model_copy(deep=True)
            for service_id, hint in self.research_hints_by_service.items()
        }
        descriptors_by_service_id = {
            loaded_descriptor_identifier(descriptor): descriptor
            for descriptor in self.descriptors
        }

        for service in services:
            descriptor = (
                descriptors_by_service_id.get(service.descriptor_id)
                if service.descriptor_id is not None
                else None
            )
            existing_hint = hints.get(service.id, PublicResearchHints())
            github_repository = existing_hint.github_repository
            dockerhub_reference = existing_hint.dockerhub_reference
            if (
                github_repository is None
                and descriptor is not None
                and descriptor.descriptor.project_url is not None
                and descriptor.descriptor.project_url.startswith("https://github.com/")
            ):
                github_repository = descriptor.descriptor.project_url
            if dockerhub_reference is None and service.image is not None:
                dockerhub_reference = service.image
            if github_repository is None and dockerhub_reference is None:
                continue
            hints[service.id] = PublicResearchHints(
                github_repository=github_repository,
                dockerhub_reference=dockerhub_reference,
            )
        return hints

    def _collect_adapter_evidence(
        self,
        *,
        state: InvestigationWorkflowState,
        base_step_count: int,
    ) -> _CollectedAdapterEvidence:
        """Collect prompt-safe adapter facts for relevant services when possible."""
        if self.credential_material_service is None:
            return _CollectedAdapterEvidence(evidence=AdapterEvidenceCollection())

        relevant_services = _workflow_relevant_services(
            incident=state["incident"],
            findings=state["findings"],
            services=state["services"],
        )
        evidence_steps: list[EvidenceStep] = []
        adapter_facts: list[PromptSafeAdapterFact] = []
        edge_observations: list[_AdapterEdgeObservation] = []
        next_order = base_step_count + 1

        for service in relevant_services:
            for adapter in _bound_adapters_for_service(
                service=service,
                descriptors=self.descriptors,
                adapter_registry=self.adapter_registry,
            ):
                resolution = self.credential_material_service.resolve_adapter_credentials(
                    service_id=service.id,
                    credential_keys=adapter.credential_keys,
                    now=state["started_at"],
                )
                if resolution.state is not AdapterCredentialState.AVAILABLE:
                    evidence_steps.append(
                        _adapter_skip_step(
                            order=next_order,
                            service=service,
                            adapter=adapter,
                            resolution=resolution,
                            timestamp=state["started_at"],
                        )
                    )
                    next_order += 1
                    continue

                adapter_result = asyncio.run(
                    execute_service_adapter(
                        adapter,
                        service=service,
                        credentials=resolution.credentials,
                        now=state["started_at"],
                    )
                )
                prompt_safe_fact = redact_adapter_result_for_prompt(
                    adapter_result,
                    redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
                )
                evidence_steps.append(
                    _adapter_result_step(
                        order=next_order,
                        service=service,
                        adapter=adapter,
                        resolution=resolution,
                        prompt_safe_fact=prompt_safe_fact,
                        timestamp=state["started_at"],
                    )
                )
                next_order += 1
                if adapter_result.status is AdapterStatus.SUCCESS and prompt_safe_fact.facts:
                    adapter_facts.append(prompt_safe_fact)
                if adapter_result.edges_discovered:
                    edge_observations.append(
                        _AdapterEdgeObservation(
                            source_service_id=service.id,
                            adapter_id=adapter.adapter_id,
                            observed_at=adapter_result.timestamp,
                            edges=tuple(adapter_result.edges_discovered),
                        )
                    )

        return _CollectedAdapterEvidence(
            evidence=AdapterEvidenceCollection(
                evidence_steps=evidence_steps,
                adapter_facts=adapter_facts,
            ),
            edge_observations=edge_observations,
        )


def _workflow_relevant_services(
    *,
    incident: Incident,
    findings: list[Finding],
    services: list[Service],
) -> list[Service]:
    """Return services worth attempting deep inspection for this investigation."""
    services_by_id = {service.id: service for service in services}
    relevant_service_ids: list[str] = []
    if (
        incident.root_cause_service is not None
        and incident.root_cause_service in services_by_id
    ):
        relevant_service_ids.append(incident.root_cause_service)
    for service_id in incident.affected_services:
        if service_id in services_by_id and service_id not in relevant_service_ids:
            relevant_service_ids.append(service_id)
    for finding in findings:
        if finding.service_id in services_by_id and finding.service_id not in relevant_service_ids:
            relevant_service_ids.append(finding.service_id)
    for service_id in _workflow_related_context_service_ids(
        relevant_service_ids=relevant_service_ids,
        services_by_id=services_by_id,
        descriptor_ids=("networking/cloudflared", "identity/authentik"),
    ):
        if service_id not in relevant_service_ids:
            relevant_service_ids.append(service_id)
    return [services_by_id[service_id] for service_id in relevant_service_ids]


def _workflow_related_context_service_ids(
    *,
    relevant_service_ids: list[str],
    services_by_id: Mapping[str, Service],
    descriptor_ids: tuple[str, ...],
) -> list[str]:
    """Return directly connected context services worth inspecting for this incident."""
    context_service_ids = {
        service.id
        for service in services_by_id.values()
        if service.descriptor_id in descriptor_ids
    }
    if not context_service_ids:
        return []

    related_service_ids: list[str] = []
    for service_id in relevant_service_ids:
        for neighbor_id in _workflow_neighbor_service_ids(
            service_id=service_id,
            services_by_id=services_by_id,
        ):
            if (
                neighbor_id in context_service_ids
                and neighbor_id not in relevant_service_ids
                and neighbor_id not in related_service_ids
            ):
                related_service_ids.append(neighbor_id)
    return related_service_ids


def _workflow_neighbor_service_ids(
    *,
    service_id: str,
    services_by_id: Mapping[str, Service],
) -> list[str]:
    """Return direct graph neighbors for one service from dependencies or dependents."""
    service = services_by_id.get(service_id)
    if service is None:
        return []

    neighbor_ids = {
        edge.target_service_id
        for edge in service.dependencies
        if edge.target_service_id in services_by_id
    }
    neighbor_ids.update(
        dependent_id
        for dependent_id in service.dependents
        if dependent_id in services_by_id
    )
    for candidate_service in services_by_id.values():
        if candidate_service.id == service_id:
            continue
        if any(edge.target_service_id == service_id for edge in candidate_service.dependencies):
            neighbor_ids.add(candidate_service.id)
        if service_id in candidate_service.dependents:
            neighbor_ids.add(candidate_service.id)
    return sorted(neighbor_ids)


def _bound_adapters_for_service(
    *,
    service: Service,
    descriptors: tuple[LoadedServiceDescriptor, ...],
    adapter_registry: AdapterRegistry,
) -> list[ServiceAdapter]:
    """Resolve unique bound adapters for one descriptor-backed service."""
    if service.descriptor_id is None:
        return []
    descriptor = next(
        (
            item
            for item in descriptors
            if loaded_descriptor_identifier(item) == service.descriptor_id
        ),
        None,
    )
    if descriptor is None:
        return []

    adapters: list[ServiceAdapter] = []
    seen_adapter_ids: set[str] = set()
    for surface in descriptor.descriptor.inspection.surfaces:
        adapter = adapter_registry.get(
            descriptor_id=service.descriptor_id,
            surface_id=surface.id,
        )
        if adapter is None or adapter.adapter_id in seen_adapter_ids:
            continue
        seen_adapter_ids.add(adapter.adapter_id)
        adapters.append(adapter)
    return adapters


def _adapter_skip_step(
    *,
    order: int,
    service: Service,
    adapter: ServiceAdapter,
    resolution: AdapterCredentialResolution,
    timestamp: datetime,
) -> EvidenceStep:
    """Build one evidence step for a skipped adapter invocation."""
    state_label = (
        "vault is locked"
        if resolution.state is AdapterCredentialState.LOCKED
        else "credentials are not configured"
    )
    return EvidenceStep(
        order=order,
        action="inspect_service_adapter",
        target=service.id,
        result_summary=(
            f"Deep inspection via {adapter.adapter_id} skipped because {state_label}."
        ),
        result_data={
            "service_id": service.id,
            "adapter_id": adapter.adapter_id,
            "credential_state": resolution.state.value,
            "missing_credentials": cast(JsonValue, list(resolution.missing_keys)),
            "status": "skipped",
            "reason": resolution.detail,
        },
        timestamp=timestamp,
    )


def _adapter_result_step(
    *,
    order: int,
    service: Service,
    adapter: ServiceAdapter,
    resolution: AdapterCredentialResolution,
    prompt_safe_fact: PromptSafeAdapterFact,
    timestamp: datetime,
) -> EvidenceStep:
    """Build one evidence step from an executed adapter result."""
    facts_available = bool(prompt_safe_fact.facts)
    if prompt_safe_fact.status is AdapterStatus.SUCCESS:
        summary = (
            f"Deep inspection via {adapter.adapter_id} returned "
            f"{len(prompt_safe_fact.facts)} fact group(s) for {service.name}."
        )
    else:
        summary = (
            f"Deep inspection via {adapter.adapter_id} completed with status "
            f"{prompt_safe_fact.status.value}."
        )
    return EvidenceStep(
        order=order,
        action="inspect_service_adapter",
        target=service.id,
        result_summary=summary,
        result_data={
            "service_id": service.id,
            "adapter_id": adapter.adapter_id,
            "credential_state": resolution.state.value,
            "status": prompt_safe_fact.status.value,
            "facts_available": facts_available,
            "fact_keys": cast(JsonValue, sorted(prompt_safe_fact.facts.keys())),
            "excluded_paths": cast(JsonValue, list(prompt_safe_fact.excluded_paths)),
            "reason": prompt_safe_fact.reason,
        },
        timestamp=timestamp,
    )


def _apply_runtime_observed_upgrades(
    *,
    services: list[Service],
    descriptors: tuple[LoadedServiceDescriptor, ...],
    observations: list[_AdapterEdgeObservation],
) -> list[Service]:
    """Upgrade existing dependency edges when adapters confirm them at runtime."""
    if not observations:
        return services

    services_by_id = {service.id: service for service in services}
    alias_index = _unique_service_alias_index(services)
    confidence_effects = _descriptor_confidence_effects(descriptors)
    updated_services: list[Service] = []

    for service in services:
        observed = [
            item
            for item in observations
            if item.source_service_id == service.id
        ]
        if not observed:
            updated_services.append(service)
            continue

        edges_by_target = {
            edge.target_service_id: edge
            for edge in service.dependencies
        }
        changed = False
        allowed_surfaces = (
            confidence_effects.get(service.descriptor_id, {})
            if service.descriptor_id is not None
            else {}
        )
        for observation in observed:
            for discovered_edge in observation.edges:
                if allowed_surfaces.get(discovered_edge.surface_id) is not True:
                    continue
                target_service_id = alias_index.get(
                    discovered_edge.target_service_name.casefold()
                )
                if target_service_id is None or target_service_id == service.id:
                    continue
                current_edge = edges_by_target.get(target_service_id)
                if current_edge is None or current_edge.confidence not in {
                    DependencyConfidence.CONFIGURED,
                    DependencyConfidence.INFERRED,
                }:
                    continue
                target_service = services_by_id.get(target_service_id)
                if target_service is None:
                    continue
                edges_by_target[target_service_id] = current_edge.model_copy(
                    update={
                        "confidence": DependencyConfidence.RUNTIME_OBSERVED,
                        "description": _runtime_observed_edge_description(
                            current_description=current_edge.description,
                            adapter_id=observation.adapter_id,
                            target_service=target_service,
                        ),
                    }
                )
                changed = True

        if not changed:
            updated_services.append(service)
            continue
        updated_services.append(
            service.model_copy(
                update={
                    "dependencies": sorted(
                        edges_by_target.values(),
                        key=lambda edge: edge.target_service_id,
                    )
                }
            )
        )

    return updated_services


def _descriptor_confidence_effects(
    descriptors: tuple[LoadedServiceDescriptor, ...],
) -> dict[str, dict[str, bool]]:
    """Return which descriptor surfaces are allowed to confirm runtime edges."""
    effects: dict[str, dict[str, bool]] = {}
    for descriptor in descriptors:
        descriptor_key = loaded_descriptor_identifier(descriptor)
        effects[descriptor_key] = {
            surface.id: (
                surface.confidence_effect
                is DescriptorInspectionConfidenceEffect.UPGRADE_TO_RUNTIME_OBSERVED
            )
            for surface in descriptor.descriptor.inspection.surfaces
        }
    return effects


def _unique_service_alias_index(services: list[Service]) -> dict[str, str]:
    """Build a deterministic alias index for exact, unique service matches only."""
    alias_counts: dict[str, int] = {}
    alias_to_service_id: dict[str, str] = {}
    for service in services:
        for alias in _service_aliases(service):
            alias_counts[alias] = alias_counts.get(alias, 0) + 1
            alias_to_service_id.setdefault(alias, service.id)
    return {
        alias: service_id
        for alias, service_id in alias_to_service_id.items()
        if alias_counts.get(alias) == 1
    }


def _service_aliases(service: Service) -> set[str]:
    """Return exact aliases that are safe to use for adapter-edge matching."""
    aliases = {service.name.casefold(), service.id.removeprefix("svc-").casefold()}
    if service.descriptor_id is not None:
        aliases.add(service.descriptor_id.split("/")[-1].casefold())
    return {alias for alias in aliases if alias}


def _runtime_observed_edge_description(
    *,
    current_description: str | None,
    adapter_id: str,
    target_service: Service,
) -> str:
    """Append a stable runtime-observed confirmation note to one edge description."""
    confirmation = (
        f"Adapter {adapter_id} confirmed the relationship to {target_service.name} "
        "at runtime."
    )
    if current_description is None or current_description == "":
        return confirmation
    if confirmation in current_description:
        return current_description
    return f"{current_description} {confirmation}"


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
    graph.add_node("collect_research", workflow._collect_research)
    graph.add_node("build_prompt", workflow._build_prompt)
    graph.add_node("synthesize", workflow._synthesize)
    graph.add_node("persist", workflow._persist)
    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "collect_evidence")
    graph.add_edge("collect_evidence", "collect_research")
    graph.add_edge("collect_research", "build_prompt")
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


def _with_degraded_reason(
    synthesis: InvestigationSynthesis,
    degraded_reason: str,
) -> InvestigationSynthesis:
    """Append one degraded-mode reason to an existing synthesis payload."""
    return synthesis.model_copy(
        update={
            "degraded_mode_note": _combine_degraded_notes(
                synthesis.degraded_mode_note,
                degraded_reason,
            )
        }
    )


def _cloud_retained_reason(trigger_reasons: tuple[str, ...], detail: str) -> str:
    """Render one explicit note about why cloud escalation fell back to local output."""
    joined_reasons = ", ".join(trigger_reasons)
    return (
        "Cloud escalation criteria matched "
        f"({joined_reasons}), but {detail}"
    )


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
