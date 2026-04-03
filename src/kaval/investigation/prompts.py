"""Prompt templates for Phase 2A incident investigations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from textwrap import dedent
from typing import Literal, Sequence, cast

from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.research import Tier2ResearchBundle
from kaval.models import (
    Incident,
    JsonValue,
    KavalModel,
    ModelUsed,
    NonNegativeInt,
    RiskAssessment,
)

type JsonObject = dict[str, JsonValue]

_RESEARCH_ONLY_DEGRADED_NOTE = (
    "Use Tier 2 research when it is provided. "
    "If research was skipped or incomplete, reflect the lower confidence explicitly."
)

INVESTIGATION_SYSTEM_PROMPT = dedent(
    """
    You are Kaval's Phase 2B investigation analyst for Unraid and homelab incidents.

    Work from the provided incident context only. Treat evidence as facts, inference as
    conclusions drawn from those facts, and recommendation as a bounded proposal with
    explicit risk framing.

    Hard rules:
    - Do not invent missing evidence, external research, or credential-derived facts.
    - Use provided Tier 2 research only when it is present.
    - If research was skipped, missing, or offline, say so explicitly instead of pretending
      the investigation was complete.
    - Do not recommend rollback, VM actions, config mutation, credential requests, or
      any system-changing action other than `restart_container`.
    - If the evidence does not justify a restart, return `action_type="none"`.
    - Keep the reasoning transparent and tied to the provided evidence trail.
    - Respect degraded-mode notes and any Operational Memory warnings.

    Return structured output that preserves three layers:
    1. evidence_summary: the strongest facts that drove the conclusion
    2. inference: the likely root cause plus confidence
    3. recommendation: restart-only or no-action, with explicit risk details
    """
).strip()

INVESTIGATION_RESPONSE_SCHEMA: JsonObject = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "evidence_summary",
        "inference",
        "recommendation",
        "degraded_mode_note",
    ],
    "properties": {
        "evidence_summary": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "inference": {
            "type": "object",
            "additionalProperties": False,
            "required": ["root_cause", "confidence", "reasoning"],
            "properties": {
                "root_cause": {"type": "string"},
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
                "reasoning": {"type": "string"},
            },
        },
        "recommendation": {
            "type": "object",
            "additionalProperties": False,
            "required": ["summary", "action_type", "target", "rationale", "risk"],
            "properties": {
                "summary": {"type": "string"},
                "action_type": {
                    "type": "string",
                    "enum": ["restart_container", "none"],
                },
                "target": {
                    "type": ["string", "null"],
                },
                "rationale": {"type": "string"},
                "risk": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["overall_risk", "checks", "reversible", "warnings"],
                    "properties": {
                        "overall_risk": {
                            "type": "string",
                            "enum": ["low", "medium", "high"],
                        },
                        "checks": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["check", "result", "detail"],
                                "properties": {
                                    "check": {"type": "string"},
                                    "result": {
                                        "type": "string",
                                        "enum": ["pass", "fail", "unknown"],
                                    },
                                    "detail": {"type": "string"},
                                },
                            },
                        },
                        "reversible": {"type": "boolean"},
                        "warnings": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
            },
        },
        "degraded_mode_note": {
            "type": ["string", "null"],
        },
    },
}


@dataclass(frozen=True, slots=True)
class InvestigationPromptBundle:
    """The rendered prompt payload consumed by the later model-integration layer."""

    system_prompt: str
    user_prompt: str
    response_schema_name: str
    response_schema: JsonObject


class InvestigationInference(KavalModel):
    """Structured inference returned from the synthesis layer."""

    root_cause: str
    confidence: float
    reasoning: str


class InvestigationRecommendation(KavalModel):
    """Restart-only recommendation output for Phase 2A synthesis."""

    summary: str
    action_type: Literal["restart_container", "none"]
    target: str | None
    rationale: str
    risk: RiskAssessment


class InvestigationSynthesis(KavalModel):
    """Structured synthesis consumed by the workflow and notifications."""

    evidence_summary: list[str]
    inference: InvestigationInference
    recommendation: InvestigationRecommendation
    degraded_mode_note: str | None = None
    model_used: ModelUsed = ModelUsed.NONE
    cloud_model_calls: int = NonNegativeInt


def build_investigation_prompt_bundle(
    *,
    incident: Incident,
    evidence: InvestigationEvidenceResult,
    research: Tier2ResearchBundle | None = None,
    degraded_reasons: Sequence[str] = (),
    now: datetime | None = None,
) -> InvestigationPromptBundle:
    """Render the prompt bundle used for Phase 2A investigation synthesis."""
    effective_now = now or datetime.now(tz=UTC)
    return InvestigationPromptBundle(
        system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        user_prompt=_render_user_prompt(
            incident=incident,
            evidence=evidence,
            research=research,
            degraded_reasons=degraded_reasons,
            now=effective_now,
        ),
        response_schema_name="phase2a_investigation",
        response_schema=INVESTIGATION_RESPONSE_SCHEMA,
    )


def _render_user_prompt(
    *,
    incident: Incident,
    evidence: InvestigationEvidenceResult,
    research: Tier2ResearchBundle | None,
    degraded_reasons: Sequence[str],
    now: datetime,
) -> str:
    """Render the user prompt with incident, evidence, memory, and response contract."""
    sections = [
        _render_incident_section(incident=incident, now=now),
        _render_evidence_section(evidence),
        _render_adapter_facts_section(evidence),
        _render_research_section(research),
        _render_memory_section(evidence),
        _render_constraints_section(degraded_reasons),
        _render_response_contract(),
    ]
    return "\n\n".join(section for section in sections if section).strip()


def _render_incident_section(*, incident: Incident, now: datetime) -> str:
    """Render the stable incident summary section."""
    incident_payload: JsonObject = {
        "generated_at": now.isoformat(),
        "incident_id": incident.id,
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "affected_services": cast(JsonValue, list(incident.affected_services)),
        "trigger_findings": cast(JsonValue, list(incident.trigger_findings)),
        "all_findings": cast(JsonValue, list(incident.all_findings)),
        "triggering_symptom": incident.triggering_symptom,
        "suspected_cause": incident.suspected_cause,
        "root_cause_service": incident.root_cause_service,
        "changes_correlated": cast(JsonValue, list(incident.changes_correlated)),
        "grouping_window_start": incident.grouping_window_start.isoformat(),
        "grouping_window_end": incident.grouping_window_end.isoformat(),
    }
    return "Incident Summary:\n" + _render_json(incident_payload)


def _render_evidence_section(evidence: InvestigationEvidenceResult) -> str:
    """Render ordered evidence steps as structured numbered blocks."""
    rendered_steps = []
    for step in evidence.evidence_steps:
        rendered_steps.append(
            "\n".join(
                [
                    f"{step.order}. [{step.action}] {step.target}",
                    f"Summary: {step.result_summary}",
                    "Data:",
                    _render_json(step.result_data),
                ]
            )
        )
    return "Evidence Steps:\n" + "\n\n".join(rendered_steps)


def _render_memory_section(evidence: InvestigationEvidenceResult) -> str:
    """Render Operational Memory context separately from the evidence steps."""
    memory = evidence.operational_memory
    memory_payload: JsonObject = {
        "recurrence_count": memory.recurrence_count,
        "applied_redaction_level": memory.applied_redaction_level.value,
        "warnings": cast(JsonValue, list(memory.warnings)),
        "system_profile": (
            cast(JsonValue, memory.system_profile.model_dump(mode="json"))
            if memory.system_profile is not None
            else None
        ),
        "journal_entries": cast(
            JsonValue,
            [entry.model_dump(mode="json") for entry in memory.journal_entries],
        ),
        "user_notes": cast(
            JsonValue,
            [note.model_dump(mode="json") for note in memory.user_notes],
        ),
    }
    return "Operational Memory:\n" + _render_json(memory_payload)


def _render_adapter_facts_section(evidence: InvestigationEvidenceResult) -> str:
    """Render prompt-safe adapter facts when they have been supplied."""
    if not evidence.adapter_facts:
        return ""
    payload = cast(
        JsonValue,
        [item.model_dump(mode="json") for item in evidence.adapter_facts],
    )
    return "Adapter Facts:\n" + _render_json(payload)


def _render_research_section(research: Tier2ResearchBundle | None) -> str:
    """Render ordered Tier 2 research context when it is available."""
    if research is None:
        return ""
    if not research.research_steps and not research.service_results and not research.warnings:
        return ""

    rendered_steps = []
    for step in research.research_steps:
        rendered_steps.append(
            "\n".join(
                [
                    f"{step.order}. [{step.action}] {step.source}",
                    f"Summary: {step.result_summary}",
                ]
            )
        )

    research_payload: JsonObject = {
        "skipped_offline": research.skipped_offline,
        "degraded_reasons": cast(JsonValue, list(research.degraded_reasons)),
        "warnings": cast(JsonValue, list(research.warnings)),
        "service_results": cast(
            JsonValue,
            [result.model_dump(mode="json") for result in research.service_results],
        ),
    }
    sections = [
        (
            "Research Steps:\n" + "\n\n".join(rendered_steps)
            if rendered_steps
            else "Research Steps:\nNone"
        ),
        "Research Results:\n" + _render_json(research_payload),
    ]
    return "\n\n".join(sections)


def _render_constraints_section(degraded_reasons: Sequence[str]) -> str:
    """Render the explicit bounded-remediation and degraded-mode constraints."""
    lines = [
        "Phase Constraints:",
        "- Keep the answer aligned to evidence -> inference -> recommendation.",
        "- Recommendation may be `restart_container` only, or `none` if restart is not justified.",
        "- Do not mention rollback, VM actions, config mutation, or credential-gated API data.",
        f"- {_RESEARCH_ONLY_DEGRADED_NOTE}",
    ]
    if degraded_reasons:
        lines.append("- Degraded mode details:")
        lines.extend(f"  - {reason}" for reason in degraded_reasons)
    return "\n".join(lines)


def _render_response_contract() -> str:
    """Render the response-shape instructions the model must follow."""
    contract: JsonObject = {
        "evidence_summary": ["fact 1", "fact 2"],
        "inference": {
            "root_cause": "string",
            "confidence": 0.0,
            "reasoning": "string",
        },
        "recommendation": {
            "summary": "string",
            "action_type": "restart_container | none",
            "target": "string | null",
            "rationale": "string",
            "risk": {
                "overall_risk": "low | medium | high",
                "checks": [
                    {"check": "string", "result": "pass|fail|unknown", "detail": "string"}
                ],
                "reversible": True,
                "warnings": ["string"],
            },
        },
        "degraded_mode_note": "string | null",
    }
    return "Response Contract:\nReturn JSON matching this shape exactly:\n" + _render_json(contract)


def _render_json(payload: JsonValue) -> str:
    """Render stable pretty-printed JSON for prompt sections."""
    return json.dumps(payload, indent=2, sort_keys=True)
