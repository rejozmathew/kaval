"""Unit tests for the Phase 2A local-model investigation client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from urllib import request

from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.local_model import (
    LocalModelConfig,
    OpenAICompatibleInvestigationSynthesizer,
    load_local_model_config_from_env,
    probe_local_model_connection,
)
from kaval.investigation.prompts import InvestigationPromptBundle, build_investigation_prompt_bundle
from kaval.models import (
    EvidenceStep,
    Incident,
    IncidentStatus,
    JournalConfidence,
    JournalEntry,
    ModelUsed,
    OperationalMemoryResult,
    RedactionLevel,
    Severity,
    UserNote,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for local-model tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_load_local_model_config_defaults_to_localhost_ollama_shape() -> None:
    """A configured model name should enable the local client with a safe default base URL."""
    config = load_local_model_config_from_env({"KAVAL_LOCAL_MODEL_NAME": "qwen3:8b"})

    assert config is not None
    assert config.base_url == "http://localhost:11434"
    assert config.model == "qwen3:8b"
    assert config.timeout_seconds == 30.0


def test_load_local_model_config_returns_none_when_disabled() -> None:
    """An explicit disable flag should bypass the local-model client cleanly."""
    config = load_local_model_config_from_env(
        {
            "KAVAL_LOCAL_MODEL_ENABLED": "false",
            "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
        }
    )

    assert config is None


def test_synthesizer_shapes_request_and_parses_structured_json_response() -> None:
    """The synthesizer should send chat-completions JSON and validate the structured result."""
    captured_request: dict[str, object] = {}
    incident, evidence, prompt_bundle = build_prompt_inputs()
    structured_response = {
        "evidence_summary": ["DelugeVPN logs show tunnel inactivity."],
        "inference": {
            "root_cause": "DelugeVPN VPN tunnel dropped",
            "confidence": 0.92,
            "reasoning": (
                "Logs, change timing, and recurrence all point to the VPN tunnel."
            ),
        },
        "recommendation": {
            "summary": "Restart delugevpn.",
            "action_type": "restart_container",
            "target": "delugevpn",
            "rationale": "Restart is the only bounded remediation in Phase 2A.",
            "risk": {
                "overall_risk": "low",
                "checks": [
                    {
                        "check": "bounded_action_scope",
                        "result": "pass",
                        "detail": (
                            "The target stays within the affected container scope."
                        ),
                    }
                ],
                "reversible": True,
                "warnings": [],
            },
        },
        "degraded_mode_note": None,
    }

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        headers = {key.lower(): value for key, value in http_request.header_items()}
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        captured_request.update(
            {
                "url": http_request.full_url,
                "headers": headers,
                "body": body,
                "timeout": timeout_seconds,
            }
        )
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": f"```json\n{json.dumps(structured_response)}\n```"
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 312,
                    "completion_tokens": 88,
                },
            }
        ).encode("utf-8")

    synthesizer = OpenAICompatibleInvestigationSynthesizer(
        config=LocalModelConfig(
            base_url="http://localhost:11434/",
            model="qwen3:8b",
            api_key="local-secret",
            timeout_seconds=12.5,
        ),
        transport=transport,
    )

    result = synthesizer.synthesize(
        incident=incident,
        evidence=evidence,
        prompt_bundle=prompt_bundle,
    )

    assert captured_request["url"] == "http://localhost:11434/v1/chat/completions"
    headers = captured_request["headers"]
    assert isinstance(headers, dict)
    assert headers["authorization"] == "Bearer local-secret"
    assert headers["content-type"] == "application/json"
    body = captured_request["body"]
    assert isinstance(body, dict)
    assert body["model"] == "qwen3:8b"
    assert body["temperature"] == 0.0
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1]["role"] == "user"
    assert captured_request["timeout"] == 12.5

    assert result.model_used == ModelUsed.LOCAL
    assert result.cloud_model_calls == 0
    assert result.local_input_tokens == 312
    assert result.local_output_tokens == 88
    assert result.estimated_total_cost_usd == 0.0
    assert result.inference.root_cause == "DelugeVPN VPN tunnel dropped"
    assert result.recommendation.action_type == "restart_container"
    assert result.recommendation.target == "delugevpn"


def test_local_model_connection_probe_uses_small_json_probe() -> None:
    """The explicit connection test should accept a minimal JSON acknowledgement."""
    captured_request: dict[str, object] = {}

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        captured_request["url"] = http_request.full_url
        captured_request["timeout"] = timeout_seconds
        captured_request["body"] = body
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"connection_ok": true}',
                        }
                    }
                ]
            }
        ).encode("utf-8")

    probe_local_model_connection(
        config=LocalModelConfig(
            base_url="http://localhost:11434",
            model="qwen3:8b",
            timeout_seconds=8.0,
        ),
        transport=transport,
    )

    assert captured_request["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured_request["timeout"] == 8.0
    body = cast(dict[str, object], captured_request["body"])
    assert body["messages"][0]["content"] == "Return JSON only."
    assert body["messages"][1]["content"] == '{"connection_ok": true}'


def build_prompt_inputs(
) -> tuple[Incident, InvestigationEvidenceResult, InvestigationPromptBundle]:
    """Build a small prompt input set for local-model tests."""
    incident = Incident(
        id="inc-delugevpn",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn"],
        affected_services=["svc-delugevpn"],
        triggering_symptom="VPN tunnel inactive",
        suspected_cause="DelugeVPN VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.88,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=["chg-delugevpn-restart"],
        grouping_window_start=ts(14, 20),
        grouping_window_end=ts(14, 25),
        created_at=ts(14, 20),
        updated_at=ts(14, 25),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )
    evidence = InvestigationEvidenceResult(
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="summarize_incident_findings",
                target="inc-delugevpn",
                result_summary="DelugeVPN reports the VPN tunnel is inactive.",
                result_data={"finding_ids": ["find-delugevpn"]},
                timestamp=ts(14, 26),
            ),
            EvidenceStep(
                order=2,
                action="inspect_dependency_graph",
                target="inc-delugevpn",
                result_summary="No downstream services are affected in this reduced test case.",
                result_data={"upstream_services": ["svc-delugevpn"]},
                timestamp=ts(14, 27),
            ),
        ],
        operational_memory=OperationalMemoryResult(
            system_profile=None,
            journal_entries=[
                JournalEntry(
                    id="jrnl-delugevpn-2",
                    incident_id="inc-old-2",
                    date=ts(10, 0).date(),
                    services=["svc-delugevpn"],
                    summary="DelugeVPN dropped its tunnel previously.",
                    root_cause="VPN tunnel inactive.",
                    resolution="Restarted DelugeVPN container.",
                    time_to_resolution_minutes=6.0,
                    model_used="local",
                    tags=["delugevpn", "recurrence"],
                    lesson="Restart restored connectivity quickly.",
                    recurrence_count=2,
                    confidence=JournalConfidence.CONFIRMED,
                    user_confirmed=True,
                    last_verified_at=ts(10, 0),
                    applies_to_version=None,
                    superseded_by=None,
                    stale_after_days=None,
                )
            ],
            user_notes=[
                UserNote(
                    id="note-delugevpn",
                    service_id="svc-delugevpn",
                    note="Provider endpoint rotates often.",
                    safe_for_model=True,
                    last_verified_at=ts(11, 0),
                    stale=False,
                    added_at=ts(11, 0),
                    updated_at=ts(11, 5),
                )
            ],
            recurrence_count=2,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ),
    )
    prompt_bundle = build_investigation_prompt_bundle(
        incident=incident,
        evidence=evidence,
        now=ts(14, 30),
    )
    return incident, evidence, prompt_bundle
