"""Unit tests for the optional cloud-model investigation client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from urllib import request

from kaval.investigation.cloud_model import (
    CloudEscalationPolicy,
    CloudInvestigationSynthesizer,
    CloudModelConfig,
    build_cloud_safe_prompt_bundle,
    evaluate_cloud_escalation_policy,
    load_cloud_model_config_from_env,
)
from kaval.investigation.prompts import InvestigationPromptBundle, InvestigationSynthesis
from kaval.models import (
    DescriptorSource,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    InvestigationTrigger,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_load_cloud_model_config_uses_anthropic_defaults() -> None:
    """Configured Anthropic cloud settings should resolve into a normalized config."""
    config = load_cloud_model_config_from_env(
        {
            "KAVAL_CLOUD_MODEL_NAME": "claude-sonnet-4-20250514",
            "ANTHROPIC_API_KEY": "anthropic-secret",
        }
    )

    assert config is not None
    assert config.provider == "anthropic"
    assert config.base_url == "https://api.anthropic.com"
    assert config.model == "claude-sonnet-4-20250514"


def test_build_cloud_safe_prompt_bundle_redacts_service_details() -> None:
    """Cloud prompt assembly should strip service identifiers and internal URLs."""
    incident = build_incident()
    service = build_service()
    prompt_bundle = InvestigationPromptBundle(
        system_prompt="Respond with JSON only.",
        user_prompt=(
            "incident inc-delugevpn service svc-delugevpn DelugeVPN "
            "container-delugevpn downloads/delugevpn "
            'memory {"applied_redaction_level": "redact_for_local"} '
            "url=http://delugevpn:8112/api/status token=abc123"
        ),
        response_schema_name="phase2b_investigation",
        response_schema={"type": "object"},
    )

    cloud_prompt = build_cloud_safe_prompt_bundle(
        prompt_bundle=prompt_bundle,
        incident=incident,
        services=[service],
    )

    assert "inc-delugevpn" not in cloud_prompt.user_prompt
    assert "svc-delugevpn" not in cloud_prompt.user_prompt
    assert "DelugeVPN" not in cloud_prompt.user_prompt
    assert "container-delugevpn" not in cloud_prompt.user_prompt
    assert "downloads/delugevpn" not in cloud_prompt.user_prompt
    assert "http://delugevpn:8112/api/status" not in cloud_prompt.user_prompt
    assert "abc123" not in cloud_prompt.user_prompt
    assert '"applied_redaction_level": "redact_for_cloud"' in cloud_prompt.user_prompt
    assert "[SERVICE_1]" in cloud_prompt.user_prompt
    assert "[CONTAINER_1]" in cloud_prompt.user_prompt
    assert "Privacy note:" in cloud_prompt.system_prompt


def test_cloud_synthesizer_shapes_anthropic_request_and_parses_response() -> None:
    """Anthropic cloud synthesis should send messages JSON and validate the response."""
    captured_request: dict[str, object] = {}

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
        response = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        cloud_response_payload().model_dump(mode="json")
                    ),
                }
            ]
        }
        return json.dumps(response).encode("utf-8")

    synthesizer = CloudInvestigationSynthesizer(
        config=CloudModelConfig(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_key="anthropic-secret",
            base_url="https://api.anthropic.com/",
            timeout_seconds=21.0,
        ),
        transport=transport,
    )

    result = synthesizer.synthesize(prompt_bundle=build_cloud_safe_prompt_bundle_for_test())

    assert captured_request["url"] == "https://api.anthropic.com/v1/messages"
    headers = cast(dict[str, str], captured_request["headers"])
    assert headers["x-api-key"] == "anthropic-secret"
    assert headers["anthropic-version"] == "2023-06-01"
    body = cast(dict[str, object], captured_request["body"])
    assert body["model"] == "claude-sonnet-4-20250514"
    assert body["messages"] == [{"role": "user", "content": "cloud-safe-user"}]
    assert body["system"] == "cloud-safe-system"
    assert captured_request["timeout"] == 21.0

    assert result.model_used.value == "cloud"
    assert result.cloud_model_calls == 1
    assert result.inference.confidence == 0.92


def test_evaluate_cloud_escalation_policy_requires_explicit_trigger() -> None:
    """Cloud escalation should remain off when no configured threshold matches."""
    decision = evaluate_cloud_escalation_policy(
        incident=build_incident(),
        findings=[build_finding(domain="downloads")],
        investigations=[],
        local_synthesis=cloud_response_payload().model_copy(
            update={"model_used": "local", "cloud_model_calls": 0}
        ),
        changelog_research_available=False,
        trigger=InvestigationTrigger.AUTO,
        now=ts(14, 30),
        policy=CloudEscalationPolicy(local_confidence_lt=0.4),
        offline=False,
    )

    assert decision.should_use_cloud is False
    assert decision.blocked_reason is None
    assert decision.trigger_reasons == ()


def build_cloud_safe_prompt_bundle_for_test() -> object:
    """Build a minimal cloud-safe prompt bundle for cloud client tests."""
    from kaval.investigation.cloud_model import CloudSafePromptBundle

    return CloudSafePromptBundle(
        system_prompt="cloud-safe-system",
        user_prompt="cloud-safe-user",
        response_schema_name="phase2b_investigation",
        response_schema={"type": "object"},
    )


def build_incident() -> Incident:
    """Build a minimal incident for cloud-model tests."""
    return Incident(
        id="inc-delugevpn",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn"],
        affected_services=["svc-delugevpn"],
        triggering_symptom="VPN tunnel inactive",
        suspected_cause="VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
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


def build_service() -> Service:
    """Build a minimal service for cloud prompt redaction tests."""
    return Service(
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
        dependents=[],
        last_check=ts(14, 0),
        active_findings=1,
        active_incidents=1,
    )


def build_finding(*, domain: str) -> Finding:
    """Build a minimal finding for escalation-policy tests."""
    return Finding(
        id="find-delugevpn",
        title="DelugeVPN tunnel inactive",
        severity=Severity.HIGH,
        domain=domain,
        service_id="svc-delugevpn",
        summary="Tunnel inactive.",
        evidence=[],
        impact="Downloads cannot proceed.",
        confidence=0.95,
        status=FindingStatus.GROUPED,
        incident_id="inc-delugevpn",
        related_changes=[],
        created_at=ts(14, 0),
        resolved_at=None,
    )


def cloud_response_payload() -> InvestigationSynthesis:
    """Build a deterministic synthesis payload."""
    return InvestigationSynthesis.model_validate(
        {
            "evidence_summary": ["VPN tunnel inactive."],
            "inference": {
                "root_cause": "DelugeVPN VPN tunnel dropped",
                "confidence": 0.92,
                "reasoning": "Evidence and recurrence align with tunnel loss.",
            },
            "recommendation": {
                "summary": "Restart delugevpn.",
                "action_type": "restart_container",
                "target": "delugevpn",
                "rationale": "Restart is the only bounded remediation.",
                "risk": {
                    "overall_risk": "low",
                    "checks": [
                        {
                            "check": "bounded_action_scope",
                            "result": "pass",
                            "detail": "Restart stays inside one container.",
                        }
                    ],
                    "reversible": True,
                    "warnings": [],
                },
            },
            "degraded_mode_note": None,
            "model_used": "local",
            "cloud_model_calls": 0,
        }
    )
