"""Unit tests for adapter degradation and fallback helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.integrations import (
    AdapterDiagnosticStatus,
    AdapterFallbackState,
    AdapterRuntimeObservedDowngradePolicy,
    AdapterStalenessPolicy,
    apply_adapter_fallback_to_insight_level,
    apply_runtime_observed_fallback,
    evaluate_adapter_fallback,
)
from kaval.models import DependencyConfidence, ServiceInsightLevel


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for fallback tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_evaluate_adapter_fallback_returns_active_for_healthy_current_facts() -> None:
    """Healthy adapters with fresh facts should remain active."""
    decision = evaluate_adapter_fallback(
        adapter_id="radarr_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.HEALTHY,
        observed_at=ts(10, 0),
        now=ts(10, 45),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert decision.state == AdapterFallbackState.ACTIVE
    assert decision.use_base_inference is False
    assert decision.allow_adapter_facts is True
    assert decision.allow_runtime_observed_upgrades is True
    assert decision.stale_at == ts(11, 0)


def test_evaluate_adapter_fallback_marks_stale_facts_for_healthy_adapter() -> None:
    """Healthy adapters with stale facts should fall back to base inference."""
    decision = evaluate_adapter_fallback(
        adapter_id="radarr_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.HEALTHY,
        observed_at=ts(10, 0),
        now=ts(11, 1),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert decision.state == AdapterFallbackState.STALE
    assert decision.use_base_inference is True
    assert decision.allow_adapter_facts is False
    assert decision.allow_runtime_observed_upgrades is False


def test_evaluate_adapter_fallback_marks_degraded_adapter_even_with_recent_facts() -> None:
    """Degraded adapters should stop contributing trusted deep-inspection data."""
    decision = evaluate_adapter_fallback(
        adapter_id="radarr_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.PARSE_ERROR,
        observed_at=ts(10, 30),
        now=ts(10, 45),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
        reason="Response schema changed.",
    )

    assert decision.state == AdapterFallbackState.DEGRADED
    assert decision.reason == "Response schema changed."
    assert decision.use_base_inference is True
    assert decision.allow_adapter_facts is False


def test_evaluate_adapter_fallback_marks_unconfigured_adapters() -> None:
    """Unconfigured adapters should use base inference without pretending to be broken."""
    decision = evaluate_adapter_fallback(
        adapter_id="cloudflare_api",
        configured=False,
        disabled=False,
        diagnostic_status=None,
        observed_at=None,
        now=ts(12, 0),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert decision.state == AdapterFallbackState.UNCONFIGURED
    assert decision.use_base_inference is True
    assert decision.allow_adapter_facts is False


def test_evaluate_adapter_fallback_marks_disabled_adapters() -> None:
    """Disabled adapters should stay out of the active deep-inspection path."""
    decision = evaluate_adapter_fallback(
        adapter_id="cloudflare_api",
        configured=True,
        disabled=True,
        diagnostic_status=AdapterDiagnosticStatus.HEALTHY,
        observed_at=ts(11, 30),
        now=ts(12, 0),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert decision.state == AdapterFallbackState.DISABLED
    assert decision.use_base_inference is True
    assert decision.allow_runtime_observed_upgrades is False


def test_runtime_observed_fallback_uses_the_declared_policy() -> None:
    """Runtime-observed edges should downgrade explicitly when fallback is active."""
    stale_decision = evaluate_adapter_fallback(
        adapter_id="npm_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.HEALTHY,
        observed_at=ts(9, 0),
        now=ts(10, 5),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert apply_runtime_observed_fallback(
        confidence=DependencyConfidence.RUNTIME_OBSERVED,
        fallback_decision=stale_decision,
        downgrade_policy=AdapterRuntimeObservedDowngradePolicy(
            fallback_confidence=DependencyConfidence.CONFIGURED
        ),
    ) == DependencyConfidence.CONFIGURED
    assert apply_runtime_observed_fallback(
        confidence=DependencyConfidence.INFERRED,
        fallback_decision=stale_decision,
        downgrade_policy=AdapterRuntimeObservedDowngradePolicy(),
    ) == DependencyConfidence.INFERRED


def test_runtime_observed_policy_rejects_invalid_targets() -> None:
    """Fallback policies must resolve to configured or inferred confidence only."""
    with pytest.raises(ValueError, match="configured or inferred"):
        AdapterRuntimeObservedDowngradePolicy(
            fallback_confidence=DependencyConfidence.USER_CONFIRMED
        )


def test_adapter_fallback_caps_deep_inspection_insight_levels() -> None:
    """Fallback should cap deep-inspection-only insight to Level 3."""
    degraded_decision = evaluate_adapter_fallback(
        adapter_id="authentik_api",
        configured=True,
        disabled=False,
        diagnostic_status=AdapterDiagnosticStatus.AUTH_FAILED,
        observed_at=ts(11, 45),
        now=ts(12, 0),
        staleness_policy=AdapterStalenessPolicy(refresh_interval_minutes=30),
    )

    assert apply_adapter_fallback_to_insight_level(
        insight_level=ServiceInsightLevel.DEEP_INSPECTED,
        fallback_decision=degraded_decision,
    ) == ServiceInsightLevel.INVESTIGATION_READY
    assert apply_adapter_fallback_to_insight_level(
        insight_level=ServiceInsightLevel.OPERATOR_ENRICHED,
        fallback_decision=degraded_decision,
    ) == ServiceInsightLevel.INVESTIGATION_READY
    assert apply_adapter_fallback_to_insight_level(
        insight_level=ServiceInsightLevel.MONITORED,
        fallback_decision=degraded_decision,
    ) == ServiceInsightLevel.MONITORED
