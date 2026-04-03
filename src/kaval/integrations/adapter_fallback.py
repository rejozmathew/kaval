"""Internal degradation and fallback helpers for deep-inspection adapters."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import Field, model_validator

from kaval.integrations.adapter_diagnostics import AdapterDiagnosticStatus
from kaval.models import DependencyConfidence, KavalModel, ServiceInsightLevel


class AdapterFactFreshness(StrEnum):
    """Freshness states for adapter-derived facts."""

    CURRENT = "current"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class AdapterFallbackState(StrEnum):
    """Internal fallback states for deep-inspection adapters."""

    ACTIVE = "active"
    STALE = "stale"
    DEGRADED = "degraded"
    UNCONFIGURED = "unconfigured"
    DISABLED = "disabled"


class AdapterStalenessPolicy(KavalModel):
    """Staleness policy for adapter-derived facts and upgrades."""

    refresh_interval_minutes: int = Field(gt=0)
    stale_after_multiplier: float = Field(default=2.0, gt=0.0)

    def stale_after(self) -> timedelta:
        """Return the age at which adapter-derived data becomes stale."""
        return timedelta(
            minutes=self.refresh_interval_minutes * self.stale_after_multiplier
        )

    def stale_at(self, observed_at: datetime) -> datetime:
        """Return the timestamp when one adapter observation becomes stale."""
        return observed_at + self.stale_after()


class AdapterRuntimeObservedDowngradePolicy(KavalModel):
    """Fallback policy for runtime-observed confidence upgrades."""

    fallback_confidence: DependencyConfidence = DependencyConfidence.INFERRED

    @model_validator(mode="after")
    def validate_fallback_confidence(
        self,
    ) -> AdapterRuntimeObservedDowngradePolicy:
        """Keep downgrade targets inside the approved fallback set."""
        if self.fallback_confidence not in {
            DependencyConfidence.CONFIGURED,
            DependencyConfidence.INFERRED,
        }:
            msg = "runtime-observed fallback must resolve to configured or inferred"
            raise ValueError(msg)
        return self


class AdapterFallbackDecision(KavalModel):
    """Internal decision describing whether adapter output can still be trusted."""

    adapter_id: str = Field(min_length=1)
    state: AdapterFallbackState
    diagnostic_status: AdapterDiagnosticStatus | None = None
    freshness: AdapterFactFreshness
    observed_at: datetime | None = None
    stale_at: datetime | None = None
    use_base_inference: bool
    allow_adapter_facts: bool
    allow_runtime_observed_upgrades: bool
    reason: str | None = None


def evaluate_adapter_fact_freshness(
    *,
    observed_at: datetime | None,
    now: datetime,
    staleness_policy: AdapterStalenessPolicy,
) -> AdapterFactFreshness:
    """Return whether adapter-derived facts are current, stale, or unavailable."""
    if observed_at is None:
        return AdapterFactFreshness.UNAVAILABLE
    if observed_at + staleness_policy.stale_after() < now:
        return AdapterFactFreshness.STALE
    return AdapterFactFreshness.CURRENT


def evaluate_adapter_fallback(
    *,
    adapter_id: str,
    configured: bool,
    disabled: bool,
    diagnostic_status: AdapterDiagnosticStatus | None,
    observed_at: datetime | None,
    now: datetime,
    staleness_policy: AdapterStalenessPolicy,
    reason: str | None = None,
) -> AdapterFallbackDecision:
    """Build the internal fallback decision for one adapter at one point in time."""
    freshness = evaluate_adapter_fact_freshness(
        observed_at=observed_at,
        now=now,
        staleness_policy=staleness_policy,
    )
    stale_at = None if observed_at is None else staleness_policy.stale_at(observed_at)

    if disabled:
        return AdapterFallbackDecision(
            adapter_id=adapter_id,
            state=AdapterFallbackState.DISABLED,
            diagnostic_status=diagnostic_status,
            freshness=freshness,
            observed_at=observed_at,
            stale_at=stale_at,
            use_base_inference=True,
            allow_adapter_facts=False,
            allow_runtime_observed_upgrades=False,
            reason=reason or "Adapter is disabled.",
        )
    if not configured:
        return AdapterFallbackDecision(
            adapter_id=adapter_id,
            state=AdapterFallbackState.UNCONFIGURED,
            diagnostic_status=diagnostic_status,
            freshness=freshness,
            observed_at=observed_at,
            stale_at=stale_at,
            use_base_inference=True,
            allow_adapter_facts=False,
            allow_runtime_observed_upgrades=False,
            reason=reason or "Adapter credentials or required inputs are not configured.",
        )
    if diagnostic_status is None:
        if freshness == AdapterFactFreshness.CURRENT:
            return AdapterFallbackDecision(
                adapter_id=adapter_id,
                state=AdapterFallbackState.ACTIVE,
                diagnostic_status=None,
                freshness=freshness,
                observed_at=observed_at,
                stale_at=stale_at,
                use_base_inference=False,
                allow_adapter_facts=True,
                allow_runtime_observed_upgrades=True,
                reason=reason,
            )
        return AdapterFallbackDecision(
            adapter_id=adapter_id,
            state=AdapterFallbackState.STALE,
            diagnostic_status=None,
            freshness=freshness,
            observed_at=observed_at,
            stale_at=stale_at,
            use_base_inference=True,
            allow_adapter_facts=False,
            allow_runtime_observed_upgrades=False,
            reason=reason or "Adapter facts are not current enough to trust.",
        )
    if diagnostic_status == AdapterDiagnosticStatus.HEALTHY:
        if freshness == AdapterFactFreshness.CURRENT:
            return AdapterFallbackDecision(
                adapter_id=adapter_id,
                state=AdapterFallbackState.ACTIVE,
                diagnostic_status=diagnostic_status,
                freshness=freshness,
                observed_at=observed_at,
                stale_at=stale_at,
                use_base_inference=False,
                allow_adapter_facts=True,
                allow_runtime_observed_upgrades=True,
                reason=reason,
            )
        return AdapterFallbackDecision(
            adapter_id=adapter_id,
            state=AdapterFallbackState.STALE,
            diagnostic_status=diagnostic_status,
            freshness=freshness,
            observed_at=observed_at,
            stale_at=stale_at,
            use_base_inference=True,
            allow_adapter_facts=False,
            allow_runtime_observed_upgrades=False,
            reason=reason or "Adapter facts are stale and fallback is required.",
        )
    return AdapterFallbackDecision(
        adapter_id=adapter_id,
        state=AdapterFallbackState.DEGRADED,
        diagnostic_status=diagnostic_status,
        freshness=freshness,
        observed_at=observed_at,
        stale_at=stale_at,
        use_base_inference=True,
        allow_adapter_facts=False,
        allow_runtime_observed_upgrades=False,
        reason=reason or "Adapter is degraded and fallback is required.",
    )


def apply_runtime_observed_fallback(
    *,
    confidence: DependencyConfidence,
    fallback_decision: AdapterFallbackDecision,
    downgrade_policy: AdapterRuntimeObservedDowngradePolicy,
) -> DependencyConfidence:
    """Return the effective edge confidence after adapter fallback is applied."""
    if confidence != DependencyConfidence.RUNTIME_OBSERVED:
        return confidence
    if fallback_decision.allow_runtime_observed_upgrades:
        return confidence
    return downgrade_policy.fallback_confidence


def apply_adapter_fallback_to_insight_level(
    *,
    insight_level: ServiceInsightLevel,
    fallback_decision: AdapterFallbackDecision,
) -> ServiceInsightLevel:
    """Cap insight at Level 3 when deep inspection is no longer trusted."""
    if insight_level <= ServiceInsightLevel.INVESTIGATION_READY:
        return insight_level
    if fallback_decision.allow_adapter_facts:
        return insight_level
    return ServiceInsightLevel.INVESTIGATION_READY
