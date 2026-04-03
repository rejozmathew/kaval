"""Typed refresh-cadence contracts for deep-inspection adapters."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import Field, model_validator

from kaval.integrations.adapter_fallback import AdapterStalenessPolicy
from kaval.models import KavalModel


class AdapterRefreshTrigger(StrEnum):
    """Triggers that can cause an adapter fact refresh."""

    SCHEDULED = "scheduled"
    INVESTIGATION = "investigation"


class AdapterRefreshPolicy(KavalModel):
    """Refresh policy for one deep-inspection adapter."""

    adapter_id: str = Field(min_length=1)
    refresh_interval_minutes: int = Field(ge=1)
    rate_limit_aware: bool = False
    investigation_refresh_enabled: bool = True

    def refresh_interval(self) -> timedelta:
        """Return the background refresh interval."""
        return timedelta(minutes=self.refresh_interval_minutes)

    def staleness_policy(self) -> AdapterStalenessPolicy:
        """Return the staleness policy derived from the refresh interval."""
        return AdapterStalenessPolicy(
            refresh_interval_minutes=self.refresh_interval_minutes
        )


class AdapterRefreshConfig(KavalModel):
    """Default and override policies for adapter refresh cadence."""

    default_policies: list[AdapterRefreshPolicy] = Field(
        default_factory=lambda: list(default_adapter_refresh_policies())
    )
    overrides: list[AdapterRefreshPolicy] = Field(default_factory=list)
    generic_default_refresh_minutes: int = Field(default=30, ge=1)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "AdapterRefreshConfig":
        """Reject duplicate policy keys that would make cadence ambiguous."""
        _ensure_unique_policy_ids(self.default_policies, label="default_policies")
        _ensure_unique_policy_ids(self.overrides, label="overrides")
        return self


class AdapterRefreshRequest(KavalModel):
    """One requested adapter refresh target."""

    adapter_id: str = Field(min_length=1)
    service_id: str = Field(min_length=1)


class AdapterRefreshDecision(KavalModel):
    """Resolved refresh decision for one adapter-service pair."""

    adapter_id: str = Field(min_length=1)
    service_id: str = Field(min_length=1)
    refresh_due: bool
    trigger: AdapterRefreshTrigger | None = None
    refresh_interval_minutes: int = Field(ge=1)
    rate_limit_aware: bool = False
    last_refreshed_at: datetime | None = None
    next_refresh_at: datetime | None = None
    reason: str


_DEFAULT_ADAPTER_REFRESH_POLICIES: tuple[AdapterRefreshPolicy, ...] = (
    AdapterRefreshPolicy(adapter_id="npm_api", refresh_interval_minutes=30),
    AdapterRefreshPolicy(adapter_id="radarr_api", refresh_interval_minutes=30),
    AdapterRefreshPolicy(adapter_id="authentik_api", refresh_interval_minutes=30),
    AdapterRefreshPolicy(adapter_id="pihole_api", refresh_interval_minutes=30),
    AdapterRefreshPolicy(
        adapter_id="cloudflare_api",
        refresh_interval_minutes=60,
        rate_limit_aware=True,
    ),
)


class AdapterRefreshScheduler:
    """In-memory scheduler for adapter fact refresh decisions."""

    def __init__(self, config: AdapterRefreshConfig | None = None) -> None:
        """Initialize the scheduler with optional cadence configuration."""
        self._config = config or AdapterRefreshConfig()
        self._last_refreshed_at: dict[tuple[str, str], datetime] = {}

    def last_refreshed_at(self, *, adapter_id: str, service_id: str) -> datetime | None:
        """Return the last refresh timestamp for one adapter-service pair."""
        return self._last_refreshed_at.get((adapter_id, service_id))

    def mark_refreshed(
        self,
        *,
        adapter_id: str,
        service_id: str,
        refreshed_at: datetime,
    ) -> None:
        """Record that one adapter-service pair refreshed successfully."""
        self._last_refreshed_at[(adapter_id, service_id)] = refreshed_at

    def due_refreshes(
        self,
        *,
        requests: Sequence[AdapterRefreshRequest],
        now: datetime,
        investigation_service_ids: Sequence[str] = (),
    ) -> list[AdapterRefreshDecision]:
        """Return refresh decisions for the requested adapter-service pairs."""
        return [
            resolve_adapter_refresh_decision(
                config=self._config,
                request=request,
                now=now,
                last_refreshed_at=self.last_refreshed_at(
                    adapter_id=request.adapter_id,
                    service_id=request.service_id,
                ),
                investigation_service_ids=investigation_service_ids,
            )
            for request in requests
        ]


def default_adapter_refresh_policies() -> tuple[AdapterRefreshPolicy, ...]:
    """Return the canonical built-in adapter refresh defaults."""
    return _DEFAULT_ADAPTER_REFRESH_POLICIES


def resolve_adapter_refresh_policy(
    *,
    config: AdapterRefreshConfig,
    adapter_id: str,
) -> AdapterRefreshPolicy:
    """Resolve the effective policy for one adapter."""
    override = _policy_for_adapter(config.overrides, adapter_id=adapter_id)
    if override is not None:
        return override
    default_policy = _policy_for_adapter(config.default_policies, adapter_id=adapter_id)
    if default_policy is not None:
        return default_policy
    return AdapterRefreshPolicy(
        adapter_id=adapter_id,
        refresh_interval_minutes=config.generic_default_refresh_minutes,
    )


def resolve_adapter_refresh_decision(
    *,
    config: AdapterRefreshConfig,
    request: AdapterRefreshRequest,
    now: datetime,
    last_refreshed_at: datetime | None,
    investigation_service_ids: Sequence[str] = (),
) -> AdapterRefreshDecision:
    """Resolve whether one adapter-service pair should refresh now."""
    policy = resolve_adapter_refresh_policy(
        config=config,
        adapter_id=request.adapter_id,
    )
    next_refresh_at = None
    if last_refreshed_at is not None:
        next_refresh_at = last_refreshed_at + policy.refresh_interval()

    if (
        policy.investigation_refresh_enabled
        and request.service_id in set(investigation_service_ids)
    ):
        return AdapterRefreshDecision(
            adapter_id=request.adapter_id,
            service_id=request.service_id,
            refresh_due=True,
            trigger=AdapterRefreshTrigger.INVESTIGATION,
            refresh_interval_minutes=policy.refresh_interval_minutes,
            rate_limit_aware=policy.rate_limit_aware,
            last_refreshed_at=last_refreshed_at,
            next_refresh_at=next_refresh_at,
            reason="Active investigation requested an immediate adapter refresh.",
        )
    if last_refreshed_at is None:
        return AdapterRefreshDecision(
            adapter_id=request.adapter_id,
            service_id=request.service_id,
            refresh_due=True,
            trigger=AdapterRefreshTrigger.SCHEDULED,
            refresh_interval_minutes=policy.refresh_interval_minutes,
            rate_limit_aware=policy.rate_limit_aware,
            last_refreshed_at=None,
            next_refresh_at=None,
            reason="No adapter refresh has been recorded yet.",
        )
    if now >= last_refreshed_at + policy.refresh_interval():
        return AdapterRefreshDecision(
            adapter_id=request.adapter_id,
            service_id=request.service_id,
            refresh_due=True,
            trigger=AdapterRefreshTrigger.SCHEDULED,
            refresh_interval_minutes=policy.refresh_interval_minutes,
            rate_limit_aware=policy.rate_limit_aware,
            last_refreshed_at=last_refreshed_at,
            next_refresh_at=next_refresh_at,
            reason="Adapter refresh interval has elapsed.",
        )
    return AdapterRefreshDecision(
        adapter_id=request.adapter_id,
        service_id=request.service_id,
        refresh_due=False,
        trigger=None,
        refresh_interval_minutes=policy.refresh_interval_minutes,
        rate_limit_aware=policy.rate_limit_aware,
        last_refreshed_at=last_refreshed_at,
        next_refresh_at=next_refresh_at,
        reason="Adapter refresh is not due yet.",
    )


def _policy_for_adapter(
    policies: Sequence[AdapterRefreshPolicy],
    *,
    adapter_id: str,
) -> AdapterRefreshPolicy | None:
    """Return the policy registered for one adapter, if any."""
    for policy in policies:
        if policy.adapter_id == adapter_id:
            return policy
    return None


def _ensure_unique_policy_ids(
    policies: Sequence[AdapterRefreshPolicy],
    *,
    label: str,
) -> None:
    """Reject duplicate adapter policy identifiers."""
    seen_policy_ids: set[str] = set()
    for policy in policies:
        if policy.adapter_id in seen_policy_ids:
            msg = f"{label} must not contain duplicate adapter_id values: {policy.adapter_id}"
            raise ValueError(msg)
        seen_policy_ids.add(policy.adapter_id)
