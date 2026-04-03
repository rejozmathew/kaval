"""Unit tests for Phase 3A adapter refresh cadence."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.integrations import (
    AdapterRefreshConfig,
    AdapterRefreshPolicy,
    AdapterRefreshRequest,
    AdapterRefreshScheduler,
    AdapterRefreshTrigger,
    default_adapter_refresh_policies,
    resolve_adapter_refresh_decision,
    resolve_adapter_refresh_policy,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter refresh tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_default_adapter_refresh_policies_include_rate_limited_cloudflare() -> None:
    """Cloudflare should ship with a safer default interval than local adapters."""
    defaults = {
        policy.adapter_id: policy.refresh_interval_minutes
        for policy in default_adapter_refresh_policies()
    }
    cloudflare = resolve_adapter_refresh_policy(
        config=AdapterRefreshConfig(),
        adapter_id="cloudflare_api",
    )

    assert defaults["radarr_api"] == 30
    assert defaults["cloudflare_api"] == 60
    assert cloudflare.rate_limit_aware is True


def test_adapter_refresh_config_rejects_duplicate_adapter_ids() -> None:
    """Duplicate adapter policies should fail validation."""
    with pytest.raises(ValueError, match="duplicate adapter_id values"):
        AdapterRefreshConfig(
            overrides=[
                AdapterRefreshPolicy(adapter_id="radarr_api", refresh_interval_minutes=45),
                AdapterRefreshPolicy(adapter_id="radarr_api", refresh_interval_minutes=60),
            ]
        )


def test_adapter_refresh_scheduler_marks_first_refresh_as_due() -> None:
    """Unseen adapter-service pairs should refresh on the first scheduler pass."""
    scheduler = AdapterRefreshScheduler()

    decisions = scheduler.due_refreshes(
        requests=[
            AdapterRefreshRequest(adapter_id="radarr_api", service_id="svc-radarr")
        ],
        now=ts(12, 0),
    )

    assert decisions[0].refresh_due is True
    assert decisions[0].trigger == AdapterRefreshTrigger.SCHEDULED
    assert decisions[0].reason == "No adapter refresh has been recorded yet."


def test_adapter_refresh_scheduler_honors_background_interval() -> None:
    """Background refresh should wait until the adapter interval elapses."""
    scheduler = AdapterRefreshScheduler()
    scheduler.mark_refreshed(
        adapter_id="radarr_api",
        service_id="svc-radarr",
        refreshed_at=ts(12, 0),
    )

    decision = scheduler.due_refreshes(
        requests=[
            AdapterRefreshRequest(adapter_id="radarr_api", service_id="svc-radarr")
        ],
        now=ts(12, 20),
    )[0]

    assert decision.refresh_due is False
    assert decision.next_refresh_at == ts(12, 30)


def test_adapter_refresh_scheduler_supports_investigation_trigger() -> None:
    """Active investigations should force an immediate refresh for the target service."""
    scheduler = AdapterRefreshScheduler()
    scheduler.mark_refreshed(
        adapter_id="radarr_api",
        service_id="svc-radarr",
        refreshed_at=ts(12, 0),
    )

    decision = scheduler.due_refreshes(
        requests=[
            AdapterRefreshRequest(adapter_id="radarr_api", service_id="svc-radarr")
        ],
        now=ts(12, 5),
        investigation_service_ids=["svc-radarr"],
    )[0]

    assert decision.refresh_due is True
    assert decision.trigger == AdapterRefreshTrigger.INVESTIGATION


def test_adapter_refresh_policy_allows_generic_fallback_for_unknown_adapters() -> None:
    """Unknown adapters should still resolve through the generic default policy."""
    decision = resolve_adapter_refresh_decision(
        config=AdapterRefreshConfig(generic_default_refresh_minutes=45),
        request=AdapterRefreshRequest(
            adapter_id="custom_adapter",
            service_id="svc-custom",
        ),
        now=ts(12, 0),
        last_refreshed_at=ts(11, 0),
    )

    assert decision.refresh_due is True
    assert decision.refresh_interval_minutes == 45
    assert decision.rate_limit_aware is False
