"""Unit tests for Phase 3B severity-based incident alert routing."""

from __future__ import annotations

from kaval.models import Severity
from kaval.notifications.routing import (
    IncidentAlertRoute,
    IncidentAlertRoutingPolicy,
)


def test_default_alert_routing_policy_matches_phase3b_requirements() -> None:
    """The shipped default routing policy should match the PRD severity matrix."""
    policy = IncidentAlertRoutingPolicy()

    assert policy.route_for(Severity.CRITICAL) == IncidentAlertRoute.IMMEDIATE
    assert policy.route_for(Severity.HIGH) == IncidentAlertRoute.IMMEDIATE_WITH_DEDUP
    assert policy.route_for(Severity.MEDIUM) == IncidentAlertRoute.HOURLY_DIGEST
    assert policy.route_for(Severity.LOW) == IncidentAlertRoute.DASHBOARD_ONLY
    assert policy.dedup_window_minutes == 15
    assert policy.digest_window_minutes == 60


def test_alert_routing_policy_allows_explicit_route_overrides() -> None:
    """Tests can override the policy without widening the runtime surface."""
    policy = IncidentAlertRoutingPolicy(
        critical=IncidentAlertRoute.IMMEDIATE_WITH_DEDUP,
        medium=IncidentAlertRoute.DASHBOARD_ONLY,
        dedup_window_minutes=20,
        digest_window_minutes=30,
    )

    assert policy.route_for(Severity.CRITICAL) == IncidentAlertRoute.IMMEDIATE_WITH_DEDUP
    assert policy.route_for(Severity.MEDIUM) == IncidentAlertRoute.DASHBOARD_ONLY
    assert policy.dedup_window_minutes == 20
    assert policy.digest_window_minutes == 30
