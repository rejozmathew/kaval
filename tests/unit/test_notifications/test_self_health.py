"""Unit tests for Kaval self-health notification helpers."""

from __future__ import annotations

from kaval.notifications.self_health import (
    SelfHealthNotificationPolicy,
    format_self_health_label,
    load_self_health_notification_policy_from_env,
)


def test_self_health_policy_defaults_to_critical_only() -> None:
    """Critical self-health issues should be enabled by default."""
    policy = load_self_health_notification_policy_from_env({})

    assert policy == SelfHealthNotificationPolicy(
        critical_enabled=True,
        degraded_enabled=False,
    )


def test_self_health_policy_reads_boolean_env_overrides() -> None:
    """Env flags should allow the later settings UI to reuse the same policy shape."""
    policy = load_self_health_notification_policy_from_env(
        {
            "KAVAL_SELF_HEALTH_NOTIFY_CRITICAL": "false",
            "KAVAL_SELF_HEALTH_NOTIFY_DEGRADED": "true",
        }
    )

    assert policy == SelfHealthNotificationPolicy(
        critical_enabled=False,
        degraded_enabled=True,
    )


def test_format_self_health_label_expands_layer_identifiers() -> None:
    """Capability-layer identifiers should read cleanly in notifications."""
    assert format_self_health_label("notification_channels") == "Notification Channels"
