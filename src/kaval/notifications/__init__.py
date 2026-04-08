"""Notification package."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from kaval.notifications.bus import (
    NotificationBus,
    NotificationBusConfig,
    NotificationChannelConfig,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    load_notification_bus_config_from_env,
)
from kaval.notifications.formatter import format_incident_notification
from kaval.notifications.grouped import (
    IncidentNotificationDispatcher,
    IncidentNotificationDispatchResult,
    IncidentNotificationDispatchStatus,
)
from kaval.notifications.routing import (
    AlertMaintenanceWindow,
    IncidentAlertRoute,
    IncidentAlertRouter,
    IncidentAlertRoutingContext,
    IncidentAlertRoutingPolicy,
    IncidentAlertRoutingResult,
    IncidentAlertRoutingStatus,
    PendingDigestIncident,
    PendingIncidentDigest,
    QuietHoursHeldIncident,
)
from kaval.notifications.telegram_interactive import (
    TelegramConfig,
    TelegramDeliveryResult,
    TelegramDeliveryStatus,
    TelegramInteractiveHandler,
    TelegramWebhookConfig,
    load_telegram_config_from_env,
    load_telegram_webhook_config_from_env,
)

_LAZY_EXPORT_TO_MODULE = {
    "TelegramMemoryCommand": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandError": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandHandler": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandKind": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandParseError": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandResult": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandServiceAmbiguousError": "kaval.notifications.telegram_memory",
    "TelegramMemoryCommandServiceNotFoundError": "kaval.notifications.telegram_memory",
    "parse_telegram_memory_command": "kaval.notifications.telegram_memory",
    "supports_telegram_memory_command": "kaval.notifications.telegram_memory",
    "SelfHealthNotificationDispatcher": "kaval.notifications.self_health",
    "SelfHealthNotificationIssue": "kaval.notifications.self_health",
    "SelfHealthNotificationPolicy": "kaval.notifications.self_health",
    "SelfHealthNotificationResult": "kaval.notifications.self_health",
    "SelfHealthNotificationStatus": "kaval.notifications.self_health",
    "build_self_health_notification_payload": "kaval.notifications.self_health",
    "collect_self_health_issues": "kaval.notifications.self_health",
    "format_self_health_label": "kaval.notifications.self_health",
    "load_self_health_notification_policy_from_env": "kaval.notifications.self_health",
}

__all__ = [
    "IncidentNotificationDispatchResult",
    "IncidentNotificationDispatchStatus",
    "IncidentNotificationDispatcher",
    "AlertMaintenanceWindow",
    "IncidentAlertRoute",
    "IncidentAlertRouter",
    "IncidentAlertRoutingContext",
    "IncidentAlertRoutingPolicy",
    "IncidentAlertRoutingResult",
    "IncidentAlertRoutingStatus",
    "NotificationBus",
    "NotificationBusConfig",
    "NotificationChannelConfig",
    "NotificationDeliveryResult",
    "NotificationDeliveryStatus",
    "PendingDigestIncident",
    "PendingIncidentDigest",
    "QuietHoursHeldIncident",
    "SelfHealthNotificationDispatcher",
    "SelfHealthNotificationIssue",
    "SelfHealthNotificationPolicy",
    "SelfHealthNotificationResult",
    "SelfHealthNotificationStatus",
    "TelegramConfig",
    "TelegramDeliveryResult",
    "TelegramDeliveryStatus",
    "TelegramInteractiveHandler",
    "TelegramWebhookConfig",
    "TelegramMemoryCommand",
    "TelegramMemoryCommandError",
    "TelegramMemoryCommandHandler",
    "TelegramMemoryCommandKind",
    "TelegramMemoryCommandParseError",
    "TelegramMemoryCommandResult",
    "TelegramMemoryCommandServiceAmbiguousError",
    "TelegramMemoryCommandServiceNotFoundError",
    "format_incident_notification",
    "load_telegram_config_from_env",
    "load_telegram_webhook_config_from_env",
    "load_notification_bus_config_from_env",
    "load_self_health_notification_policy_from_env",
    "parse_telegram_memory_command",
    "supports_telegram_memory_command",
    "build_self_health_notification_payload",
    "collect_self_health_issues",
    "format_self_health_label",
]


def __getattr__(name: str) -> Any:
    """Resolve selected exports lazily to avoid import cycles."""
    module_name = _LAZY_EXPORT_TO_MODULE.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value
