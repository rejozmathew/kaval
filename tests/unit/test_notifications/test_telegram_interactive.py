"""Unit tests for Telegram interactive notification delivery."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from urllib import request

from kaval.models import NotificationPayload, NotificationSourceType, Severity
from kaval.notifications.telegram_interactive import (
    TelegramConfig,
    TelegramDeliveryStatus,
    TelegramInteractiveHandler,
    load_telegram_config_from_env,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Telegram notification tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_load_telegram_config_returns_none_when_credentials_are_missing() -> None:
    """Telegram delivery should stay disabled until both bot token and chat ID exist."""
    config = load_telegram_config_from_env({"KAVAL_TELEGRAM_BOT_TOKEN": "bot-token-only"})

    assert config is None


def test_telegram_handler_builds_inline_keyboard_for_restart_recommendation() -> None:
    """Restart-capable notifications should send approve/details/dismiss inline actions."""
    captured: dict[str, object] = {}

    def transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
        captured["url"] = telegram_request.full_url
        captured["timeout"] = timeout_seconds
        captured["body"] = json.loads(cast(bytes, telegram_request.data).decode("utf-8"))
        return b'{"ok": true}'

    handler = TelegramInteractiveHandler(
        config=TelegramConfig(
            bot_token="bot-token",
            chat_id="12345",
            timeout_seconds=8.0,
        ),
        transport=transport,
    )

    result = handler.send(build_payload())

    assert result.status == TelegramDeliveryStatus.SENT
    assert result.attempted is True
    assert captured["url"] == "https://api.telegram.org/botbot-token/sendMessage"
    assert captured["timeout"] == 8.0
    body = cast(dict[str, object], captured["body"])
    assert body["chat_id"] == "12345"
    assert "Radarr and DelugeVPN degraded" in cast(str, body["text"])
    reply_markup = cast(dict[str, object], body["reply_markup"])
    inline_keyboard = cast(list[list[dict[str, str]]], reply_markup["inline_keyboard"])
    buttons = inline_keyboard[0]
    assert [button["text"] for button in buttons] == [
        "Approve restart",
        "Full details",
        "Dismiss",
    ]
    assert buttons[0]["callback_data"] == "approve:inc-delugevpn"


def test_telegram_handler_skips_cleanly_when_not_configured() -> None:
    """Missing Telegram config should not break notification callers."""
    result = TelegramInteractiveHandler(config=None).send(build_payload())

    assert result.status == TelegramDeliveryStatus.SKIPPED
    assert result.attempted is False


def build_payload() -> NotificationPayload:
    """Build a representative incident notification payload."""
    return NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id="inc-delugevpn",
        incident_id="inc-delugevpn",
        severity=Severity.HIGH,
        title="Radarr and DelugeVPN degraded",
        summary="Download pipeline blocked.",
        body="Root cause likely DelugeVPN VPN tunnel dropped.",
        evidence_lines=[
            'DelugeVPN logs: "VPN tunnel inactive"',
            'Radarr: "Download client not available"',
        ],
        recommended_action="Restart DelugeVPN",
        action_buttons=[],
        dedup_key="incident:inc-delugevpn",
        created_at=ts(14, 30),
    )
