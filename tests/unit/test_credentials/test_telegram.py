"""Unit tests for Telegram credential-request prompts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast
from urllib import request

import pytest

from kaval.credentials import (
    CredentialRequest,
    CredentialRequestMode,
    CredentialRequestStatus,
    TelegramCredentialRequestHandler,
    build_credential_request_callback_id,
    parse_credential_request_callback_id,
)
from kaval.notifications.telegram_interactive import TelegramConfig, TelegramDeliveryStatus


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Telegram credential tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_telegram_handler_builds_credential_request_buttons() -> None:
    """Credential prompts should render explicit session, vault, and skip buttons."""
    captured: dict[str, object] = {}

    def transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
        captured["url"] = telegram_request.full_url
        captured["timeout"] = timeout_seconds
        captured["body"] = json.loads(cast(bytes, telegram_request.data).decode("utf-8"))
        return b'{"ok": true}'

    handler = TelegramCredentialRequestHandler(
        config=TelegramConfig(bot_token="bot-token", chat_id="12345", timeout_seconds=8.0),
        transport=transport,
    )

    result = handler.send(build_request())

    assert result.status == TelegramDeliveryStatus.SENT
    assert captured["url"] == "https://api.telegram.org/botbot-token/sendMessage"
    assert captured["timeout"] == 8.0
    body = cast(dict[str, object], captured["body"])
    assert "Radarr needs a credential" in cast(str, body["text"])
    reply_markup = cast(dict[str, object], body["reply_markup"])
    inline_keyboard = cast(list[list[dict[str, str]]], reply_markup["inline_keyboard"])
    buttons = inline_keyboard[0]
    assert [button["text"] for button in buttons] == [
        "Session only",
        "Store in vault",
        "Skip",
    ]
    assert buttons[0]["callback_data"] == build_credential_request_callback_id(
        request_id="credreq-1",
        mode=CredentialRequestMode.VOLATILE,
    )


def test_parse_callback_round_trips_request_id_and_mode() -> None:
    """Callback parsing should recover the request ID and chosen mode."""
    callback_id = build_credential_request_callback_id(
        request_id="credreq-1",
        mode=CredentialRequestMode.VAULT,
    )

    parsed = parse_credential_request_callback_id(callback_id)

    assert parsed.request_id == "credreq-1"
    assert parsed.mode == CredentialRequestMode.VAULT


def test_parse_callback_rejects_unknown_prefix() -> None:
    """Credential callback parsing should reject unrelated callback IDs."""
    with pytest.raises(ValueError, match="unsupported credential-request callback"):
        parse_credential_request_callback_id("approve:inc-1")


def build_request() -> CredentialRequest:
    """Build one representative pending credential request."""
    return CredentialRequest(
        id="credreq-1",
        incident_id="inc-1",
        investigation_id="inv-1",
        service_id="svc-radarr",
        service_name="Radarr",
        credential_key="api_key",
        credential_description="Radarr API Key",
        credential_location="Radarr Web UI -> Settings -> General -> API Key",
        reason="Logs are vague and the diagnostics API would narrow the fault.",
        status=CredentialRequestStatus.PENDING,
        requested_at=ts(18, 10),
        expires_at=ts(18, 40),
    )
