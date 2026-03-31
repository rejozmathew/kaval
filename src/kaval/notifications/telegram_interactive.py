"""Telegram Bot API delivery with inline actions for Phase 2A notifications."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, cast
from urllib import error, request

from kaval.models import (
    KavalModel,
    NotificationAction,
    NotificationActionStyle,
    NotificationActionType,
    NotificationPayload,
)

type TelegramTransport = Callable[[request.Request, float], bytes]


class TelegramDeliveryStatus(StrEnum):
    """Outcomes reported by the Telegram interactive handler."""

    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class TelegramConfig:
    """Runtime configuration for Telegram Bot API delivery."""

    bot_token: str
    chat_id: str
    api_base_url: str = "https://api.telegram.org"
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        """Normalize the API base URL and validate timeout values."""
        normalized_api_base_url = self.api_base_url.rstrip("/")
        if not normalized_api_base_url:
            msg = "api_base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        object.__setattr__(self, "api_base_url", normalized_api_base_url)


class TelegramDeliveryResult(KavalModel):
    """The outcome of one Telegram delivery attempt."""

    status: TelegramDeliveryStatus
    message_text: str
    attempted: bool
    detail: str


@dataclass(frozen=True, slots=True)
class TelegramInteractiveHandler:
    """Send one incident notification to Telegram with inline actions."""

    config: TelegramConfig | None = None
    transport: TelegramTransport | None = None

    def send(self, payload: NotificationPayload) -> TelegramDeliveryResult:
        """Send one notification to Telegram or skip cleanly when not configured."""
        message_text = _telegram_message_text(payload)
        if self.config is None:
            return TelegramDeliveryResult(
                status=TelegramDeliveryStatus.SKIPPED,
                message_text=message_text,
                attempted=False,
                detail="Telegram is not configured.",
            )

        body = {
            "chat_id": self.config.chat_id,
            "text": message_text,
            "reply_markup": {
                "inline_keyboard": [
                    [
                        _keyboard_button(button)
                        for button in _telegram_actions(payload)
                    ]
                ]
            },
        }
        telegram_request = request.Request(
            url=(
                f"{self.config.api_base_url}/bot{self.config.bot_token}/sendMessage"
            ),
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            self._transport()(telegram_request, self.config.timeout_seconds)
        except (TimeoutError, OSError, error.HTTPError, error.URLError):
            return TelegramDeliveryResult(
                status=TelegramDeliveryStatus.FAILED,
                message_text=message_text,
                attempted=True,
                detail="Telegram delivery failed.",
            )

        return TelegramDeliveryResult(
            status=TelegramDeliveryStatus.SENT,
            message_text=message_text,
            attempted=True,
            detail="Telegram delivery succeeded.",
        )

    def _transport(self) -> TelegramTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


def load_telegram_config_from_env(env: Mapping[str, str] | None = None) -> TelegramConfig | None:
    """Load optional Telegram configuration from the environment."""
    source = env or os.environ
    bot_token = source.get("KAVAL_TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = source.get("KAVAL_TELEGRAM_CHAT_ID", "").strip()
    if not bot_token or not chat_id:
        return None

    api_base_url = source.get("KAVAL_TELEGRAM_API_BASE_URL", "https://api.telegram.org")
    timeout_value = source.get("KAVAL_TELEGRAM_TIMEOUT_SECONDS", "15").strip()
    try:
        timeout_seconds = float(timeout_value)
    except ValueError as exc:
        raise ValueError("KAVAL_TELEGRAM_TIMEOUT_SECONDS must be numeric") from exc

    return TelegramConfig(
        bot_token=bot_token,
        chat_id=chat_id,
        api_base_url=api_base_url,
        timeout_seconds=timeout_seconds,
    )


def _telegram_actions(payload: NotificationPayload) -> list[NotificationAction]:
    """Return the payload's actions or synthesize the default Phase 2A controls."""
    if payload.action_buttons:
        return payload.action_buttons

    source_id = payload.incident_id or payload.source_id
    actions: list[NotificationAction] = []
    if payload.recommended_action is not None:
        actions.append(
            NotificationAction(
                label="Approve restart",
                action=NotificationActionType.APPROVE,
                style=NotificationActionStyle.PRIMARY,
                callback_id=f"approve:{source_id}",
            )
        )
    actions.append(
        NotificationAction(
            label="Full details",
            action=NotificationActionType.VIEW_DETAILS,
            style=NotificationActionStyle.SECONDARY,
            callback_id=f"view_details:{source_id}",
        )
    )
    actions.append(
        NotificationAction(
            label="Dismiss",
            action=NotificationActionType.DISMISS,
            style=NotificationActionStyle.DANGER,
            callback_id=f"dismiss:{source_id}",
        )
    )
    return actions


def _telegram_message_text(payload: NotificationPayload) -> str:
    """Render the text body sent through Telegram."""
    return f"{payload.title}\n\n{payload.body}"


def _keyboard_button(action: NotificationAction) -> dict[str, str]:
    """Convert one notification action into a Telegram inline keyboard button."""
    if action.callback_id is None:
        msg = "Telegram interactive buttons require callback_id"
        raise ValueError(msg)
    return {
        "text": action.label,
        "callback_data": action.callback_id,
    }


def _default_transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one request to the Telegram Bot API."""
    with request.urlopen(telegram_request, timeout=timeout_seconds) as response:
        return cast(bytes, response.read())
