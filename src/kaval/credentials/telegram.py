"""Telegram prompt rendering for the Phase 2B credential-request flow."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, cast
from urllib import error, request

from kaval.credentials.models import CredentialRequest, CredentialRequestMode
from kaval.models import KavalModel
from kaval.notifications.telegram_interactive import (
    TelegramConfig,
    TelegramDeliveryResult,
    TelegramDeliveryStatus,
)

type TelegramTransport = Callable[[request.Request, float], bytes]

_CALLBACK_PREFIX = "credential_request"


class ParsedCredentialTelegramCallback(KavalModel):
    """One parsed Telegram callback action for a credential request."""

    request_id: str
    mode: CredentialRequestMode


def build_credential_request_callback_id(
    *,
    request_id: str,
    mode: CredentialRequestMode,
) -> str:
    """Encode one Telegram callback identifier for a credential request."""
    return f"{_CALLBACK_PREFIX}:{request_id}:{mode.value}"


def parse_credential_request_callback_id(callback_id: str) -> ParsedCredentialTelegramCallback:
    """Parse one Telegram callback identifier back into request metadata."""
    prefix, separator, remainder = callback_id.partition(":")
    if prefix != _CALLBACK_PREFIX or not separator:
        msg = "unsupported credential-request callback"
        raise ValueError(msg)
    request_id, separator, raw_mode = remainder.partition(":")
    if not request_id or not separator or not raw_mode:
        msg = "credential-request callback is malformed"
        raise ValueError(msg)
    try:
        mode = CredentialRequestMode(raw_mode)
    except ValueError as exc:
        raise ValueError("credential-request callback mode is invalid") from exc
    return ParsedCredentialTelegramCallback(request_id=request_id, mode=mode)


def build_credential_request_message(credential_request: CredentialRequest) -> str:
    """Render one Telegram-safe credential request prompt."""
    return (
        f"{credential_request.service_name} needs a credential for deeper investigation.\n\n"
        f"Reason: {credential_request.reason}\n"
        f"Credential: {credential_request.credential_description}\n"
        f"Find it: {credential_request.credential_location}\n\n"
        "Choose whether Kaval should wait for a session-only value, queue the request "
        "for the vault flow, or continue without it."
    )


@dataclass(frozen=True, slots=True)
class TelegramCredentialRequestHandler:
    """Send one credential request prompt to Telegram with UAC-style choices."""

    config: TelegramConfig | None = None
    transport: TelegramTransport | None = None

    def send(self, credential_request: CredentialRequest) -> TelegramDeliveryResult:
        """Send one credential request prompt or skip cleanly when not configured."""
        message_text = build_credential_request_message(credential_request)
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
                        _keyboard_button(
                            label="Session only",
                            callback_id=build_credential_request_callback_id(
                                request_id=credential_request.id,
                                mode=CredentialRequestMode.VOLATILE,
                            ),
                        ),
                        _keyboard_button(
                            label="Store in vault",
                            callback_id=build_credential_request_callback_id(
                                request_id=credential_request.id,
                                mode=CredentialRequestMode.VAULT,
                            ),
                        ),
                        _keyboard_button(
                            label="Skip",
                            callback_id=build_credential_request_callback_id(
                                request_id=credential_request.id,
                                mode=CredentialRequestMode.SKIP,
                            ),
                        ),
                    ]
                ]
            },
        }
        telegram_request = request.Request(
            url=f"{self.config.api_base_url}/bot{self.config.bot_token}/sendMessage",
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


def _keyboard_button(*, label: str, callback_id: str) -> dict[str, str]:
    """Build one Telegram inline-keyboard button."""
    return {
        "text": label,
        "callback_data": callback_id,
    }


def _default_transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one request to the Telegram Bot API."""
    with request.urlopen(telegram_request, timeout=timeout_seconds) as response:
        return cast(bytes, response.read())
