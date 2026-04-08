"""Security-focused tests for Telegram command ingress."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app


def test_telegram_update_route_returns_not_found_when_ingress_is_not_configured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Telegram ingress should stay disabled until both delivery and webhook config exist."""
    monkeypatch.delenv("KAVAL_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("KAVAL_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("KAVAL_TELEGRAM_WEBHOOK_SECRET", raising=False)
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/telegram/updates",
            json=telegram_update(chat_id=-100123, text="/notes DelugeVPN"),
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "telegram command ingress not configured"}


def test_telegram_update_route_rejects_missing_or_invalid_secret_tokens(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Telegram ingress must reject requests without the configured secret header."""
    monkeypatch.setenv("KAVAL_TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("KAVAL_TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("KAVAL_TELEGRAM_WEBHOOK_SECRET", "telegram-secret")
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        missing_response = client.post(
            "/api/v1/telegram/updates",
            json=telegram_update(chat_id=-100123, text="/notes DelugeVPN"),
        )
        invalid_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong-secret"},
            json=telegram_update(chat_id=-100123, text="/notes DelugeVPN"),
        )

    assert missing_response.status_code == 401
    assert missing_response.json() == {"detail": "invalid telegram webhook secret"}
    assert invalid_response.status_code == 401
    assert invalid_response.json() == {"detail": "invalid telegram webhook secret"}
    assert "wrong-secret" not in invalid_response.text


def test_telegram_update_route_rejects_unauthorized_chat_without_echoing_chat_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Telegram ingress should only accept commands from the configured chat."""
    monkeypatch.setenv("KAVAL_TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("KAVAL_TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("KAVAL_TELEGRAM_WEBHOOK_SECRET", "telegram-secret")
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(chat_id=-999999, text="/notes DelugeVPN"),
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "telegram update chat is not authorized"}
    assert "-999999" not in response.text


def telegram_update(*, chat_id: int, text: str) -> dict[str, object]:
    """Build a minimal Telegram update payload for ingress security tests."""
    return {
        "update_id": 1,
        "message": {
            "message_id": 10,
            "chat": {"id": chat_id, "type": "private"},
            "text": text,
        },
    }
