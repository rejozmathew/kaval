"""Integration tests for inbound Telegram memory command ingress."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import cast
from urllib import request

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import (
    DescriptorSource,
    JournalConfidence,
    JournalEntry,
    Service,
    ServiceStatus,
    ServiceType,
    UserNote,
)


def ts(day: int, hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Telegram ingress tests."""
    return datetime(2026, 4, day, hour, minute, tzinfo=UTC)


def test_telegram_update_route_processes_memory_commands_end_to_end(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Inbound Telegram updates should reach the memory command handler end to end."""
    monkeypatch.setenv("KAVAL_TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("KAVAL_TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("KAVAL_TELEGRAM_WEBHOOK_SECRET", "telegram-secret")
    database_path = seed_database(tmp_path)
    deliveries: list[dict[str, object]] = []

    def transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
        deliveries.append(json.loads(cast(bytes, telegram_request.data).decode("utf-8")))
        return b'{"ok": true}'

    app = create_app(database_path=database_path, telegram_transport=transport)

    with TestClient(app) as client:
        note_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=1,
                message_id=10,
                chat_id=-100123,
                text='/note "Ubuntu Server" Check the LVM partition before restart.',
            ),
        )
        notes_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=2,
                message_id=11,
                chat_id=-100123,
                text="/notes DelugeVPN",
            ),
        )
        journal_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=3,
                message_id=12,
                chat_id=-100123,
                text='/journal "Ubuntu Server"',
            ),
        )
        recurrence_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=4,
                message_id=13,
                chat_id=-100123,
                text="/recurrence",
            ),
        )
        ignored_response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=5,
                message_id=14,
                chat_id=-100123,
                text="/start",
            ),
        )

    assert note_response.status_code == 200
    assert note_response.json() == {
        "status": "processed",
        "detail": "telegram memory command processed",
        "reply_delivery_status": "sent",
    }
    assert notes_response.status_code == 200
    assert notes_response.json()["reply_delivery_status"] == "sent"
    assert journal_response.status_code == 200
    assert journal_response.json()["reply_delivery_status"] == "sent"
    assert recurrence_response.status_code == 200
    assert recurrence_response.json()["reply_delivery_status"] == "sent"
    assert ignored_response.status_code == 200
    assert ignored_response.json() == {
        "status": "ignored",
        "detail": "telegram update did not contain a supported memory command",
        "reply_delivery_status": None,
    }

    assert [delivery["reply_to_message_id"] for delivery in deliveries] == [10, 11, 12, 13]
    assert all(delivery["chat_id"] == "-100123" for delivery in deliveries)
    assert deliveries[0]["text"].startswith("Saved note for Ubuntu Server.")
    assert "Recent notes for DelugeVPN:" in cast(str, deliveries[1]["text"])
    assert "Recent journal entries for Ubuntu Server:" in cast(str, deliveries[2]["text"])
    assert "Active recurrence patterns:" in cast(str, deliveries[3]["text"])

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        ubuntu_notes = [
            note.note
            for note in database.list_user_notes()
            if note.service_id == "svc-ubuntu-server"
        ]
    finally:
        database.close()

    assert ubuntu_notes == ["Check the LVM partition before restart."]


def test_telegram_update_route_replies_with_parser_errors_for_supported_commands(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Supported command errors should return a Telegram reply instead of being ignored."""
    monkeypatch.setenv("KAVAL_TELEGRAM_BOT_TOKEN", "bot-token")
    monkeypatch.setenv("KAVAL_TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setenv("KAVAL_TELEGRAM_WEBHOOK_SECRET", "telegram-secret")
    database_path = seed_database(tmp_path)
    deliveries: list[dict[str, object]] = []

    def transport(telegram_request: request.Request, timeout_seconds: float) -> bytes:
        deliveries.append(json.loads(cast(bytes, telegram_request.data).decode("utf-8")))
        return b'{"ok": true}'

    app = create_app(database_path=database_path, telegram_transport=transport)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/telegram/updates",
            headers={"X-Telegram-Bot-Api-Secret-Token": "telegram-secret"},
            json=telegram_update(
                update_id=1,
                message_id=10,
                chat_id=-100123,
                text="/notes",
            ),
        )

    assert response.status_code == 200
    assert response.json() == {
        "status": "processed",
        "detail": "telegram memory command rejected",
        "reply_delivery_status": "sent",
    }
    assert len(deliveries) == 1
    assert deliveries[0]["text"] == "/notes requires <service>"


def telegram_update(
    *,
    update_id: int,
    message_id: int,
    chat_id: int,
    text: str,
) -> dict[str, object]:
    """Build one Telegram message update payload."""
    return {
        "update_id": update_id,
        "message": {
            "message_id": message_id,
            "chat": {"id": chat_id, "type": "private"},
            "text": text,
        },
    }


def seed_database(tmp_path: Path) -> Path:
    """Bootstrap a temporary database with note and journal fixtures."""
    database_path = tmp_path / "kaval.db"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(build_service("svc-delugevpn", "DelugeVPN"))
        database.upsert_service(build_service("svc-ubuntu-server", "Ubuntu Server"))
        database.upsert_user_note(
            UserNote(
                id="note-1",
                service_id="svc-delugevpn",
                note="Restart only after confirming the VPN tunnel is up.",
                safe_for_model=False,
                last_verified_at=ts(1, 9),
                stale=True,
                added_at=ts(1, 9),
                updated_at=ts(1, 9),
            )
        )
        database.upsert_journal_entry(
            build_journal_entry(
                entry_id="jrnl-ubuntu",
                services=["svc-ubuntu-server"],
                summary="Ubuntu Server disk pressure returned after package upgrades.",
                recurrence_count=2,
                confidence=JournalConfidence.CONFIRMED,
                entry_date=date(2026, 4, 2),
            )
        )
    finally:
        database.close()
    return database_path


def build_service(service_id: str, name: str) -> Service:
    """Build one minimal persisted service for Telegram ingress tests."""
    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="media",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=DescriptorSource.SHIPPED,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=ts(1, 8),
        active_findings=0,
        active_incidents=0,
    )


def build_journal_entry(
    *,
    entry_id: str,
    services: list[str],
    summary: str,
    recurrence_count: int,
    confidence: JournalConfidence,
    entry_date: date,
) -> JournalEntry:
    """Build one journal entry for Telegram ingress tests."""
    return JournalEntry(
        id=entry_id,
        incident_id=f"inc-{entry_id}",
        date=entry_date,
        services=services,
        summary=summary,
        root_cause=summary,
        resolution="Operator follow-up completed.",
        time_to_resolution_minutes=10.0,
        model_used="local",
        tags=["recurrence"],
        lesson="Track the recurring pattern.",
        recurrence_count=recurrence_count,
        confidence=confidence,
        user_confirmed=confidence is JournalConfidence.CONFIRMED,
        last_verified_at=ts(1, 12),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=180,
    )
