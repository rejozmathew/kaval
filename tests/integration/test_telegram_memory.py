"""Integration tests for transport-local Telegram memory command handling."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

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
from kaval.notifications.telegram_memory import (
    TelegramMemoryCommandHandler,
    TelegramMemoryCommandServiceAmbiguousError,
)


def ts(day: int, hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Telegram memory tests."""
    return datetime(2026, 4, day, hour, minute, tzinfo=UTC)


def test_telegram_memory_handler_wires_note_notes_and_journal_commands(
    tmp_path: Path,
) -> None:
    """The local handler should create notes and read notes/journal entries."""
    database = build_database(tmp_path)
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
        database.upsert_user_note(
            UserNote(
                id="note-2",
                service_id="svc-delugevpn",
                note="DNS recovery is usually faster than a full restart.",
                safe_for_model=True,
                last_verified_at=ts(2, 11),
                stale=False,
                added_at=ts(2, 11),
                updated_at=ts(2, 11),
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

        handler = TelegramMemoryCommandHandler(database=database, result_limit=5)

        create_result = handler.handle_message(
            '/note "Ubuntu Server" Check the LVM partition before expanding disk.',
            now=ts(3, 14),
        )
        notes_result = handler.handle_message("/notes DelugeVPN")
        journal_result = handler.handle_message('/journal "Ubuntu Server"')

        assert create_result.service is not None
        assert create_result.service.service_id == "svc-ubuntu-server"
        assert create_result.created_note is not None
        assert create_result.created_note.note == (
            "Check the LVM partition before expanding disk."
        )
        assert "Saved note for Ubuntu Server." in create_result.message_text

        stored_ubuntu_notes = [
            note.note
            for note in database.list_user_notes()
            if note.service_id == "svc-ubuntu-server"
        ]
        assert stored_ubuntu_notes == ["Check the LVM partition before expanding disk."]

        assert [note.note_id for note in notes_result.notes] == ["note-2", "note-1"]
        assert "[not-for-model, stale]" in notes_result.message_text
        assert "DNS recovery is usually faster" in notes_result.message_text

        assert [entry.journal_entry_id for entry in journal_result.journal_entries] == [
            "jrnl-ubuntu"
        ]
        assert "recurrence 2x" in journal_result.message_text
        assert "Ubuntu Server disk pressure returned" in journal_result.message_text
    finally:
        database.close()


def test_telegram_memory_handler_reports_recurrence_and_ambiguous_note_targets(
    tmp_path: Path,
) -> None:
    """The local handler should summarize recurrence and reject ambiguous note targets."""
    database = build_database(tmp_path)
    try:
        database.upsert_service(build_service("svc-media", "Media"))
        database.upsert_service(build_service("svc-media-server", "Media Server"))
        database.upsert_service(build_service("svc-delugevpn", "DelugeVPN"))
        database.upsert_journal_entry(
            build_journal_entry(
                entry_id="jrnl-media-server",
                services=["svc-media-server"],
                summary="Media Server cache pressure has recurred repeatedly.",
                recurrence_count=3,
                confidence=JournalConfidence.CONFIRMED,
                entry_date=date(2026, 4, 3),
            )
        )
        database.upsert_journal_entry(
            build_journal_entry(
                entry_id="jrnl-delugevpn",
                services=["svc-delugevpn"],
                summary="DelugeVPN tunnel instability recurred after ISP changes.",
                recurrence_count=2,
                confidence=JournalConfidence.LIKELY,
                entry_date=date(2026, 4, 2),
            )
        )

        handler = TelegramMemoryCommandHandler(database=database, result_limit=5)
        recurrence_result = handler.handle_message("/recurrence")

        assert [item.journal_entry_id for item in recurrence_result.recurrences] == [
            "jrnl-media-server",
            "jrnl-delugevpn",
        ]
        assert recurrence_result.recurrences[0].services == ["Media Server"]
        assert recurrence_result.message_text.startswith("Active recurrence patterns:")
        assert "3x Media Server" in recurrence_result.message_text

        with pytest.raises(
            TelegramMemoryCommandServiceAmbiguousError,
            match="note command is ambiguous",
        ):
            handler.handle_message("/note Media Server restart after maintenance")
    finally:
        database.close()


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_service(service_id: str, name: str) -> Service:
    """Build a minimal persisted service for Telegram memory tests."""
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
    """Build one journal entry for Telegram memory command tests."""
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
