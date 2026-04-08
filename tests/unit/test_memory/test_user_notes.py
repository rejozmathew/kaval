"""Unit tests for the Phase 3B user-note lifecycle service."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.database import KavalDatabase
from kaval.memory.note_models import UserNoteCreate, UserNoteUpdate
from kaval.memory.user_notes import UserNoteNotFoundError, UserNoteService


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for user-note tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def build_service(tmp_path: Path) -> tuple[KavalDatabase, UserNoteService]:
    """Create a bootstrapped database plus note service."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database, UserNoteService(database=database)


def test_user_note_service_tracks_versions_and_archive_lifecycle(tmp_path: Path) -> None:
    """Updates should snapshot prior content and archive should hide active notes."""
    database, service = build_service(tmp_path)
    try:
        created = service.create_note(
            UserNoteCreate(
                service_id="svc-delugevpn",
                note="Restarting DelugeVPN is safe after confirming the tunnel is up.",
                safe_for_model=True,
            ),
            now=ts(9),
        )

        updated = service.update_note(
            created.id,
            UserNoteUpdate(
                note="Restart DelugeVPN only after verifying the VPN tunnel is up.",
                safe_for_model=False,
                stale=True,
            ),
            now=ts(10, 15),
        )

        versions_after_update = service.list_versions(created.id)
        assert [(version.version_number, version.current) for version in versions_after_update] == [
            (1, False),
            (2, True),
        ]
        assert versions_after_update[0].note.note == created.note
        assert versions_after_update[0].note.safe_for_model is True
        assert versions_after_update[1].note.note == updated.note
        assert versions_after_update[1].note.safe_for_model is False
        assert versions_after_update[1].note.stale is True

        archived = service.archive_note(created.id, archived_at=ts(11))

        assert archived.archived is True
        assert archived.current is True
        assert archived.version_number == 2
        assert service.list_notes() == []
        assert database.list_user_notes() == []

        archived_versions = service.list_versions(created.id)
        assert [
            (version.version_number, version.current, version.archived)
            for version in archived_versions
        ] == [(1, False, False), (2, True, True)]
        assert archived_versions[-1].note.note == updated.note
    finally:
        database.close()


def test_user_note_service_filters_and_hard_deletes_archived_history(tmp_path: Path) -> None:
    """Service filters should ignore archived notes and hard delete should remove history."""
    database, service = build_service(tmp_path)
    try:
        primary = service.create_note(
            UserNoteCreate(service_id="svc-primary", note="Primary service note."),
            now=ts(12),
        )
        archived_candidate = service.create_note(
            UserNoteCreate(service_id="svc-secondary", note="Secondary service note."),
            now=ts(12, 30),
        )
        service.create_note(
            UserNoteCreate(service_id=None, note="Global note."),
            now=ts(12, 45),
        )

        assert [note.id for note in service.list_notes(service_id="svc-primary")] == [primary.id]
        assert [note.service_id for note in service.list_notes()] == [
            "svc-primary",
            "svc-secondary",
            None,
        ]

        service.archive_note(archived_candidate.id, archived_at=ts(13))
        service.delete_note(archived_candidate.id)

        assert [note.service_id for note in service.list_notes()] == ["svc-primary", None]
        assert database.list_user_note_versions(archived_candidate.id) == []

        with pytest.raises(UserNoteNotFoundError):
            service.list_versions(archived_candidate.id)
        with pytest.raises(UserNoteNotFoundError):
            service.update_note("note-missing", UserNoteUpdate(note="updated"))
        with pytest.raises(UserNoteNotFoundError):
            service.delete_note("note-missing")
    finally:
        database.close()
