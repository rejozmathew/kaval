"""User-note CRUD and version-history helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from kaval.database import KavalDatabase
from kaval.memory.note_models import UserNoteCreate, UserNoteUpdate, UserNoteVersion
from kaval.models import UserNote


class UserNoteNotFoundError(RuntimeError):
    """Raised when the requested user note does not exist."""


@dataclass(slots=True)
class UserNoteService:
    """Manage active user notes plus archived/versioned note history."""

    database: KavalDatabase

    def list_notes(self, *, service_id: str | None = None) -> list[UserNote]:
        """Return active user notes, optionally filtered to one service."""
        notes = self.database.list_user_notes()
        if service_id is None:
            return notes
        return [note for note in notes if note.service_id == service_id]

    def create_note(
        self,
        note_data: UserNoteCreate,
        now: datetime | None = None,
    ) -> UserNote:
        """Create and persist one active user note."""
        effective_now = now or datetime.now(tz=UTC)
        user_note = UserNote(
            id=f"note-{uuid4()}",
            **note_data.model_dump(),
            added_at=effective_now,
            updated_at=effective_now,
        )
        self.database.upsert_user_note(user_note)
        return user_note

    def update_note(
        self,
        note_id: str,
        update_data: UserNoteUpdate,
        now: datetime | None = None,
    ) -> UserNote:
        """Update one active user note and store the prior version snapshot."""
        current_note = self.database.get_user_note(note_id)
        if current_note is None:
            raise UserNoteNotFoundError(f"user note not found: {note_id}")

        effective_now = now or datetime.now(tz=UTC)
        current_version = self._current_version_number(note_id)
        self.database.upsert_user_note_version(
            UserNoteVersion(
                note_id=note_id,
                version_number=current_version,
                recorded_at=effective_now,
                archived=False,
                current=False,
                note=current_note,
            )
        )
        updated_note = current_note.model_copy(
            update={
                **update_data.model_dump(exclude_unset=True),
                "updated_at": effective_now,
            }
        )
        self.database.upsert_user_note(updated_note)
        return updated_note

    def archive_note(
        self,
        note_id: str,
        *,
        archived_at: datetime | None = None,
    ) -> UserNoteVersion:
        """Soft-delete one active user note into retained version history."""
        current_note = self.database.get_user_note(note_id)
        if current_note is None:
            raise UserNoteNotFoundError(f"user note not found: {note_id}")

        effective_archived_at = archived_at or datetime.now(tz=UTC)
        archived_version = UserNoteVersion(
            note_id=note_id,
            version_number=self._current_version_number(note_id),
            recorded_at=effective_archived_at,
            archived=True,
            current=True,
            note=current_note,
        )
        self.database.upsert_user_note_version(archived_version)
        self.database.delete_user_note(note_id)
        return archived_version

    def delete_note(self, note_id: str) -> None:
        """Hard-delete one note and any retained version history."""
        active_note = self.database.get_user_note(note_id)
        versions = self.database.list_user_note_versions(note_id)
        if active_note is None and not versions:
            raise UserNoteNotFoundError(f"user note not found: {note_id}")
        if active_note is not None:
            self.database.delete_user_note(note_id)
        if versions:
            self.database.delete_user_note_versions(note_id)

    def list_versions(self, note_id: str) -> list[UserNoteVersion]:
        """Return version history plus the current note snapshot when active."""
        stored_versions = self.database.list_user_note_versions(note_id)
        active_note = self.database.get_user_note(note_id)
        if active_note is None and not stored_versions:
            raise UserNoteNotFoundError(f"user note not found: {note_id}")

        if active_note is not None:
            current_version = UserNoteVersion(
                note_id=note_id,
                version_number=self._current_version_number(note_id),
                recorded_at=active_note.updated_at,
                archived=False,
                current=True,
                note=active_note,
            )
            return [*stored_versions, current_version]

        if not stored_versions:
            raise UserNoteNotFoundError(f"user note not found: {note_id}")
        latest_index = len(stored_versions) - 1
        return [
            version.model_copy(update={"current": index == latest_index})
            for index, version in enumerate(stored_versions)
        ]

    def _current_version_number(self, note_id: str) -> int:
        """Return the version number that corresponds to the active note snapshot."""
        return len(self.database.list_user_note_versions(note_id)) + 1
