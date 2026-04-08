"""Typed user-note history models for Phase 3B note management."""

from __future__ import annotations

from datetime import datetime
from typing import Self
from uuid import uuid4

from pydantic import Field, model_validator

from kaval.models import KavalModel, UserNote


def _new_user_note_version_id() -> str:
    """Return a stable identifier for one persisted user-note version snapshot."""
    return f"notever-{uuid4()}"


class UserNoteCreate(KavalModel):
    """Typed input for creating one active user note."""

    service_id: str | None = None
    note: str = Field(min_length=1)
    safe_for_model: bool = True
    last_verified_at: datetime | None = None
    stale: bool = False


class UserNoteUpdate(KavalModel):
    """Typed input for updating one active user note."""

    service_id: str | None = None
    note: str | None = Field(default=None, min_length=1)
    safe_for_model: bool | None = None
    last_verified_at: datetime | None = None
    stale: bool | None = None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> Self:
        """Require at least one field so note updates stay meaningful."""
        if not self.model_fields_set:
            msg = "at least one user note field must be provided"
            raise ValueError(msg)
        return self


class UserNoteVersion(KavalModel):
    """One stored or synthesized version entry for a user note."""

    id: str = Field(default_factory=_new_user_note_version_id, min_length=1)
    note_id: str = Field(min_length=1)
    version_number: int = Field(ge=1)
    recorded_at: datetime
    archived: bool = False
    current: bool = False
    note: UserNote
