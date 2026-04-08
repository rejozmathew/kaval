"""Transport-local Telegram memory command parsing and handling."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from pydantic import Field

from kaval.database import KavalDatabase
from kaval.memory.note_models import UserNoteCreate
from kaval.memory.user_notes import UserNoteService
from kaval.models import JournalConfidence, JournalEntry, KavalModel, Service, UserNote

_DEFAULT_RESULT_LIMIT = 5
_ALIAS_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")
_SUPPORTED_COMMAND_NAMES = frozenset({"/note", "/notes", "/journal", "/recurrence"})


class TelegramMemoryCommandError(RuntimeError):
    """Base error for transport-local Telegram memory commands."""


class TelegramMemoryCommandParseError(TelegramMemoryCommandError):
    """Raised when one Telegram memory command cannot be parsed."""


class TelegramMemoryCommandServiceNotFoundError(TelegramMemoryCommandError):
    """Raised when a Telegram command references an unknown service."""


class TelegramMemoryCommandServiceAmbiguousError(TelegramMemoryCommandError):
    """Raised when a Telegram command matches more than one service or split."""


class TelegramMemoryCommandKind(StrEnum):
    """Supported Telegram memory commands for Phase 3B."""

    NOTE = "note"
    NOTES = "notes"
    JOURNAL = "journal"
    RECURRENCE = "recurrence"


class TelegramMemoryCommand(KavalModel):
    """One parsed Telegram memory command."""

    kind: TelegramMemoryCommandKind
    raw_arguments: str = ""


class TelegramMemoryServiceRef(KavalModel):
    """One service reference resolved for a Telegram memory command."""

    service_id: str
    service_name: str


class TelegramMemoryNoteSummary(KavalModel):
    """Compact note summary returned by Telegram memory commands."""

    note_id: str
    note: str
    safe_for_model: bool
    stale: bool
    updated_at: datetime


class TelegramMemoryJournalSummary(KavalModel):
    """Compact journal summary returned by Telegram memory commands."""

    journal_entry_id: str
    date: date
    summary: str
    confidence: JournalConfidence
    recurrence_count: int


class TelegramMemoryRecurrenceSummary(KavalModel):
    """One active recurrence pattern surfaced through Telegram."""

    journal_entry_id: str
    date: date
    services: list[str] = Field(default_factory=list)
    summary: str
    confidence: JournalConfidence
    recurrence_count: int


class TelegramMemoryCommandResult(KavalModel):
    """Structured result for one Telegram memory command execution."""

    kind: TelegramMemoryCommandKind
    service: TelegramMemoryServiceRef | None = None
    created_note: TelegramMemoryNoteSummary | None = None
    notes: list[TelegramMemoryNoteSummary] = Field(default_factory=list)
    journal_entries: list[TelegramMemoryJournalSummary] = Field(default_factory=list)
    recurrences: list[TelegramMemoryRecurrenceSummary] = Field(default_factory=list)
    message_text: str


@dataclass(slots=True)
class TelegramMemoryCommandHandler:
    """Handle transport-local Telegram memory commands against persisted state."""

    database: KavalDatabase
    result_limit: int = _DEFAULT_RESULT_LIMIT

    def __post_init__(self) -> None:
        """Validate command-output limits."""
        if self.result_limit <= 0:
            msg = "result_limit must be positive"
            raise ValueError(msg)

    def handle_message(
        self,
        message_text: str,
        *,
        now: datetime | None = None,
    ) -> TelegramMemoryCommandResult:
        """Parse one Telegram memory command and handle it locally."""
        return self.handle(parse_telegram_memory_command(message_text), now=now)

    def handle(
        self,
        command: TelegramMemoryCommand,
        *,
        now: datetime | None = None,
    ) -> TelegramMemoryCommandResult:
        """Execute one previously parsed Telegram memory command."""
        if command.kind is TelegramMemoryCommandKind.NOTE:
            return self._handle_note(command.raw_arguments, now=now)
        if command.kind is TelegramMemoryCommandKind.NOTES:
            return self._handle_notes(command.raw_arguments)
        if command.kind is TelegramMemoryCommandKind.JOURNAL:
            return self._handle_journal(command.raw_arguments)
        return self._handle_recurrence()

    def _handle_note(
        self,
        raw_arguments: str,
        *,
        now: datetime | None,
    ) -> TelegramMemoryCommandResult:
        """Create one new note from a Telegram `/note` command."""
        service, note_text = self._resolve_note_target(raw_arguments)
        created_note = UserNoteService(database=self.database).create_note(
            UserNoteCreate(service_id=service.id, note=note_text),
            now=now,
        )
        service_ref = _service_ref(service)
        note_summary = _note_summary(created_note)
        return TelegramMemoryCommandResult(
            kind=TelegramMemoryCommandKind.NOTE,
            service=service_ref,
            created_note=note_summary,
            message_text=(
                f"Saved note for {service.name}.\n\n"
                f"{note_text}"
            ),
        )

    def _handle_notes(self, raw_arguments: str) -> TelegramMemoryCommandResult:
        """List recent notes for one service from a Telegram `/notes` command."""
        service = self._resolve_service(raw_arguments)
        notes = [
            _note_summary(note)
            for note in _recent_notes(
                UserNoteService(database=self.database).list_notes(service_id=service.id),
                limit=self.result_limit,
            )
        ]
        return TelegramMemoryCommandResult(
            kind=TelegramMemoryCommandKind.NOTES,
            service=_service_ref(service),
            notes=notes,
            message_text=_format_notes_message(
                service=service,
                notes=notes,
                total_count=len(UserNoteService(database=self.database).list_notes(service_id=service.id)),
            ),
        )

    def _handle_journal(self, raw_arguments: str) -> TelegramMemoryCommandResult:
        """List recent journal entries for one service from `/journal`."""
        service = self._resolve_service(raw_arguments)
        journal_entries = [
            _journal_summary(entry)
            for entry in _recent_journal_entries(
                self.database.list_journal_entries(),
                service_id=service.id,
                limit=self.result_limit,
            )
        ]
        return TelegramMemoryCommandResult(
            kind=TelegramMemoryCommandKind.JOURNAL,
            service=_service_ref(service),
            journal_entries=journal_entries,
            message_text=_format_journal_message(service=service, entries=journal_entries),
        )

    def _handle_recurrence(self) -> TelegramMemoryCommandResult:
        """List active recurrence patterns from `/recurrence`."""
        service_name_map = {
            service.id: service.name for service in self.database.list_services()
        }
        recurrences = [
            _recurrence_summary(entry, service_name_map=service_name_map)
            for entry in _active_recurrence_entries(
                self.database.list_journal_entries(),
                limit=self.result_limit,
            )
        ]
        return TelegramMemoryCommandResult(
            kind=TelegramMemoryCommandKind.RECURRENCE,
            recurrences=recurrences,
            message_text=_format_recurrence_message(recurrences),
        )

    def _resolve_note_target(self, raw_arguments: str) -> tuple[Service, str]:
        """Resolve the service and note text for one `/note` command."""
        tokens = _split_command_arguments(raw_arguments)
        if len(tokens) < 2:
            msg = "/note requires <service> <text>"
            raise TelegramMemoryCommandParseError(msg)

        candidates: list[tuple[Service, str]] = []
        for split_index in range(1, len(tokens)):
            service_query = " ".join(tokens[:split_index])
            note_text = " ".join(tokens[split_index:]).strip()
            if not note_text:
                continue
            service_matches = self._resolve_service_candidates(service_query)
            if len(service_matches) == 1:
                candidates.append((service_matches[0], note_text))

        unique_candidates: dict[tuple[str, str], tuple[Service, str]] = {
            (service.id, note_text): (service, note_text)
            for service, note_text in candidates
        }
        if len(unique_candidates) == 1:
            return next(iter(unique_candidates.values()))
        if len(unique_candidates) > 1:
            msg = "note command is ambiguous; quote the service name or use the service id"
            raise TelegramMemoryCommandServiceAmbiguousError(msg)

        msg = (
            "note command could not resolve a service; "
            "use a known service id or quote multi-word service names"
        )
        raise TelegramMemoryCommandServiceNotFoundError(msg)

    def _resolve_service(self, query: str) -> Service:
        """Resolve one service query deterministically."""
        matches = self._resolve_service_candidates(query)
        if not matches:
            msg = f"service not found: {query.strip()}"
            raise TelegramMemoryCommandServiceNotFoundError(msg)
        if len(matches) > 1:
            service_names = ", ".join(service.name for service in matches)
            msg = (
                f"service reference is ambiguous: {query.strip()} "
                f"matches {service_names}"
            )
            raise TelegramMemoryCommandServiceAmbiguousError(msg)
        return matches[0]

    def _resolve_service_candidates(self, query: str) -> list[Service]:
        """Return all deterministic service matches for one query."""
        cleaned_query = _normalize_service_query(query)
        if not cleaned_query:
            return []
        services = self.database.list_services()
        exact_matches = _match_services(
            services,
            query=cleaned_query.casefold(),
            normalize=False,
        )
        if exact_matches:
            return exact_matches
        return _match_services(
            services,
            query=_normalize_alias(cleaned_query),
            normalize=True,
        )


def parse_telegram_memory_command(message_text: str) -> TelegramMemoryCommand:
    """Parse one Telegram memory command from raw transport text."""
    stripped_text = message_text.strip()
    if not stripped_text:
        msg = "telegram memory command must not be empty"
        raise TelegramMemoryCommandParseError(msg)

    command_text, _, raw_arguments = stripped_text.partition(" ")
    command_name = _canonical_command_name(command_text)
    arguments = raw_arguments.strip()
    if command_name == "/note":
        if not arguments:
            msg = "/note requires <service> <text>"
            raise TelegramMemoryCommandParseError(msg)
        return TelegramMemoryCommand(
            kind=TelegramMemoryCommandKind.NOTE,
            raw_arguments=arguments,
        )
    if command_name == "/notes":
        if not arguments:
            msg = "/notes requires <service>"
            raise TelegramMemoryCommandParseError(msg)
        return TelegramMemoryCommand(
            kind=TelegramMemoryCommandKind.NOTES,
            raw_arguments=arguments,
        )
    if command_name == "/journal":
        if not arguments:
            msg = "/journal requires <service>"
            raise TelegramMemoryCommandParseError(msg)
        return TelegramMemoryCommand(
            kind=TelegramMemoryCommandKind.JOURNAL,
            raw_arguments=arguments,
        )
    if command_name == "/recurrence":
        if arguments:
            msg = "/recurrence does not accept arguments"
            raise TelegramMemoryCommandParseError(msg)
        return TelegramMemoryCommand(kind=TelegramMemoryCommandKind.RECURRENCE)

    msg = f"unsupported telegram memory command: {command_text}"
    raise TelegramMemoryCommandParseError(msg)


def supports_telegram_memory_command(message_text: str) -> bool:
    """Return whether raw Telegram text targets the Phase 3B memory commands."""
    stripped_text = message_text.strip()
    if not stripped_text:
        return False
    command_text, _, _ = stripped_text.partition(" ")
    return _canonical_command_name(command_text) in _SUPPORTED_COMMAND_NAMES


def _match_services(
    services: list[Service],
    *,
    query: str,
    normalize: bool,
) -> list[Service]:
    """Return stable service matches for one exact or normalized query."""
    service_ids: set[str] = set()
    matches: list[Service] = []
    for service in services:
        aliases = _service_aliases(service, normalize=normalize)
        if query not in aliases or service.id in service_ids:
            continue
        service_ids.add(service.id)
        matches.append(service)
    matches.sort(key=lambda item: (item.name.casefold(), item.id))
    return matches


def _canonical_command_name(command_text: str) -> str:
    """Normalize one Telegram command token, stripping any bot-name suffix."""
    normalized = command_text.casefold().strip()
    command_name, separator, bot_name = normalized.partition("@")
    if separator and bot_name and command_name.startswith("/"):
        return command_name
    return normalized


def _service_aliases(service: Service, *, normalize: bool) -> set[str]:
    """Return deterministic aliases for one service."""
    aliases = {
        service.id,
        service.id.removeprefix("svc-"),
        service.name,
    }
    if normalize:
        return {
            normalized
            for alias in aliases
            if (normalized := _normalize_alias(alias))
        }
    return {alias.casefold().strip() for alias in aliases if alias.strip()}


def _normalize_service_query(query: str) -> str:
    """Return a parsed service query suitable for deterministic matching."""
    try:
        tokens = shlex.split(query)
    except ValueError as exc:
        msg = "telegram memory command arguments contain unmatched quotes"
        raise TelegramMemoryCommandParseError(msg) from exc
    return " ".join(tokens).strip()


def _split_command_arguments(arguments: str) -> list[str]:
    """Split one command argument string using shell-style quoting rules."""
    try:
        return shlex.split(arguments)
    except ValueError as exc:
        msg = "telegram memory command arguments contain unmatched quotes"
        raise TelegramMemoryCommandParseError(msg) from exc


def _normalize_alias(value: str) -> str:
    """Return a compact alias used for conservative fallback service matching."""
    return _ALIAS_NORMALIZE_RE.sub("", value.casefold())


def _service_ref(service: Service) -> TelegramMemoryServiceRef:
    """Return the Telegram-facing reference for one resolved service."""
    return TelegramMemoryServiceRef(service_id=service.id, service_name=service.name)


def _note_summary(note: UserNote) -> TelegramMemoryNoteSummary:
    """Return a compact note summary from a persisted user note."""
    return TelegramMemoryNoteSummary(
        note_id=note.id,
        note=note.note,
        safe_for_model=note.safe_for_model,
        stale=note.stale,
        updated_at=note.updated_at,
    )


def _journal_summary(entry: JournalEntry) -> TelegramMemoryJournalSummary:
    """Return a compact Telegram summary for one journal entry."""
    return TelegramMemoryJournalSummary(
        journal_entry_id=entry.id,
        date=entry.date,
        summary=entry.summary,
        confidence=entry.confidence,
        recurrence_count=entry.recurrence_count,
    )


def _recurrence_summary(
    entry: JournalEntry,
    *,
    service_name_map: dict[str, str],
) -> TelegramMemoryRecurrenceSummary:
    """Return a compact recurrence summary for one journal entry."""
    return TelegramMemoryRecurrenceSummary(
        journal_entry_id=entry.id,
        date=entry.date,
        services=[
            service_name_map.get(service_id, service_id)
            for service_id in entry.services
        ],
        summary=entry.summary,
        confidence=entry.confidence,
        recurrence_count=entry.recurrence_count,
    )


def _recent_notes(notes: list[UserNote], *, limit: int) -> list[UserNote]:
    """Return notes ordered from most recently updated to oldest."""
    return sorted(
        notes,
        key=lambda item: (
            getattr(item, "updated_at"),
            getattr(item, "id"),
        ),
        reverse=True,
    )[:limit]


def _recent_journal_entries(
    journal_entries: list[JournalEntry],
    *,
    service_id: str,
    limit: int,
) -> list[JournalEntry]:
    """Return recent journal entries touching one service."""
    return sorted(
        [
            entry
            for entry in journal_entries
            if service_id in entry.services
        ],
        key=lambda entry: (entry.date, entry.id),
        reverse=True,
    )[:limit]


def _active_recurrence_entries(
    journal_entries: list[JournalEntry],
    *,
    limit: int,
) -> list[JournalEntry]:
    """Return current recurrence-carrying journal entries in stable order."""
    return sorted(
        [
            entry
            for entry in journal_entries
            if entry.recurrence_count > 1 and entry.superseded_by is None
        ],
        key=lambda entry: (entry.recurrence_count, entry.date, entry.id),
        reverse=True,
    )[:limit]


def _format_notes_message(
    *,
    service: Service,
    notes: list[TelegramMemoryNoteSummary],
    total_count: int,
) -> str:
    """Format the Telegram text for one `/notes` response."""
    if not notes:
        return f"No notes found for {service.name}."
    header = f"Recent notes for {service.name}:"
    if total_count > len(notes):
        header = (
            f"Recent notes for {service.name} "
            f"(showing {len(notes)} of {total_count}):"
        )
    lines = [header]
    for note in notes:
        lines.append(
            f"- {note.updated_at.date().isoformat()} "
            f"[{_format_note_flags(note)}] {note.note}"
        )
    return "\n".join(lines)


def _format_journal_message(
    *,
    service: Service,
    entries: list[TelegramMemoryJournalSummary],
) -> str:
    """Format the Telegram text for one `/journal` response."""
    if not entries:
        return f"No journal entries found for {service.name}."
    lines = [f"Recent journal entries for {service.name}:"]
    for entry in entries:
        recurrence_suffix = (
            f", recurrence {entry.recurrence_count}x"
            if entry.recurrence_count > 1
            else ""
        )
        lines.append(
            f"- {entry.date.isoformat()} "
            f"[{entry.confidence.value}{recurrence_suffix}] {entry.summary}"
        )
    return "\n".join(lines)


def _format_recurrence_message(
    recurrences: list[TelegramMemoryRecurrenceSummary],
) -> str:
    """Format the Telegram text for one `/recurrence` response."""
    if not recurrences:
        return "No active recurrence patterns found."
    lines = ["Active recurrence patterns:"]
    for recurrence in recurrences:
        service_names = ", ".join(recurrence.services) or "unknown services"
        lines.append(
            f"- {recurrence.recurrence_count}x {service_names} "
            f"({recurrence.date.isoformat()}, {recurrence.confidence.value}): "
            f"{recurrence.summary}"
        )
    return "\n".join(lines)


def _format_note_flags(note: TelegramMemoryNoteSummary) -> str:
    """Return compact trust flags for one note summary."""
    flags = ["model-safe" if note.safe_for_model else "not-for-model"]
    if note.stale:
        flags.append("stale")
    return ", ".join(flags)
