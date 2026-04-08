"""Unit tests for transport-local Telegram memory command parsing."""

from __future__ import annotations

import pytest

from kaval.notifications.telegram_memory import (
    TelegramMemoryCommandKind,
    TelegramMemoryCommandParseError,
    parse_telegram_memory_command,
    supports_telegram_memory_command,
)


def test_parse_telegram_memory_command_supports_note_and_recurrence() -> None:
    """Supported Telegram memory commands should parse into typed command models."""
    note_command = parse_telegram_memory_command(
        '/note@KavalBot "Ubuntu Server" Check the LVM partition first.'
    )
    recurrence_command = parse_telegram_memory_command("/recurrence")

    assert note_command.kind is TelegramMemoryCommandKind.NOTE
    assert note_command.raw_arguments == '"Ubuntu Server" Check the LVM partition first.'
    assert recurrence_command.kind is TelegramMemoryCommandKind.RECURRENCE
    assert recurrence_command.raw_arguments == ""


def test_parse_telegram_memory_command_rejects_invalid_shapes() -> None:
    """Unsupported or incomplete Telegram memory commands should fail clearly."""
    with pytest.raises(TelegramMemoryCommandParseError, match="/notes requires <service>"):
        parse_telegram_memory_command("/notes")

    with pytest.raises(
        TelegramMemoryCommandParseError,
        match="/recurrence does not accept arguments",
    ):
        parse_telegram_memory_command("/recurrence extra")

    with pytest.raises(
        TelegramMemoryCommandParseError,
        match="unsupported telegram memory command",
    ):
        parse_telegram_memory_command("/memory")


def test_supports_telegram_memory_command_distinguishes_supported_commands() -> None:
    """Ingress should recognize only the supported Phase 3B memory commands."""
    assert supports_telegram_memory_command("/notes DelugeVPN") is True
    assert supports_telegram_memory_command("/journal@KavalBot DelugeVPN") is True
    assert supports_telegram_memory_command("/start") is False
    assert supports_telegram_memory_command("note: DelugeVPN is flaky") is False
