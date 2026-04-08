"""Operational memory package with lazy exports to avoid import cycles."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORT_TO_MODULE = {
    "DEFAULT_JOURNAL_STALE_AFTER_DAYS": "kaval.memory.journal",
    "IncidentResolutionConflictError": "kaval.memory.journal",
    "IncidentResolutionError": "kaval.memory.journal",
    "IncidentResolutionNotFoundError": "kaval.memory.journal",
    "IncidentResolutionResult": "kaval.memory.journal",
    "OperationalJournalService": "kaval.memory.journal",
    "RecurrenceAnalysis": "kaval.memory.recurrence",
    "detect_recurrences": "kaval.memory.recurrence",
    "CloudRedactionReplacement": "kaval.memory.redaction",
    "StructuredRedactionPolicy": "kaval.memory.redaction",
    "StructuredRedactionResult": "kaval.memory.redaction",
    "build_cloud_redaction_replacements": "kaval.memory.redaction",
    "redact_for_cloud": "kaval.memory.redaction",
    "redact_for_local": "kaval.memory.redaction",
    "redact_json_value": "kaval.memory.redaction",
    "redact_text": "kaval.memory.redaction",
}

__all__ = list(_EXPORT_TO_MODULE)


def __getattr__(name: str) -> Any:
    """Resolve package-level exports lazily so submodules stay decoupled."""
    module_name = _EXPORT_TO_MODULE.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value
