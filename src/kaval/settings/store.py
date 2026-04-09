"""Shared helpers for persisted admin settings documents."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import yaml  # type: ignore[import-untyped]


def load_settings_document(path: Path) -> tuple[dict[str, object], str | None]:
    """Load one persisted YAML settings root as a string-keyed mapping."""
    if not path.exists():
        return {}, None
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return {}, f"Persisted settings YAML could not be parsed: {exc}"
    if payload is None:
        return {}, None
    if not isinstance(payload, Mapping):
        return {}, "Persisted settings root must be a YAML mapping."
    return normalize_mapping(payload), None


def write_settings_document(path: Path, root_document: Mapping[str, object]) -> None:
    """Write one normalized persisted settings root to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(dict(root_document), sort_keys=False),
        encoding="utf-8",
    )


def normalize_mapping(value: Mapping[Any, Any]) -> dict[str, object]:
    """Convert one arbitrary mapping into a string-keyed plain dictionary."""
    normalized: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            msg = "settings mappings must use string keys"
            raise ValueError(msg)
        if isinstance(item, Mapping):
            normalized[key] = normalize_mapping(item)
            continue
        normalized[key] = cast(object, item)
    return normalized


def deep_merge(
    base: Mapping[str, object],
    overrides: Mapping[str, object],
) -> dict[str, object]:
    """Merge one nested override mapping over a base mapping."""
    merged = dict(base)
    for key, value in overrides.items():
        current_value = merged.get(key)
        if isinstance(current_value, dict) and isinstance(value, Mapping):
            merged[key] = deep_merge(current_value, normalize_mapping(value))
            continue
        merged[key] = value
    return merged
