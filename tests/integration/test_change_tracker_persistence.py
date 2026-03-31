"""Integration tests for persisting detected change events."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.change_tracker import ChangeTracker, persist_changes
from kaval.database import KavalDatabase
from kaval.discovery.docker import build_discovery_snapshot

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"


def load_json_fixture(name: str) -> dict[str, object]:
    """Load a Docker JSON fixture for change persistence tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_persist_changes_writes_detected_events_to_sqlite(tmp_path: Path) -> None:
    """Detected change events should persist cleanly into the existing changes table."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()

    tracker = ChangeTracker()
    tracker.detect_changes(_snapshot(discovered_at=ts(20, 0)))
    changes = tracker.detect_changes(
        _snapshot(
            discovered_at=ts(20, 10),
            def456_restart_count=7,
        )
    )

    persist_changes(database, changes)

    stored_change = database.get_change(changes[0].id)
    assert stored_change == changes[0]


def _snapshot(
    *,
    discovered_at: datetime,
    def456_restart_count: int = 4,
) -> object:
    """Build a Docker discovery snapshot for persistence tests."""
    abc123 = copy.deepcopy(load_json_fixture("container_inspect_abc123.json"))
    def456 = copy.deepcopy(load_json_fixture("container_inspect_def456.json"))
    def456["RestartCount"] = def456_restart_count
    return build_discovery_snapshot(
        [abc123, def456],
        {
            "sha256:img-radarr": load_json_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_json_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
        discovered_at=discovered_at,
    )
