"""Integration tests for running the Unraid system check through the scheduler."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.unraid import build_discovery_snapshot, decode_graphql_data
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.unraid_system import UnraidSystemCheck
from kaval.monitoring.scheduler import CheckScheduler

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by the Unraid system integration test."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic scheduler assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_unraid_system_check_runs_through_scheduler() -> None:
    """The scheduler should execute the Unraid system check and surface findings."""
    payload = load_fixture("discovery_response.json")
    payload["data"]["array"]["state"] = "STOPPED"  # type: ignore[index]
    snapshot = build_discovery_snapshot(
        decode_graphql_data(payload),
        discovered_at=ts(18, 25),
    )
    scheduler = CheckScheduler([UnraidSystemCheck(interval_seconds=600)])

    result = scheduler.run_due_checks(
        CheckContext(services=[], unraid_snapshot=snapshot, now=ts(18, 30))
    )

    assert result.executed_checks == ("unraid_system",)
    assert len(result.findings) == 1
    assert result.findings[0].service_id == "svc-system-unraid"
