"""Unit tests for the Unraid system monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.unraid import build_discovery_snapshot, decode_graphql_data
from kaval.models import Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.unraid_system import UnraidSystemCheck

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture used by Unraid system check tests."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_unraid_system_check_skips_healthy_fixture() -> None:
    """A healthy fixture should emit no Unraid system findings."""
    snapshot = _snapshot_from_payload(load_fixture("discovery_response.json"))

    findings = UnraidSystemCheck().run(
        CheckContext(services=[], unraid_snapshot=snapshot, now=ts(18, 0))
    )

    assert findings == []


def test_unraid_system_check_flags_array_and_disk_status() -> None:
    """Degraded array and disk statuses should emit findings."""
    payload = load_fixture("discovery_response.json")
    payload["data"]["array"]["state"] = "REBUILDING"  # type: ignore[index]
    payload["data"]["array"]["disks"][1]["status"] = "DISK_DSBL"  # type: ignore[index]
    snapshot = _snapshot_from_payload(payload)

    findings = UnraidSystemCheck().run(
        CheckContext(services=[], unraid_snapshot=snapshot, now=ts(18, 5))
    )

    assert len(findings) == 2
    assert findings[0].title == "Unraid array is not healthy"
    assert findings[0].severity == Severity.HIGH
    assert findings[1].title == "Unraid disk disk1 reports a degraded status"
    assert findings[1].severity == Severity.HIGH


def test_unraid_system_check_flags_share_capacity_thresholds() -> None:
    """Shares above the configured usage thresholds should emit findings."""
    payload = load_fixture("discovery_response.json")
    payload["data"]["shares"][0]["used"] = 92
    payload["data"]["shares"][0]["free"] = 8
    payload["data"]["shares"][0]["total"] = 100
    snapshot = _snapshot_from_payload(payload)

    findings = UnraidSystemCheck().run(
        CheckContext(services=[], unraid_snapshot=snapshot, now=ts(18, 10))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-share-media"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].summary == "Share media is using 92.0% of its reported capacity."


def _snapshot_from_payload(payload: dict[str, object]):
    """Build a typed Unraid snapshot from a GraphQL fixture payload."""
    data = decode_graphql_data(payload)
    return build_discovery_snapshot(data, discovered_at=ts(17, 55))
