"""Unit tests for the Phase 1 Unraid discovery adapter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.discovery.unraid import (
    UnraidArraySnapshot,
    UnraidClientConfig,
    UnraidDiscoverySnapshot,
    UnraidGraphQLError,
    build_discovery_snapshot,
    decode_graphql_data,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture for Unraid discovery tests."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_unraid_client_config_builds_graphql_url() -> None:
    """The client config should normalize the GraphQL endpoint URL."""
    config = UnraidClientConfig(base_url="http://tower.local/", api_key="secret")

    assert config.graphql_url() == "http://tower.local/graphql"


def test_build_discovery_snapshot_from_fixture() -> None:
    """The Unraid fixture should map cleanly into typed discovery models."""
    payload = load_fixture("discovery_response.json")
    data = decode_graphql_data(payload)

    snapshot = build_discovery_snapshot(data, discovered_at=ts(9, 30))

    assert isinstance(snapshot, UnraidDiscoverySnapshot)
    assert snapshot.discovered_at == ts(9, 30)
    assert snapshot.system_info.hostname == "zactower"
    assert snapshot.system_info.os.release == "7.2.1"
    assert snapshot.system_info.cpu.brand == "Intel i3-12100T"
    assert snapshot.array == UnraidArraySnapshot(
        state="STARTED",
        capacity={"free": 8589934592, "used": 4519714816, "total": 13109649408},
        disks=[
            {
                "name": "parity",
                "size": 4000000000000,
                "status": "VALID",
                "temp": 35,
            },
            {
                "name": "disk1",
                "size": 4000000000000,
                "status": "OK",
                "temp": 34,
            },
        ],
    )
    assert [container.id for container in snapshot.containers] == ["abc123", "def456"]
    assert snapshot.containers[0].auto_start is True
    assert snapshot.vms[0].name == "Ubuntu Server"
    assert snapshot.shares[0].primary_storage == "array"
    assert snapshot.plugins[0].update_available is False


def test_decode_graphql_data_raises_for_errors() -> None:
    """GraphQL error payloads should fail fast with a typed error."""
    payload = load_fixture("graphql_error_response.json")

    with pytest.raises(UnraidGraphQLError, match="Cannot query field"):
        decode_graphql_data(payload)
