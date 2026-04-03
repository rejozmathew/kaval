"""Unit tests for the Radarr deep-inspection adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

from kaval.integrations.radarr_adapter import RadarrAdapter, RadarrClient
from kaval.integrations.service_adapters import AdapterStatus
from kaval.models import (
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "radarr"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def load_fixture(name: str) -> bytes:
    """Load one Radarr fixture as raw bytes."""
    return (FIXTURES_DIR / name).read_bytes()


def build_service() -> Service:
    """Create a representative Radarr service record."""
    return Service(
        id="svc-radarr",
        name="Radarr",
        type=ServiceType.CONTAINER,
        category="arr",
        status=ServiceStatus.HEALTHY,
        descriptor_id="arr/radarr",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-radarr",
        vm_id=None,
        image="linuxserver/radarr:5.6.0",
        endpoints=[
            Endpoint(
                name="web_ui",
                protocol=EndpointProtocol.HTTP,
                host="radarr",
                port=7878,
                path="/",
                auth_required=False,
                expected_status=200,
            )
        ],
        dependencies=[],
        dependents=[],
        last_check=ts(10),
        active_findings=0,
        active_incidents=0,
    )


def test_radarr_adapter_collects_structured_facts_and_runtime_edges() -> None:
    """The adapter should collect investigation facts without exposing raw fields."""
    calls: list[str] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        calls.append(http_request.full_url)
        assert http_request.headers["X-api-key"] == "radarr-secret"
        if http_request.full_url.endswith("/api/v3/system/status"):
            return load_fixture("system_status.json")
        if http_request.full_url.endswith("/api/v3/health"):
            return load_fixture("health.json")
        if http_request.full_url.endswith("/api/v3/downloadclient"):
            return load_fixture("downloadclients.json")
        if http_request.full_url.endswith("/api/v3/indexer"):
            return load_fixture("indexers.json")
        if http_request.full_url.endswith("/api/v3/queue/status"):
            return load_fixture("queue_status.json")
        if http_request.full_url.endswith("/api/v3/queue/details"):
            return load_fixture("queue_details.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = RadarrAdapter(client=RadarrClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"api_key": "radarr-secret"}))

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert result.facts["version"] == {
        "version_string": "5.6.0.9041",
        "major": 5,
        "minor": 6,
        "patch": 0,
        "build": 9041,
    }
    assert result.facts["runtime_info"] == {
        "app_name": "Radarr",
        "instance_name": "Radarr",
        "branch": "master",
        "os_name": "Linux",
        "os_version": "6.6.45",
        "mode": "console",
        "database_type": "sqlite",
        "is_docker": True,
        "is_linux": True,
        "is_windows": False,
        "is_osx": False,
        "is_production": True,
    }
    assert result.facts["startup_path"] == "/app/radarr/bin"
    assert result.facts["download_client_status"] == {
        "configured": 2,
        "enabled": 2,
        "warning_count": 0,
        "error_count": 1,
    }
    assert result.facts["indexer_status"] == {
        "configured": 2,
        "rss_enabled": 1,
        "automatic_search_enabled": 2,
        "interactive_search_enabled": 2,
        "warning_count": 1,
        "error_count": 0,
    }
    assert len(result.facts["download_clients"]) == 2
    assert all("fields" not in item for item in result.facts["download_clients"])
    assert len(result.facts["indexers"]) == 2
    assert result.facts["queue_status"] == {
        "total_count": 3,
        "count": 2,
        "unknown_count": 1,
        "errors": True,
        "warnings": True,
        "unknown_errors": False,
        "unknown_warnings": True,
    }
    assert [item["id"] for item in result.facts["queue_items"]] == [101, 102]
    assert [edge.target_service_name for edge in result.edges_discovered] == [
        "DelugeVPN",
        "qBittorrent",
    ]
    assert calls == [
        "http://localhost:7878/api/v3/system/status",
        "http://localhost:7878/api/v3/health",
        "http://localhost:7878/api/v3/downloadclient",
        "http://localhost:7878/api/v3/indexer",
        "http://localhost:7878/api/v3/queue/status",
        "http://localhost:7878/api/v3/queue/details",
    ]


def test_radarr_adapter_reports_auth_failures_cleanly() -> None:
    """Authentication failures should surface without throwing."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        raise error.HTTPError(
            http_request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    adapter = RadarrAdapter(client=RadarrClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"api_key": "wrong"}))

    assert result.status == AdapterStatus.AUTH_FAILED
    assert result.facts == {}
    assert result.edges_discovered == []


def test_radarr_adapter_reports_connection_failures_cleanly() -> None:
    """Transport failures should surface as connection failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        raise error.URLError("connection refused")

    adapter = RadarrAdapter(client=RadarrClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"api_key": "radarr-secret"}))

    assert result.status == AdapterStatus.CONNECTION_FAILED
    assert result.reason == "Radarr API request failed"


def test_radarr_adapter_reports_parse_failures_cleanly() -> None:
    """Invalid JSON or response shapes should surface as parse failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api/v3/system/status"):
            return load_fixture("system_status.json")
        if http_request.full_url.endswith("/api/v3/health"):
            return load_fixture("health.json")
        if http_request.full_url.endswith("/api/v3/downloadclient"):
            return b"{\"not\": \"a list\"}"
        if http_request.full_url.endswith("/api/v3/indexer"):
            return load_fixture("indexers.json")
        if http_request.full_url.endswith("/api/v3/queue/status"):
            return load_fixture("queue_status.json")
        if http_request.full_url.endswith("/api/v3/queue/details"):
            return load_fixture("queue_details.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = RadarrAdapter(client=RadarrClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"api_key": "radarr-secret"}))

    assert result.status == AdapterStatus.PARSE_ERROR
    assert result.reason == "Radarr download client response was not a list"


def test_radarr_adapter_reports_version_incompatibility_cleanly() -> None:
    """Unsupported major versions should stop before further requests."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api/v3/system/status"):
            return (
                b"{"
                b"\"appName\":\"Radarr\","
                b"\"instanceName\":\"Radarr\","
                b"\"version\":\"2.0.0.1\","
                b"\"startupPath\":\"/app\","
                b"\"osName\":\"Linux\","
                b"\"osVersion\":\"6.6.45\","
                b"\"mode\":\"console\","
                b"\"branch\":\"master\","
                b"\"databaseType\":\"sqlite\","
                b"\"isProduction\":true,"
                b"\"isLinux\":true,"
                b"\"isOsx\":false,"
                b"\"isWindows\":false,"
                b"\"isDocker\":true"
                b"}"
            )
        raise AssertionError("version check should stop further requests")

    adapter = RadarrAdapter(client=RadarrClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"api_key": "radarr-secret"}))

    assert result.status == AdapterStatus.VERSION_INCOMPATIBLE
    assert "outside the supported range" in (result.reason or "")
