"""Unit tests for the Nginx Proxy Manager deep-inspection adapter."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

from kaval.integrations.npm_adapter import (
    NginxProxyManagerAdapter,
    NginxProxyManagerClient,
    NginxProxyManagerClientConfig,
)
from kaval.integrations.service_adapters import AdapterStatus
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "npm"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def load_fixture(name: str) -> bytes:
    """Load one NPM fixture as raw bytes."""
    return (FIXTURES_DIR / name).read_bytes()


def build_service() -> Service:
    """Create a representative NPM service record."""
    return Service(
        id="svc-nginx-proxy-manager",
        name="Nginx Proxy Manager",
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.HEALTHY,
        descriptor_id="networking/nginx_proxy_manager",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-npm",
        vm_id=None,
        image="jc21/nginx-proxy-manager:2.12.1",
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=ts(10),
        active_findings=0,
        active_incidents=0,
    )


def test_npm_adapter_collects_proxy_hosts_certificates_and_upstream_edges() -> None:
    """The adapter should authenticate and return structured NPM facts."""
    calls: list[tuple[str, str]] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        calls.append((http_request.get_method(), http_request.full_url))
        if http_request.full_url.endswith("/api"):
            return load_fixture("status.json")
        if http_request.full_url.endswith("/api/tokens"):
            assert http_request.data is not None
            assert json.loads(http_request.data.decode("utf-8")) == {
                "identity": "admin@example.com",
                "secret": "super-secret",
            }
            return load_fixture("token.json")
        if http_request.full_url.endswith("/api/nginx/proxy-hosts"):
            assert http_request.headers["Authorization"] == "Bearer npm-access-token"
            return load_fixture("proxy_hosts.json")
        if http_request.full_url.endswith("/api/nginx/certificates"):
            assert http_request.headers["Authorization"] == "Bearer npm-access-token"
            return load_fixture("certificates.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = NginxProxyManagerAdapter(
        client=NginxProxyManagerClient(
            config=NginxProxyManagerClientConfig(base_url="http://npm.local:81"),
            transport=transport,
        )
    )

    result = asyncio.run(
        adapter.inspect(
            build_service(),
            {"identity": "admin@example.com", "secret": "super-secret"},
        )
    )

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert result.facts["version"] == {
        "major": 2,
        "minor": 12,
        "revision": 1,
        "version_string": "2.12.1",
    }
    assert len(result.facts["proxy_hosts"]) == 2
    assert len(result.facts["certificates"]) == 1
    assert result.facts["certificate_bindings"] == [
        {
            "proxy_host_id": 12,
            "proxy_host_domains": ["app.example.com", "www.app.example.com"],
            "certificate_id": 44,
            "certificate_domains": ["app.example.com", "*.example.com"],
            "certificate_expires_on": "2026-06-01T00:00:00Z",
        }
    ]
    assert [edge.target_service_name for edge in result.edges_discovered] == [
        "radarr",
        "prowlarr",
    ]
    assert calls == [
        ("GET", "http://npm.local:81/api"),
        ("POST", "http://npm.local:81/api/tokens"),
        ("GET", "http://npm.local:81/api/nginx/proxy-hosts"),
        ("GET", "http://npm.local:81/api/nginx/certificates"),
    ]


def test_npm_adapter_reports_auth_failures_cleanly() -> None:
    """Authentication failures should surface without throwing."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api"):
            return load_fixture("status.json")
        raise error.HTTPError(
            http_request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    adapter = NginxProxyManagerAdapter(
        client=NginxProxyManagerClient(transport=transport)
    )

    result = asyncio.run(
        adapter.inspect(
            build_service(),
            {"identity": "admin@example.com", "secret": "wrong"},
        )
    )

    assert result.status == AdapterStatus.AUTH_FAILED
    assert result.facts == {}
    assert result.edges_discovered == []


def test_npm_adapter_reports_connection_failures_cleanly() -> None:
    """Transport failures should surface as connection failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        raise error.URLError("connection refused")

    adapter = NginxProxyManagerAdapter(
        client=NginxProxyManagerClient(transport=transport)
    )

    result = asyncio.run(
        adapter.inspect(
            build_service(),
            {"identity": "admin@example.com", "secret": "super-secret"},
        )
    )

    assert result.status == AdapterStatus.CONNECTION_FAILED
    assert result.reason == "NPM API request failed"


def test_npm_adapter_reports_parse_failures_cleanly() -> None:
    """Invalid JSON or response shapes should surface as parse failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api"):
            return load_fixture("status.json")
        if http_request.full_url.endswith("/api/tokens"):
            return load_fixture("token.json")
        if http_request.full_url.endswith("/api/nginx/proxy-hosts"):
            return b"{\"not\": \"a list\"}"
        if http_request.full_url.endswith("/api/nginx/certificates"):
            return load_fixture("certificates.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = NginxProxyManagerAdapter(
        client=NginxProxyManagerClient(transport=transport)
    )

    result = asyncio.run(
        adapter.inspect(
            build_service(),
            {"identity": "admin@example.com", "secret": "super-secret"},
        )
    )

    assert result.status == AdapterStatus.PARSE_ERROR
    assert result.reason == "NPM proxy-host response was not a list"


def test_npm_adapter_reports_version_incompatibility_cleanly() -> None:
    """Unsupported major versions should stop before auth or data fetches."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api"):
            return json.dumps(
                {
                    "status": "OK",
                    "setup": False,
                    "version": {"major": 3, "minor": 0, "revision": 0},
                }
            ).encode("utf-8")
        raise AssertionError("version check should stop further requests")

    adapter = NginxProxyManagerAdapter(
        client=NginxProxyManagerClient(transport=transport)
    )

    result = asyncio.run(
        adapter.inspect(
            build_service(),
            {"identity": "admin@example.com", "secret": "super-secret"},
        )
    )

    assert result.status == AdapterStatus.VERSION_INCOMPATIBLE
    assert "outside the supported range" in (result.reason or "")
