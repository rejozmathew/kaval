"""Unit tests for the Pi-hole deep-inspection adapter."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

from kaval.integrations.pihole_adapter import PiHoleAdapter, PiHoleClient
from kaval.integrations.service_adapters import AdapterStatus
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "pihole"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def load_fixture(name: str) -> bytes:
    """Load one Pi-hole fixture as raw bytes."""
    return (FIXTURES_DIR / name).read_bytes()


def build_service() -> Service:
    """Create a representative Pi-hole service record."""
    return Service(
        id="svc-pihole",
        name="Pi-hole",
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.HEALTHY,
        descriptor_id="networking/pihole",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-pihole",
        vm_id=None,
        image="pihole/pihole:2026.01.0",
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=ts(11),
        active_findings=0,
        active_incidents=0,
    )


def test_pihole_adapter_collects_structured_facts_with_authenticated_session() -> None:
    """The adapter should authenticate once and return normalized Pi-hole facts."""
    calls: list[tuple[str, str]] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        calls.append((http_request.get_method(), http_request.full_url))
        if http_request.full_url == "http://pi.hole/api/auth":
            assert http_request.data is not None
            assert json.loads(http_request.data.decode("utf-8")) == {
                "password": "pihole-password",
            }
            return load_fixture("auth.json")
        assert http_request.get_header("X-ftl-sid") == "sid-123"
        if http_request.full_url == "http://pi.hole/api/config/dns":
            return load_fixture("dns_config.json")
        if http_request.full_url == "http://pi.hole/api/dns/blocking":
            return load_fixture("dns_blocking.json")
        if http_request.full_url == "http://pi.hole/api/stats/summary":
            return load_fixture("stats_summary.json")
        if http_request.full_url == "http://pi.hole/api/config/dhcp":
            return load_fixture("dhcp_config.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = PiHoleAdapter(client=PiHoleClient(transport=transport))

    result = asyncio.run(
        adapter.inspect(build_service(), {"password": "pihole-password"})
    )

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert result.facts["upstream_dns_servers"] == [
        {"address": "1.1.1.1", "port": None},
        {"address": "9.9.9.9", "port": 5353},
    ]
    assert result.facts["blocklist_status"] == {
        "blocking_enabled": True,
        "domains_being_blocked": 145632,
        "last_gravity_update": "2026-04-03T10:00:00Z",
        "queries_total": 12345,
        "queries_blocked": 678,
        "percent_blocked": 5.49,
    }
    assert result.facts["dhcp_config"] == {
        "active": True,
        "start": "192.168.1.100",
        "end": "192.168.1.150",
        "router": "192.168.1.1",
        "netmask": "255.255.255.0",
        "lease_time": "24h",
        "ipv6": False,
    }
    assert result.edges_discovered == []
    assert calls == [
        ("POST", "http://pi.hole/api/auth"),
        ("GET", "http://pi.hole/api/config/dns"),
        ("GET", "http://pi.hole/api/dns/blocking"),
        ("GET", "http://pi.hole/api/stats/summary"),
        ("GET", "http://pi.hole/api/config/dhcp"),
    ]


def test_pihole_adapter_supports_open_api_without_password() -> None:
    """Open Pi-hole installs should still produce facts without credentials."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        assert http_request.get_header("X-ftl-sid") is None
        if http_request.full_url == "http://pi.hole/api/config/dns":
            return load_fixture("dns_config.json")
        if http_request.full_url == "http://pi.hole/api/dns/blocking":
            return load_fixture("dns_blocking.json")
        if http_request.full_url == "http://pi.hole/api/stats/summary":
            return load_fixture("stats_summary.json")
        if http_request.full_url == "http://pi.hole/api/config/dhcp":
            return load_fixture("dhcp_config.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = PiHoleAdapter(client=PiHoleClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {}))

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert result.facts["blocklist_status"]["blocking_enabled"] is True


def test_pihole_adapter_reports_auth_failures_cleanly() -> None:
    """Wrong Pi-hole credentials should surface as auth failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        raise error.HTTPError(
            http_request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    adapter = PiHoleAdapter(client=PiHoleClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"password": "wrong"}))

    assert result.status == AdapterStatus.AUTH_FAILED
    assert result.reason == "Pi-hole authentication failed"
    assert result.facts == {}
    assert result.edges_discovered == []


def test_pihole_adapter_reports_missing_password_when_api_is_protected() -> None:
    """Protected Pi-hole installs should fail clearly if no password is supplied."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        raise error.HTTPError(
            http_request.full_url,
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )

    adapter = PiHoleAdapter(client=PiHoleClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {}))

    assert result.status == AdapterStatus.AUTH_FAILED
    assert (
        result.reason
        == "Pi-hole password or application password is required"
    )


def test_pihole_adapter_reports_connection_failures_cleanly() -> None:
    """Transport failures should surface as connection failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        raise error.URLError("connection refused")

    adapter = PiHoleAdapter(client=PiHoleClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), {"password": "pihole-password"}))

    assert result.status == AdapterStatus.CONNECTION_FAILED
    assert result.reason == "Pi-hole API request failed"
