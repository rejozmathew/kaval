"""Unit tests for the Cloudflare deep-inspection adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

from kaval.integrations.cloudflare_adapter import CloudflareAdapter, CloudflareClient
from kaval.integrations.service_adapters import AdapterStatus
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cloudflare"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def load_fixture(name: str) -> bytes:
    """Load one Cloudflare fixture as raw bytes."""
    return (FIXTURES_DIR / name).read_bytes()


def build_service() -> Service:
    """Create a representative cloudflared service record."""
    return Service(
        id="svc-cloudflared",
        name="cloudflared",
        type=ServiceType.CONTAINER,
        category="networking",
        status=ServiceStatus.HEALTHY,
        descriptor_id="networking/cloudflared",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-cloudflared",
        vm_id=None,
        image="cloudflare/cloudflared:2026.4.0",
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=ts(10),
        active_findings=0,
        active_incidents=0,
    )


def build_credentials() -> dict[str, str]:
    """Create the minimal explicit Cloudflare adapter input bundle."""
    return {
        "api_token": "cloudflare-token",
        "zone_name": "example.com",
        "account_id": "account-123",
        "tunnel_id": "tunnel-123",
    }


def test_cloudflare_adapter_collects_approved_scope_facts() -> None:
    """The adapter should return normalized facts for the approved Cloudflare scope."""
    calls: list[str] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        assert http_request.headers["Authorization"] == "Bearer cloudflare-token"
        calls.append(http_request.full_url)
        if http_request.full_url == "https://api.cloudflare.com/client/v4/zones?name=example.com":
            return load_fixture("zones.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records?page=1&per_page=100"
        ):
            return load_fixture("dns_records.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/settings/ssl"
        ):
            return load_fixture("ssl_mode.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123"
        ):
            return load_fixture("tunnel.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123/connections"
        ):
            return load_fixture("tunnel_connections.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/certificates?zone_id=zone-123"
        ):
            return load_fixture("origin_certificates.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = CloudflareAdapter(client=CloudflareClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), build_credentials()))

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert result.facts["zone"] == {
        "id": "zone-123",
        "name": "example.com",
        "status": "active",
        "paused": False,
        "type": "full",
    }
    assert result.facts["ssl_mode"] == {
        "id": "ssl",
        "value": "strict",
        "editable": True,
        "modified_on": "2026-04-03T10:30:00Z",
    }
    assert result.facts["proxy_status"] == {
        "total_records": 3,
        "proxied_records": 2,
        "dns_only_records": 1,
        "tunnel_routed_records": 1,
    }
    assert result.facts["tunnel_status"] == {
        "status": "healthy",
        "connection_count": 2,
        "active_connections": 1,
        "pending_reconnects": 1,
        "is_active": True,
        "last_connected_at": "2026-04-03T10:31:00Z",
    }
    assert result.facts["tunnel_dns_records"] == [
        {
            "id": "dns-2",
            "type": "CNAME",
            "name": "app.example.com",
            "content": "tunnel-123.cfargotunnel.com",
            "ttl": 1,
            "proxied": True,
            "proxiable": True,
            "comment": "cloudflared tunnel route",
            "created_on": "2026-01-10T10:05:00Z",
            "modified_on": "2026-04-03T10:05:00Z",
        }
    ]
    assert result.facts["origin_certificate_access"] == {
        "available": True,
        "reason": None,
    }
    assert result.facts["origin_certificates"] == [
        {
            "identifier": "origin-cert-1",
            "hostnames": ["example.com", "*.example.com"],
            "signature": "OriginECC",
            "requested_validity_days": 365,
            "expires_on": "2027-04-03T00:00:00Z",
        }
    ]
    assert result.edges_discovered == []
    assert calls == [
        "https://api.cloudflare.com/client/v4/zones?name=example.com",
        "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records?page=1&per_page=100",
        "https://api.cloudflare.com/client/v4/zones/zone-123/settings/ssl",
        "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123",
        "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123/connections",
        "https://api.cloudflare.com/client/v4/certificates?zone_id=zone-123",
    ]


def test_cloudflare_adapter_requires_zone_settings_read_for_ssl_mode() -> None:
    """Missing Zone Settings Read should fail clearly at the SSL mode step."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url == "https://api.cloudflare.com/client/v4/zones?name=example.com":
            return load_fixture("zones.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records?page=1&per_page=100"
        ):
            return load_fixture("dns_records.json")
        raise error.HTTPError(
            http_request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=None,
        )

    adapter = CloudflareAdapter(client=CloudflareClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), build_credentials()))

    assert result.status == AdapterStatus.AUTH_FAILED
    assert result.reason == "Cloudflare token requires Zone Settings Read to fetch SSL mode"
    assert result.facts == {}
    assert result.edges_discovered == []


def test_cloudflare_adapter_requires_tunnel_read_permission_for_tunnel_status() -> None:
    """Missing account-scoped tunnel-read access should fail clearly."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url == "https://api.cloudflare.com/client/v4/zones?name=example.com":
            return load_fixture("zones.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records?page=1&per_page=100"
        ):
            return load_fixture("dns_records.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/settings/ssl"
        ):
            return load_fixture("ssl_mode.json")
        raise error.HTTPError(
            http_request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=None,
        )

    adapter = CloudflareAdapter(client=CloudflareClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), build_credentials()))

    assert result.status == AdapterStatus.AUTH_FAILED
    assert "account-scoped tunnel-read permission" in (result.reason or "")
    assert result.facts == {}
    assert result.edges_discovered == []


def test_cloudflare_adapter_treats_origin_certificate_access_as_optional() -> None:
    """Origin certificate access should not be required for approved-scope success."""
    calls: list[str] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        calls.append(http_request.full_url)
        if http_request.full_url == "https://api.cloudflare.com/client/v4/zones?name=example.com":
            return load_fixture("zones.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/dns_records?page=1&per_page=100"
        ):
            return load_fixture("dns_records.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/zones/zone-123/settings/ssl"
        ):
            return load_fixture("ssl_mode.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123"
        ):
            return load_fixture("tunnel.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/accounts/account-123/cfd_tunnel/tunnel-123/connections"
        ):
            return load_fixture("tunnel_connections.json")
        if (
            http_request.full_url
            == "https://api.cloudflare.com/client/v4/certificates?zone_id=zone-123"
        ):
            raise error.HTTPError(
                http_request.full_url,
                403,
                "Forbidden",
                hdrs=None,
                fp=None,
            )
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = CloudflareAdapter(client=CloudflareClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), build_credentials()))

    assert result.status == AdapterStatus.SUCCESS
    assert result.facts["origin_certificates"] == []
    assert result.facts["origin_certificate_access"] == {
        "available": False,
        "reason": "Cloudflare token lacks permission to fetch origin certificates",
    }
    assert all("/teamnet/" not in url for url in calls)
    assert all("/routes" not in url for url in calls)


def test_cloudflare_adapter_reports_connection_failures_cleanly() -> None:
    """Transport failures should surface as connection failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        raise error.URLError("connection refused")

    adapter = CloudflareAdapter(client=CloudflareClient(transport=transport))

    result = asyncio.run(adapter.inspect(build_service(), build_credentials()))

    assert result.status == AdapterStatus.CONNECTION_FAILED
    assert result.reason == "Cloudflare API request failed"
