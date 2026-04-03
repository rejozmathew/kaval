"""Unit tests for the Authentik deep-inspection adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

from kaval.integrations.authentik_adapter import AuthentikAdapter, AuthentikClient
from kaval.integrations.service_adapters import AdapterStatus
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "authentik"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def load_fixture(name: str) -> bytes:
    """Load one Authentik fixture as raw bytes."""
    return (FIXTURES_DIR / name).read_bytes()


def build_service() -> Service:
    """Create a representative Authentik service record."""
    return Service(
        id="svc-authentik",
        name="Authentik",
        type=ServiceType.CONTAINER,
        category="identity",
        status=ServiceStatus.HEALTHY,
        descriptor_id="identity/authentik",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-authentik",
        vm_id=None,
        image="ghcr.io/goauthentik/server:2026.5.0",
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=ts(10),
        active_findings=0,
        active_incidents=0,
    )


def test_authentik_adapter_collects_identity_topology_facts_safely() -> None:
    """The adapter should collect Authentik topology without exposing sensitive blobs."""
    calls: list[str] = []

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        calls.append(http_request.full_url)
        assert http_request.headers["Authorization"] == "Bearer authentik-token"
        if http_request.full_url.endswith("/api/v3/core/applications/?page=1&page_size=100"):
            return load_fixture("applications.json")
        if http_request.full_url.endswith("/api/v3/providers/all/?page=1&page_size=100"):
            return load_fixture("providers.json")
        if http_request.full_url.endswith("/api/v3/outposts/instances/?page=1&page_size=100"):
            return load_fixture("outposts.json")
        if http_request.full_url.endswith(
            "/api/v3/outposts/instances/05a8f4bc-daea-4b41-b5dd-b38db7359b1f/health/"
        ):
            return load_fixture("outpost_health.json")
        if http_request.full_url.endswith("/api/v3/admin/version/"):
            return load_fixture("version.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = AuthentikAdapter(client=AuthentikClient(transport=transport))

    result = asyncio.run(
        adapter.inspect(build_service(), {"api_token": "authentik-token"})
    )

    assert result.status == AdapterStatus.SUCCESS
    assert result.reason is None
    assert len(result.facts["applications"]) == 2
    assert result.facts["applications"][0]["provider"]["name"] == "Nextcloud OIDC"
    assert result.facts["applications"][1]["backchannel_providers"][0]["name"] == "Grafana SCIM"
    assert len(result.facts["providers"]) == 3
    assert result.facts["providers"][2]["assigned_backchannel_application_slug"] == "grafana"
    assert result.facts["outposts"] == [
        {
            "pk": "05a8f4bc-daea-4b41-b5dd-b38db7359b1f",
            "name": "Proxy Outpost",
            "type": "proxy",
            "refresh_interval_s": 5,
            "managed": None,
            "providers": [
                {
                    "pk": 12,
                    "name": "Nextcloud OIDC",
                    "component": "ak-provider-oauth2-form",
                    "meta_model_name": "authentik_providers_oauth2.oauth2provider",
                    "assigned_application_slug": "nextcloud",
                    "assigned_application_name": "Nextcloud",
                },
                {
                    "pk": 13,
                    "name": "Grafana SAML",
                    "component": "ak-provider-saml-form",
                    "meta_model_name": "authentik_providers_saml.samlprovider",
                    "assigned_application_slug": "grafana",
                    "assigned_application_name": "Grafana",
                },
            ],
        }
    ]
    assert all("config" not in item for item in result.facts["outposts"])
    assert all("token_identifier" not in item for item in result.facts["outposts"])
    assert result.facts["outpost_health"] == [
        {
            "outpost_pk": "05a8f4bc-daea-4b41-b5dd-b38db7359b1f",
            "outpost_name": "Proxy Outpost",
            "uid": "proxy-outpost-1",
            "hostname": "authentik-proxy-01",
            "last_seen": "2026-04-03T10:05:00Z",
            "version": "2026.5.0",
            "version_should": "2026.5.0",
            "version_outdated": False,
            "golang_version": "go1.24.2",
            "openssl_enabled": True,
            "openssl_version": "3.0.15",
            "fips_enabled": False,
        }
    ]
    assert result.facts["system_health"] == {
        "version_current": "2026.5.0",
        "version_latest": "2026.5.0",
        "version_latest_valid": True,
        "outdated": False,
        "outpost_outdated": True,
    }
    assert result.edges_discovered == []
    assert calls == [
        "http://localhost:9000/api/v3/core/applications/?page=1&page_size=100",
        "http://localhost:9000/api/v3/providers/all/?page=1&page_size=100",
        "http://localhost:9000/api/v3/outposts/instances/?page=1&page_size=100",
        "http://localhost:9000/api/v3/outposts/instances/05a8f4bc-daea-4b41-b5dd-b38db7359b1f/health/",
        "http://localhost:9000/api/v3/admin/version/",
    ]


def test_authentik_adapter_reports_auth_failures_cleanly() -> None:
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

    adapter = AuthentikAdapter(client=AuthentikClient(transport=transport))

    result = asyncio.run(
        adapter.inspect(build_service(), {"api_token": "wrong-token"})
    )

    assert result.status == AdapterStatus.AUTH_FAILED
    assert result.facts == {}
    assert result.edges_discovered == []


def test_authentik_adapter_reports_connection_failures_cleanly() -> None:
    """Transport failures should surface as connection failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        raise error.URLError("connection refused")

    adapter = AuthentikAdapter(client=AuthentikClient(transport=transport))

    result = asyncio.run(
        adapter.inspect(build_service(), {"api_token": "authentik-token"})
    )

    assert result.status == AdapterStatus.CONNECTION_FAILED
    assert result.reason == "Authentik API request failed"


def test_authentik_adapter_reports_parse_failures_cleanly() -> None:
    """Invalid shapes should surface as parse failures."""

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del timeout_seconds
        if http_request.full_url.endswith("/api/v3/core/applications/?page=1&page_size=100"):
            return load_fixture("applications.json")
        if http_request.full_url.endswith("/api/v3/providers/all/?page=1&page_size=100"):
            return b"{\"results\": \"not-a-list\"}"
        if http_request.full_url.endswith("/api/v3/outposts/instances/?page=1&page_size=100"):
            return load_fixture("outposts.json")
        if http_request.full_url.endswith("/api/v3/admin/version/"):
            return load_fixture("version.json")
        raise AssertionError(f"unexpected request: {http_request.full_url}")

    adapter = AuthentikAdapter(client=AuthentikClient(transport=transport))

    result = asyncio.run(
        adapter.inspect(build_service(), {"api_token": "authentik-token"})
    )

    assert result.status == AdapterStatus.PARSE_ERROR
    assert result.reason == "Authentik provider list payload shape was invalid"
