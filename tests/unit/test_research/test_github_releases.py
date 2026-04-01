"""Unit tests for the Phase 2B GitHub releases client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib import request

import pytest

from kaval.integrations.external_apis.github_releases import (
    GitHubReleaseFeed,
    GitHubReleasesClient,
    GitHubReleasesClientConfig,
    GitHubReleasesOfflineError,
    GitHubReleasesResponseError,
    decode_release_payload,
    parse_repository_reference,
)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "github"


def load_fixture(name: str) -> object:
    """Load a JSON fixture used by GitHub releases tests."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for release-feed assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_client_config_builds_stable_api_endpoint() -> None:
    """The client config should normalize GitHub API URLs and query strings."""
    config = GitHubReleasesClientConfig(base_url="https://api.github.com/")

    assert config.endpoint(
        "/repos/NginxProxyManager/nginx-proxy-manager/releases",
        {"per_page": "2", "page": "1"},
    ) == (
        "https://api.github.com/repos/NginxProxyManager/nginx-proxy-manager/releases"
        "?per_page=2&page=1"
    )


def test_parse_repository_reference_accepts_owner_name_and_github_url() -> None:
    """Repository references should normalize from the forms used in descriptors."""
    direct = parse_repository_reference("NginxProxyManager/nginx-proxy-manager")
    from_url = parse_repository_reference(
        "https://github.com/binhex/arch-delugevpn.git/tree/main"
    )

    assert direct.full_name == "NginxProxyManager/nginx-proxy-manager"
    assert from_url.full_name == "binhex/arch-delugevpn"


def test_decode_release_payload_maps_fixture_to_stable_contract() -> None:
    """GitHub release fixtures should parse into the internal release contract."""
    release = decode_release_payload(load_fixture("release_npm_v2.12.1.json"))

    assert release.tag_name == "v2.12.1"
    assert release.draft is False
    assert release.prerelease is False
    assert release.body is not None
    assert "OpenSSL 3.5.5" in release.body
    assert release.published_at == ts(18, 15)


def test_fetch_releases_raises_explicit_offline_error_when_disabled() -> None:
    """Offline mode should skip GitHub research before any transport call."""
    client = GitHubReleasesClient(
        config=GitHubReleasesClientConfig(offline_mode=True),
        transport=_unexpected_transport,
    )

    with pytest.raises(GitHubReleasesOfflineError, match="offline mode enabled"):
        client.fetch_releases("NginxProxyManager/nginx-proxy-manager")


def test_fetch_releases_raises_response_error_for_invalid_json_shape() -> None:
    """Non-list releases payloads should fail with a typed response error."""
    client = GitHubReleasesClient(
        transport=lambda http_request, timeout_seconds: b"{\"unexpected\": true}"
    )

    with pytest.raises(GitHubReleasesResponseError, match="was not a list"):
        client.fetch_releases("NginxProxyManager/nginx-proxy-manager")


def test_fetch_releases_returns_typed_release_feed() -> None:
    """The release list path should produce a deterministic feed model."""
    response_body = json.dumps(load_fixture("releases_npm.json")).encode("utf-8")

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        return response_body

    client = GitHubReleasesClient(transport=transport)

    feed = client.fetch_releases(
        "NginxProxyManager/nginx-proxy-manager",
        limit=2,
        fetched_at=ts(19, 0),
    )

    assert isinstance(feed, GitHubReleaseFeed)
    assert feed.repository.full_name == "NginxProxyManager/nginx-proxy-manager"
    assert feed.source_url == (
        "https://github.com/NginxProxyManager/nginx-proxy-manager/releases"
    )
    assert feed.fetched_at == ts(19, 0)
    assert [release.tag_name for release in feed.releases] == ["v2.12.1", "v2.12.0"]


def _unexpected_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Fail if offline-mode tests accidentally hit a transport path."""
    del http_request, timeout_seconds
    raise AssertionError("transport should not be called")
