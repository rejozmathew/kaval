"""Integration tests for the Phase 2B GitHub releases client."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import parse

import pytest

from kaval.integrations.external_apis.github_releases import (
    GitHubReleasesClient,
    GitHubReleasesClientConfig,
    GitHubReleasesNotFoundError,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "github"


def load_fixture(name: str) -> bytes:
    """Load a canned GitHub API response body."""
    return (FIXTURES_DIR / name).read_bytes()


class _RecordingGitHubHandler(BaseHTTPRequestHandler):
    """Record GitHub API request details and return deterministic fixtures."""

    responses = {
        "/repos/NginxProxyManager/nginx-proxy-manager/releases?per_page=2&page=1": (
            200,
            load_fixture("releases_npm.json"),
        ),
        "/repos/NginxProxyManager/nginx-proxy-manager/releases/tags/v2.12.1": (
            200,
            load_fixture("release_npm_v2.12.1.json"),
        ),
    }
    received_paths: list[str] = []
    received_headers: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        """Record the request path and return the matching fixture."""
        parsed = parse.urlsplit(self.path)
        path_with_query = parsed.path
        if parsed.query:
            path_with_query = f"{path_with_query}?{parsed.query}"

        status_code, response_body = self.responses.get(path_with_query, (404, b"{}"))
        _RecordingGitHubHandler.received_paths.append(path_with_query)
        _RecordingGitHubHandler.received_headers.append(
            {key.lower(): value for key, value in self.headers.items()}
        )

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the test server log output."""
        return


def test_github_releases_client_fetches_release_list_and_tag_details() -> None:
    """The client should shape stable GitHub API requests for list and tag lookups."""
    _RecordingGitHubHandler.received_paths = []
    _RecordingGitHubHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GitHubReleasesClient(
            config=GitHubReleasesClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                user_agent="kaval-test/1.0",
            )
        )

        feed = client.fetch_releases("NginxProxyManager/nginx-proxy-manager", limit=2)
        release = client.fetch_release_by_tag(
            "https://github.com/NginxProxyManager/nginx-proxy-manager",
            tag_name="v2.12.1",
        )

        assert [item.tag_name for item in feed.releases] == ["v2.12.1", "v2.12.0"]
        assert release.tag_name == "v2.12.1"
        assert _RecordingGitHubHandler.received_paths == [
            "/repos/NginxProxyManager/nginx-proxy-manager/releases?per_page=2&page=1",
            "/repos/NginxProxyManager/nginx-proxy-manager/releases/tags/v2.12.1",
        ]
        assert all(
            headers["accept"] == "application/vnd.github+json"
            for headers in _RecordingGitHubHandler.received_headers
        )
        assert all(
            headers["user-agent"] == "kaval-test/1.0"
            for headers in _RecordingGitHubHandler.received_headers
        )
        assert all(
            headers["x-github-api-version"] == "2022-11-28"
            for headers in _RecordingGitHubHandler.received_headers
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_github_releases_client_raises_typed_not_found_error() -> None:
    """HTTP 404 responses should surface as explicit not-found failures."""
    _RecordingGitHubHandler.received_paths = []
    _RecordingGitHubHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingGitHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GitHubReleasesClient(
            config=GitHubReleasesClientConfig(base_url=f"http://127.0.0.1:{server.server_port}")
        )

        with pytest.raises(GitHubReleasesNotFoundError):
            client.fetch_release_by_tag(
                "NginxProxyManager/nginx-proxy-manager",
                tag_name="v0.0.0-does-not-exist",
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
