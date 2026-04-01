"""Integration tests for the Phase 2B Docker Hub client."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import parse

import pytest

from kaval.integrations.external_apis.dockerhub import (
    DockerHubClient,
    DockerHubClientConfig,
    DockerHubNotFoundError,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "dockerhub"


def load_fixture(name: str) -> bytes:
    """Load a canned Docker Hub API response body."""
    return (FIXTURES_DIR / name).read_bytes()


class _RecordingDockerHubHandler(BaseHTTPRequestHandler):
    """Record Docker Hub request details and return deterministic fixtures."""

    responses = {
        "/v2/namespaces/jc21/repositories/nginx-proxy-manager": (
            200,
            load_fixture("repository_npm.json"),
        ),
        "/v2/namespaces/jc21/repositories/nginx-proxy-manager/tags?page_size=2&page=1": (
            200,
            load_fixture("tags_npm.json"),
        ),
        "/v2/namespaces/jc21/repositories/nginx-proxy-manager/tags/2.12.1": (
            200,
            load_fixture("tag_npm_2.12.1.json"),
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
        _RecordingDockerHubHandler.received_paths.append(path_with_query)
        _RecordingDockerHubHandler.received_headers.append(
            {key.lower(): value for key, value in self.headers.items()}
        )

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the test server log output."""
        return


def test_dockerhub_client_fetches_repository_tags_and_tag_details() -> None:
    """The client should shape stable Docker Hub API requests for repo and tag lookups."""
    _RecordingDockerHubHandler.received_paths = []
    _RecordingDockerHubHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingDockerHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = DockerHubClient(
            config=DockerHubClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}/v2",
                user_agent="kaval-test/1.0",
            )
        )

        repository = client.fetch_repository("jc21/nginx-proxy-manager")
        tags = client.fetch_tags("jc21/nginx-proxy-manager", page_size=2)
        tag = client.fetch_tag(
            "https://hub.docker.com/r/jc21/nginx-proxy-manager",
            tag_name="2.12.1",
        )

        assert repository.repository == "nginx-proxy-manager"
        assert [item.name for item in tags.tags] == ["2.12.1", "2.12.0"]
        assert tag.name == "2.12.1"
        assert _RecordingDockerHubHandler.received_paths == [
            "/v2/namespaces/jc21/repositories/nginx-proxy-manager",
            "/v2/namespaces/jc21/repositories/nginx-proxy-manager/tags?page_size=2&page=1",
            "/v2/namespaces/jc21/repositories/nginx-proxy-manager/tags/2.12.1",
        ]
        assert all(
            headers["accept"] == "application/json"
            for headers in _RecordingDockerHubHandler.received_headers
        )
        assert all(
            headers["user-agent"] == "kaval-test/1.0"
            for headers in _RecordingDockerHubHandler.received_headers
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_dockerhub_client_raises_typed_not_found_error() -> None:
    """HTTP 404 responses should surface as explicit Docker Hub not-found failures."""
    _RecordingDockerHubHandler.received_paths = []
    _RecordingDockerHubHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingDockerHubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = DockerHubClient(
            config=DockerHubClientConfig(base_url=f"http://127.0.0.1:{server.server_port}/v2")
        )

        with pytest.raises(DockerHubNotFoundError):
            client.fetch_tag("jc21/nginx-proxy-manager", tag_name="0.0.0-missing")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
