"""Integration tests for the Phase 1 Docker discovery client."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import parse

from kaval.discovery.docker import DockerClientConfig, DockerDiscoveryClient

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"


def load_fixture(name: str) -> bytes:
    """Load a JSON fixture as a response body."""
    return (FIXTURES_DIR / name).read_bytes()


class _RecordingDockerHandler(BaseHTTPRequestHandler):
    """Record GET requests and return canned Docker API fixtures."""

    events_path = (
        "/v1.43/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D"
        "&since=1775239200&until=1775239260"
    )
    responses = {
        "/v1.43/containers/json?all=1": load_fixture("container_list_response.json"),
        "/v1.43/containers/abc123/json": load_fixture("container_inspect_abc123.json"),
        "/v1.43/containers/def456/json": load_fixture("container_inspect_def456.json"),
        "/v1.43/containers/def456/logs?stdout=1&stderr=1&tail=200&timestamps=0": load_fixture(
            "container_logs_def456.txt"
        ),
        events_path: load_fixture("container_events.ndjson"),
        "/v1.43/images/sha256%3Aimg-radarr/json": load_fixture(
            "image_inspect_sha256_img-radarr.json"
        ),
        "/v1.43/images/sha256%3Aimg-delugevpn/json": load_fixture(
            "image_inspect_sha256_img-delugevpn.json"
        ),
    }
    received_paths: list[str] = []
    received_headers: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        """Record the discovery request and return the canned fixture."""
        parsed = parse.urlsplit(self.path)
        path_with_query = parsed.path
        if parsed.query:
            path_with_query = f"{path_with_query}?{parsed.query}"

        response_body = self.responses.get(path_with_query)
        if response_body is None:
            self.send_response(404)
            self.end_headers()
            return

        _RecordingDockerHandler.received_paths.append(path_with_query)
        _RecordingDockerHandler.received_headers.append(
            {key.lower(): value for key, value in self.headers.items()}
        )

        self.send_response(200)
        content_type = (
            "text/plain"
            if path_with_query.endswith("/logs?stdout=1&stderr=1&tail=200&timestamps=0")
            else "application/json"
        )
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the test server log output."""
        return


def test_docker_discovery_client_fetches_container_and_image_details() -> None:
    """The client should discover containers and images through HTTP GETs only."""
    _RecordingDockerHandler.received_paths = []
    _RecordingDockerHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingDockerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = DockerDiscoveryClient(
            DockerClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                api_key="test-api-key",
            )
        )

        snapshot = client.fetch_discovery_snapshot()

        assert [container.name for container in snapshot.containers] == ["radarr", "delugevpn"]
        assert snapshot.images[0].id.startswith("sha256:")
        assert _RecordingDockerHandler.received_paths == [
            "/v1.43/containers/json?all=1",
            "/v1.43/containers/abc123/json",
            "/v1.43/images/sha256%3Aimg-radarr/json",
            "/v1.43/containers/def456/json",
            "/v1.43/images/sha256%3Aimg-delugevpn/json",
        ]
        assert all(
            headers["x-api-key"] == "test-api-key"
            for headers in _RecordingDockerHandler.received_headers
        )
        assert all(
            headers["accept"] == "application/json"
            for headers in _RecordingDockerHandler.received_headers
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_docker_discovery_client_fetches_recent_container_logs() -> None:
    """The client should fetch plain-text container logs through the Docker API."""
    _RecordingDockerHandler.received_paths = []
    _RecordingDockerHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingDockerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = DockerDiscoveryClient(
            DockerClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                api_key="test-api-key",
            )
        )

        logs = client.fetch_container_logs("def456", tail_lines=200)

        assert "VPN tunnel inactive" in logs
        assert _RecordingDockerHandler.received_paths == [
            "/v1.43/containers/def456/logs?stdout=1&stderr=1&tail=200&timestamps=0"
        ]
        assert _RecordingDockerHandler.received_headers[0]["x-api-key"] == "test-api-key"
        assert _RecordingDockerHandler.received_headers[0]["accept"] == "text/plain"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_docker_discovery_client_fetches_container_events() -> None:
    """The client should fetch newline-delimited Docker container events."""
    _RecordingDockerHandler.received_paths = []
    _RecordingDockerHandler.received_headers = []

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingDockerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = DockerDiscoveryClient(
            DockerClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                api_key="test-api-key",
            )
        )

        events = client.fetch_container_events(
            since=datetime.fromtimestamp(1775239200, tz=UTC),
            until=datetime.fromtimestamp(1775239260, tz=UTC),
        )

        assert [event.action for event in events] == ["start", "die"]
        assert [event.container_id for event in events] == ["abc123", "def456"]
        assert _RecordingDockerHandler.received_paths == [_RecordingDockerHandler.events_path]
        assert _RecordingDockerHandler.received_headers[0]["x-api-key"] == "test-api-key"
        assert _RecordingDockerHandler.received_headers[0]["accept"] == "text/plain"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
