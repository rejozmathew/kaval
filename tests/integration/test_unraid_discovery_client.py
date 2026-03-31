"""Integration tests for the Phase 1 Unraid discovery client."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from kaval.discovery.unraid import (
    UNRAID_DISCOVERY_QUERY,
    UnraidClientConfig,
    UnraidGraphQLClient,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_fixture(name: str) -> bytes:
    """Load a JSON fixture as a response body."""
    return (FIXTURES_DIR / name).read_bytes()


class _RecordingHandler(BaseHTTPRequestHandler):
    """Capture the request sent by the Unraid discovery client."""

    response_body = load_fixture("discovery_response.json")
    received_path = ""
    received_headers: dict[str, str] = {}
    received_body: dict[str, object] = {}

    def do_POST(self) -> None:  # noqa: N802
        """Record the discovery request and return the canned fixture."""
        length = int(self.headers["Content-Length"])
        raw_body = self.rfile.read(length).decode("utf-8")

        _RecordingHandler.received_path = self.path
        _RecordingHandler.received_headers = {
            key.lower(): value for key, value in self.headers.items()
        }
        _RecordingHandler.received_body = json.loads(raw_body)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, format: str, *args: object) -> None:
        """Silence the test server log output."""
        return


def test_unraid_graphql_client_fetches_discovery_snapshot() -> None:
    """The client should POST a discovery query with the Unraid API key."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = UnraidGraphQLClient(
            UnraidClientConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                api_key="test-api-key",
            )
        )

        snapshot = client.fetch_discovery_snapshot()

        assert snapshot.system_info.hostname == "zactower"
        assert len(snapshot.containers) == 2
        assert _RecordingHandler.received_path == "/graphql"
        assert _RecordingHandler.received_headers["x-api-key"] == "test-api-key"
        assert _RecordingHandler.received_headers["content-type"] == "application/json"
        assert _RecordingHandler.received_body == {"query": UNRAID_DISCOVERY_QUERY}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
