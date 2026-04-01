"""Unit tests for the bounded Docker restart client."""

from __future__ import annotations

import socketserver
import threading
from pathlib import Path

import pytest

from kaval.executor.docker_actions import DockerActionError, DockerUnixClient


class _RecordingDockerHandler(socketserver.BaseRequestHandler):
    """Record one raw HTTP request and return a configured HTTP response."""

    requests: list[str] = []
    response_bytes: bytes = b""

    def handle(self) -> None:
        """Store the request line and send the configured fake Docker response."""
        chunks: list[bytes] = []
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        self.requests.append(b"".join(chunks).decode("utf-8", errors="replace"))
        self.request.sendall(self.response_bytes)


class _DockerTestServer(socketserver.UnixStreamServer):
    """Small Unix-socket server used to fake Docker API responses."""

    allow_reuse_address = False


def _start_docker_test_server(
    socket_path: Path,
    *,
    response_bytes: bytes,
) -> tuple[_DockerTestServer, threading.Thread]:
    _RecordingDockerHandler.requests = []
    _RecordingDockerHandler.response_bytes = response_bytes
    server = _DockerTestServer(str(socket_path), _RecordingDockerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_restart_container_posts_expected_docker_path(tmp_path: Path) -> None:
    """The restart client should send the restart_container request over the Unix socket."""
    socket_path = tmp_path / "docker.sock"
    server, thread = _start_docker_test_server(
        socket_path,
        response_bytes=b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    )
    try:
        client = DockerUnixClient(socket_path)

        client.restart_container("delugevpn")

        assert _RecordingDockerHandler.requests
        request_text = _RecordingDockerHandler.requests[0]
        assert "POST /containers/delugevpn/restart?t=10 HTTP/1.1" in request_text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_restart_container_raises_for_missing_container(tmp_path: Path) -> None:
    """A Docker 404 should surface as a bounded DockerActionError."""
    socket_path = tmp_path / "docker.sock"
    server, thread = _start_docker_test_server(
        socket_path,
        response_bytes=(
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Length: 22\r\n\r\n"
            b"container was missing"
        ),
    )
    try:
        client = DockerUnixClient(socket_path)

        with pytest.raises(DockerActionError, match="was not found"):
            client.restart_container("missing-container")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
