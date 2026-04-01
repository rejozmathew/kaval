"""Bounded Docker Engine actions used by the internal executor process."""

from __future__ import annotations

import http.client
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


class DockerActionError(RuntimeError):
    """Raised when the bounded Docker action path cannot complete successfully."""


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """Minimal HTTP connection that speaks over a Unix domain socket."""

    def __init__(self, socket_path: Path, *, timeout: float) -> None:
        super().__init__(host="localhost", timeout=timeout)
        self._socket_path = str(socket_path)

    def connect(self) -> None:
        """Open the Unix domain socket used to reach the Docker daemon."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


@dataclass(frozen=True, slots=True)
class DockerUnixClient:
    """Tiny Docker Engine client limited to the restart-container action."""

    socket_path: Path
    timeout_seconds: float = 10.0

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Restart one container through the mounted Docker daemon socket."""
        status, reason, body = self._perform_request(
            method="POST",
            path=f"/containers/{quote(container, safe='')}/restart?t={wait_timeout_seconds}",
        )
        if status == 204:
            return
        if status == 404:
            raise DockerActionError(f"container '{container}' was not found")
        detail = body or reason or "unknown Docker daemon error"
        raise DockerActionError(f"Docker restart request failed with status {status}: {detail}")

    def _perform_request(self, *, method: str, path: str) -> tuple[int, str, str]:
        """Execute one Docker Engine request over the Unix socket."""
        connection = _UnixSocketHTTPConnection(
            self.socket_path,
            timeout=self.timeout_seconds,
        )
        try:
            connection.request(method, path)
            response = connection.getresponse()
            try:
                raw_payload = response.read()
            except http.client.IncompleteRead as exc:
                raw_payload = exc.partial
            payload = raw_payload.decode("utf-8", errors="replace").strip()
            return response.status, response.reason, payload
        except OSError as exc:
            msg = f"failed to reach Docker socket at {self.socket_path}: {exc}"
            raise DockerActionError(msg) from exc
        finally:
            connection.close()
