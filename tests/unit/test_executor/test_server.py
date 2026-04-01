"""Unit tests for the internal executor Unix-socket service."""

from __future__ import annotations

import socket
import stat
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from kaval.actions.approvals import sign_approval_token
from kaval.database import KavalDatabase
from kaval.executor.server import ExecutorServerConfig, ExecutorService, create_executor_server
from kaval.models import (
    ActionType,
    ApprovalToken,
    ExecutorActionRequest,
    ExecutorActionResult,
    ExecutorActionStatus,
)

_TEST_SECRET = "test-secret"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class _SequencedClock:
    """Return a fixed sequence of timestamps for deterministic executor tests."""

    def __init__(self, *timestamps: datetime) -> None:
        self._timestamps: Iterator[datetime] = iter(timestamps)

    def __call__(self) -> datetime:
        return next(self._timestamps)


class _FakeDockerClient:
    """In-memory fake for the executor's bounded restart dependency."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self._error = error

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Record the requested restart and optionally raise a fake runtime error."""
        del wait_timeout_seconds
        self.calls.append(container)
        if self._error is not None:
            raise self._error


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary Kaval database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_token(
    *,
    action: ActionType = ActionType.RESTART_CONTAINER,
    target: str = "delugevpn",
    expires_at: datetime | None = None,
) -> ApprovalToken:
    """Create a signed approval token for executor tests."""
    token = ApprovalToken(
        token_id=f"tok-{action.value}-{target}",
        incident_id="inc-1",
        action=action,
        target=target,
        approved_by="telegram-user",
        issued_at=ts(14, 30),
        expires_at=expires_at or ts(14, 35),
        nonce=f"nonce-{action.value}-{target}",
        hmac_signature="",
        used_at=None,
        result=None,
    )
    return sign_approval_token(token, secret=_TEST_SECRET)


def build_request(token: ApprovalToken) -> ExecutorActionRequest:
    """Build the frozen request contract from a signed approval token."""
    return ExecutorActionRequest(
        action=token.action,
        target=token.target,
        approval_token=token,
    )


def build_service(
    tmp_path: Path,
    *,
    docker_client: _FakeDockerClient | None = None,
    clock: _SequencedClock | None = None,
) -> ExecutorService:
    """Create an ExecutorService backed by a temporary database."""
    return ExecutorService(
        config=ExecutorServerConfig(
            socket_path=tmp_path / "executor.sock",
            database_path=tmp_path / "kaval.db",
            approval_hmac_secret=_TEST_SECRET,
        ),
        docker_client=docker_client or _FakeDockerClient(),
        now_factory=clock or _SequencedClock(ts(14, 31), ts(14, 32)),
    )


def test_executor_service_executes_restart_and_marks_token_used(tmp_path: Path) -> None:
    """Valid restart requests should execute once and consume the approval token."""
    database = build_database(tmp_path)
    token = build_token()
    database.upsert_approval_token(token)
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client=docker_client)

    result = service.execute_request(build_request(token))

    assert result.status is ExecutorActionStatus.SUCCESS
    assert docker_client.calls == ["delugevpn"]
    database = build_database(tmp_path)
    stored_token = database.get_approval_token(token.token_id)
    database.close()
    assert stored_token is not None
    assert stored_token.used_at == ts(14, 31)
    assert stored_token.result is not None
    assert stored_token.result.startswith("success:")


def test_executor_service_rejects_replayed_token(tmp_path: Path) -> None:
    """Previously consumed approval tokens should be rejected without re-executing."""
    database = build_database(tmp_path)
    token = build_token()
    database.upsert_approval_token(
        token.model_copy(
            update={
                "used_at": ts(14, 31),
                "result": "success: container 'delugevpn' restarted successfully",
            }
        )
    )
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client=docker_client)

    result = service.execute_request(build_request(token))

    assert result.status is ExecutorActionStatus.REJECTED
    assert "already been used" in result.detail
    assert docker_client.calls == []


def test_executor_service_rejects_expired_token(tmp_path: Path) -> None:
    """Expired approval tokens should be rejected before any Docker action runs."""
    database = build_database(tmp_path)
    token = build_token(expires_at=ts(14, 31))
    database.upsert_approval_token(token)
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(
        tmp_path,
        docker_client=docker_client,
        clock=_SequencedClock(ts(14, 31), ts(14, 32)),
    )

    result = service.execute_request(build_request(token))

    assert result.status is ExecutorActionStatus.REJECTED
    assert "has expired" in result.detail
    assert docker_client.calls == []


def test_executor_service_rejects_invalid_signature(tmp_path: Path) -> None:
    """Tokens signed with the wrong secret should fail integrity validation."""
    database = build_database(tmp_path)
    token = sign_approval_token(build_token(), secret="wrong-secret")
    database.upsert_approval_token(token)
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client=docker_client)

    result = service.execute_request(build_request(token))

    assert result.status is ExecutorActionStatus.REJECTED
    assert "signature is invalid" in result.detail
    assert docker_client.calls == []


def test_executor_service_rejects_non_allowlisted_action(tmp_path: Path) -> None:
    """Only restart_container should be allowed in the Phase 2A executor."""
    token = build_token(action=ActionType.START_VM, target="vm-ubuntu")
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client=docker_client)

    result = service.execute_request(build_request(token))

    assert result.status is ExecutorActionStatus.REJECTED
    assert "only supported action" in result.detail
    assert docker_client.calls == []


def test_executor_socket_server_round_trip_and_permissions(tmp_path: Path) -> None:
    """The Unix-socket server should answer requests and create a restricted socket."""
    database = build_database(tmp_path)
    token = build_token()
    database.upsert_approval_token(token)
    database.close()
    socket_path = tmp_path / "run" / "executor.sock"
    docker_client = _FakeDockerClient()
    server = create_executor_server(
        ExecutorServerConfig(
            socket_path=socket_path,
            database_path=tmp_path / "kaval.db",
            approval_hmac_secret=_TEST_SECRET,
        ),
        docker_client=docker_client,
        now_factory=_SequencedClock(ts(14, 31), ts(14, 32)),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(socket_path))
        client.sendall(build_request(token).model_dump_json().encode("utf-8"))
        client.shutdown(socket.SHUT_WR)
        response_chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response_chunks.append(chunk)
        client.close()

        result = ExecutorActionResult.model_validate_json(
            b"".join(response_chunks).decode("utf-8")
        )

        assert result.status is ExecutorActionStatus.SUCCESS
        assert docker_client.calls == ["delugevpn"]
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o660
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
