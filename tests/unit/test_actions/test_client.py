"""Unit tests for the Core→Executor Unix-socket client."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.actions import (
    ExecutorClient,
    ExecutorClientConfig,
    UnsupportedExecutorActionError,
)
from kaval.actions.approvals import sign_approval_token, verify_approval_token_signature
from kaval.database import KavalDatabase
from kaval.executor.server import ExecutorServerConfig, create_executor_server
from kaval.models import ActionType, ApprovalToken, ExecutorActionStatus

_TEST_SECRET = "test-secret"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic action-client tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class _SequencedClock:
    """Return a fixed sequence of timestamps for deterministic tests."""

    def __init__(self, *timestamps: datetime) -> None:
        self._timestamps: Iterator[datetime] = iter(timestamps)

    def __call__(self) -> datetime:
        return next(self._timestamps)


class _FakeDockerClient:
    """In-memory fake for the bounded executor restart dependency."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Record each bounded restart request."""
        del wait_timeout_seconds
        self.calls.append(container)


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary Kaval database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_client(
    tmp_path: Path,
    *,
    socket_path: Path | None = None,
) -> ExecutorClient:
    """Create a deterministic Core→Executor client for tests."""
    return ExecutorClient(
        config=ExecutorClientConfig(
            socket_path=socket_path or tmp_path / "executor.sock",
            database_path=tmp_path / "kaval.db",
            approval_hmac_secret=_TEST_SECRET,
        ),
        now_factory=lambda: ts(14, 30),
        token_id_factory=lambda: "tok-client",
        nonce_factory=lambda: "nonce-client",
    )


def test_issue_approval_token_persists_signed_restart_token(tmp_path: Path) -> None:
    """Issuing an approval token should persist a signed restart-only token."""
    client = build_client(tmp_path)

    token = client.issue_approval_token(
        incident_id="inc-1",
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approved_by="telegram-user",
    )

    assert token.token_id == "tok-client"
    assert verify_approval_token_signature(token, secret=_TEST_SECRET) is True
    database = build_database(tmp_path)
    stored_token = database.get_approval_token(token.token_id)
    database.close()
    assert stored_token == token


def test_execute_approved_action_round_trips_over_unix_socket(tmp_path: Path) -> None:
    """The Core client should submit the frozen request over the executor Unix socket."""
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
        client = build_client(tmp_path, socket_path=socket_path)
        token = client.issue_approval_token(
            incident_id="inc-1",
            action=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            approved_by="telegram-user",
        )

        result = client.execute_approved_action(token)

        assert result.status is ExecutorActionStatus.SUCCESS
        assert docker_client.calls == ["delugevpn"]
        database = build_database(tmp_path)
        stored_token = database.get_approval_token(token.token_id)
        database.close()
        assert stored_token is not None
        assert stored_token.used_at == ts(14, 31)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_submit_request_rejects_non_allowlisted_action_before_transport(tmp_path: Path) -> None:
    """Core should reject unsupported actions before any socket transport is used."""
    transport_calls: list[bytes] = []

    def fake_transport(socket_path: Path, payload: bytes, timeout_seconds: float) -> bytes:
        del socket_path, timeout_seconds
        transport_calls.append(payload)
        return b""

    client = ExecutorClient(
        config=ExecutorClientConfig(
            socket_path=tmp_path / "executor.sock",
            database_path=tmp_path / "kaval.db",
            approval_hmac_secret=_TEST_SECRET,
        ),
        transport=fake_transport,
    )
    token = sign_approval_token(
        ApprovalToken(
            token_id="tok-start-vm",
            incident_id="inc-start-vm",
            action=ActionType.START_VM,
            target="vm-ubuntu",
            approved_by="telegram-user",
            issued_at=ts(14, 30),
            expires_at=ts(14, 35),
            nonce="nonce-start-vm",
            hmac_signature="",
            used_at=None,
            result=None,
        ),
        secret=_TEST_SECRET,
    )

    with pytest.raises(UnsupportedExecutorActionError, match="restart_container"):
        client.execute_approved_action(token)

    assert transport_calls == []


def test_executor_client_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The packaged runtime environment should load into the typed client config."""
    monkeypatch.setenv("KAVAL_EXECUTOR_SOCKET", "/run/kaval/executor.sock")
    monkeypatch.setenv("KAVAL_DATABASE_PATH", "/data/kaval.db")
    monkeypatch.setenv("KAVAL_MIGRATIONS_DIR", "/app/migrations")
    monkeypatch.setenv("KAVAL_APPROVAL_HMAC_SECRET", _TEST_SECRET)
    monkeypatch.setenv("KAVAL_APPROVAL_TTL_SECONDS", "600")
    monkeypatch.setenv("KAVAL_EXECUTOR_REQUEST_TIMEOUT_SECONDS", "12.5")

    config = ExecutorClientConfig.from_env()

    assert config.socket_path == Path("/run/kaval/executor.sock")
    assert config.database_path == Path("/data/kaval.db")
    assert config.migrations_dir == Path("/app/migrations")
    assert config.approval_ttl_seconds == 600
    assert config.request_timeout_seconds == 12.5
