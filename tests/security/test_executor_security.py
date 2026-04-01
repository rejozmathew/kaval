"""Security-focused tests for the approval-gated executor path."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.actions import ExecutorClient, ExecutorClientConfig, UnsupportedExecutorActionError
from kaval.actions.approvals import sign_approval_token
from kaval.database import KavalDatabase
from kaval.executor.server import ExecutorServerConfig, ExecutorService
from kaval.models import ActionType, ApprovalToken, ExecutorActionRequest, ExecutorActionStatus

_TEST_SECRET = "test-secret"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


class _FakeDockerClient:
    """Simple fake used to assert that rejected requests do not reach Docker."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Record the bounded restart request."""
        del wait_timeout_seconds
        self.calls.append(container)


def build_database(tmp_path: Path) -> KavalDatabase:
    """Create and bootstrap a temporary database."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    return database


def build_token() -> ApprovalToken:
    """Create a signed restart approval token."""
    token = ApprovalToken(
        token_id="tok-security",
        incident_id="inc-security",
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approved_by="telegram-user",
        issued_at=ts(14, 30),
        expires_at=ts(14, 35),
        nonce="nonce-security",
        hmac_signature="",
        used_at=None,
        result=None,
    )
    return sign_approval_token(token, secret=_TEST_SECRET)


def build_service(tmp_path: Path, docker_client: _FakeDockerClient) -> ExecutorService:
    """Create an executor service with a deterministic clock."""
    timestamps = iter([ts(14, 31), ts(14, 32), ts(14, 33), ts(14, 34)])
    return ExecutorService(
        config=ExecutorServerConfig(
            socket_path=tmp_path / "executor.sock",
            database_path=tmp_path / "kaval.db",
            approval_hmac_secret=_TEST_SECRET,
        ),
        docker_client=docker_client,
        now_factory=lambda: next(timestamps),
    )


def test_executor_replay_prevention_consumes_token_once(tmp_path: Path) -> None:
    """A valid approval token should succeed once and then be rejected on replay."""
    database = build_database(tmp_path)
    token = build_token()
    database.upsert_approval_token(token)
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client)
    request = ExecutorActionRequest(
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approval_token=token,
    )

    first_result = service.execute_request(request)
    second_result = service.execute_request(request)

    assert first_result.status is ExecutorActionStatus.SUCCESS
    assert second_result.status is ExecutorActionStatus.REJECTED
    assert "already been used" in second_result.detail
    assert docker_client.calls == ["delugevpn"]


def test_invalid_signature_does_not_consume_stored_token(tmp_path: Path) -> None:
    """Signature failures should not mark the stored token as used."""
    database = build_database(tmp_path)
    token = sign_approval_token(build_token(), secret="wrong-secret")
    database.upsert_approval_token(token)
    database.close()
    docker_client = _FakeDockerClient()
    service = build_service(tmp_path, docker_client)
    request = ExecutorActionRequest(
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approval_token=token,
    )

    result = service.execute_request(request)

    assert result.status is ExecutorActionStatus.REJECTED
    assert "signature is invalid" in result.detail
    assert docker_client.calls == []
    database = build_database(tmp_path)
    stored_token = database.get_approval_token(token.token_id)
    database.close()
    assert stored_token is not None
    assert stored_token.used_at is None


def test_core_client_rejects_non_restart_actions_before_transport(tmp_path: Path) -> None:
    """Core should not send unsupported actions across the executor socket boundary."""
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
