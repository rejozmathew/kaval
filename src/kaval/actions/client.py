"""Core-side Unix-socket client for approval-gated executor actions."""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self
from uuid import uuid4

from kaval.actions.approvals import get_approval_hmac_secret, sign_approval_token
from kaval.database import KavalDatabase
from kaval.models import ActionType, ApprovalToken, ExecutorActionRequest, ExecutorActionResult

type SocketTransport = Callable[[Path, bytes, float], bytes]
type TimestampFactory = Callable[[], datetime]
type TokenValueFactory = Callable[[], str]

ALLOWED_CORE_EXECUTOR_ACTIONS = frozenset({ActionType.RESTART_CONTAINER})


class ExecutorClientError(RuntimeError):
    """Raised when the Core-side executor client cannot complete a request."""


class UnsupportedExecutorActionError(ExecutorClientError):
    """Raised when Core attempts to issue or dispatch a non-allowlisted action."""


@dataclass(frozen=True, slots=True)
class ExecutorClientConfig:
    """Runtime configuration for the Core→Executor Unix-socket client."""

    socket_path: Path = Path("/run/kaval/executor.sock")
    database_path: Path = Path("/data/kaval.db")
    migrations_dir: Path | None = None
    approval_hmac_secret: str | None = None
    approval_ttl_seconds: int = 900
    request_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        """Validate positive timeout and TTL settings."""
        if self.approval_ttl_seconds <= 0:
            msg = "approval_ttl_seconds must be positive"
            raise ValueError(msg)
        if self.request_timeout_seconds <= 0:
            msg = "request_timeout_seconds must be positive"
            raise ValueError(msg)

    @classmethod
    def from_env(cls) -> Self:
        """Build the Core→Executor client config from the runtime environment."""
        migrations_dir = os.environ.get("KAVAL_MIGRATIONS_DIR")
        return cls(
            socket_path=Path(os.environ.get("KAVAL_EXECUTOR_SOCKET", "/run/kaval/executor.sock")),
            database_path=Path(os.environ.get("KAVAL_DATABASE_PATH", "/data/kaval.db")),
            migrations_dir=Path(migrations_dir) if migrations_dir else None,
            approval_hmac_secret=get_approval_hmac_secret(),
            approval_ttl_seconds=int(os.environ.get("KAVAL_APPROVAL_TTL_SECONDS", "900")),
            request_timeout_seconds=float(
                os.environ.get("KAVAL_EXECUTOR_REQUEST_TIMEOUT_SECONDS", "10")
            ),
        )


@dataclass(slots=True)
class ExecutorClient:
    """Issue approval tokens and dispatch frozen requests over the Unix socket."""

    config: ExecutorClientConfig
    transport: SocketTransport = field(default_factory=lambda: send_executor_request)
    now_factory: TimestampFactory = field(default=lambda: datetime.now(tz=UTC))
    token_id_factory: TokenValueFactory = field(default=lambda: str(uuid4()))
    nonce_factory: TokenValueFactory = field(default=lambda: uuid4().hex)

    def issue_approval_token(
        self,
        *,
        incident_id: str,
        action: ActionType,
        target: str,
        approved_by: str,
        ttl_seconds: int | None = None,
    ) -> ApprovalToken:
        """Create, sign, persist, and return one bounded approval token."""
        _validate_allowed_action(action)
        effective_ttl_seconds = (
            self.config.approval_ttl_seconds if ttl_seconds is None else ttl_seconds
        )
        if effective_ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        issued_at = self.now_factory()
        token = ApprovalToken(
            token_id=self.token_id_factory(),
            incident_id=incident_id,
            action=action,
            target=target,
            approved_by=approved_by,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=effective_ttl_seconds),
            nonce=self.nonce_factory(),
            hmac_signature="",
            used_at=None,
            result=None,
        )
        signed_token = sign_approval_token(
            token,
            secret=self.config.approval_hmac_secret,
        )
        database = KavalDatabase(
            path=self.config.database_path,
            migrations_dir=self.config.migrations_dir,
        )
        try:
            database.bootstrap()
            database.upsert_approval_token(signed_token)
        finally:
            database.close()
        return signed_token

    def submit_request(
        self,
        *,
        action: ActionType,
        target: str,
        approval_token: ApprovalToken,
    ) -> ExecutorActionResult:
        """Send one frozen request over the Unix socket and parse the frozen result."""
        _validate_allowed_action(action)
        request = ExecutorActionRequest(
            action=action,
            target=target,
            approval_token=approval_token,
        )
        response_payload = self.transport(
            self.config.socket_path,
            request.model_dump_json().encode("utf-8"),
            self.config.request_timeout_seconds,
        )
        if not response_payload:
            msg = "executor returned an empty response"
            raise ExecutorClientError(msg)
        try:
            return ExecutorActionResult.model_validate_json(response_payload)
        except ValueError as exc:
            msg = "executor returned an invalid response payload"
            raise ExecutorClientError(msg) from exc

    def execute_approved_action(self, approval_token: ApprovalToken) -> ExecutorActionResult:
        """Dispatch one previously issued approval token to the executor."""
        return self.submit_request(
            action=approval_token.action,
            target=approval_token.target,
            approval_token=approval_token,
        )


def send_executor_request(socket_path: Path, payload: bytes, timeout_seconds: float) -> bytes:
    """Send one JSON payload to the executor over its Unix domain socket."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout_seconds)
    try:
        client.connect(str(socket_path))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    except OSError as exc:
        msg = f"failed to reach executor socket at {socket_path}: {exc}"
        raise ExecutorClientError(msg) from exc
    finally:
        client.close()


def _validate_allowed_action(action: ActionType) -> None:
    """Reject any action outside the Phase 2A restart-only allowlist."""
    if action in ALLOWED_CORE_EXECUTOR_ACTIONS:
        return
    msg = "restart_container is the only Core→Executor action allowed in Phase 2A"
    raise UnsupportedExecutorActionError(msg)
