"""Unix-socket executor service for approval-gated restart_container actions."""

from __future__ import annotations

import os
import socketserver
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, Self, cast

from pydantic import ValidationError

from kaval.actions.approvals import (
    get_approval_hmac_secret,
    verify_approval_token_signature,
)
from kaval.database import KavalDatabase
from kaval.executor.docker_actions import DockerActionError, DockerUnixClient
from kaval.models import (
    ActionType,
    ApprovalToken,
    ExecutorActionRequest,
    ExecutorActionResult,
    ExecutorActionStatus,
)

ALLOWED_EXECUTOR_ACTIONS = frozenset({ActionType.RESTART_CONTAINER})
_EXECUTION_STARTED_MARKER = "execution_started"


class ContainerRestarter(Protocol):
    """Protocol for the executor's bounded restart-container dependency."""

    def restart_container(self, container: str, *, wait_timeout_seconds: int = 10) -> None:
        """Restart one container through a deterministic code path."""


@dataclass(frozen=True, slots=True)
class ExecutorServerConfig:
    """Filesystem and secret configuration for the internal executor process."""

    socket_path: Path = Path("/run/kaval/executor.sock")
    database_path: Path = Path("/data/kaval.db")
    migrations_dir: Path | None = None
    docker_socket_path: Path = Path("/var/run/docker.sock")
    approval_hmac_secret: str | None = None
    restart_timeout_seconds: int = 10
    socket_mode: int = 0o660

    @classmethod
    def from_env(cls) -> Self:
        """Build executor settings from the packaged runtime environment."""
        migrations_dir = os.environ.get("KAVAL_MIGRATIONS_DIR")
        return cls(
            socket_path=Path(os.environ.get("KAVAL_EXECUTOR_SOCKET", "/run/kaval/executor.sock")),
            database_path=Path(os.environ.get("KAVAL_DATABASE_PATH", "/data/kaval.db")),
            migrations_dir=Path(migrations_dir) if migrations_dir else None,
            docker_socket_path=Path(
                os.environ.get("KAVAL_DOCKER_SOCKET", "/var/run/docker.sock")
            ),
            approval_hmac_secret=get_approval_hmac_secret(),
        )


@dataclass(slots=True)
class ExecutorService:
    """Validate approval tokens, enforce the allowlist, and execute restarts."""

    config: ExecutorServerConfig
    docker_client: ContainerRestarter
    now_factory: Callable[[], datetime] = field(
        default=lambda: datetime.now(tz=UTC),
    )

    def handle_request_payload(self, payload: bytes) -> ExecutorActionResult:
        """Parse and execute one Core→Executor request payload."""
        request = ExecutorActionRequest.model_validate_json(payload)
        return self.execute_request(request)

    def execute_request(self, request: ExecutorActionRequest) -> ExecutorActionResult:
        """Validate one request and execute it if its approval token is valid."""
        if request.action not in ALLOWED_EXECUTOR_ACTIONS:
            return _build_rejected_result(
                request,
                "action is not allowlisted; restart_container is the only supported action",
            )

        claimed_at = self.now_factory()
        claimed_token = self._claim_approval_token(request, claimed_at=claimed_at)
        if isinstance(claimed_token, ExecutorActionResult):
            return claimed_token

        execution_time = self.now_factory()
        try:
            self.docker_client.restart_container(
                request.target,
                wait_timeout_seconds=self.config.restart_timeout_seconds,
            )
            result = ExecutorActionResult(
                token_id=claimed_token.token_id,
                incident_id=claimed_token.incident_id,
                action=request.action,
                target=request.target,
                status=ExecutorActionStatus.SUCCESS,
                detail=f"container '{request.target}' restarted successfully",
                executed_at=execution_time,
            )
        except DockerActionError as exc:
            result = ExecutorActionResult(
                token_id=claimed_token.token_id,
                incident_id=claimed_token.incident_id,
                action=request.action,
                target=request.target,
                status=ExecutorActionStatus.FAILED,
                detail=str(exc),
                executed_at=execution_time,
            )
        except Exception as exc:  # pragma: no cover - defensive boundary
            result = ExecutorActionResult(
                token_id=claimed_token.token_id,
                incident_id=claimed_token.incident_id,
                action=request.action,
                target=request.target,
                status=ExecutorActionStatus.FAILED,
                detail=f"unexpected executor error: {exc}",
                executed_at=execution_time,
            )
        self._record_token_result(claimed_token, result)
        return result

    def _claim_approval_token(
        self,
        request: ExecutorActionRequest,
        *,
        claimed_at: datetime,
    ) -> ApprovalToken | ExecutorActionResult:
        """Claim an unused approval token atomically to prevent replay."""
        database = KavalDatabase(
            path=self.config.database_path,
            migrations_dir=self.config.migrations_dir,
        )
        database.bootstrap()
        connection = database.connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload FROM approval_tokens WHERE token_id = ?",
                (request.approval_token.token_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                return _build_rejected_result(request, "approval token was not found")
            stored_token = ApprovalToken.model_validate_json(str(row["payload"]))
            rejection = self._validate_claim_request(
                request,
                stored_token=stored_token,
                claimed_at=claimed_at,
            )
            if rejection is not None:
                connection.rollback()
                return rejection
            claimed_token = stored_token.model_copy(
                update={
                    "used_at": claimed_at,
                    "result": _EXECUTION_STARTED_MARKER,
                }
            )
            connection.execute(
                """
                UPDATE approval_tokens
                SET used_at = ?, payload = ?
                WHERE token_id = ?
                """,
                (
                    claimed_at.isoformat(),
                    claimed_token.model_dump_json(),
                    claimed_token.token_id,
                ),
            )
            connection.commit()
            return claimed_token
        except Exception:
            connection.rollback()
            raise
        finally:
            database.close()

    def _record_token_result(
        self,
        claimed_token: ApprovalToken,
        result: ExecutorActionResult,
    ) -> None:
        """Persist the final execution result for auditability."""
        database = KavalDatabase(
            path=self.config.database_path,
            migrations_dir=self.config.migrations_dir,
        )
        try:
            database.bootstrap()
            finalized_token = claimed_token.model_copy(
                update={
                    "result": f"{result.status.value}: {result.detail}",
                }
            )
            database.connection().execute(
                "BEGIN IMMEDIATE",
            )
            database.connection().execute(
                """
                UPDATE approval_tokens
                SET used_at = ?, payload = ?
                WHERE token_id = ?
                """,
                (
                    finalized_token.used_at.isoformat() if finalized_token.used_at else None,
                    finalized_token.model_dump_json(),
                    finalized_token.token_id,
                ),
            )
            database.connection().commit()
        except Exception:
            database.connection().rollback()
            raise
        finally:
            database.close()

    def _validate_claim_request(
        self,
        request: ExecutorActionRequest,
        *,
        stored_token: ApprovalToken,
        claimed_at: datetime,
    ) -> ExecutorActionResult | None:
        """Return a rejection result when the persisted token cannot be used."""
        if stored_token.action not in ALLOWED_EXECUTOR_ACTIONS:
            return _build_rejected_result(
                request,
                "approval token action is not allowlisted for the executor",
            )
        if stored_token.used_at is not None:
            return _build_rejected_result(request, "approval token has already been used")
        if stored_token.expires_at <= claimed_at:
            return _build_rejected_result(request, "approval token has expired")
        if _token_identity(stored_token) != _token_identity(request.approval_token):
            return _build_rejected_result(
                request,
                "approval token payload does not match the stored token",
            )
        if not verify_approval_token_signature(
            stored_token,
            secret=self.config.approval_hmac_secret,
        ):
            return _build_rejected_result(request, "approval token signature is invalid")
        return None


def _token_identity(token: ApprovalToken) -> tuple[str, str, str, str, str, str, str, str]:
    """Return the immutable ApprovalToken fields that must match exactly."""
    return (
        token.token_id,
        token.incident_id,
        token.action.value,
        token.target,
        token.approved_by,
        token.issued_at.isoformat(),
        token.expires_at.isoformat(),
        token.nonce,
    )


def _build_rejected_result(
    request: ExecutorActionRequest,
    detail: str,
) -> ExecutorActionResult:
    """Construct a deterministic rejected executor response."""
    return ExecutorActionResult(
        token_id=request.approval_token.token_id,
        incident_id=request.approval_token.incident_id,
        action=request.action,
        target=request.target,
        status=ExecutorActionStatus.REJECTED,
        detail=detail,
        executed_at=None,
    )


class _ExecutorSocketHandler(socketserver.StreamRequestHandler):
    """Handle one JSON request/response exchange over the executor Unix socket."""

    def handle(self) -> None:
        """Read one request payload and write one result payload."""
        payload = self.rfile.read()
        if not payload:
            return
        server = cast("_ExecutorSocketServer", self.server)
        try:
            result = server.service.handle_request_payload(payload)
        except ValidationError:
            return
        self.wfile.write(result.model_dump_json().encode("utf-8"))
        self.wfile.flush()


class _ExecutorSocketServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Threaded Unix domain socket server that exposes the internal executor."""

    daemon_threads = True

    def __init__(
        self,
        socket_path: Path,
        *,
        service: ExecutorService,
        socket_mode: int,
    ) -> None:
        self.service = service
        self._socket_path = socket_path
        self._socket_mode = socket_mode
        super().__init__(str(socket_path), _ExecutorSocketHandler)

    def server_bind(self) -> None:
        """Bind the socket and enforce the configured filesystem permissions."""
        super().server_bind()
        os.chmod(str(self.server_address), self._socket_mode)

    def server_close(self) -> None:
        """Close the bound socket and remove the filesystem entry."""
        try:
            super().server_close()
        finally:
            try:
                self._socket_path.unlink()
            except FileNotFoundError:
                pass


def create_executor_server(
    config: ExecutorServerConfig,
    *,
    docker_client: ContainerRestarter | None = None,
    now_factory: Callable[[], datetime] | None = None,
) -> _ExecutorSocketServer:
    """Create a configured Unix-socket executor server for runtime or tests."""
    config.socket_path.parent.mkdir(parents=True, exist_ok=True)
    if config.socket_path.exists():
        config.socket_path.unlink()
    service = ExecutorService(
        config=config,
        docker_client=docker_client or DockerUnixClient(config.docker_socket_path),
        now_factory=now_factory or (lambda: datetime.now(tz=UTC)),
    )
    return _ExecutorSocketServer(
        config.socket_path,
        service=service,
        socket_mode=config.socket_mode,
    )


def serve_executor(
    config: ExecutorServerConfig,
    *,
    docker_client: ContainerRestarter | None = None,
    now_factory: Callable[[], datetime] | None = None,
) -> None:
    """Run the executor socket server until it is terminated."""
    with create_executor_server(
        config,
        docker_client=docker_client,
        now_factory=now_factory,
    ) as server:
        server.serve_forever(poll_interval=0.25)


def main() -> int:
    """Launch the internal executor process from environment-backed settings."""
    serve_executor(ExecutorServerConfig.from_env())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
