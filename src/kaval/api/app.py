"""FastAPI application for the Kaval monitoring and operations surface."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketDisconnect

from kaval.api.schemas import (
    CreateCredentialRequestRequest,
    CredentialRequestChoiceRequest,
    CredentialSecretSubmissionRequest,
    HealthResponse,
    RealtimeSnapshotResponse,
    ServiceGraphEdge,
    ServiceGraphResponse,
    TelegramCredentialCallbackRequest,
    VaultUnlockRequest,
    WidgetSummaryResponse,
)
from kaval.credentials.models import CredentialRequest, VaultStatus
from kaval.credentials.request_flow import (
    CredentialRequestConflictError,
    CredentialRequestHintError,
    CredentialRequestManager,
    CredentialRequestNotFoundError,
)
from kaval.credentials.telegram import (
    parse_credential_request_callback_id,
)
from kaval.credentials.vault import (
    CredentialMaterialService,
    CredentialVault,
    CredentialVaultLockedError,
    CredentialVaultPassphraseError,
    VolatileCredentialStore,
)
from kaval.database import KavalDatabase
from kaval.models import (
    Change,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    JournalEntry,
    Service,
    ServiceStatus,
    SystemProfile,
    UserNote,
)

_ACTIVE_FINDING_STATUSES = {
    FindingStatus.NEW,
    FindingStatus.GROUPED,
    FindingStatus.INVESTIGATING,
}
_ACTIVE_INCIDENT_STATUSES = {
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.REMEDIATING,
}


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """Filesystem-backed configuration for the FastAPI app."""

    database_path: Path
    migrations_dir: Path | None
    web_dist_dir: Path
    websocket_poll_interval_seconds: float
    vault_auto_lock_minutes: int
    volatile_credential_ttl_seconds: int


def create_app(
    *,
    database_path: Path | str | None = None,
    migrations_dir: Path | str | None = None,
    web_dist_dir: Path | str | None = None,
    websocket_poll_interval: float = 2.0,
) -> FastAPI:
    """Create the Phase 1 FastAPI application."""
    settings = ApiSettings(
        database_path=_resolve_database_path(database_path),
        migrations_dir=_resolve_migrations_dir(migrations_dir),
        web_dist_dir=_resolve_web_dist_dir(web_dist_dir),
        websocket_poll_interval_seconds=websocket_poll_interval,
        vault_auto_lock_minutes=_load_positive_int_from_env(
            "KAVAL_VAULT_AUTO_LOCK_MINUTES",
            5,
        ),
        volatile_credential_ttl_seconds=_load_positive_int_from_env(
            "KAVAL_VOLATILE_CREDENTIAL_TTL_SECONDS",
            1800,
        ),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.api_settings = settings
        app.state.credential_volatile_store = VolatileCredentialStore(
            default_ttl_seconds=settings.volatile_credential_ttl_seconds,
        )
        app.state.credential_vault = CredentialVault(
            database_path=settings.database_path,
            migrations_dir=settings.migrations_dir,
            auto_lock_minutes=settings.vault_auto_lock_minutes,
        )
        database = KavalDatabase(
            path=settings.database_path,
            migrations_dir=settings.migrations_dir,
        )
        database.bootstrap()
        database.close()
        yield

    app = FastAPI(
        title="Kaval API",
        version="0.1.0",
        summary="Phase 2 monitoring, investigation, and UAC API.",
        lifespan=lifespan,
    )
    app.include_router(_health_router)
    app.include_router(_api_router)
    web_dist = settings.web_dist_dir
    if web_dist.exists():
        app.mount("/", StaticFiles(directory=web_dist, html=True), name="web")
    return app


def get_database(request: Request) -> Iterator[KavalDatabase]:
    """Yield a short-lived database handle for one API request."""
    settings: ApiSettings = request.app.state.api_settings
    database = KavalDatabase(
        path=settings.database_path,
        migrations_dir=settings.migrations_dir,
    )
    try:
        yield database
    finally:
        database.close()


ApiDatabase = Annotated[KavalDatabase, Depends(get_database)]


def get_credential_request_manager(database: ApiDatabase) -> CredentialRequestManager:
    """Build a credential-request manager bound to the current database handle."""
    return CredentialRequestManager(database=database)


ApiCredentialRequestManager = Annotated[
    CredentialRequestManager,
    Depends(get_credential_request_manager),
]


def get_credential_material_service(
    request: Request,
    database: ApiDatabase,
) -> CredentialMaterialService:
    """Build the credential material service using app-scoped storage backends."""
    settings: ApiSettings = request.app.state.api_settings
    return CredentialMaterialService(
        request_manager=CredentialRequestManager(database=database),
        volatile_store=request.app.state.credential_volatile_store,
        vault=request.app.state.credential_vault,
        default_volatile_ttl_seconds=settings.volatile_credential_ttl_seconds,
    )


ApiCredentialMaterialService = Annotated[
    CredentialMaterialService,
    Depends(get_credential_material_service),
]

_health_router = APIRouter()
_api_router = APIRouter(prefix="/api/v1")


@_health_router.get("/healthz", response_model=HealthResponse)
def healthz(database: ApiDatabase) -> HealthResponse:
    """Return a simple readiness response once the SQLite store is reachable."""
    database.connection().execute("SELECT 1").fetchone()
    return HealthResponse(status="ok", database_ready=True)


@_api_router.get("/services", response_model=list[Service])
def list_services(database: ApiDatabase) -> list[Service]:
    """List persisted services for the current monitoring graph."""
    return database.list_services()


@_api_router.get("/findings", response_model=list[Finding])
def list_findings(database: ApiDatabase) -> list[Finding]:
    """List persisted findings."""
    return database.list_findings()


@_api_router.get("/incidents", response_model=list[Incident])
def list_incidents(database: ApiDatabase) -> list[Incident]:
    """List persisted incidents."""
    return database.list_incidents()


@_api_router.get("/investigations", response_model=list[Investigation])
def list_investigations(database: ApiDatabase) -> list[Investigation]:
    """List persisted investigations."""
    return database.list_investigations()


@_api_router.get("/changes", response_model=list[Change])
def list_changes(database: ApiDatabase) -> list[Change]:
    """List persisted change events."""
    return database.list_changes()


@_api_router.get("/journal-entries", response_model=list[JournalEntry])
def list_journal_entries(database: ApiDatabase) -> list[JournalEntry]:
    """List persisted Operational Memory journal entries."""
    return database.list_journal_entries()


@_api_router.get("/user-notes", response_model=list[UserNote])
def list_user_notes(database: ApiDatabase) -> list[UserNote]:
    """List persisted Operational Memory user notes."""
    return database.list_user_notes()


@_api_router.get("/credential-requests", response_model=list[CredentialRequest])
def list_credential_requests(
    manager: ApiCredentialRequestManager,
) -> list[CredentialRequest]:
    """List persisted credential requests with explicit expiry handling."""
    return manager.list_requests()


@_api_router.post("/credential-requests", response_model=CredentialRequest, status_code=201)
def create_credential_request(
    payload: CreateCredentialRequestRequest,
    manager: ApiCredentialRequestManager,
) -> CredentialRequest:
    """Create one pending credential request from descriptor-backed hints."""
    try:
        return manager.create_request(
            incident_id=payload.incident_id,
            investigation_id=payload.investigation_id,
            service_id=payload.service_id,
            credential_key=payload.credential_key,
            reason=payload.reason,
        )
    except CredentialRequestNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CredentialRequestHintError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@_api_router.post(
    "/credential-requests/{request_id}/choice",
    response_model=CredentialRequest,
)
def record_credential_request_choice(
    request_id: str,
    payload: CredentialRequestChoiceRequest,
    manager: ApiCredentialRequestManager,
) -> CredentialRequest:
    """Record one user choice for a credential request."""
    try:
        return manager.resolve_choice(
            request_id=request_id,
            mode=payload.mode,
            decided_by=payload.decided_by,
        )
    except CredentialRequestNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CredentialRequestConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@_api_router.post(
    "/credential-requests/telegram-callback",
    response_model=CredentialRequest,
)
def record_telegram_credential_callback(
    payload: TelegramCredentialCallbackRequest,
    manager: ApiCredentialRequestManager,
) -> CredentialRequest:
    """Resolve one credential request choice from a Telegram callback identifier."""
    try:
        callback = parse_credential_request_callback_id(payload.callback_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        return manager.resolve_choice(
            request_id=callback.request_id,
            mode=callback.mode,
            decided_by=payload.decided_by,
        )
    except CredentialRequestNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CredentialRequestConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@_api_router.post(
    "/credential-requests/{request_id}/submit",
    response_model=CredentialRequest,
)
def submit_credential_secret(
    request_id: str,
    payload: CredentialSecretSubmissionRequest,
    service: ApiCredentialMaterialService,
) -> CredentialRequest:
    """Store secret material for one previously approved credential request."""
    try:
        return service.submit_secret(
            request_id=request_id,
            secret_value=payload.secret_value,
            submitted_by=payload.submitted_by,
        )
    except CredentialRequestNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CredentialRequestConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CredentialVaultLockedError as exc:
        raise HTTPException(status_code=423, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@_api_router.get("/vault/status", response_model=VaultStatus)
def vault_status(service: ApiCredentialMaterialService) -> VaultStatus:
    """Return the current initialized/locked state for the credential vault."""
    return service.vault_status()


@_api_router.post("/vault/unlock", response_model=VaultStatus)
def unlock_vault(
    payload: VaultUnlockRequest,
    service: ApiCredentialMaterialService,
) -> VaultStatus:
    """Initialize or unlock the credential vault with a master passphrase."""
    try:
        return service.unlock_vault(payload.master_passphrase)
    except CredentialVaultPassphraseError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@_api_router.post("/vault/lock", response_model=VaultStatus)
def lock_vault(service: ApiCredentialMaterialService) -> VaultStatus:
    """Explicitly lock the credential vault."""
    return service.lock_vault()


@_api_router.get("/graph", response_model=ServiceGraphResponse)
def graph(database: ApiDatabase) -> ServiceGraphResponse:
    """Return the Phase 1 service map with explicit dependency edges."""
    return build_service_graph(database.list_services())


@_api_router.get("/system-profile", response_model=SystemProfile)
def system_profile(database: ApiDatabase) -> SystemProfile:
    """Return the singleton operational-memory system profile."""
    profile = database.get_system_profile()
    if profile is None:
        raise HTTPException(status_code=404, detail="system profile not found")
    return profile


@_api_router.get("/widget", response_model=WidgetSummaryResponse)
def widget(database: ApiDatabase) -> WidgetSummaryResponse:
    """Return a compact Phase 1 health summary."""
    return build_widget_summary(
        services=database.list_services(),
        findings=database.list_findings(),
        incidents=database.list_incidents(),
    )


@_api_router.websocket("/ws")
async def websocket_updates(websocket: WebSocket) -> None:
    """Stream Phase 1 UI snapshots whenever the persisted state changes."""
    await websocket.accept()
    settings: ApiSettings = websocket.app.state.api_settings
    last_snapshot_json: str | None = None
    try:
        while True:
            snapshot = _load_realtime_snapshot(settings)
            snapshot_json = snapshot.model_dump_json()
            if snapshot_json != last_snapshot_json:
                await websocket.send_json(snapshot.model_dump(mode="json"))
                last_snapshot_json = snapshot_json
            await asyncio.sleep(settings.websocket_poll_interval_seconds)
    except WebSocketDisconnect:
        return


def build_service_graph(services: Sequence[Service]) -> ServiceGraphResponse:
    """Build the UI-facing service graph response from persisted services."""
    ordered_services = sorted(services, key=lambda service: (service.type.value, service.id))
    edges = [
        ServiceGraphEdge(
            source_service_id=service.id,
            target_service_id=dependency.target_service_id,
            confidence=dependency.confidence,
            source=dependency.source,
            description=dependency.description,
        )
        for service in ordered_services
        for dependency in sorted(
            service.dependencies,
            key=lambda dependency: dependency.target_service_id,
        )
    ]
    return ServiceGraphResponse(services=ordered_services, edges=edges)


def build_widget_summary(
    *,
    services: Sequence[Service],
    findings: Sequence[Finding],
    incidents: Sequence[Incident],
) -> WidgetSummaryResponse:
    """Build a compact health summary from persisted Phase 1 state."""
    last_updated_candidates = [
        service.last_check
        for service in services
        if service.last_check is not None
    ]
    return WidgetSummaryResponse(
        total_services=len(services),
        active_findings=sum(
            1 for finding in findings if finding.status in _ACTIVE_FINDING_STATUSES
        ),
        active_incidents=sum(
            1 for incident in incidents if incident.status in _ACTIVE_INCIDENT_STATUSES
        ),
        healthy_services=sum(
            1 for service in services if service.status == ServiceStatus.HEALTHY
        ),
        degraded_services=sum(
            1 for service in services if service.status == ServiceStatus.DEGRADED
        ),
        down_services=sum(1 for service in services if service.status == ServiceStatus.DOWN),
        stopped_services=sum(
            1 for service in services if service.status == ServiceStatus.STOPPED
        ),
        unknown_services=sum(
            1 for service in services if service.status == ServiceStatus.UNKNOWN
        ),
        last_updated=max(last_updated_candidates, default=None),
    )


def _load_realtime_snapshot(settings: ApiSettings) -> RealtimeSnapshotResponse:
    """Load one complete Phase 1 UI snapshot from SQLite."""
    database = KavalDatabase(
        path=settings.database_path,
        migrations_dir=settings.migrations_dir,
    )
    try:
        services = database.list_services()
        incidents = database.list_incidents()
        investigations = database.list_investigations()
        return RealtimeSnapshotResponse(
            kind="snapshot",
            graph=build_service_graph(services),
            incidents=incidents,
            investigations=investigations,
            widget=build_widget_summary(
                services=services,
                findings=database.list_findings(),
                incidents=incidents,
            ),
        )
    finally:
        database.close()


def _resolve_database_path(database_path: Path | str | None) -> Path:
    """Resolve the database path from an explicit argument or environment."""
    if database_path is not None:
        return Path(database_path)
    return Path(os.environ.get("KAVAL_DATABASE_PATH", "/data/kaval.db"))


def _resolve_migrations_dir(migrations_dir: Path | str | None) -> Path | None:
    """Resolve the optional migrations directory override."""
    if migrations_dir is not None:
        return Path(migrations_dir)
    environment_value = os.environ.get("KAVAL_MIGRATIONS_DIR")
    return Path(environment_value) if environment_value else None


def _resolve_web_dist_dir(web_dist_dir: Path | str | None) -> Path:
    """Resolve the frontend build directory for optional static serving."""
    if web_dist_dir is not None:
        return Path(web_dist_dir)
    environment_value = os.environ.get("KAVAL_WEB_DIST")
    if environment_value:
        return Path(environment_value)
    return Path(__file__).resolve().parents[2] / "web" / "dist"


def _load_positive_int_from_env(name: str, default: int) -> int:
    """Load one optional positive integer setting from the environment."""
    raw_value = os.environ.get(name, str(default)).strip()
    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be positive")
    return parsed


app = create_app()
