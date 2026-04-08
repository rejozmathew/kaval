"""FastAPI application for the Kaval monitoring and operations surface."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from collections import defaultdict
from collections.abc import AsyncIterator, Iterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, cast

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketDisconnect

from kaval.api.metrics import render_prometheus_metrics
from kaval.api.schemas import (
    AdapterFactSourceType,
    CreateCredentialRequestRequest,
    CreateUserNoteRequest,
    CredentialRequestChoiceRequest,
    CredentialSecretSubmissionRequest,
    HealthResponse,
    RealtimeSnapshotResponse,
    ServiceAdapterFactsItemResponse,
    ServiceAdapterFactsResponse,
    ServiceDetailAdapterConfigurationState,
    ServiceDetailAdapterHealthState,
    ServiceDetailAdapterResponse,
    ServiceDetailImproveActionKind,
    ServiceDetailImproveActionResponse,
    ServiceDetailInsightSectionResponse,
    ServiceDetailResponse,
    ServiceGraphEdge,
    ServiceGraphResponse,
    TelegramCredentialCallbackRequest,
    TelegramInboundUpdateRequest,
    TelegramInboundUpdateResponse,
    TelegramUpdateProcessingStatus,
    UpdateUserNoteRequest,
    VaultUnlockRequest,
    WidgetOverallStatus,
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
    AdapterCredentialState,
    CredentialMaterialService,
    CredentialVault,
    CredentialVaultLockedError,
    CredentialVaultPassphraseError,
    VolatileCredentialStore,
)
from kaval.database import KavalDatabase
from kaval.discovery.descriptors import (
    DescriptorInspectionSurface,
    LoadedServiceDescriptor,
    ServiceDescriptor,
)
from kaval.effectiveness import EffectivenessReport, build_effectiveness_report
from kaval.integrations import (
    AdapterFactFreshness,
    AdapterRefreshConfig,
    AdapterRegistry,
    AdapterResult,
    AdapterStatus,
    AuthentikAdapter,
    CloudflareAdapter,
    NginxProxyManagerAdapter,
    PiHoleAdapter,
    RadarrAdapter,
    ServiceAdapter,
    evaluate_adapter_fact_freshness,
    execute_service_adapter,
    resolve_adapter_refresh_policy,
)
from kaval.integrations.adapter_facts import redact_adapter_result_for_prompt
from kaval.integrations.webhooks import (
    WebhookAuthenticationError,
    WebhookPayloadTooLargeError,
    WebhookPayloadValidationError,
    WebhookRateLimiter,
    WebhookRateLimitError,
    WebhookSourceConfig,
    authorize_webhook_request,
    build_webhook_payload_record,
    load_webhook_source_configs_from_env,
)
from kaval.integrations.webhooks.normalizers import (
    load_generic_json_normalizer_config_from_env,
)
from kaval.integrations.webhooks.normalizers.generic_json import (
    GenericJsonNormalizerConfig,
)
from kaval.integrations.webhooks.pipeline import (
    WebhookPipelineError,
    WebhookPipelineProcessor,
    WebhookPipelineResult,
)
from kaval.investigation.cloud_model import load_cloud_model_config_from_env
from kaval.investigation.local_model import load_local_model_config_from_env
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.memory.note_models import UserNoteVersion
from kaval.memory.user_notes import UserNoteNotFoundError, UserNoteService
from kaval.models import (
    ApprovalToken,
    Change,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationTrigger,
    JournalEntry,
    RedactionLevel,
    Service,
    ServiceStatus,
    SystemProfile,
    UserNote,
    derive_service_insight,
)
from kaval.notifications import (
    IncidentAlertRouter,
    NotificationBus,
    TelegramInteractiveHandler,
    TelegramMemoryCommandError,
    TelegramMemoryCommandHandler,
    load_notification_bus_config_from_env,
    load_telegram_config_from_env,
    load_telegram_webhook_config_from_env,
    supports_telegram_memory_command,
)
from kaval.notifications.telegram_interactive import TelegramTransport
from kaval.runtime import (
    CapabilityHealthReport,
    CapabilityRuntimeSignalSource,
    CheckSchedulerRuntimeSignal,
    DiscoveryPipelineRuntimeSignal,
    ExecutorProcessRuntimeSignal,
    build_capability_health_report,
    probe_unix_socket,
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
_DEFAULT_ADAPTER_REGISTRY = AdapterRegistry(
    cast(
        Sequence[ServiceAdapter],
        (
            NginxProxyManagerAdapter(),
            RadarrAdapter(),
            AuthentikAdapter(),
            CloudflareAdapter(),
            PiHoleAdapter(),
        ),
    )
)


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """Filesystem-backed configuration for the FastAPI app."""

    database_path: Path
    migrations_dir: Path | None
    web_dist_dir: Path
    websocket_poll_interval_seconds: float
    vault_auto_lock_minutes: int
    volatile_credential_ttl_seconds: int
    webhook_payload_size_limit_bytes: int
    webhook_rate_limit_per_minute: int
    webhook_retention_days: int
    webhook_source_configs: dict[str, WebhookSourceConfig]
    generic_json_normalizer_config: GenericJsonNormalizerConfig | None
    widget_enabled: bool
    widget_api_key: str | None
    widget_public_url: str | None
    widget_refresh_interval_seconds: int


@dataclass(frozen=True, slots=True)
class _BoundServiceAdapter:
    """One adapter bound to one service descriptor with its declared surfaces."""

    adapter: ServiceAdapter
    surfaces: tuple[DescriptorInspectionSurface, ...]


def create_app(
    *,
    database_path: Path | str | None = None,
    migrations_dir: Path | str | None = None,
    web_dist_dir: Path | str | None = None,
    websocket_poll_interval: float = 2.0,
    telegram_transport: TelegramTransport | None = None,
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
        webhook_payload_size_limit_bytes=_load_positive_int_from_env(
            "KAVAL_WEBHOOK_PAYLOAD_SIZE_LIMIT_BYTES",
            256 * 1024,
        ),
        webhook_rate_limit_per_minute=_load_positive_int_from_env(
            "KAVAL_WEBHOOK_RATE_LIMIT_PER_MINUTE",
            60,
        ),
        webhook_retention_days=_load_positive_int_from_env(
            "KAVAL_WEBHOOK_RETENTION_DAYS",
            30,
        ),
        webhook_source_configs=load_webhook_source_configs_from_env(),
        generic_json_normalizer_config=load_generic_json_normalizer_config_from_env(),
        widget_enabled=_load_bool_from_env("KAVAL_WIDGET_ENABLED", True),
        widget_api_key=_load_optional_stripped_env("KAVAL_WIDGET_API_KEY"),
        widget_public_url=_load_optional_stripped_env("KAVAL_WIDGET_PUBLIC_URL"),
        widget_refresh_interval_seconds=_load_positive_int_from_env(
            "KAVAL_WIDGET_REFRESH_INTERVAL_SECONDS",
            60,
        ),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.started_at = datetime.now(tz=UTC)
        app.state.api_settings = settings
        app.state.credential_volatile_store = VolatileCredentialStore(
            default_ttl_seconds=settings.volatile_credential_ttl_seconds,
        )
        app.state.credential_vault = CredentialVault(
            database_path=settings.database_path,
            migrations_dir=settings.migrations_dir,
            auto_lock_minutes=settings.vault_auto_lock_minutes,
        )
        app.state.webhook_rate_limiter = WebhookRateLimiter(
            max_events_per_minute=settings.webhook_rate_limit_per_minute,
        )
        app.state.incident_alert_router = IncidentAlertRouter(
            sender=NotificationBus(config=load_notification_bus_config_from_env()),
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
    app.state.telegram_transport = telegram_transport
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


def get_user_note_service(database: ApiDatabase) -> UserNoteService:
    """Build the user-note CRUD service for the current request database handle."""
    return UserNoteService(database=database)


ApiUserNoteService = Annotated[
    UserNoteService,
    Depends(get_user_note_service),
]

ApiTelegramSecretHeader = Annotated[
    str | None,
    Header(alias="X-Telegram-Bot-Api-Secret-Token"),
]


def get_webhook_source(request: Request, source_id: str) -> WebhookSourceConfig:
    """Resolve and authorize one configured webhook source."""
    settings: ApiSettings = request.app.state.api_settings
    source = settings.webhook_source_configs.get(source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="webhook source not configured")
    try:
        authorize_webhook_request(
            config=source,
            authorization_header=request.headers.get("Authorization"),
            query_key=request.query_params.get("key"),
        )
    except WebhookAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return source


ApiWebhookSource = Annotated[WebhookSourceConfig, Depends(get_webhook_source)]

_health_router = APIRouter()
_api_router = APIRouter(prefix="/api/v1")


@_health_router.get("/healthz", response_model=HealthResponse)
def healthz(database: ApiDatabase) -> HealthResponse:
    """Return a simple readiness response once the SQLite store is reachable."""
    database.connection().execute("SELECT 1").fetchone()
    return HealthResponse(status="ok", database_ready=True)


@_health_router.get("/metrics")
def metrics(
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> Response:
    """Return Prometheus-readable aggregate metrics for the current Kaval state."""
    settings: ApiSettings = request.app.state.api_settings
    started_at: datetime = request.app.state.started_at
    checked_at = datetime.now(tz=UTC)
    services = enrich_services_with_current_insight(database.list_services())
    document = render_prometheus_metrics(
        services=services,
        findings=database.list_findings(),
        incidents=database.list_incidents(),
        investigations=database.list_investigations(),
        adapter_statuses=_build_metrics_adapter_statuses(
            services=services,
            credential_material_service=credential_material_service,
        ),
        known_adapter_ids=[
            adapter.adapter_id
            for adapter in _DEFAULT_ADAPTER_REGISTRY.list_adapters()
        ],
        approval_tokens=_list_approval_tokens(database),
        webhook_payloads=database.list_webhook_payloads(),
        webhook_event_states=database.list_webhook_event_states(),
        database_size_bytes=(
            settings.database_path.stat().st_size
            if settings.database_path.exists()
            else 0
        ),
        uptime_seconds=(checked_at - started_at).total_seconds(),
        now=checked_at,
    )
    return Response(
        content=document,
        headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
    )


@_api_router.get("/services", response_model=list[Service])
def list_services(database: ApiDatabase) -> list[Service]:
    """List persisted services for the current monitoring graph."""
    return enrich_services_with_current_insight(database.list_services())


@_api_router.get("/services/{service_id}/detail", response_model=ServiceDetailResponse)
def service_detail(
    service_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceDetailResponse:
    """Return the minimum service-detail insight payload for one service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    enriched_service = enrich_services_with_current_insight([service])[0]
    return build_service_detail_response(
        service=enriched_service,
        credential_material_service=credential_material_service,
    )


@_api_router.get(
    "/services/{service_id}/adapter-facts",
    response_model=ServiceAdapterFactsResponse,
)
def service_adapter_facts(
    service_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceAdapterFactsResponse:
    """Return read-only adapter-imported facts for one service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    return build_service_adapter_facts_response(
        service=service,
        credential_material_service=credential_material_service,
        checked_at=datetime.now(tz=UTC),
    )


@_api_router.get("/capability-health", response_model=CapabilityHealthReport)
def capability_health(
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> CapabilityHealthReport:
    """Return the current Kaval capability-health report for the UI panel."""
    checked_at = datetime.now(tz=UTC)
    quick_check_result = database.connection().execute("PRAGMA quick_check").fetchone()
    database_corruption_detected = (
        quick_check_result is None or str(quick_check_result[0]).casefold() != "ok"
    )

    discovery_signal = _typed_runtime_signal(
        database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.DISCOVERY_PIPELINE
        ),
        DiscoveryPipelineRuntimeSignal,
    )
    scheduler_signal = _typed_runtime_signal(
        database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.CHECK_SCHEDULER
        ),
        CheckSchedulerRuntimeSignal,
    )
    executor_signal = _typed_runtime_signal(
        database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.EXECUTOR_PROCESS
        ),
        ExecutorProcessRuntimeSignal,
    )
    executor_socket_path = Path(
        executor_signal.socket_path
        if executor_signal is not None
        else os.environ.get("KAVAL_EXECUTOR_SOCKET", "/run/kaval/executor.sock")
    )
    notification_bus_config = load_notification_bus_config_from_env()
    telegram_config = load_telegram_config_from_env()

    return build_capability_health_report(
        checked_at=checked_at,
        discovery_signal=discovery_signal,
        scheduler_signal=scheduler_signal,
        executor_signal=executor_signal,
        executor_socket_reachable=probe_unix_socket(executor_socket_path),
        local_model_configured=load_local_model_config_from_env() is not None,
        cloud_model_configured=load_cloud_model_config_from_env() is not None,
        notification_channel_count=(
            len(notification_bus_config.channels)
            if notification_bus_config is not None
            else 0
        )
        + (1 if telegram_config is not None else 0),
        vault_status=credential_material_service.vault_status(),
        database_reachable=True,
        migrations_current=database.migrations_current(),
        database_corruption_detected=database_corruption_detected,
    )


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
def list_user_notes_legacy(user_note_service: ApiUserNoteService) -> list[UserNote]:
    """List active user notes on the legacy Phase 2B endpoint."""
    return user_note_service.list_notes()


@_api_router.get("/memory/notes", response_model=list[UserNote])
def list_memory_notes(
    user_note_service: ApiUserNoteService,
    service_id: str | None = None,
) -> list[UserNote]:
    """List active user notes, optionally filtered to one service."""
    return user_note_service.list_notes(service_id=service_id)


@_api_router.post("/memory/notes", response_model=UserNote, status_code=201)
def create_memory_note(
    request: CreateUserNoteRequest,
    user_note_service: ApiUserNoteService,
) -> UserNote:
    """Create one active user note."""
    return user_note_service.create_note(request)


@_api_router.patch("/memory/notes/{note_id}", response_model=UserNote)
def update_memory_note(
    note_id: str,
    request: UpdateUserNoteRequest,
    user_note_service: ApiUserNoteService,
) -> UserNote:
    """Update one active user note in place."""
    try:
        return user_note_service.update_note(note_id, request)
    except UserNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@_api_router.get("/memory/notes/{note_id}/versions", response_model=list[UserNoteVersion])
def list_memory_note_versions(
    note_id: str,
    user_note_service: ApiUserNoteService,
) -> list[UserNoteVersion]:
    """List stored version history for one note, including the current snapshot."""
    try:
        return user_note_service.list_versions(note_id)
    except UserNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@_api_router.post("/memory/notes/{note_id}/archive", response_model=UserNoteVersion)
def archive_memory_note(
    note_id: str,
    user_note_service: ApiUserNoteService,
) -> UserNoteVersion:
    """Archive one active note while retaining it in version history."""
    try:
        return user_note_service.archive_note(note_id)
    except UserNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@_api_router.delete("/memory/notes/{note_id}", status_code=204)
def delete_memory_note(
    note_id: str,
    user_note_service: ApiUserNoteService,
) -> Response:
    """Hard-delete one note and any retained history snapshots."""
    try:
        user_note_service.delete_note(note_id)
    except UserNoteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@_api_router.post("/webhooks/{source_id}", status_code=202)
async def receive_webhook(
    request: Request,
    webhook_source: ApiWebhookSource,
) -> Response:
    """Authenticate, retain, and process one webhook payload into findings/incidents."""
    settings: ApiSettings = request.app.state.api_settings
    rate_limiter: WebhookRateLimiter = request.app.state.webhook_rate_limiter
    received_at = datetime.now(tz=UTC)
    try:
        rate_limiter.enforce(source_id=webhook_source.source_id, now=received_at)
    except WebhookRateLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    raw_body = await request.body()
    try:
        payload_record = build_webhook_payload_record(
            source=webhook_source,
            raw_body=raw_body,
            received_at=received_at,
            payload_size_limit_bytes=settings.webhook_payload_size_limit_bytes,
            retention_days=settings.webhook_retention_days,
        )
    except WebhookPayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except WebhookPayloadValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    database = KavalDatabase(
        path=settings.database_path,
        migrations_dir=settings.migrations_dir,
    )
    try:
        database.upsert_webhook_payload(payload_record)
        database.purge_expired_webhook_payloads(
            now=received_at,
            open_incident_ids=_active_incident_ids(database),
        )
        payload = json.loads(raw_body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="webhook payload must be a JSON object")

        try:
            pipeline_result = WebhookPipelineProcessor().process(
                database=database,
                source_id=webhook_source.source_id,
                source_type=webhook_source.source_type,
                payload=payload,
                received_at=received_at,
                raw_payload_retention_until=payload_record.raw_payload_retention_until,
                generic_json_config=settings.generic_json_normalizer_config,
            )
        except (ValueError, WebhookPipelineError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if pipeline_result.incident_id is not None:
            database.upsert_webhook_payload(
                payload_record.model_copy(update={"incident_id": pipeline_result.incident_id})
            )
        _run_webhook_follow_up(
            request=request,
            database=database,
            pipeline_result=pipeline_result,
            now=received_at,
        )
    finally:
        database.close()
    if not pipeline_result.dedup_result.should_process:
        return Response(status_code=200)
    return Response(status_code=202)


@_api_router.post("/telegram/updates", response_model=TelegramInboundUpdateResponse)
def receive_telegram_update(
    payload: TelegramInboundUpdateRequest,
    request: Request,
    database: ApiDatabase,
    secret_token: ApiTelegramSecretHeader = None,
) -> TelegramInboundUpdateResponse:
    """Authenticate and route one Telegram update into Phase 3B memory commands."""
    telegram_config = load_telegram_config_from_env()
    webhook_config = load_telegram_webhook_config_from_env()
    if telegram_config is None or webhook_config is None:
        raise HTTPException(status_code=404, detail="telegram command ingress not configured")
    if secret_token is None or not secrets.compare_digest(
        secret_token,
        webhook_config.secret_token,
    ):
        raise HTTPException(status_code=401, detail="invalid telegram webhook secret")

    message = payload.message
    if message is None:
        return TelegramInboundUpdateResponse(
            status=TelegramUpdateProcessingStatus.IGNORED,
            detail="telegram update has no message",
        )
    if str(message.chat.id) != telegram_config.chat_id:
        raise HTTPException(status_code=403, detail="telegram update chat is not authorized")
    if message.text is None or not message.text.strip():
        return TelegramInboundUpdateResponse(
            status=TelegramUpdateProcessingStatus.IGNORED,
            detail="telegram update has no text message",
        )
    if not supports_telegram_memory_command(message.text):
        return TelegramInboundUpdateResponse(
            status=TelegramUpdateProcessingStatus.IGNORED,
            detail="telegram update did not contain a supported memory command",
        )

    try:
        reply_text = TelegramMemoryCommandHandler(database=database).handle_message(
            message.text
        ).message_text
        detail = "telegram memory command processed"
    except TelegramMemoryCommandError as exc:
        reply_text = str(exc)
        detail = "telegram memory command rejected"

    delivery_result = TelegramInteractiveHandler(
        config=telegram_config,
        transport=cast(
            TelegramTransport | None,
            getattr(request.app.state, "telegram_transport", None),
        ),
    ).send_text(
        reply_text,
        chat_id=str(message.chat.id),
        reply_to_message_id=message.message_id,
    )
    return TelegramInboundUpdateResponse(
        status=TelegramUpdateProcessingStatus.PROCESSED,
        detail=detail,
        reply_delivery_status=delivery_result.status.value,
    )


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
    return build_service_graph(enrich_services_with_current_insight(database.list_services()))


@_api_router.get("/system-profile", response_model=SystemProfile)
def system_profile(database: ApiDatabase) -> SystemProfile:
    """Return the singleton operational-memory system profile."""
    profile = database.get_system_profile()
    if profile is None:
        raise HTTPException(status_code=404, detail="system profile not found")
    return profile


@_api_router.get("/widget", response_model=WidgetSummaryResponse)
def widget(
    request: Request,
    response: Response,
    database: ApiDatabase,
    manager: ApiCredentialRequestManager,
    credential_material_service: ApiCredentialMaterialService,
    authorization: Annotated[str | None, Header()] = None,
    x_kaval_widget_key: Annotated[str | None, Header(alias="X-Kaval-Widget-Key")] = None,
) -> WidgetSummaryResponse:
    """Return a compact widget summary for Homepage/Homarr-style consumers."""
    settings: ApiSettings = request.app.state.api_settings
    if not settings.widget_enabled:
        raise HTTPException(status_code=404, detail="widget api disabled")
    _authorize_widget_request(
        expected_api_key=settings.widget_api_key,
        authorization=authorization,
        x_kaval_widget_key=x_kaval_widget_key,
    )
    response.headers["X-Kaval-Widget-Refresh-Seconds"] = str(
        settings.widget_refresh_interval_seconds
    )
    response.headers["Cache-Control"] = (
        f"private, max-age={settings.widget_refresh_interval_seconds}"
        if settings.widget_api_key is not None
        else f"public, max-age={settings.widget_refresh_interval_seconds}"
    )
    services = enrich_services_with_current_insight(database.list_services())
    return build_widget_summary(
        services=services,
        findings=database.list_findings(),
        incidents=database.list_incidents(),
        investigations=database.list_investigations(),
        approval_tokens=_list_approval_tokens(database),
        descriptors=manager.descriptors,
        adapter_statuses=_build_metrics_adapter_statuses(
            services=services,
            credential_material_service=credential_material_service,
        ),
        base_url=_widget_public_url(request=request, settings=settings),
        refresh_interval_seconds=settings.widget_refresh_interval_seconds,
    )


@_api_router.get("/effectiveness", response_model=EffectivenessReport)
def effectiveness(
    database: ApiDatabase,
    manager: ApiCredentialRequestManager,
) -> EffectivenessReport:
    """Return the equal-weighted v1 effectiveness score and minimal breakdown."""
    return build_effectiveness_report(
        services=enrich_services_with_current_insight(database.list_services()),
        descriptors=manager.descriptors,
        adapter_registry=_DEFAULT_ADAPTER_REGISTRY,
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


def enrich_services_with_current_insight(services: Sequence[Service]) -> list[Service]:
    """Attach current insight levels using the active runtime investigation capability."""
    local_model_configured = load_local_model_config_from_env() is not None
    return [
        service.model_copy(
            update={
                "insight": derive_service_insight(
                    service,
                    local_model_configured=local_model_configured,
                )
            }
        )
        for service in services
    ]


def build_service_detail_response(
    *,
    service: Service,
    credential_material_service: CredentialMaterialService,
) -> ServiceDetailResponse:
    """Build the minimum later-enrichable service-detail response for one service."""
    current_level = 0 if service.insight is None else int(service.insight.level)
    loaded_descriptor = _loaded_descriptor_for_service(
        service=service,
        descriptors=credential_material_service.request_manager.descriptors,
    )
    adapter_statuses = _build_service_detail_adapter_statuses(
        service=service,
        loaded_descriptor=loaded_descriptor,
        credential_material_service=credential_material_service,
    )
    return ServiceDetailResponse(
        service=service,
        insight_section=ServiceDetailInsightSectionResponse(
            current_level=current_level,
            adapter_available=bool(adapter_statuses),
            adapters=adapter_statuses,
            improve_actions=_build_service_detail_improve_actions(
                service=service,
                loaded_descriptor=loaded_descriptor,
                adapter_statuses=adapter_statuses,
            ),
            fact_summary_available=False,
        ),
    )


def build_service_adapter_facts_response(
    *,
    service: Service,
    credential_material_service: CredentialMaterialService,
    checked_at: datetime,
) -> ServiceAdapterFactsResponse:
    """Build the stable read-only adapter-facts response for one service."""
    loaded_descriptor = _loaded_descriptor_for_service(
        service=service,
        descriptors=credential_material_service.request_manager.descriptors,
    )
    adapter_fact_items = _build_service_adapter_fact_items(
        service=service,
        loaded_descriptor=loaded_descriptor,
        credential_material_service=credential_material_service,
        checked_at=checked_at,
    )
    return ServiceAdapterFactsResponse(
        service_id=service.id,
        service_name=service.name,
        checked_at=checked_at,
        facts_available=any(item.facts_available for item in adapter_fact_items),
        adapters=adapter_fact_items,
    )


def _build_service_detail_adapter_statuses(
    *,
    service: Service,
    loaded_descriptor: LoadedServiceDescriptor | None,
    credential_material_service: CredentialMaterialService,
) -> list[ServiceDetailAdapterResponse]:
    """Build one adapter summary for each implemented deep-inspection adapter."""
    adapter_statuses: list[ServiceDetailAdapterResponse] = []
    for bound_adapter in _bound_service_adapters(
        service=service,
        loaded_descriptor=loaded_descriptor,
    ):
        adapter = bound_adapter.adapter
        resolution = credential_material_service.resolve_adapter_credentials(
            service_id=service.id,
            credential_keys=adapter.credential_keys,
        )
        configuration_state, configuration_summary = _service_detail_configuration_state(
            resolution.state
        )
        health_state, health_summary = _service_detail_health_state(
            configuration_state=configuration_state
        )
        adapter_statuses.append(
            ServiceDetailAdapterResponse(
                adapter_id=adapter.adapter_id,
                display_name=_adapter_display_name(adapter.adapter_id),
                configuration_state=configuration_state,
                configuration_summary=configuration_summary,
                health_state=health_state,
                health_summary=health_summary,
                missing_credentials=list(resolution.missing_keys),
                supported_fact_names=sorted(
                    {
                        fact_name
                        for surface in bound_adapter.surfaces
                        for fact_name in surface.facts_provided
                    }
                ),
            )
        )
    return sorted(adapter_statuses, key=lambda status: status.display_name)


def _build_service_adapter_fact_items(
    *,
    service: Service,
    loaded_descriptor: LoadedServiceDescriptor | None,
    credential_material_service: CredentialMaterialService,
    checked_at: datetime,
) -> list[ServiceAdapterFactsItemResponse]:
    """Build read-only adapter-facts payloads for one service."""
    items: list[ServiceAdapterFactsItemResponse] = []
    for bound_adapter in _bound_service_adapters(
        service=service,
        loaded_descriptor=loaded_descriptor,
    ):
        adapter = bound_adapter.adapter
        refresh_policy = resolve_adapter_refresh_policy(
            config=AdapterRefreshConfig(),
            adapter_id=adapter.adapter_id,
        )
        resolution = credential_material_service.resolve_adapter_credentials(
            service_id=service.id,
            credential_keys=adapter.credential_keys,
            now=checked_at,
        )
        configuration_state, configuration_summary = _service_detail_configuration_state(
            resolution.state
        )
        supported_fact_names = sorted(
            {
                fact_name
                for surface in bound_adapter.surfaces
                for fact_name in surface.facts_provided
            }
        )

        if resolution.state is not AdapterCredentialState.AVAILABLE:
            health_state, health_summary = _service_detail_health_state(
                configuration_state=configuration_state
            )
            items.append(
                ServiceAdapterFactsItemResponse(
                    adapter_id=adapter.adapter_id,
                    display_name=_adapter_display_name(adapter.adapter_id),
                    service_id=service.id,
                    service_name=service.name,
                    source=AdapterFactSourceType.DEEP_INSPECTION_ADAPTER,
                    read_only=adapter.read_only,
                    configuration_state=configuration_state,
                    configuration_summary=configuration_summary,
                    health_state=health_state,
                    health_summary=health_summary,
                    missing_credentials=list(resolution.missing_keys),
                    supported_fact_names=supported_fact_names,
                    facts_available=False,
                    refresh_interval_minutes=refresh_policy.refresh_interval_minutes,
                    freshness=AdapterFactFreshness.UNAVAILABLE,
                    reason=resolution.detail,
                )
            )
            continue

        adapter_result = asyncio.run(
            execute_service_adapter(
                adapter,
                service=service,
                credentials=resolution.credentials,
                now=checked_at,
            )
        )
        prompt_safe_fact = redact_adapter_result_for_prompt(
            adapter_result,
            redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        )
        facts_available = (
            adapter_result.status is AdapterStatus.SUCCESS and bool(prompt_safe_fact.facts)
        )
        facts_observed_at = adapter_result.timestamp if facts_available else None
        staleness_policy = refresh_policy.staleness_policy()
        stale_at = (
            None
            if facts_observed_at is None
            else staleness_policy.stale_at(facts_observed_at)
        )
        next_refresh_at = (
            None
            if facts_observed_at is None
            else facts_observed_at + refresh_policy.refresh_interval()
        )
        freshness = evaluate_adapter_fact_freshness(
            observed_at=facts_observed_at,
            now=checked_at,
            staleness_policy=staleness_policy,
        )
        health_state, health_summary = _service_detail_health_state_for_execution(
            adapter_result=adapter_result,
            facts_available=facts_available,
        )
        items.append(
            ServiceAdapterFactsItemResponse(
                adapter_id=adapter.adapter_id,
                display_name=_adapter_display_name(adapter.adapter_id),
                service_id=service.id,
                service_name=service.name,
                source=AdapterFactSourceType.DEEP_INSPECTION_ADAPTER,
                read_only=adapter.read_only,
                configuration_state=configuration_state,
                configuration_summary=configuration_summary,
                health_state=health_state,
                health_summary=health_summary,
                supported_fact_names=supported_fact_names,
                execution_status=adapter_result.status,
                facts_available=facts_available,
                facts=prompt_safe_fact.facts if facts_available else {},
                excluded_paths=prompt_safe_fact.excluded_paths,
                applied_redaction_level=prompt_safe_fact.applied_redaction_level,
                facts_observed_at=facts_observed_at,
                stale_at=stale_at,
                next_refresh_at=next_refresh_at,
                refresh_interval_minutes=refresh_policy.refresh_interval_minutes,
                freshness=freshness,
                reason=adapter_result.reason,
            )
        )
    return sorted(items, key=lambda item: item.display_name)


def _build_metrics_adapter_statuses(
    *,
    services: Sequence[Service],
    credential_material_service: CredentialMaterialService,
) -> list[ServiceDetailAdapterResponse]:
    """Build adapter status snapshots for every currently persisted service."""
    descriptors = credential_material_service.request_manager.descriptors
    adapter_statuses: list[ServiceDetailAdapterResponse] = []
    for service in services:
        adapter_statuses.extend(
            _build_service_detail_adapter_statuses(
                service=service,
                loaded_descriptor=_loaded_descriptor_for_service(
                    service=service,
                    descriptors=descriptors,
                ),
                credential_material_service=credential_material_service,
            )
        )
    return sorted(
        adapter_statuses,
        key=lambda status: (status.adapter_id, status.display_name),
    )


def _bound_service_adapters(
    *,
    service: Service,
    loaded_descriptor: LoadedServiceDescriptor | None,
) -> list[_BoundServiceAdapter]:
    """Return adapters bound to one service descriptor with grouped surfaces."""
    if loaded_descriptor is None or service.descriptor_id is None:
        return []

    surfaces_by_adapter_id: dict[str, list[DescriptorInspectionSurface]] = defaultdict(list)
    adapters_by_id: dict[str, ServiceAdapter] = {}
    for surface in loaded_descriptor.descriptor.inspection.surfaces:
        adapter = _DEFAULT_ADAPTER_REGISTRY.get(
            descriptor_id=service.descriptor_id,
            surface_id=surface.id,
        )
        if adapter is None:
            continue
        adapters_by_id[adapter.adapter_id] = adapter
        surfaces_by_adapter_id[adapter.adapter_id].append(surface)

    return [
        _BoundServiceAdapter(
            adapter=adapter,
            surfaces=tuple(surfaces_by_adapter_id[adapter_id]),
        )
        for adapter_id, adapter in adapters_by_id.items()
    ]


def _service_detail_health_state_for_execution(
    *,
    adapter_result: AdapterResult,
    facts_available: bool,
) -> tuple[ServiceDetailAdapterHealthState, str]:
    """Return adapter-health wording for one facts fetch attempt."""
    if adapter_result.status is AdapterStatus.SUCCESS:
        if facts_available:
            return (
                ServiceDetailAdapterHealthState.HEALTHY,
                "Adapter returned prompt-safe facts successfully.",
            )
        return (
            ServiceDetailAdapterHealthState.HEALTHY,
            "Adapter completed successfully but returned no prompt-safe facts.",
        )
    if adapter_result.status is AdapterStatus.AUTH_FAILED:
        return (
            ServiceDetailAdapterHealthState.DEGRADED,
            "Adapter authentication failed during fact collection.",
        )
    if adapter_result.status is AdapterStatus.CONNECTION_FAILED:
        return (
            ServiceDetailAdapterHealthState.DEGRADED,
            "Adapter could not reach the target service during fact collection.",
        )
    if adapter_result.status is AdapterStatus.VERSION_INCOMPATIBLE:
        return (
            ServiceDetailAdapterHealthState.DEGRADED,
            "Adapter reached the service but the version is not supported.",
        )
    if adapter_result.status is AdapterStatus.PARSE_ERROR:
        return (
            ServiceDetailAdapterHealthState.DEGRADED,
            "Adapter response parsing failed during fact collection.",
        )
    return (
        ServiceDetailAdapterHealthState.DEGRADED,
        "Adapter degraded during fact collection.",
    )


def _build_service_detail_improve_actions(
    *,
    service: Service,
    loaded_descriptor: LoadedServiceDescriptor | None,
    adapter_statuses: Sequence[ServiceDetailAdapterResponse],
) -> list[ServiceDetailImproveActionResponse]:
    """Build explicit improvement affordances for the minimum service detail view."""
    improve_actions: list[ServiceDetailImproveActionResponse] = []
    local_model_configured = load_local_model_config_from_env() is not None
    if (
        service.descriptor_id is not None
        and service.last_check is not None
        and not local_model_configured
    ):
        improve_actions.append(
            ServiceDetailImproveActionResponse(
                kind=ServiceDetailImproveActionKind.CONFIGURE_LOCAL_MODEL,
                title="Configure a local model",
                detail=(
                    "Add a local investigation model endpoint to unlock "
                    "investigation-ready insight for this service."
                ),
            )
        )

    descriptor = None if loaded_descriptor is None else loaded_descriptor.descriptor
    for adapter_status in adapter_statuses:
        if (
            adapter_status.configuration_state
            == ServiceDetailAdapterConfigurationState.UNCONFIGURED
        ):
            improve_actions.append(
                ServiceDetailImproveActionResponse(
                    kind=ServiceDetailImproveActionKind.CONFIGURE_ADAPTER,
                    title=f"Configure {adapter_status.display_name}",
                    detail=(
                        "Provide "
                        + _format_requirement_list(
                            _credential_descriptions(
                                descriptor=descriptor,
                                credential_keys=adapter_status.missing_credentials,
                            )
                        )
                        + " to enable deep inspection for this service."
                    ),
                )
            )
        elif (
            adapter_status.configuration_state
            == ServiceDetailAdapterConfigurationState.LOCKED
        ):
            improve_actions.append(
                ServiceDetailImproveActionResponse(
                    kind=ServiceDetailImproveActionKind.UNLOCK_VAULT,
                    title="Unlock the credential vault",
                    detail=(
                        f"Unlock the vault so {adapter_status.display_name} can use "
                        "stored deep-inspection credentials."
                    ),
                )
            )
    return improve_actions


def _loaded_descriptor_for_service(
    *,
    service: Service,
    descriptors: Sequence[LoadedServiceDescriptor],
) -> LoadedServiceDescriptor | None:
    """Return the shipped descriptor record that matches the persisted service."""
    if service.descriptor_id is None:
        return None
    for loaded_descriptor in descriptors:
        if _loaded_descriptor_id(loaded_descriptor) == service.descriptor_id:
            return loaded_descriptor
    return None


def _loaded_descriptor_id(loaded_descriptor: LoadedServiceDescriptor) -> str:
    """Return the stable service descriptor identifier used in persisted services."""
    return f"{loaded_descriptor.path.parent.name}/{loaded_descriptor.path.stem}"


def _service_detail_configuration_state(
    credential_state: AdapterCredentialState,
) -> tuple[ServiceDetailAdapterConfigurationState, str]:
    """Map one adapter credential-resolution state into UI detail wording."""
    if credential_state == AdapterCredentialState.AVAILABLE:
        return (
            ServiceDetailAdapterConfigurationState.CONFIGURED,
            "Required adapter inputs are configured.",
        )
    if credential_state == AdapterCredentialState.LOCKED:
        return (
            ServiceDetailAdapterConfigurationState.LOCKED,
            "Stored credentials exist, but the vault is currently locked.",
        )
    return (
        ServiceDetailAdapterConfigurationState.UNCONFIGURED,
        "Required adapter inputs have not been configured yet.",
    )


def _service_detail_health_state(
    *,
    configuration_state: ServiceDetailAdapterConfigurationState,
) -> tuple[ServiceDetailAdapterHealthState, str]:
    """Return the currently derivable adapter-health wording for the detail panel."""
    if configuration_state == ServiceDetailAdapterConfigurationState.CONFIGURED:
        return (
            ServiceDetailAdapterHealthState.UNKNOWN,
            "No adapter diagnostics have been recorded yet.",
        )
    if configuration_state == ServiceDetailAdapterConfigurationState.LOCKED:
        return (
            ServiceDetailAdapterHealthState.UNKNOWN,
            "Unlock the vault before adapter diagnostics can evaluate health.",
        )
    return (
        ServiceDetailAdapterHealthState.UNKNOWN,
        "Health will remain unknown until the adapter is configured.",
    )


def _adapter_display_name(adapter_id: str) -> str:
    """Return a compact human-readable adapter label."""
    if adapter_id.endswith("_api"):
        return f"{adapter_id[:-4].replace('_', ' ').title()} API"
    return adapter_id.replace("_", " ").title()


def _credential_descriptions(
    *,
    descriptor: ServiceDescriptor | None,
    credential_keys: Sequence[str],
) -> list[str]:
    """Resolve friendly credential descriptions from descriptor hints when available."""
    hints = {} if descriptor is None else descriptor.credential_hints
    descriptions: list[str] = []
    for credential_key in credential_keys:
        hint = hints.get(credential_key)
        if hint is not None:
            descriptions.append(hint.description)
        else:
            descriptions.append(credential_key.replace("_", " "))
    return descriptions


def _format_requirement_list(requirements: Sequence[str]) -> str:
    """Format one or more missing requirements for a user-facing affordance."""
    if not requirements:
        return "the required inputs"
    if len(requirements) == 1:
        return requirements[0]
    if len(requirements) == 2:
        return f"{requirements[0]} and {requirements[1]}"
    return f"{', '.join(requirements[:-1])}, and {requirements[-1]}"


def build_widget_summary(
    *,
    services: Sequence[Service],
    findings: Sequence[Finding],
    incidents: Sequence[Incident],
    investigations: Sequence[Investigation] = (),
    approval_tokens: Sequence[ApprovalToken] = (),
    descriptors: Sequence[LoadedServiceDescriptor] = (),
    adapter_statuses: Sequence[ServiceDetailAdapterResponse] = (),
    base_url: str | None = None,
    refresh_interval_seconds: int | None = None,
) -> WidgetSummaryResponse:
    """Build a compact widget summary from current persisted state."""
    last_updated_candidates = [
        service.last_check
        for service in services
        if service.last_check is not None
    ]
    effectiveness_score = (
        int(
            round(
                build_effectiveness_report(
                    services=services,
                    descriptors=descriptors,
                    adapter_registry=_DEFAULT_ADAPTER_REGISTRY,
                ).score_percent
            )
        )
        if descriptors
        else 0
    )
    adapters_healthy, adapters_degraded = _widget_adapter_health_counts(adapter_statuses)
    pending_approvals = _widget_pending_approval_count(approval_tokens)
    latest_investigation = _latest_investigation_timestamp(investigations)
    healthy_services = sum(
        1 for service in services if service.status == ServiceStatus.HEALTHY
    )
    degraded_services = sum(
        1 for service in services if service.status == ServiceStatus.DEGRADED
    )
    down_services = sum(1 for service in services if service.status == ServiceStatus.DOWN)
    stopped_services = sum(
        1 for service in services if service.status == ServiceStatus.STOPPED
    )
    unknown_services = sum(
        1 for service in services if service.status == ServiceStatus.UNKNOWN
    )
    active_findings = sum(
        1 for finding in findings if finding.status in _ACTIVE_FINDING_STATUSES
    )
    active_incidents = sum(
        1 for incident in incidents if incident.status in _ACTIVE_INCIDENT_STATUSES
    )
    return WidgetSummaryResponse(
        total_services=len(services),
        active_findings=active_findings,
        active_incidents=active_incidents,
        healthy_services=healthy_services,
        degraded_services=degraded_services,
        down_services=down_services,
        stopped_services=stopped_services,
        unknown_services=unknown_services,
        last_updated=max(last_updated_candidates, default=None),
        status=_widget_overall_status(
            incidents=incidents,
            active_findings=active_findings,
            degraded_services=degraded_services,
            down_services=down_services,
            stopped_services=stopped_services,
            unknown_services=unknown_services,
        ),
        services_total=len(services),
        services_healthy=healthy_services,
        services_degraded=degraded_services,
        services_down=down_services,
        last_investigation=latest_investigation,
        effectiveness_score=effectiveness_score,
        adapters_healthy=adapters_healthy,
        adapters_degraded=adapters_degraded,
        pending_approvals=pending_approvals,
        url=base_url,
        refresh_interval_seconds=refresh_interval_seconds,
    )


def _active_incident_ids(database: KavalDatabase) -> set[str]:
    """Return active incident identifiers for retention-aware webhook purging."""
    return {
        incident.id
        for incident in database.list_incidents()
        if incident.status in _ACTIVE_INCIDENT_STATUSES
    }


def _run_webhook_follow_up(
    *,
    request: Request,
    database: KavalDatabase,
    pipeline_result: WebhookPipelineResult,
    now: datetime,
) -> None:
    """Run investigation and notification follow-up for webhook-created incidents."""
    if not pipeline_result.dedup_result.should_process:
        return

    router = cast(IncidentAlertRouter, request.app.state.incident_alert_router)
    for incident in _webhook_follow_up_incidents(pipeline_result):
        workflow_result = InvestigationWorkflow(database=database).run(
            incident_id=incident.id,
            trigger=InvestigationTrigger.AUTO,
            now=now,
        )
        router.route(
            incident=workflow_result.incident,
            investigation=workflow_result.investigation,
            now=now,
        )
    router.flush_due_notifications(now=now)


def _webhook_follow_up_incidents(
    pipeline_result: WebhookPipelineResult,
) -> list[Incident]:
    """Return stable unique incidents that need post-webhook investigation."""
    if pipeline_result.incident_result is None:
        return []
    incidents_by_id: dict[str, Incident] = {}
    for incident in (
        *pipeline_result.incident_result.created_incidents,
        *pipeline_result.incident_result.updated_incidents,
    ):
        incidents_by_id[incident.id] = incident
    return sorted(incidents_by_id.values(), key=lambda incident: incident.id)


def _list_approval_tokens(database: KavalDatabase) -> list[ApprovalToken]:
    """Return approval tokens without expanding the database surface for one route."""
    rows = database.connection().execute(
        "SELECT payload FROM approval_tokens ORDER BY expires_at, token_id"
    ).fetchall()
    return [ApprovalToken.model_validate_json(str(row["payload"])) for row in rows]


def _authorize_widget_request(
    *,
    expected_api_key: str | None,
    authorization: str | None,
    x_kaval_widget_key: str | None,
) -> None:
    """Authorize one widget request when optional API-key auth is configured."""
    if expected_api_key is None:
        return
    presented_key = x_kaval_widget_key
    if presented_key is None and authorization is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.casefold() == "bearer" and token.strip():
            presented_key = token.strip()
    if presented_key is None:
        raise HTTPException(status_code=401, detail="widget api key required")
    if not secrets.compare_digest(presented_key, expected_api_key):
        raise HTTPException(status_code=403, detail="invalid widget api key")


def _widget_public_url(*, request: Request, settings: ApiSettings) -> str:
    """Return the widget-facing base URL from config or the current request."""
    if settings.widget_public_url is not None:
        return settings.widget_public_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _latest_investigation_timestamp(
    investigations: Sequence[Investigation],
) -> datetime | None:
    """Return the latest completed or started investigation timestamp."""
    candidates = [
        investigation.completed_at or investigation.started_at
        for investigation in investigations
    ]
    filtered = [candidate for candidate in candidates if candidate is not None]
    return max(filtered, default=None)


def _widget_adapter_health_counts(
    adapter_statuses: Sequence[ServiceDetailAdapterResponse],
) -> tuple[int, int]:
    """Return coarse healthy/degraded adapter counts for the widget summary."""
    healthy = 0
    degraded = 0
    for adapter_status in adapter_statuses:
        if adapter_status.configuration_state == ServiceDetailAdapterConfigurationState.CONFIGURED:
            healthy += 1
            continue
        degraded += 1
    return healthy, degraded


def _widget_pending_approval_count(approval_tokens: Sequence[ApprovalToken]) -> int:
    """Return the count of approval tokens that are still pending."""
    now = datetime.now(tz=UTC)
    return sum(
        1
        for token in approval_tokens
        if token.used_at is None and token.expires_at > now and token.result is None
    )


def _widget_overall_status(
    *,
    incidents: Sequence[Incident],
    active_findings: int,
    degraded_services: int,
    down_services: int,
    stopped_services: int,
    unknown_services: int,
) -> WidgetOverallStatus:
    """Return the coarse overall widget status from active service and incident state."""
    if down_services > 0 or any(
        incident.status in _ACTIVE_INCIDENT_STATUSES and incident.severity.value == "critical"
        for incident in incidents
    ):
        return WidgetOverallStatus.CRITICAL
    if (
        active_findings > 0
        or any(incident.status in _ACTIVE_INCIDENT_STATUSES for incident in incidents)
        or degraded_services > 0
        or stopped_services > 0
        or unknown_services > 0
    ):
        return WidgetOverallStatus.DEGRADED
    return WidgetOverallStatus.HEALTHY


def _load_realtime_snapshot(settings: ApiSettings) -> RealtimeSnapshotResponse:
    """Load one complete Phase 1 UI snapshot from SQLite."""
    database = KavalDatabase(
        path=settings.database_path,
        migrations_dir=settings.migrations_dir,
    )
    try:
        services = enrich_services_with_current_insight(database.list_services())
        incidents = database.list_incidents()
        investigations = database.list_investigations()
        manager = CredentialRequestManager(database=database)
        return RealtimeSnapshotResponse(
            kind="snapshot",
            graph=build_service_graph(services),
            incidents=incidents,
            investigations=investigations,
            widget=build_widget_summary(
                services=services,
                findings=database.list_findings(),
                incidents=incidents,
                investigations=investigations,
                approval_tokens=_list_approval_tokens(database),
                descriptors=manager.descriptors,
            ),
        )
    finally:
        database.close()


def _typed_runtime_signal[TSignal](
    signal: object,
    signal_type: type[TSignal],
) -> TSignal | None:
    """Return one runtime signal only when it matches the expected type."""
    return signal if isinstance(signal, signal_type) else None


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


def _load_bool_from_env(name: str, default: bool) -> bool:
    """Load one optional boolean setting from the environment."""
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _load_optional_stripped_env(name: str) -> str | None:
    """Return one optional stripped environment value when configured."""
    raw_value = os.environ.get(name)
    if raw_value is None:
        return None
    stripped = raw_value.strip()
    return stripped or None


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
