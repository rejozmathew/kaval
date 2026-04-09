"""FastAPI application for the Kaval monitoring and operations surface."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from collections import Counter, defaultdict
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import uuid4

import yaml  # type: ignore[import-untyped]
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    WebSocket,
)
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.websockets import WebSocketDisconnect

from kaval.api.metrics import render_prometheus_metrics
from kaval.api.schemas import (
    AdapterFactSourceType,
    CreateCredentialRequestRequest,
    CreateUserNoteRequest,
    CredentialRequestChoiceRequest,
    CredentialSecretSubmissionRequest,
    CredentialVaultChangePasswordRequest,
    CredentialVaultCredentialResponse,
    CredentialVaultEntrySource,
    CredentialVaultMutationResponse,
    CredentialVaultResponse,
    CredentialVaultTestItemResponse,
    CredentialVaultTestResponse,
    DescriptorCommunityExportResponse,
    DescriptorEditContainerDependencyRequest,
    DescriptorEditEndpointRequest,
    DescriptorEditMatchRequest,
    DescriptorEditMode,
    DescriptorValidationAffectedServiceResponse,
    DescriptorValidationDependencyImpactResponse,
    DescriptorValidationMatchPreviewResponse,
    DescriptorViewContainerDependencyResponse,
    DescriptorViewCredentialHintResponse,
    DescriptorViewEndpointResponse,
    DescriptorViewFailureModeResponse,
    DescriptorViewInspectionSurfaceResponse,
    DescriptorViewLogSignalsResponse,
    DescriptorViewMatchResponse,
    FindingDismissRequest,
    FindingDismissResponse,
    FindingFeedbackSuggestionAction,
    FindingFeedbackSuggestionResponse,
    FindingReviewItemResponse,
    FindingReviewResponse,
    GraphEdgeMutationResponse,
    GraphEdgeUpsertRequest,
    HealthResponse,
    MaintenanceModeMutationResponse,
    MaintenanceModeResponse,
    MaintenanceWindowResponse,
    MaintenanceWindowUpdateRequest,
    ModelSettingsCloudScopeResponse,
    ModelSettingsEscalationResponse,
    ModelSettingsLocalScopeResponse,
    ModelSettingsMutationResponse,
    ModelSettingsResponse,
    ModelSettingsScopeResponse,
    ModelSettingsSecretSource,
    ModelSettingsTestRequest,
    ModelSettingsTestResponse,
    ModelSettingsTestScope,
    ModelSettingsTestTarget,
    ModelSettingsUpdateRequest,
    MonitoringSettingsCheckResponse,
    MonitoringSettingsEffectiveCheckResponse,
    MonitoringSettingsEffectiveServiceResponse,
    MonitoringSettingsMutationResponse,
    MonitoringSettingsResolutionSource,
    MonitoringSettingsResponse,
    MonitoringSettingsScopeResponse,
    MonitoringSettingsServiceOverrideResponse,
    MonitoringSettingsUpdateRequest,
    NotificationSettingsChannelScopeResponse,
    NotificationSettingsMutationResponse,
    NotificationSettingsQuietHoursResponse,
    NotificationSettingsResponse,
    NotificationSettingsRoutingResponse,
    NotificationSettingsScopeResponse,
    NotificationSettingsSecretSource,
    NotificationSettingsTestRequest,
    NotificationSettingsTestResponse,
    NotificationSettingsTestScope,
    NotificationSettingsUpdateRequest,
    QuarantinedDescriptorActionResponse,
    QuarantinedDescriptorQueueItemResponse,
    RealtimeSnapshotResponse,
    RecommendationActionResponse,
    RecommendationItemResponse,
    RecommendationsResponse,
    ServiceAdapterFactsItemResponse,
    ServiceAdapterFactsResponse,
    ServiceDescriptorGenerateResponse,
    ServiceDescriptorSaveRequest,
    ServiceDescriptorSaveResponse,
    ServiceDescriptorValidationPreviewResponse,
    ServiceDescriptorValidationResponse,
    ServiceDescriptorViewResponse,
    ServiceDetailAdapterConfigurationState,
    ServiceDetailAdapterHealthState,
    ServiceDetailAdapterResponse,
    ServiceDetailCheckSuppressionMutationResponse,
    ServiceDetailCheckSuppressionUpdateRequest,
    ServiceDetailImproveActionKind,
    ServiceDetailImproveActionResponse,
    ServiceDetailInsightSectionResponse,
    ServiceDetailMonitoringCheckResponse,
    ServiceDetailMonitoringSectionResponse,
    ServiceDetailResponse,
    ServiceGraphEdge,
    ServiceGraphNodeMeta,
    ServiceGraphResponse,
    SystemSettingsAboutModelStatusResponse,
    SystemSettingsAboutResponse,
    SystemSettingsDatabaseStatusResponse,
    SystemSettingsExportGuidanceResponse,
    SystemSettingsExportTarget,
    SystemSettingsImportGuidanceResponse,
    SystemSettingsImportTarget,
    SystemSettingsLogLevel,
    SystemSettingsMutationResponse,
    SystemSettingsResponse,
    SystemSettingsScopeResponse,
    SystemSettingsSensitivity,
    SystemSettingsTransferGuidanceResponse,
    SystemSettingsUpdateRequest,
    TelegramCredentialCallbackRequest,
    TelegramInboundUpdateRequest,
    TelegramInboundUpdateResponse,
    TelegramUpdateProcessingStatus,
    UpdateUserNoteRequest,
    VaultUnlockRequest,
    WidgetOverallStatus,
    WidgetSummaryResponse,
)
from kaval.credentials.models import CredentialRequest, VaultCredentialRecord, VaultStatus
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
    CredentialVaultError,
    CredentialVaultLockedError,
    CredentialVaultNotInitializedError,
    CredentialVaultPassphraseError,
    VaultCredentialTestResult,
    VolatileCredentialStore,
)
from kaval.database import KavalDatabase
from kaval.discovery.descriptor_generation import (
    AutoGeneratedDescriptorGenerator,
    DescriptorGenerationPolicyError,
    QuarantinedDescriptorReviewState,
    delete_quarantined_descriptor_review_record,
    load_quarantined_descriptor_review_record,
    validate_quarantined_descriptor_policy,
    write_quarantined_descriptor_review_record,
)
from kaval.discovery.descriptors import (
    DescriptorContainerDependency,
    DescriptorDependencies,
    DescriptorEndpoint,
    DescriptorInspectionSurface,
    DescriptorMatchRule,
    LoadedServiceDescriptor,
    ServiceDescriptor,
    build_auto_generated_descriptor_path,
    build_auto_generated_descriptor_reference_path,
    build_service_descriptor_community_export,
    build_user_descriptor_path,
    build_user_descriptor_reference_path,
    load_auto_generated_service_descriptors,
    load_service_descriptor,
    loaded_descriptor_identifier,
    write_auto_generated_descriptor,
    write_user_descriptor,
)
from kaval.effectiveness import (
    EffectivenessReport,
    build_descriptor_ids_with_adapters,
    build_effectiveness_report,
    maximum_achievable_insight_level,
)
from kaval.grouping import transition_incident
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
from kaval.investigation.cloud_model import (
    CloudModelConfig,
    CloudModelError,
    CloudTransport,
    probe_cloud_model_connection,
)
from kaval.investigation.local_model import (
    LocalModelConfig,
    LocalModelError,
    LocalModelResponseError,
    LocalModelTransportError,
    RequestTransport,
    probe_local_model_connection,
)
from kaval.investigation.workflow import InvestigationWorkflow
from kaval.maintenance import active_maintenance_windows
from kaval.memory.note_models import UserNoteVersion
from kaval.memory.user_notes import UserNoteNotFoundError, UserNoteService
from kaval.models import (
    ApprovalToken,
    Change,
    ChangeType,
    DependencyOverride,
    DependencyOverrideState,
    DescriptorSource,
    Finding,
    FindingFeedbackReason,
    FindingFeedbackRecord,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationTrigger,
    JournalEntry,
    MaintenanceScope,
    MaintenanceWindowRecord,
    NotificationPayload,
    NotificationSourceType,
    RedactionLevel,
    Service,
    ServiceCheckOverride,
    ServiceCheckOverrideScope,
    ServiceStatus,
    ServiceType,
    Severity,
    SystemProfile,
    UserNote,
    derive_service_insight,
)
from kaval.monitoring import (
    MonitoringCadenceConfig,
    default_monitoring_check_cadences,
    resolve_monitoring_cadence_decision,
    resolve_service_check_execution,
)
from kaval.monitoring.catalog import (
    check_applies_to_service,
    monitoring_check_catalog,
    monitoring_check_entry,
)
from kaval.monitoring_thresholds import (
    monitoring_threshold_defaults,
    monitoring_threshold_summary,
)
from kaval.notifications import (
    IncidentAlertRouter,
    NotificationBus,
    TelegramInteractiveHandler,
    TelegramMemoryCommandError,
    TelegramMemoryCommandHandler,
    load_telegram_config_from_env,
    load_telegram_webhook_config_from_env,
    supports_telegram_memory_command,
)
from kaval.notifications.bus import (
    AppriseAdapter,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
)
from kaval.notifications.routing import (
    AlertMaintenanceWindow,
    IncidentAlertRoute,
    IncidentAlertRoutingPolicy,
)
from kaval.notifications.telegram_interactive import TelegramTransport
from kaval.recommendations import (
    NoisyCheckPattern,
    RecommendationCandidate,
    build_proactive_recommendations,
)
from kaval.runtime import (
    CapabilityHealthReport,
    CapabilityRuntimeSignalSource,
    CheckSchedulerRuntimeSignal,
    DiscoveryPipelineRuntimeSignal,
    ExecutorProcessRuntimeSignal,
    build_capability_health_report,
    probe_unix_socket,
)
from kaval.settings import (
    ModelSettingsService,
    MonitoringSettingsService,
    NotificationSettingsService,
    SystemSettingsService,
    default_settings_path,
)
from kaval.settings.model_config import (
    ManagedCloudEscalationSettings,
    ManagedCloudModelSettings,
    ManagedLocalModelSettings,
    ManagedModelSettings,
)
from kaval.settings.monitoring_config import (
    ManagedMonitoringCheckSettings,
    ManagedMonitoringSettings,
)
from kaval.settings.notification_config import (
    ManagedNotificationQuietHoursSettings,
    ManagedNotificationSettings,
    NotificationChannelWrite,
)
from kaval.settings.system_config import ManagedSystemSettings

_ACTIVE_FINDING_STATUSES = {
    FindingStatus.NEW,
    FindingStatus.GROUPED,
    FindingStatus.INVESTIGATING,
}
_FINDING_FEEDBACK_SUGGESTION_THRESHOLD = 5
_RECENT_DISMISSED_FINDINGS_LIMIT = 8
_RUNTIME_LOG_LEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "trace": logging.DEBUG,
}
_RUNTIME_LOGGER_NAMES = ("kaval", "uvicorn", "uvicorn.error", "uvicorn.access")
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
    settings_path: Path
    migrations_dir: Path | None
    services_dir: Path
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
    settings_path: Path | str | None = None,
    migrations_dir: Path | str | None = None,
    services_dir: Path | str | None = None,
    web_dist_dir: Path | str | None = None,
    websocket_poll_interval: float = 2.0,
    telegram_transport: TelegramTransport | None = None,
    local_model_transport: RequestTransport | None = None,
    cloud_model_transport: CloudTransport | None = None,
    notification_bus_adapter_factory: Callable[[], AppriseAdapter] | None = None,
) -> FastAPI:
    """Create the Phase 1 FastAPI application."""
    settings = ApiSettings(
        database_path=_resolve_database_path(database_path),
        settings_path=_resolve_settings_path(settings_path),
        migrations_dir=_resolve_migrations_dir(migrations_dir),
        services_dir=_resolve_services_dir(services_dir),
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
        app.state.model_settings_service = ModelSettingsService(
            settings_path=settings.settings_path,
        )
        app.state.system_settings_service = SystemSettingsService(
            settings_path=settings.settings_path,
        )
        _apply_runtime_log_level(
            app,
            app.state.system_settings_service.active_snapshot().log_level,
        )
        app.state.monitoring_settings_service = MonitoringSettingsService(
            settings_path=settings.settings_path,
        )
        app.state.notification_settings_service = NotificationSettingsService(
            settings_path=settings.settings_path,
        )
        app.state.webhook_rate_limiter = WebhookRateLimiter(
            max_events_per_minute=settings.webhook_rate_limit_per_minute,
        )
        app.state.notification_sender = _ManagedNotificationSender(
            settings_service=app.state.notification_settings_service,
            vault=app.state.credential_vault,
            adapter_factory=notification_bus_adapter_factory,
        )
        app.state.incident_alert_router = IncidentAlertRouter(
            sender=app.state.notification_sender,
            policy=app.state.notification_settings_service.resolve_routing_policy(),
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
    app.state.local_model_transport = local_model_transport
    app.state.cloud_model_transport = cloud_model_transport
    app.state.notification_bus_adapter_factory = notification_bus_adapter_factory
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


def get_credential_request_manager(
    request: Request,
    database: ApiDatabase,
) -> CredentialRequestManager:
    """Build a credential-request manager bound to the current database handle."""
    settings: ApiSettings = request.app.state.api_settings
    return CredentialRequestManager(
        database=database,
        services_dir=settings.services_dir,
    )


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
        request_manager=CredentialRequestManager(
            database=database,
            services_dir=settings.services_dir,
        ),
        volatile_store=request.app.state.credential_volatile_store,
        vault=request.app.state.credential_vault,
        default_volatile_ttl_seconds=settings.volatile_credential_ttl_seconds,
    )


ApiCredentialMaterialService = Annotated[
    CredentialMaterialService,
    Depends(get_credential_material_service),
]


def get_model_settings_service(request: Request) -> ModelSettingsService:
    """Return the app-scoped staged/active model settings service."""
    return cast(ModelSettingsService, request.app.state.model_settings_service)


ApiModelSettingsService = Annotated[
    ModelSettingsService,
    Depends(get_model_settings_service),
]


def get_system_settings_service(request: Request) -> SystemSettingsService:
    """Return the app-scoped staged/active system settings service."""
    return cast(SystemSettingsService, request.app.state.system_settings_service)


ApiSystemSettingsService = Annotated[
    SystemSettingsService,
    Depends(get_system_settings_service),
]


def get_monitoring_settings_service(request: Request) -> MonitoringSettingsService:
    """Return the app-scoped staged/active monitoring settings service."""
    return cast(
        MonitoringSettingsService,
        request.app.state.monitoring_settings_service,
    )


ApiMonitoringSettingsService = Annotated[
    MonitoringSettingsService,
    Depends(get_monitoring_settings_service),
]


def get_notification_settings_service(request: Request) -> NotificationSettingsService:
    """Return the app-scoped staged/active notification settings service."""
    return cast(
        NotificationSettingsService,
        request.app.state.notification_settings_service,
    )


ApiNotificationSettingsService = Annotated[
    NotificationSettingsService,
    Depends(get_notification_settings_service),
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
    services = enrich_services_with_current_insight(
        database.list_services(),
        local_model_configured=_active_local_model_configured_for_app(request.app),
    )
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
def list_services(
    request: Request,
    database: ApiDatabase,
) -> list[Service]:
    """List persisted services for the current monitoring graph."""
    return enrich_services_with_current_insight(
        database.list_services(),
        local_model_configured=_active_local_model_configured_for_app(request.app),
    )


@_api_router.get("/services/{service_id}/detail", response_model=ServiceDetailResponse)
def service_detail(
    request: Request,
    service_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    monitoring_settings: ApiMonitoringSettingsService,
) -> ServiceDetailResponse:
    """Return the detailed service payload for one service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    local_model_configured = _active_local_model_configured_for_app(request.app)
    enriched_service = enrich_services_with_current_insight(
        [service],
        local_model_configured=local_model_configured,
    )[0]
    return build_service_detail_response(
        service=enriched_service,
        credential_material_service=credential_material_service,
        local_model_configured=local_model_configured,
        monitoring_settings=monitoring_settings,
        database=database,
    )


@_api_router.put(
    "/services/{service_id}/checks/{check_id}/suppression",
    response_model=ServiceDetailCheckSuppressionMutationResponse,
)
def update_service_check_suppression(
    request: Request,
    service_id: str,
    check_id: str,
    payload: ServiceDetailCheckSuppressionUpdateRequest,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    monitoring_settings: ApiMonitoringSettingsService,
) -> ServiceDetailCheckSuppressionMutationResponse:
    """Update one explicit per-service suppression toggle across active and staged state."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    try:
        entry = monitoring_check_entry(check_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not check_applies_to_service(check_id, service):
        raise HTTPException(
            status_code=400,
            detail=f"check {check_id} does not apply to service {service_id}",
        )
    previous_active_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.ACTIVE
    )
    previous_staged_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.STAGED
    )
    now = datetime.now(tz=UTC)
    next_active_overrides = _service_check_suppression_overrides(
        overrides=previous_active_overrides,
        scope=ServiceCheckOverrideScope.ACTIVE,
        service_id=service_id,
        check_id=check_id,
        suppressed=payload.suppressed,
        now=now,
    )
    next_staged_overrides = _service_check_suppression_overrides(
        overrides=previous_staged_overrides,
        scope=ServiceCheckOverrideScope.STAGED,
        service_id=service_id,
        check_id=check_id,
        suppressed=payload.suppressed,
        now=now,
    )
    database.replace_service_check_overrides(
        scope=ServiceCheckOverrideScope.ACTIVE,
        overrides=next_active_overrides,
    )
    database.replace_service_check_overrides(
        scope=ServiceCheckOverrideScope.STAGED,
        overrides=next_staged_overrides,
    )
    local_model_configured = _active_local_model_configured_for_app(request.app)
    enriched_service = enrich_services_with_current_insight(
        [service],
        local_model_configured=local_model_configured,
    )[0]
    audit_change = _build_service_check_suppression_change(
        service=service,
        check_label=entry.label,
        check_id=check_id,
        previous_active_override=_service_check_override_for(
            overrides=previous_active_overrides,
            service_id=service_id,
            check_id=check_id,
        ),
        previous_staged_override=_service_check_override_for(
            overrides=previous_staged_overrides,
            service_id=service_id,
            check_id=check_id,
        ),
        current_active_override=_service_check_override_for(
            overrides=next_active_overrides,
            service_id=service_id,
            check_id=check_id,
        ),
        current_staged_override=_service_check_override_for(
            overrides=next_staged_overrides,
            service_id=service_id,
            check_id=check_id,
        ),
        suppressed=payload.suppressed,
    )
    database.upsert_change(audit_change)
    return ServiceDetailCheckSuppressionMutationResponse(
        detail=build_service_detail_response(
            service=enriched_service,
            credential_material_service=credential_material_service,
            local_model_configured=local_model_configured,
            monitoring_settings=monitoring_settings,
            database=database,
        ),
        audit_change=audit_change,
    )


@_api_router.get(
    "/services/{service_id}/descriptor",
    response_model=ServiceDescriptorViewResponse,
)
def service_descriptor_view(
    service_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceDescriptorViewResponse:
    """Return the rendered descriptor view for one matched service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    loaded_descriptor = _loaded_descriptor_for_service(
        service=service,
        descriptors=credential_material_service.request_manager.descriptors,
    )
    if loaded_descriptor is None:
        raise HTTPException(status_code=404, detail="descriptor not found")
    return build_service_descriptor_view_response(
        loaded_descriptor,
        services_dir=credential_material_service.request_manager.services_dir,
    )


@_api_router.put(
    "/services/{service_id}/descriptor/validate",
    response_model=ServiceDescriptorValidationResponse,
)
def validate_service_descriptor(
    service_id: str,
    request: ServiceDescriptorSaveRequest,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceDescriptorValidationResponse:
    """Validate one pending descriptor edit and preview bounded likely impact."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    loaded_descriptor = _loaded_descriptor_for_service(
        service=service,
        descriptors=credential_material_service.request_manager.descriptors,
    )
    if loaded_descriptor is None:
        raise HTTPException(status_code=404, detail="descriptor not found")

    try:
        proposed_descriptor = _proposed_descriptor_from_save_request(
            request=request,
            loaded_descriptor=loaded_descriptor,
        )
    except HTTPException as exc:
        return ServiceDescriptorValidationResponse(
            valid=False,
            errors=[_http_exception_detail(exc)],
        )

    preview = _build_descriptor_validation_preview(
        service=service,
        services=database.list_services(),
        loaded_descriptor=loaded_descriptor,
        proposed_descriptor=proposed_descriptor,
        services_dir=credential_material_service.request_manager.services_dir,
    )
    return ServiceDescriptorValidationResponse(
        valid=True,
        warnings=_descriptor_policy_warnings(
            loaded_descriptor=loaded_descriptor,
            proposed_descriptor=proposed_descriptor,
            preview=preview,
        ),
        preview=preview,
    )


@_api_router.put(
    "/services/{service_id}/descriptor",
    response_model=ServiceDescriptorSaveResponse,
)
def save_service_descriptor(
    service_id: str,
    request: ServiceDescriptorSaveRequest,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceDescriptorSaveResponse:
    """Persist one reviewed user override for the selected service descriptor."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    loaded_descriptor = _loaded_descriptor_for_service(
        service=service,
        descriptors=credential_material_service.request_manager.descriptors,
    )
    if loaded_descriptor is None:
        raise HTTPException(status_code=404, detail="descriptor not found")

    updated_descriptor = _proposed_descriptor_from_save_request(
        request=request,
        loaded_descriptor=loaded_descriptor,
    )

    saved_descriptor = write_user_descriptor(
        services_dir=credential_material_service.request_manager.services_dir,
        descriptor=updated_descriptor,
    )
    database.update_descriptor_source_for_services(
        descriptor_id=loaded_descriptor_identifier(saved_descriptor),
        descriptor_source=DescriptorSource.USER,
    )
    audit_change = _build_descriptor_save_change(
        service=service,
        previous_descriptor=loaded_descriptor,
        saved_descriptor=saved_descriptor,
    )
    database.upsert_change(audit_change)
    credential_material_service.request_manager.reload_descriptors()
    refreshed_service = database.get_service(service_id)
    refreshed_descriptor = (
        None
        if refreshed_service is None
        else _loaded_descriptor_for_service(
            service=refreshed_service,
            descriptors=credential_material_service.request_manager.descriptors,
        )
    )
    return ServiceDescriptorSaveResponse(
        descriptor=build_service_descriptor_view_response(
            saved_descriptor if refreshed_descriptor is None else refreshed_descriptor,
            services_dir=credential_material_service.request_manager.services_dir,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/services/{service_id}/descriptor/auto-generate",
    response_model=ServiceDescriptorGenerateResponse,
)
def auto_generate_service_descriptor(
    service_id: str,
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> ServiceDescriptorGenerateResponse:
    """Generate one quarantined descriptor candidate for an unmatched container service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    _validate_auto_generated_descriptor_target(service)

    model_settings = cast(ModelSettingsService, request.app.state.model_settings_service)
    try:
        local_model_config = model_settings.resolve_local_model_config(
            scope="active",
            vault=cast(CredentialVault, request.app.state.credential_vault),
        )
    except CredentialVaultLockedError:
        local_model_config = None
    if local_model_config is None:
        raise HTTPException(
            status_code=409,
            detail="local model is not configured for descriptor generation",
        )

    generator = AutoGeneratedDescriptorGenerator(
        config=local_model_config,
        transport=cast(
            RequestTransport | None,
            getattr(request.app.state, "local_model_transport", None),
        ),
    )
    try:
        generated_descriptor = generator.generate(service=service)
    except (DescriptorGenerationPolicyError, LocalModelResponseError) as exc:
        raise HTTPException(
            status_code=502,
            detail="local model returned an invalid quarantined descriptor candidate",
        ) from exc
    except LocalModelTransportError as exc:
        raise HTTPException(
            status_code=502,
            detail="local model request failed during descriptor generation",
        ) from exc

    services_dir = credential_material_service.request_manager.services_dir
    previous_path = build_auto_generated_descriptor_path(services_dir, generated_descriptor)
    previous_descriptor = (
        load_service_descriptor(previous_path) if previous_path.exists() else None
    )
    saved_descriptor = write_auto_generated_descriptor(
        services_dir=services_dir,
        descriptor=generated_descriptor,
    )
    delete_quarantined_descriptor_review_record(
        services_dir,
        category=saved_descriptor.descriptor.category,
        descriptor_id=saved_descriptor.descriptor.id,
    )
    audit_change = _build_auto_generated_descriptor_change(
        service=service,
        previous_descriptor=previous_descriptor,
        saved_descriptor=saved_descriptor,
    )
    database.upsert_change(audit_change)
    return ServiceDescriptorGenerateResponse(
        service_id=service.id,
        service_name=service.name,
        descriptor=build_service_descriptor_view_response(
            saved_descriptor,
            services_dir=services_dir,
        ),
        audit_change=audit_change,
        warnings=[
            "Quarantined auto-generated descriptors stay inactive until review and promotion.",
            "This candidate does not change active matching, incident grouping, "
            "or action recommendations.",
        ],
    )


@_api_router.get(
    "/descriptors/auto-generated",
    response_model=list[QuarantinedDescriptorQueueItemResponse],
)
def list_auto_generated_descriptor_queue(
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> list[QuarantinedDescriptorQueueItemResponse]:
    """List quarantined descriptor candidates with current review context."""
    services_dir = credential_material_service.request_manager.services_dir
    candidates = load_auto_generated_service_descriptors([services_dir])
    services = database.list_services()
    return [
        _build_quarantined_descriptor_queue_item(
            loaded_descriptor=candidate,
            services=services,
            services_dir=services_dir,
        )
        for candidate in candidates
    ]


@_api_router.put(
    "/descriptors/auto-generated/{category}/{descriptor_id}",
    response_model=QuarantinedDescriptorActionResponse,
)
def edit_auto_generated_descriptor(
    category: str,
    descriptor_id: str,
    request: ServiceDescriptorSaveRequest,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> QuarantinedDescriptorActionResponse:
    """Edit one quarantined descriptor candidate in place."""
    loaded_descriptor = _load_quarantined_descriptor(
        services_dir=credential_material_service.request_manager.services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    edited_descriptor = _quarantined_descriptor_from_save_request(
        request=request,
        loaded_descriptor=loaded_descriptor,
    )
    saved_descriptor = _save_quarantined_descriptor_edit(
        services_dir=credential_material_service.request_manager.services_dir,
        previous_descriptor=loaded_descriptor,
        descriptor=edited_descriptor,
    )
    audit_change = _build_quarantined_descriptor_edit_change(
        previous_descriptor=loaded_descriptor,
        saved_descriptor=saved_descriptor,
    )
    database.upsert_change(audit_change)
    return QuarantinedDescriptorActionResponse(
        descriptor_id=loaded_descriptor_identifier(saved_descriptor),
        action="edited",
        review_state=QuarantinedDescriptorReviewState.PENDING.value,
        descriptor=build_service_descriptor_view_response(
            saved_descriptor,
            services_dir=credential_material_service.request_manager.services_dir,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/descriptors/auto-generated/{category}/{descriptor_id}/promote",
    response_model=QuarantinedDescriptorActionResponse,
)
def promote_auto_generated_descriptor(
    category: str,
    descriptor_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> QuarantinedDescriptorActionResponse:
    """Promote one quarantined descriptor candidate into the reviewed user tree."""
    services_dir = credential_material_service.request_manager.services_dir
    loaded_descriptor = _load_quarantined_descriptor(
        services_dir=services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    promoted_descriptor = loaded_descriptor.descriptor.model_copy(
        update={
            "source": DescriptorSource.USER,
            "verified": True,
        }
    )
    user_path = build_user_descriptor_path(services_dir, promoted_descriptor)
    if user_path.exists():
        raise HTTPException(
            status_code=409,
            detail="reviewed user descriptor already exists for this descriptor id",
        )
    saved_descriptor = write_user_descriptor(
        services_dir=services_dir,
        descriptor=promoted_descriptor,
    )
    loaded_descriptor.path.unlink()
    delete_quarantined_descriptor_review_record(
        services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    credential_material_service.request_manager.reload_descriptors()
    audit_change = _build_quarantined_descriptor_promote_change(
        previous_descriptor=loaded_descriptor,
        saved_descriptor=saved_descriptor,
    )
    database.upsert_change(audit_change)
    return QuarantinedDescriptorActionResponse(
        descriptor_id=loaded_descriptor_identifier(saved_descriptor),
        action="promoted",
        review_state=None,
        descriptor=build_service_descriptor_view_response(
            saved_descriptor,
            services_dir=services_dir,
        ),
        audit_change=audit_change,
    )


@_api_router.get(
    "/descriptors/user/{category}/{descriptor_id}/community-export",
    response_model=DescriptorCommunityExportResponse,
)
def export_descriptor_for_community(
    category: str,
    descriptor_id: str,
    credential_material_service: ApiCredentialMaterialService,
) -> DescriptorCommunityExportResponse:
    """Export one promoted auto-generated descriptor in a contributor-safe format."""
    services_dir = credential_material_service.request_manager.services_dir
    loaded_descriptor = _load_user_descriptor(
        services_dir=services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    descriptor = loaded_descriptor.descriptor
    if descriptor.source is not DescriptorSource.USER or not descriptor.verified:
        raise HTTPException(
            status_code=409,
            detail="descriptor must be promoted into the reviewed user tree before export",
        )
    if descriptor.generated_at is None:
        raise HTTPException(
            status_code=400,
            detail="only promoted auto-generated descriptors can be exported through this path",
        )
    community_export = build_service_descriptor_community_export(descriptor)
    return DescriptorCommunityExportResponse(
        descriptor_id=loaded_descriptor_identifier(loaded_descriptor),
        target_path=community_export.target_path,
        yaml_text=community_export.yaml_text,
        omitted_fields=list(community_export.omitted_fields),
    )


@_api_router.post(
    "/descriptors/auto-generated/{category}/{descriptor_id}/dismiss",
    response_model=QuarantinedDescriptorActionResponse,
)
def dismiss_auto_generated_descriptor(
    category: str,
    descriptor_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> QuarantinedDescriptorActionResponse:
    """Dismiss one quarantined descriptor candidate and remove it from the queue."""
    services_dir = credential_material_service.request_manager.services_dir
    loaded_descriptor = _load_quarantined_descriptor(
        services_dir=services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    loaded_descriptor.path.unlink()
    delete_quarantined_descriptor_review_record(
        services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    audit_change = _build_quarantined_descriptor_dismiss_change(
        loaded_descriptor=loaded_descriptor,
    )
    database.upsert_change(audit_change)
    return QuarantinedDescriptorActionResponse(
        descriptor_id=loaded_descriptor_identifier(loaded_descriptor),
        action="dismissed",
        review_state=None,
        descriptor=None,
        audit_change=audit_change,
    )


@_api_router.post(
    "/descriptors/auto-generated/{category}/{descriptor_id}/defer",
    response_model=QuarantinedDescriptorActionResponse,
)
def defer_auto_generated_descriptor(
    category: str,
    descriptor_id: str,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
) -> QuarantinedDescriptorActionResponse:
    """Mark one quarantined descriptor candidate as explicitly deferred."""
    services_dir = credential_material_service.request_manager.services_dir
    loaded_descriptor = _load_quarantined_descriptor(
        services_dir=services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    review_record = write_quarantined_descriptor_review_record(
        services_dir,
        descriptor=loaded_descriptor.descriptor,
        review_state=QuarantinedDescriptorReviewState.DEFERRED,
        updated_at=datetime.now(tz=UTC),
    )
    audit_change = _build_quarantined_descriptor_defer_change(
        loaded_descriptor=loaded_descriptor,
    )
    database.upsert_change(audit_change)
    return QuarantinedDescriptorActionResponse(
        descriptor_id=loaded_descriptor_identifier(loaded_descriptor),
        action="deferred",
        review_state=review_record.review_state.value,
        descriptor=build_service_descriptor_view_response(
            loaded_descriptor,
            services_dir=services_dir,
        ),
        audit_change=audit_change,
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
    request: Request,
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
    model_settings = cast(ModelSettingsService, request.app.state.model_settings_service)
    notification_settings = cast(
        NotificationSettingsService,
        request.app.state.notification_settings_service,
    )

    return build_capability_health_report(
        checked_at=checked_at,
        discovery_signal=discovery_signal,
        scheduler_signal=scheduler_signal,
        executor_signal=executor_signal,
        executor_socket_reachable=probe_unix_socket(executor_socket_path),
        local_model_configured=model_settings.active_local_configured(),
        cloud_model_configured=model_settings.active_cloud_configured(),
        notification_channel_count=notification_settings.configured_channel_count(
            scope="active"
        ),
        vault_status=credential_material_service.vault_status(),
        database_reachable=True,
        migrations_current=database.migrations_current(),
        database_corruption_detected=database_corruption_detected,
    )


@_api_router.get("/settings/models", response_model=ModelSettingsResponse)
def get_model_settings(
    model_settings: ApiModelSettingsService,
) -> ModelSettingsResponse:
    """Return staged and active model settings with explicit apply state."""
    return build_model_settings_response(model_settings)


@_api_router.put("/settings/models", response_model=ModelSettingsMutationResponse)
def update_model_settings(
    payload: ModelSettingsUpdateRequest,
    request: Request,
    database: ApiDatabase,
    model_settings: ApiModelSettingsService,
) -> ModelSettingsMutationResponse:
    """Persist one complete staged model-settings update."""
    previous_staged = model_settings.staged_snapshot()
    vault = cast(CredentialVault, request.app.state.credential_vault)
    try:
        model_settings.update_staged(
            local=ManagedLocalModelSettings(
                enabled=payload.local.enabled,
                model=payload.local.model,
                base_url=payload.local.base_url,
                timeout_seconds=payload.local.timeout_seconds,
            ),
            local_api_key=payload.local.api_key,
            clear_local_api_key=payload.local.clear_stored_api_key,
            cloud=ManagedCloudModelSettings(
                enabled=payload.cloud.enabled,
                provider=payload.cloud.provider,
                model=payload.cloud.model,
                base_url=payload.cloud.base_url,
                timeout_seconds=payload.cloud.timeout_seconds,
                max_output_tokens=payload.cloud.max_output_tokens,
            ),
            cloud_api_key=payload.cloud.api_key,
            clear_cloud_api_key=payload.cloud.clear_stored_api_key,
            escalation=ManagedCloudEscalationSettings(
                finding_count_gt=payload.escalation.finding_count_gt,
                local_confidence_lt=payload.escalation.local_confidence_lt,
                escalate_on_multiple_domains=payload.escalation.escalate_on_multiple_domains,
                escalate_on_changelog_research=payload.escalation.escalate_on_changelog_research,
                escalate_on_user_request=payload.escalation.escalate_on_user_request,
                max_cloud_calls_per_day=payload.escalation.max_cloud_calls_per_day,
                max_cloud_calls_per_incident=payload.escalation.max_cloud_calls_per_incident,
            ),
            vault=vault,
        )
    except CredentialVaultLockedError as exc:
        raise HTTPException(
            status_code=409,
            detail="vault must be unlocked to store model API keys",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    audit_change = _build_model_settings_change(
        action="saved",
        previous=previous_staged,
        current=model_settings.staged_snapshot(),
        config_path=Path(model_settings.settings_path),
        apply_required=model_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return ModelSettingsMutationResponse(
        settings=build_model_settings_response(model_settings),
        audit_change=audit_change,
    )


@_api_router.post("/settings/models/apply", response_model=ModelSettingsMutationResponse)
def apply_model_settings(
    database: ApiDatabase,
    model_settings: ApiModelSettingsService,
) -> ModelSettingsMutationResponse:
    """Apply the staged model-settings snapshot into the active runtime."""
    previous_active = model_settings.active_snapshot()
    model_settings.apply()
    audit_change = _build_model_settings_change(
        action="applied",
        previous=previous_active,
        current=model_settings.active_snapshot(),
        config_path=Path(model_settings.settings_path),
        apply_required=model_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return ModelSettingsMutationResponse(
        settings=build_model_settings_response(model_settings),
        audit_change=audit_change,
    )


@_api_router.post("/settings/models/test", response_model=ModelSettingsTestResponse)
def test_model_settings_connection(
    payload: ModelSettingsTestRequest,
    request: Request,
    model_settings: ApiModelSettingsService,
) -> ModelSettingsTestResponse:
    """Run one explicit bounded model connectivity test against staged or active settings."""
    vault = cast(CredentialVault, request.app.state.credential_vault)
    checked_at = datetime.now(tz=UTC)
    try:
        if payload.target is ModelSettingsTestTarget.LOCAL:
            local_config = model_settings.resolve_local_model_config(
                scope=_model_settings_scope_value(payload.scope),
                vault=vault,
            )
            if local_config is None:
                return ModelSettingsTestResponse(
                    target=payload.target,
                    scope=payload.scope,
                    ok=False,
                    checked_at=checked_at,
                    message="Selected local model settings are not configured.",
            )
            probe_local_model_connection(
                config=local_config,
                transport=cast(
                    RequestTransport | None,
                    getattr(request.app.state, "local_model_transport", None),
                ),
            )
            return ModelSettingsTestResponse(
                target=payload.target,
                scope=payload.scope,
                ok=True,
                checked_at=checked_at,
                message="Local model endpoint accepted the explicit settings test.",
            )

        cloud_config = model_settings.resolve_cloud_model_config(
            scope=_model_settings_scope_value(payload.scope),
            vault=vault,
        )
        if cloud_config is None:
            return ModelSettingsTestResponse(
                target=payload.target,
                scope=payload.scope,
                ok=False,
                checked_at=checked_at,
                message="Selected cloud model settings are not configured.",
            )
        probe_cloud_model_connection(
            config=cloud_config,
            transport=cast(
                CloudTransport | None,
                getattr(request.app.state, "cloud_model_transport", None),
            ),
        )
        return ModelSettingsTestResponse(
            target=payload.target,
            scope=payload.scope,
            ok=True,
            checked_at=checked_at,
            message="Cloud model endpoint accepted the explicit settings test.",
        )
    except CredentialVaultLockedError:
        return ModelSettingsTestResponse(
            target=payload.target,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message="Vault is locked; unlock it before testing a vault-backed model API key.",
        )
    except (ValueError, LocalModelError, CloudModelError) as exc:
        return ModelSettingsTestResponse(
            target=payload.target,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message=str(exc),
        )


@_api_router.get("/settings/notifications", response_model=NotificationSettingsResponse)
def get_notification_settings(
    notification_settings: ApiNotificationSettingsService,
) -> NotificationSettingsResponse:
    """Return staged and active notification settings with explicit apply state."""
    return build_notification_settings_response(notification_settings)


@_api_router.put(
    "/settings/notifications",
    response_model=NotificationSettingsMutationResponse,
)
def update_notification_settings(
    payload: NotificationSettingsUpdateRequest,
    request: Request,
    database: ApiDatabase,
    notification_settings: ApiNotificationSettingsService,
) -> NotificationSettingsMutationResponse:
    """Persist one complete staged notification-settings update."""
    previous_staged = notification_settings.staged_snapshot()
    vault = cast(CredentialVault, request.app.state.credential_vault)
    try:
        notification_settings.update_staged(
            channels=[
                NotificationChannelWrite(
                    id=channel.id,
                    name=channel.name,
                    enabled=channel.enabled,
                    destination=channel.destination,
                )
                for channel in payload.channels
            ],
            routing=_build_notification_routing_policy(payload),
            quiet_hours=ManagedNotificationQuietHoursSettings(
                enabled=payload.quiet_hours.enabled,
                start_time_local=payload.quiet_hours.start_time_local,
                end_time_local=payload.quiet_hours.end_time_local,
                timezone=payload.quiet_hours.timezone,
            ),
            vault=vault,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_change = _build_notification_settings_change(
        action="saved",
        previous=previous_staged,
        current=notification_settings.staged_snapshot(),
        config_path=notification_settings.settings_path,
        apply_required=notification_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return NotificationSettingsMutationResponse(
        settings=build_notification_settings_response(notification_settings),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/notifications/apply",
    response_model=NotificationSettingsMutationResponse,
)
def apply_notification_settings(
    request: Request,
    database: ApiDatabase,
    notification_settings: ApiNotificationSettingsService,
) -> NotificationSettingsMutationResponse:
    """Apply the current staged notification settings to runtime use."""
    previous_active = notification_settings.active_snapshot()
    notification_settings.apply()
    router = cast(IncidentAlertRouter, request.app.state.incident_alert_router)
    sender = cast(_ManagedNotificationSender, request.app.state.notification_sender)
    router.reconfigure(
        sender=sender,
        policy=notification_settings.resolve_routing_policy(scope="active"),
    )
    audit_change = _build_notification_settings_change(
        action="applied",
        previous=previous_active,
        current=notification_settings.active_snapshot(),
        config_path=notification_settings.settings_path,
        apply_required=notification_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return NotificationSettingsMutationResponse(
        settings=build_notification_settings_response(notification_settings),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/notifications/test",
    response_model=NotificationSettingsTestResponse,
)
def test_notification_settings_channel(
    payload: NotificationSettingsTestRequest,
    request: Request,
    notification_settings: ApiNotificationSettingsService,
) -> NotificationSettingsTestResponse:
    """Send one explicit bounded notification test through the selected channel."""
    scope = _notification_settings_scope_value(payload.scope)
    checked_at = datetime.now(tz=UTC)
    snapshot = (
        notification_settings.active_snapshot()
        if scope == "active"
        else notification_settings.staged_snapshot()
    )
    channel = next(
        (
            item
            for item in snapshot.channels
            if item.id == payload.channel_id
        ),
        None,
    )
    if channel is None:
        return NotificationSettingsTestResponse(
            channel_id=payload.channel_id,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message="Selected notification channel does not exist.",
        )
    if not channel.enabled:
        return NotificationSettingsTestResponse(
            channel_id=payload.channel_id,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message="Selected notification channel is disabled.",
        )

    vault = cast(CredentialVault, request.app.state.credential_vault)
    try:
        config = notification_settings.resolve_bus_config(
            scope=scope,
            vault=vault,
            channel_id=payload.channel_id,
        )
    except CredentialVaultLockedError:
        return NotificationSettingsTestResponse(
            channel_id=payload.channel_id,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message=(
                "Vault is locked; unlock it before testing a vault-backed "
                "notification destination."
            ),
        )

    if config is None or not config.channels:
        return NotificationSettingsTestResponse(
            channel_id=payload.channel_id,
            scope=payload.scope,
            ok=False,
            checked_at=checked_at,
            message="Selected notification channel is not configured.",
        )

    bus = NotificationBus(
        config=config,
        adapter_factory=cast(
            Callable[[], AppriseAdapter] | None,
            getattr(request.app.state, "notification_bus_adapter_factory", None),
        ),
    )
    result = bus.send(
        _build_notification_settings_test_payload(
            channel_name=channel.name,
            checked_at=checked_at,
        )
    )
    return NotificationSettingsTestResponse(
        channel_id=payload.channel_id,
        scope=payload.scope,
        ok=result.status == NotificationDeliveryStatus.SENT,
        checked_at=checked_at,
        message=(
            "Explicit notification channel test delivered successfully."
            if result.status == NotificationDeliveryStatus.SENT
            else result.detail
        ),
    )


@_api_router.get("/settings/monitoring", response_model=MonitoringSettingsResponse)
def get_monitoring_settings(
    database: ApiDatabase,
    monitoring_settings: ApiMonitoringSettingsService,
) -> MonitoringSettingsResponse:
    """Return staged and active monitoring settings with explicit apply state."""
    return build_monitoring_settings_response(
        monitoring_settings=monitoring_settings,
        database=database,
    )


@_api_router.put(
    "/settings/monitoring",
    response_model=MonitoringSettingsMutationResponse,
)
def update_monitoring_settings(
    payload: MonitoringSettingsUpdateRequest,
    database: ApiDatabase,
    monitoring_settings: ApiMonitoringSettingsService,
) -> MonitoringSettingsMutationResponse:
    """Persist one complete staged monitoring-settings update."""
    services = database.list_services()
    _validate_monitoring_settings_payload(payload=payload, services=services)
    previous_staged = monitoring_settings.staged_snapshot()
    previous_staged_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.STAGED
    )
    monitoring_settings.update_staged(
        checks=[
            ManagedMonitoringCheckSettings(
                check_id=check.check_id,
                enabled=check.enabled,
                interval_seconds=check.interval_seconds,
                tls_warning_days=check.tls_warning_days,
                restart_delta_threshold=check.restart_delta_threshold,
                probe_timeout_seconds=check.probe_timeout_seconds,
            )
            for check in payload.checks
        ]
    )
    database.replace_service_check_overrides(
        scope=ServiceCheckOverrideScope.STAGED,
        overrides=_monitoring_service_overrides_from_payload(
            payload=payload,
            scope=ServiceCheckOverrideScope.STAGED,
            now=datetime.now(tz=UTC),
        ),
    )
    audit_change = _build_monitoring_settings_change(
        action="saved",
        previous=previous_staged,
        previous_service_overrides=previous_staged_overrides,
        current=monitoring_settings.staged_snapshot(),
        current_service_overrides=database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.STAGED
        ),
        config_path=monitoring_settings.settings_path,
        apply_required=_monitoring_apply_required(
            monitoring_settings=monitoring_settings,
            database=database,
        ),
    )
    database.upsert_change(audit_change)
    return MonitoringSettingsMutationResponse(
        settings=build_monitoring_settings_response(
            monitoring_settings=monitoring_settings,
            database=database,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/monitoring/apply",
    response_model=MonitoringSettingsMutationResponse,
)
def apply_monitoring_settings(
    database: ApiDatabase,
    monitoring_settings: ApiMonitoringSettingsService,
) -> MonitoringSettingsMutationResponse:
    """Apply the staged monitoring settings to runtime use."""
    previous_active = monitoring_settings.active_snapshot()
    previous_active_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.ACTIVE
    )
    staged_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.STAGED
    )
    applied_at = datetime.now(tz=UTC)
    monitoring_settings.apply(now=applied_at)
    database.replace_service_check_overrides(
        scope=ServiceCheckOverrideScope.ACTIVE,
        overrides=[
            override.model_copy(
                update={
                    "scope": ServiceCheckOverrideScope.ACTIVE,
                    "updated_at": applied_at,
                }
            )
            for override in staged_overrides
        ],
    )
    audit_change = _build_monitoring_settings_change(
        action="applied",
        previous=previous_active,
        previous_service_overrides=previous_active_overrides,
        current=monitoring_settings.active_snapshot(),
        current_service_overrides=database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE
        ),
        config_path=monitoring_settings.settings_path,
        apply_required=_monitoring_apply_required(
            monitoring_settings=monitoring_settings,
            database=database,
        ),
    )
    database.upsert_change(audit_change)
    return MonitoringSettingsMutationResponse(
        settings=build_monitoring_settings_response(
            monitoring_settings=monitoring_settings,
            database=database,
        ),
        audit_change=audit_change,
    )


@_api_router.get("/settings/system", response_model=SystemSettingsResponse)
def get_system_settings(
    request: Request,
    database: ApiDatabase,
    system_settings: ApiSystemSettingsService,
    model_settings: ApiModelSettingsService,
) -> SystemSettingsResponse:
    """Return staged and active system settings with runtime/about metadata."""
    return build_system_settings_response(
        request=request,
        database=database,
        system_settings=system_settings,
        model_settings=model_settings,
    )


@_api_router.put("/settings/system", response_model=SystemSettingsMutationResponse)
def update_system_settings(
    payload: SystemSettingsUpdateRequest,
    request: Request,
    database: ApiDatabase,
    system_settings: ApiSystemSettingsService,
    model_settings: ApiModelSettingsService,
) -> SystemSettingsMutationResponse:
    """Persist one complete staged system-settings update."""
    previous_staged = system_settings.staged_snapshot()
    system_settings.update_staged(
        log_level=cast(
            Literal["critical", "error", "warning", "info", "debug", "trace"],
            str(payload.log_level),
        ),
        audit_detail_retention_days=payload.audit_detail_retention_days,
        audit_summary_retention_days=payload.audit_summary_retention_days,
    )
    audit_change = _build_system_settings_change(
        action="saved",
        previous=previous_staged,
        current=system_settings.staged_snapshot(),
        config_path=system_settings.settings_path,
        apply_required=system_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return SystemSettingsMutationResponse(
        settings=build_system_settings_response(
            request=request,
            database=database,
            system_settings=system_settings,
            model_settings=model_settings,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/system/apply",
    response_model=SystemSettingsMutationResponse,
)
def apply_system_settings(
    request: Request,
    database: ApiDatabase,
    system_settings: ApiSystemSettingsService,
    model_settings: ApiModelSettingsService,
) -> SystemSettingsMutationResponse:
    """Apply the staged system settings to runtime use."""
    previous_active = system_settings.active_snapshot()
    current_active = system_settings.apply()
    _apply_runtime_log_level(request.app, current_active.log_level)
    audit_change = _build_system_settings_change(
        action="applied",
        previous=previous_active,
        current=current_active,
        config_path=system_settings.settings_path,
        apply_required=system_settings.apply_required(),
    )
    database.upsert_change(audit_change)
    return SystemSettingsMutationResponse(
        settings=build_system_settings_response(
            request=request,
            database=database,
            system_settings=system_settings,
            model_settings=model_settings,
        ),
        audit_change=audit_change,
    )


@_api_router.get("/settings/vault", response_model=CredentialVaultResponse)
def get_credential_vault(
    request: Request,
    credential_material_service: ApiCredentialMaterialService,
    model_settings: ApiModelSettingsService,
    notification_settings: ApiNotificationSettingsService,
) -> CredentialVaultResponse:
    """Return operator-facing vault status and stored-credential metadata."""
    return build_credential_vault_response(
        request=request,
        credential_material_service=credential_material_service,
        model_settings=model_settings,
        notification_settings=notification_settings,
    )


@_api_router.post(
    "/settings/vault/unlock",
    response_model=CredentialVaultMutationResponse,
)
def unlock_credential_vault(
    payload: VaultUnlockRequest,
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    model_settings: ApiModelSettingsService,
    notification_settings: ApiNotificationSettingsService,
) -> CredentialVaultMutationResponse:
    """Initialize or unlock the credential vault through the admin settings flow."""
    previous_status = credential_material_service.vault_status()
    try:
        credential_material_service.unlock_vault(payload.master_passphrase)
    except CredentialVaultPassphraseError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_change = _build_credential_vault_change(
        action="unlocked",
        previous_status=previous_status,
        current_status=credential_material_service.vault_status(),
    )
    database.upsert_change(audit_change)
    return CredentialVaultMutationResponse(
        vault=build_credential_vault_response(
            request=request,
            credential_material_service=credential_material_service,
            model_settings=model_settings,
            notification_settings=notification_settings,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/vault/lock",
    response_model=CredentialVaultMutationResponse,
)
def lock_credential_vault(
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    model_settings: ApiModelSettingsService,
    notification_settings: ApiNotificationSettingsService,
) -> CredentialVaultMutationResponse:
    """Explicitly lock the credential vault through the admin settings flow."""
    previous_status = credential_material_service.vault_status()
    credential_material_service.lock_vault()
    audit_change = _build_credential_vault_change(
        action="locked",
        previous_status=previous_status,
        current_status=credential_material_service.vault_status(),
    )
    database.upsert_change(audit_change)
    return CredentialVaultMutationResponse(
        vault=build_credential_vault_response(
            request=request,
            credential_material_service=credential_material_service,
            model_settings=model_settings,
            notification_settings=notification_settings,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/vault/change-password",
    response_model=CredentialVaultMutationResponse,
)
def change_credential_vault_password(
    payload: CredentialVaultChangePasswordRequest,
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    model_settings: ApiModelSettingsService,
    notification_settings: ApiNotificationSettingsService,
) -> CredentialVaultMutationResponse:
    """Rotate the vault master passphrase and keep the vault unlocked afterward."""
    previous_status = credential_material_service.vault_status()
    try:
        credential_material_service.change_vault_master_passphrase(
            current_master_passphrase=payload.current_master_passphrase,
            new_master_passphrase=payload.new_master_passphrase,
        )
    except CredentialVaultPassphraseError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CredentialVaultNotInitializedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except CredentialVaultError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_change = _build_credential_vault_change(
        action="changed_password",
        previous_status=previous_status,
        current_status=credential_material_service.vault_status(),
    )
    database.upsert_change(audit_change)
    return CredentialVaultMutationResponse(
        vault=build_credential_vault_response(
            request=request,
            credential_material_service=credential_material_service,
            model_settings=model_settings,
            notification_settings=notification_settings,
        ),
        audit_change=audit_change,
    )


@_api_router.post(
    "/settings/vault/test",
    response_model=CredentialVaultTestResponse,
)
def test_credential_vault(
    request: Request,
    database: ApiDatabase,
    credential_material_service: ApiCredentialMaterialService,
    model_settings: ApiModelSettingsService,
    notification_settings: ApiNotificationSettingsService,
) -> CredentialVaultTestResponse:
    """Explicitly test whether stored vault credentials remain readable."""
    checked_at = datetime.now(tz=UTC)
    try:
        results = credential_material_service.test_vault_credentials(now=checked_at)
    except CredentialVaultLockedError:
        return CredentialVaultTestResponse(
            vault=build_credential_vault_response(
                request=request,
                credential_material_service=credential_material_service,
                model_settings=model_settings,
                notification_settings=notification_settings,
            ),
            ok=False,
            checked_at=checked_at,
            tested_credentials=0,
            readable_credentials=0,
            results=[],
            message="Vault is locked; unlock it before testing stored credentials.",
            audit_change=None,
        )
    except CredentialVaultError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    response = build_credential_vault_response(
        request=request,
        credential_material_service=credential_material_service,
        model_settings=model_settings,
        notification_settings=notification_settings,
    )
    if not results:
        return CredentialVaultTestResponse(
            vault=response,
            ok=True,
            checked_at=checked_at,
            tested_credentials=0,
            readable_credentials=0,
            results=[],
            message="No stored credentials are currently in the vault.",
            audit_change=None,
        )

    readable_credentials = sum(1 for item in results if item.ok)
    credential_map = {item.reference_id: item for item in response.credentials}
    audit_change = _build_credential_vault_test_change(
        tested_credentials=len(results),
        readable_credentials=readable_credentials,
    )
    database.upsert_change(audit_change)
    return CredentialVaultTestResponse(
        vault=response,
        ok=readable_credentials == len(results),
        checked_at=checked_at,
        tested_credentials=len(results),
        readable_credentials=readable_credentials,
        results=[
            _build_credential_vault_test_item_response(
                item,
                checked_at=checked_at,
                credential_map=credential_map,
            )
            for item in results
        ],
        message=(
            "Explicit vault readability test passed for all stored credentials."
            if readable_credentials == len(results)
            else "Vault readability test found unreadable stored credentials."
        ),
        audit_change=audit_change,
    )


@_api_router.get("/findings/review", response_model=FindingReviewResponse)
def review_findings(
    database: ApiDatabase,
) -> FindingReviewResponse:
    """Return active findings, recent dismissals, and advisory noise-control suggestions."""
    return build_finding_review_response(database=database)


@_api_router.get("/maintenance", response_model=MaintenanceModeResponse)
def get_maintenance_mode(
    database: ApiDatabase,
) -> MaintenanceModeResponse:
    """Return the current active global and per-service maintenance windows."""
    return build_maintenance_mode_response(database=database)


@_api_router.put(
    "/maintenance/global",
    response_model=MaintenanceModeMutationResponse,
)
def enable_global_maintenance(
    payload: MaintenanceWindowUpdateRequest,
    database: ApiDatabase,
) -> MaintenanceModeMutationResponse:
    """Enable or refresh the global maintenance window."""
    now = datetime.now(tz=UTC)
    maintenance_window = MaintenanceWindowRecord(
        scope=MaintenanceScope.GLOBAL,
        started_at=now,
        expires_at=now + timedelta(minutes=payload.duration_minutes),
    )
    database.upsert_maintenance_window(maintenance_window)
    audit_change = _build_maintenance_change(
        scope=MaintenanceScope.GLOBAL,
        service=None,
        duration_minutes=payload.duration_minutes,
        enabled=True,
        now=now,
    )
    database.upsert_change(audit_change)
    return MaintenanceModeMutationResponse(
        maintenance=build_maintenance_mode_response(database=database, now=now),
        audit_change=audit_change,
    )


@_api_router.delete(
    "/maintenance/global",
    response_model=MaintenanceModeMutationResponse,
)
def clear_global_maintenance(
    database: ApiDatabase,
) -> MaintenanceModeMutationResponse:
    """Clear the active global maintenance window."""
    active_global = _active_global_maintenance_window(database=database)
    if active_global is None:
        raise HTTPException(status_code=404, detail="global maintenance is not active")
    now = datetime.now(tz=UTC)
    database.delete_maintenance_window(scope=MaintenanceScope.GLOBAL)
    audit_change = _build_maintenance_change(
        scope=MaintenanceScope.GLOBAL,
        service=None,
        duration_minutes=None,
        enabled=False,
        now=now,
    )
    database.upsert_change(audit_change)
    return MaintenanceModeMutationResponse(
        maintenance=build_maintenance_mode_response(database=database, now=now),
        audit_change=audit_change,
    )


@_api_router.put(
    "/services/{service_id}/maintenance",
    response_model=MaintenanceModeMutationResponse,
)
def enable_service_maintenance(
    service_id: str,
    payload: MaintenanceWindowUpdateRequest,
    database: ApiDatabase,
) -> MaintenanceModeMutationResponse:
    """Enable or refresh the maintenance window for one service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    now = datetime.now(tz=UTC)
    database.upsert_maintenance_window(
        MaintenanceWindowRecord(
            scope=MaintenanceScope.SERVICE,
            service_id=service_id,
            started_at=now,
            expires_at=now + timedelta(minutes=payload.duration_minutes),
        )
    )
    audit_change = _build_maintenance_change(
        scope=MaintenanceScope.SERVICE,
        service=service,
        duration_minutes=payload.duration_minutes,
        enabled=True,
        now=now,
    )
    database.upsert_change(audit_change)
    return MaintenanceModeMutationResponse(
        maintenance=build_maintenance_mode_response(database=database, now=now),
        audit_change=audit_change,
    )


@_api_router.delete(
    "/services/{service_id}/maintenance",
    response_model=MaintenanceModeMutationResponse,
)
def clear_service_maintenance(
    service_id: str,
    database: ApiDatabase,
) -> MaintenanceModeMutationResponse:
    """Clear the active maintenance window for one service."""
    service = database.get_service(service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    active_window = _active_service_maintenance_window(
        database=database,
        service_id=service_id,
    )
    if active_window is None:
        raise HTTPException(status_code=404, detail="service maintenance is not active")
    now = datetime.now(tz=UTC)
    database.delete_maintenance_window(
        scope=MaintenanceScope.SERVICE,
        service_id=service_id,
    )
    audit_change = _build_maintenance_change(
        scope=MaintenanceScope.SERVICE,
        service=service,
        duration_minutes=None,
        enabled=False,
        now=now,
    )
    database.upsert_change(audit_change)
    return MaintenanceModeMutationResponse(
        maintenance=build_maintenance_mode_response(database=database, now=now),
        audit_change=audit_change,
    )


@_api_router.post(
    "/findings/{finding_id}/dismiss",
    response_model=FindingDismissResponse,
)
def dismiss_finding(
    finding_id: str,
    payload: FindingDismissRequest,
    database: ApiDatabase,
) -> FindingDismissResponse:
    """Dismiss one finding with an explicit operator-provided noise reason."""
    finding = database.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.status in {FindingStatus.RESOLVED, FindingStatus.DISMISSED}:
        raise HTTPException(
            status_code=409,
            detail="only active findings can be dismissed as noise",
        )
    now = datetime.now(tz=UTC)
    dismissed_finding = finding.model_copy(
        update={
            "status": FindingStatus.DISMISSED,
            "resolved_at": now,
        }
    )
    database.upsert_finding(dismissed_finding)
    database.upsert_finding_feedback_record(
        FindingFeedbackRecord(
            id=f"ffb-{uuid4()}",
            finding_id=finding.id,
            service_id=finding.service_id,
            finding_domain=finding.domain,
            reason=payload.reason,
            recorded_at=now,
        )
    )
    if finding.incident_id is not None:
        incident = database.get_incident(finding.incident_id)
        if incident is not None and incident.status not in {
            IncidentStatus.RESOLVED,
            IncidentStatus.DISMISSED,
        } and not _incident_has_active_findings(
            database=database,
            incident_id=finding.incident_id,
        ):
            database.upsert_incident(
                transition_incident(
                    incident,
                    IncidentStatus.DISMISSED,
                    changed_at=now,
                )
            )
    audit_change = _build_finding_dismiss_change(
        finding=dismissed_finding,
        previous_status=finding.status,
        reason=payload.reason,
        database=database,
    )
    database.upsert_change(audit_change)
    return FindingDismissResponse(
        finding=dismissed_finding,
        review=build_finding_review_response(database=database),
        audit_change=audit_change,
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
def list_changes(
    database: ApiDatabase,
    system_settings: ApiSystemSettingsService,
) -> list[Change]:
    """List persisted change events within the active audit summary window."""
    active_settings = system_settings.active_snapshot()
    cutoff = datetime.now(tz=UTC) - timedelta(
        days=active_settings.audit_summary_retention_days
    )
    return [change for change in database.list_changes() if change.timestamp >= cutoff]


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
def graph(
    request: Request,
    database: ApiDatabase,
    manager: ApiCredentialRequestManager,
) -> ServiceGraphResponse:
    """Return the Phase 1 service map with explicit dependency edges."""
    return build_service_graph(
        enrich_services_with_current_insight(
            database.list_services(),
            local_model_configured=_active_local_model_configured_for_app(request.app),
        ),
        descriptors=manager.descriptors,
    )


@_api_router.put("/graph/edges", response_model=GraphEdgeMutationResponse)
def upsert_graph_edge(
    request: GraphEdgeUpsertRequest,
    database: ApiDatabase,
) -> GraphEdgeMutationResponse:
    """Confirm or edit one dependency edge through the admin graph."""
    services = database.list_services()
    services_by_id = {service.id: service for service in services}
    _validate_graph_edge_request(request=request, services_by_id=services_by_id)

    existing_edge = _find_dependency_edge(
        services_by_id=services_by_id,
        source_service_id=request.source_service_id,
        target_service_id=request.target_service_id,
    )
    description = _effective_graph_edge_description(
        requested_description=request.description,
        existing_edge=existing_edge,
    )

    if _graph_edge_replacement_requested(request):
        database.upsert_dependency_override(
            DependencyOverride(
                source_service_id=str(request.previous_source_service_id),
                target_service_id=str(request.previous_target_service_id),
                state=DependencyOverrideState.ABSENT,
                description=None,
                updated_at=datetime.now(tz=UTC),
            )
        )

    database.upsert_dependency_override(
        DependencyOverride(
            source_service_id=request.source_service_id,
            target_service_id=request.target_service_id,
            state=DependencyOverrideState.PRESENT,
            description=description,
            updated_at=datetime.now(tz=UTC),
        )
    )
    audit_change = _build_graph_edge_change(
        services_by_id=services_by_id,
        request=request,
        description=description,
        removed=False,
    )
    database.upsert_change(audit_change)
    updated_edge = _require_graph_edge(
        build_service_graph(database.list_services()).edges,
        source_service_id=request.source_service_id,
        target_service_id=request.target_service_id,
    )
    return GraphEdgeMutationResponse(edge=updated_edge, audit_change=audit_change)


@_api_router.delete(
    "/graph/edges/{source_service_id}/{target_service_id}",
    response_model=GraphEdgeMutationResponse,
)
def delete_graph_edge(
    source_service_id: str,
    target_service_id: str,
    database: ApiDatabase,
) -> GraphEdgeMutationResponse:
    """Remove one dependency edge from the effective graph through an admin override."""
    services = database.list_services()
    services_by_id = {service.id: service for service in services}
    if source_service_id not in services_by_id or target_service_id not in services_by_id:
        raise HTTPException(status_code=404, detail="service not found")
    if source_service_id == target_service_id:
        raise HTTPException(
            status_code=400,
            detail="dependency edges cannot target the same service",
        )

    database.upsert_dependency_override(
        DependencyOverride(
            source_service_id=source_service_id,
            target_service_id=target_service_id,
            state=DependencyOverrideState.ABSENT,
            description=None,
            updated_at=datetime.now(tz=UTC),
        )
    )
    audit_change = _build_graph_edge_change(
        services_by_id=services_by_id,
        request=GraphEdgeUpsertRequest(
            source_service_id=source_service_id,
            target_service_id=target_service_id,
        ),
        description=None,
        removed=True,
    )
    database.upsert_change(audit_change)
    return GraphEdgeMutationResponse(edge=None, audit_change=audit_change)


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
    services = enrich_services_with_current_insight(
        database.list_services(),
        local_model_configured=_active_local_model_configured_for_app(request.app),
    )
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
    request: Request,
    database: ApiDatabase,
    manager: ApiCredentialRequestManager,
) -> EffectivenessReport:
    """Return the equal-weighted v1 effectiveness score and minimal breakdown."""
    return build_effectiveness_report(
        services=enrich_services_with_current_insight(
            database.list_services(),
            local_model_configured=_active_local_model_configured_for_app(request.app),
        ),
        descriptors=manager.descriptors,
        adapter_registry=_DEFAULT_ADAPTER_REGISTRY,
    )


@_api_router.get("/recommendations", response_model=RecommendationsResponse)
def recommendations(
    database: ApiDatabase,
    model_settings: ApiModelSettingsService,
) -> RecommendationsResponse:
    """Return ranked proactive admin recommendations derived from current state."""
    return build_proactive_recommendations_response(
        database=database,
        model_settings=model_settings,
    )


@_api_router.websocket("/ws")
async def websocket_updates(websocket: WebSocket) -> None:
    """Stream Phase 1 UI snapshots whenever the persisted state changes."""
    await websocket.accept()
    settings: ApiSettings = websocket.app.state.api_settings
    last_snapshot_json: str | None = None
    try:
        while True:
            snapshot = _load_realtime_snapshot(websocket.app)
            snapshot_json = snapshot.model_dump_json()
            if snapshot_json != last_snapshot_json:
                await websocket.send_json(snapshot.model_dump(mode="json"))
                last_snapshot_json = snapshot_json
            await asyncio.sleep(settings.websocket_poll_interval_seconds)
    except WebSocketDisconnect:
        return


def build_service_graph(
    services: Sequence[Service],
    *,
    descriptors: Sequence[LoadedServiceDescriptor] = (),
) -> ServiceGraphResponse:
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
    descriptor_ids_with_adapters = build_descriptor_ids_with_adapters(
        descriptors=descriptors,
        adapter_registry=_DEFAULT_ADAPTER_REGISTRY,
    )
    node_meta = [
        ServiceGraphNodeMeta(
            service_id=service.id,
            target_insight_level=target_level,
            improve_available=(
                service.insight is None or int(service.insight.level) < target_level
            ),
        )
        for service in ordered_services
        for target_level in [
            int(
                maximum_achievable_insight_level(
                    service=service,
                    descriptor_ids_with_adapters=descriptor_ids_with_adapters,
                )
            )
        ]
    ]
    return ServiceGraphResponse(services=ordered_services, edges=edges, node_meta=node_meta)


def _validate_graph_edge_request(
    *,
    request: GraphEdgeUpsertRequest,
    services_by_id: dict[str, Service],
) -> None:
    """Reject malformed or unknown graph-edge mutation requests."""
    if (
        request.source_service_id not in services_by_id
        or request.target_service_id not in services_by_id
    ):
        raise HTTPException(status_code=404, detail="service not found")
    if request.source_service_id == request.target_service_id:
        raise HTTPException(
            status_code=400,
            detail="dependency edges cannot target the same service",
        )
    previous_fields = (
        request.previous_source_service_id,
        request.previous_target_service_id,
    )
    if any(field is None for field in previous_fields) and any(
        field is not None for field in previous_fields
    ):
        raise HTTPException(
            status_code=400,
            detail="previous edge source and target must be provided together",
        )
    if request.previous_source_service_id is not None:
        if (
            request.previous_source_service_id not in services_by_id
            or request.previous_target_service_id not in services_by_id
        ):
            raise HTTPException(status_code=404, detail="service not found")
        if (
            request.previous_source_service_id == request.source_service_id
            and request.previous_target_service_id == request.target_service_id
        ):
            return
        if request.previous_source_service_id == request.previous_target_service_id:
            raise HTTPException(
                status_code=400,
                detail="dependency edges cannot target the same service",
            )


def _graph_edge_replacement_requested(request: GraphEdgeUpsertRequest) -> bool:
    """Return whether the request replaces a different existing edge."""
    return (
        request.previous_source_service_id is not None
        and request.previous_target_service_id is not None
        and (
            request.previous_source_service_id != request.source_service_id
            or request.previous_target_service_id != request.target_service_id
        )
    )


def _find_dependency_edge(
    *,
    services_by_id: dict[str, Service],
    source_service_id: str,
    target_service_id: str,
) -> ServiceGraphEdge | None:
    """Return one effective dependency edge from the current service graph."""
    source_service = services_by_id.get(source_service_id)
    if source_service is None:
        return None
    for dependency in source_service.dependencies:
        if dependency.target_service_id == target_service_id:
            return ServiceGraphEdge(
                source_service_id=source_service_id,
                target_service_id=target_service_id,
                confidence=dependency.confidence,
                source=dependency.source,
                description=dependency.description,
            )
    return None


def _require_graph_edge(
    edges: Sequence[ServiceGraphEdge],
    *,
    source_service_id: str,
    target_service_id: str,
) -> ServiceGraphEdge:
    """Return one edge from a graph response or raise if it is missing."""
    edge = next(
        (
            candidate
            for candidate in edges
            if candidate.source_service_id == source_service_id
            and candidate.target_service_id == target_service_id
        ),
        None,
    )
    if edge is None:
        raise HTTPException(status_code=500, detail="graph edge was not persisted")
    return edge


def _effective_graph_edge_description(
    *,
    requested_description: str | None,
    existing_edge: ServiceGraphEdge | None,
) -> str:
    """Resolve the user-visible description to persist for one edge."""
    if requested_description is not None and requested_description.strip():
        return requested_description.strip()
    if existing_edge is not None and existing_edge.description is not None:
        return existing_edge.description
    return "Dependency confirmed by the local admin."


def _build_graph_edge_change(
    *,
    services_by_id: dict[str, Service],
    request: GraphEdgeUpsertRequest,
    description: str | None,
    removed: bool,
) -> Change:
    """Build one auditable config-change record for a graph edge mutation."""
    source_name = services_by_id[request.source_service_id].name
    target_name = services_by_id[request.target_service_id].name
    if removed:
        summary = f"Removed dependency edge {source_name} -> {target_name}."
    elif _graph_edge_replacement_requested(request):
        previous_source_name = services_by_id[str(request.previous_source_service_id)].name
        previous_target_name = services_by_id[str(request.previous_target_service_id)].name
        summary = (
            "Edited dependency edge "
            f"{previous_source_name} -> {previous_target_name} to "
            f"{source_name} -> {target_name}."
        )
    else:
        summary = f"Confirmed dependency edge {source_name} -> {target_name}."
    return Change(
        id=f"chg-graph-edge-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=request.source_service_id,
        description=summary,
        old_value=(
            None
            if request.previous_source_service_id is None
            or request.previous_target_service_id is None
            else f"{request.previous_source_service_id}->{request.previous_target_service_id}"
        ),
        new_value=(
            None
            if removed
            else f"{request.source_service_id}->{request.target_service_id}"
        ),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    ).model_copy(
        update={
            "description": (
                f"{summary} {description}"
                if description and description not in summary
                else summary
            )
        }
    )


def build_model_settings_response(
    model_settings: ModelSettingsService,
) -> ModelSettingsResponse:
    """Build the typed staged/active model-settings response payload."""
    return ModelSettingsResponse(
        config_path=str(model_settings.settings_path),
        load_error=model_settings.load_error,
        apply_required=model_settings.apply_required(),
        last_applied_at=model_settings.last_applied_at,
        active=_model_settings_scope_payload(model_settings, scope="active"),
        staged=_model_settings_scope_payload(model_settings, scope="staged"),
    )


def _model_settings_scope_payload(
    model_settings: ModelSettingsService,
    *,
    scope: Literal["active", "staged"],
) -> ModelSettingsScopeResponse:
    """Build one staged or active model-settings scope payload."""
    snapshot = (
        model_settings.active_snapshot()
        if scope == "active"
        else model_settings.staged_snapshot()
    )
    local_source = _model_settings_secret_source(
        model_settings.local_api_key_source(scope=scope)
    )
    cloud_source = _model_settings_secret_source(
        model_settings.cloud_api_key_source(scope=scope)
    )
    return ModelSettingsScopeResponse(
        local=ModelSettingsLocalScopeResponse(
            enabled=snapshot.local.enabled,
            provider=snapshot.local.provider,
            model=snapshot.local.model,
            base_url=snapshot.local.base_url,
            timeout_seconds=snapshot.local.timeout_seconds,
            api_key_ref=snapshot.local.api_key_ref,
            api_key_source=local_source,
            api_key_configured=local_source is not ModelSettingsSecretSource.UNSET,
            configured=bool(snapshot.local.enabled and snapshot.local.model),
        ),
        cloud=ModelSettingsCloudScopeResponse(
            enabled=snapshot.cloud.enabled,
            provider=snapshot.cloud.provider,
            model=snapshot.cloud.model,
            base_url=snapshot.cloud.base_url,
            timeout_seconds=snapshot.cloud.timeout_seconds,
            max_output_tokens=snapshot.cloud.max_output_tokens,
            api_key_ref=snapshot.cloud.api_key_ref,
            api_key_source=cloud_source,
            api_key_configured=cloud_source is not ModelSettingsSecretSource.UNSET,
            configured=bool(
                snapshot.cloud.enabled
                and snapshot.cloud.model
                and cloud_source is not ModelSettingsSecretSource.UNSET
            ),
        ),
        escalation=ModelSettingsEscalationResponse(
            **snapshot.escalation.model_dump(mode="json")
        ),
    )


def _model_settings_secret_source(source: str) -> ModelSettingsSecretSource:
    """Convert one internal secret-source value into the API enum."""
    if source == "vault":
        return ModelSettingsSecretSource.VAULT
    if source == "env":
        return ModelSettingsSecretSource.ENV
    return ModelSettingsSecretSource.UNSET


def _model_settings_scope_value(
    scope: ModelSettingsTestScope,
) -> Literal["active", "staged"]:
    """Convert the API scope enum into the internal staged/active selector."""
    return "active" if scope is ModelSettingsTestScope.ACTIVE else "staged"


def build_system_settings_response(
    *,
    request: Request,
    database: KavalDatabase,
    system_settings: SystemSettingsService,
    model_settings: ModelSettingsService,
) -> SystemSettingsResponse:
    """Build the typed staged/active system-settings response payload."""
    checked_at = datetime.now(tz=UTC)
    return SystemSettingsResponse(
        config_path=str(system_settings.settings_path),
        load_error=system_settings.load_error,
        apply_required=system_settings.apply_required(),
        last_applied_at=system_settings.last_applied_at,
        active=_system_settings_scope_payload(
            system_settings,
            scope="active",
        ),
        staged=_system_settings_scope_payload(
            system_settings,
            scope="staged",
        ),
        database=_system_settings_database_status(
            request=request,
            database=database,
        ),
        transfer_guidance=_system_settings_transfer_guidance(),
        about=_system_settings_about_payload(
            request=request,
            checked_at=checked_at,
            system_settings=system_settings,
            model_settings=model_settings,
        ),
    )


def _system_settings_scope_payload(
    system_settings: SystemSettingsService,
    *,
    scope: Literal["active", "staged"],
) -> SystemSettingsScopeResponse:
    """Build one staged or active system-settings scope payload."""
    snapshot = (
        system_settings.active_snapshot()
        if scope == "active"
        else system_settings.staged_snapshot()
    )
    return SystemSettingsScopeResponse(
        log_level=SystemSettingsLogLevel(snapshot.log_level),
        audit_detail_retention_days=snapshot.audit_detail_retention_days,
        audit_summary_retention_days=snapshot.audit_summary_retention_days,
    )


def _system_settings_database_status(
    *,
    request: Request,
    database: KavalDatabase,
) -> SystemSettingsDatabaseStatusResponse:
    """Build the read-only database maintenance payload for system settings."""
    settings = cast(ApiSettings, request.app.state.api_settings)
    database_path = settings.database_path
    quick_check_result = database.connection().execute("PRAGMA quick_check").fetchone()
    quick_check_message = (
        str(quick_check_result[0]) if quick_check_result is not None else "no result"
    )
    journal_mode_result = database.connection().execute("PRAGMA journal_mode").fetchone()
    journal_mode = (
        str(journal_mode_result[0]) if journal_mode_result is not None else "unknown"
    )
    return SystemSettingsDatabaseStatusResponse(
        path=str(database_path),
        exists=database_path.exists(),
        size_bytes=database_path.stat().st_size if database_path.exists() else 0,
        migrations_current=database.migrations_current(),
        quick_check_ok=quick_check_message.casefold() == "ok",
        quick_check_result=quick_check_message,
        journal_mode=journal_mode,
    )


def _system_settings_transfer_guidance() -> SystemSettingsTransferGuidanceResponse:
    """Build Phase 3C import/export warnings without enabling transfer flows."""
    return SystemSettingsTransferGuidanceResponse(
        phase_guardrail=(
            "Phase 3C exposes warnings and scope only. Automated backup, export, "
            "and import execution stays out of scope until Phase 4."
        ),
        exports=[
            SystemSettingsExportGuidanceResponse(
                target=SystemSettingsExportTarget.OPERATIONAL_MEMORY,
                label="Operational memory",
                available=False,
                sensitivity=SystemSettingsSensitivity.HIGH,
                warning=(
                    "Operational-memory exports can contain sensitive incident context, "
                    "user notes, system topology, and credential references."
                ),
            ),
            SystemSettingsExportGuidanceResponse(
                target=SystemSettingsExportTarget.SETTINGS,
                label="Settings",
                available=False,
                sensitivity=SystemSettingsSensitivity.HIGH,
                warning=(
                    "Settings exports exclude raw vault secrets, but still include "
                    "sensitive endpoints, routing policy, and secret reference identifiers."
                ),
            ),
            SystemSettingsExportGuidanceResponse(
                target=SystemSettingsExportTarget.DESCRIPTORS,
                label="Descriptors",
                available=False,
                sensitivity=SystemSettingsSensitivity.MEDIUM,
                warning=(
                    "Descriptor exports can reveal sensitive hostnames, shares, ports, "
                    "dependency topology, and reviewed service assumptions."
                ),
            ),
        ],
        imports=[
            SystemSettingsImportGuidanceResponse(
                target=SystemSettingsImportTarget.DESCRIPTORS,
                label="Descriptor import",
                available=False,
                warning=(
                    "Descriptor imports can activate sensitive topology assumptions. "
                    "Review and promote descriptors explicitly before runtime use."
                ),
            ),
            SystemSettingsImportGuidanceResponse(
                target=SystemSettingsImportTarget.NOTES,
                label="Notes import",
                available=False,
                warning=(
                    "Imported notes may contain sensitive operator context and must be "
                    "reviewed before they become trusted operational memory."
                ),
            ),
            SystemSettingsImportGuidanceResponse(
                target=SystemSettingsImportTarget.CONFIGURATION_BACKUP,
                label="Configuration backup import",
                available=False,
                warning=(
                    "Configuration backup import can overwrite sensitive routing and "
                    "endpoint settings. Phase 3C surfaces the warning only, not the action."
                ),
            ),
        ],
    )


def _system_settings_about_payload(
    *,
    request: Request,
    checked_at: datetime,
    system_settings: SystemSettingsService,
    model_settings: ModelSettingsService,
) -> SystemSettingsAboutResponse:
    """Build the current runtime/build/about payload for system settings."""
    settings = cast(ApiSettings, request.app.state.api_settings)
    started_at = cast(datetime, request.app.state.started_at)
    runtime_log_level = cast(
        str,
        getattr(
            request.app.state,
            "runtime_log_level",
            system_settings.active_snapshot().log_level,
        ),
    )
    model_snapshot = model_settings.active_snapshot()
    local_summary = (
        f"Enabled · {model_snapshot.local.model} · {model_snapshot.local.base_url}"
        if model_snapshot.local.enabled and model_snapshot.local.model
        else "Disabled"
    )
    cloud_summary = (
        f"Enabled · {model_snapshot.cloud.provider} · {model_snapshot.cloud.model}"
        if model_snapshot.cloud.enabled and model_snapshot.cloud.model
        else "Disabled"
    )
    escalation_summary = (
        f"Finding>{model_snapshot.escalation.finding_count_gt}, "
        f"confidence<{model_snapshot.escalation.local_confidence_lt:.2f}, "
        f"caps {model_snapshot.escalation.max_cloud_calls_per_day}/day and "
        f"{model_snapshot.escalation.max_cloud_calls_per_incident}/incident"
    )
    return SystemSettingsAboutResponse(
        api_title=request.app.title,
        api_version=request.app.version,
        api_summary=request.app.summary,
        checked_at=checked_at,
        started_at=started_at,
        uptime_seconds=max((checked_at - started_at).total_seconds(), 0.0),
        runtime_log_level=SystemSettingsLogLevel(runtime_log_level),
        settings_path=str(settings.settings_path),
        database_path=str(settings.database_path),
        services_dir=str(settings.services_dir),
        web_dist_dir=str(settings.web_dist_dir),
        web_bundle_present=settings.web_dist_dir.exists(),
        model_status=SystemSettingsAboutModelStatusResponse(
            local_model_enabled=model_snapshot.local.enabled,
            local_model_configured=model_settings.active_local_configured(),
            local_model_summary=local_summary,
            cloud_model_enabled=model_snapshot.cloud.enabled,
            cloud_model_configured=model_settings.active_cloud_configured(),
            cloud_model_summary=cloud_summary,
            escalation_summary=escalation_summary,
        ),
    )


def build_notification_settings_response(
    notification_settings: NotificationSettingsService,
) -> NotificationSettingsResponse:
    """Build the typed staged/active notification-settings response payload."""
    effective_now = datetime.now(tz=UTC)
    return NotificationSettingsResponse(
        config_path=str(notification_settings.settings_path),
        load_error=notification_settings.load_error,
        apply_required=notification_settings.apply_required(),
        last_applied_at=notification_settings.last_applied_at,
        active=_notification_settings_scope_payload(
            notification_settings,
            scope="active",
            now=effective_now,
        ),
        staged=_notification_settings_scope_payload(
            notification_settings,
            scope="staged",
            now=effective_now,
        ),
    )


def _notification_settings_scope_payload(
    notification_settings: NotificationSettingsService,
    *,
    scope: Literal["active", "staged"],
    now: datetime,
) -> NotificationSettingsScopeResponse:
    """Build one staged or active notification-settings scope payload."""
    snapshot = (
        notification_settings.active_snapshot()
        if scope == "active"
        else notification_settings.staged_snapshot()
    )
    quiet_until = snapshot.quiet_hours.quiet_until(now=now)
    return NotificationSettingsScopeResponse(
        channels=[
            NotificationSettingsChannelScopeResponse(
                id=channel.id,
                name=channel.name,
                kind=channel.kind,
                enabled=channel.enabled,
                destination_ref=channel.destination_ref,
                destination_source=_notification_settings_secret_source(
                    notification_settings.channel_destination_source(
                        channel_id=channel.id,
                        scope=scope,
                    )
                ),
                destination_configured=(
                    notification_settings.channel_destination_source(
                        channel_id=channel.id,
                        scope=scope,
                    )
                    != "unset"
                ),
            )
            for channel in snapshot.channels
        ],
        routing=NotificationSettingsRoutingResponse(
            **snapshot.routing.model_dump(mode="json")
        ),
        quiet_hours=NotificationSettingsQuietHoursResponse(
            enabled=snapshot.quiet_hours.enabled,
            start_time_local=snapshot.quiet_hours.start_time_local,
            end_time_local=snapshot.quiet_hours.end_time_local,
            timezone=snapshot.quiet_hours.timezone,
            active_now=quiet_until is not None,
            quiet_until=quiet_until,
        ),
        configured_channel_count=notification_settings.configured_channel_count(
            scope=scope
        ),
    )


def _notification_settings_secret_source(
    source: str,
) -> NotificationSettingsSecretSource:
    """Convert one internal destination-source value into the API enum."""
    if source == "vault":
        return NotificationSettingsSecretSource.VAULT
    if source == "env":
        return NotificationSettingsSecretSource.ENV
    return NotificationSettingsSecretSource.UNSET


def _notification_settings_scope_value(
    scope: NotificationSettingsTestScope,
) -> Literal["active", "staged"]:
    """Convert the API scope enum into the internal staged/active selector."""
    return "active" if scope is NotificationSettingsTestScope.ACTIVE else "staged"


def build_monitoring_settings_response(
    *,
    monitoring_settings: MonitoringSettingsService,
    database: KavalDatabase,
) -> MonitoringSettingsResponse:
    """Build the typed staged/active monitoring-settings response payload."""
    effective_now = datetime.now(tz=UTC)
    return MonitoringSettingsResponse(
        config_path=str(monitoring_settings.settings_path),
        load_error=monitoring_settings.load_error,
        apply_required=_monitoring_apply_required(
            monitoring_settings=monitoring_settings,
            database=database,
        ),
        last_applied_at=monitoring_settings.last_applied_at,
        active=_monitoring_settings_scope_payload(
            monitoring_settings=monitoring_settings,
            database=database,
            scope="active",
            now=effective_now,
        ),
        staged=_monitoring_settings_scope_payload(
            monitoring_settings=monitoring_settings,
            database=database,
            scope="staged",
            now=effective_now,
        ),
    )


def _monitoring_settings_scope_payload(
    *,
    monitoring_settings: MonitoringSettingsService,
    database: KavalDatabase,
    scope: Literal["active", "staged"],
    now: datetime,
) -> MonitoringSettingsScopeResponse:
    """Build one staged or active monitoring-settings scope payload."""
    services = database.list_services()
    incidents = [
        incident
        for incident in database.list_incidents()
        if incident.status in _ACTIVE_INCIDENT_STATUSES
    ]
    overrides = database.list_service_check_overrides(
        scope=(
            ServiceCheckOverrideScope.ACTIVE
            if scope == "active"
            else ServiceCheckOverrideScope.STAGED
        )
    )
    cadence = monitoring_settings.resolve_cadence_config(
        scope=scope,
        service_overrides=overrides,
    )
    return MonitoringSettingsScopeResponse(
        checks=_monitoring_check_response_payloads(
            monitoring_settings=monitoring_settings,
            scope=scope,
        ),
        service_overrides=_monitoring_service_override_payloads(
            services=services,
            overrides=overrides,
        ),
        effective_services=_monitoring_effective_service_payloads(
            monitoring_settings=monitoring_settings,
            scope=scope,
            services=services,
            service_overrides=overrides,
            incidents=incidents,
            cadence=cadence,
            now=now,
        ),
    )


def _monitoring_check_response_payloads(
    *,
    monitoring_settings: MonitoringSettingsService,
    scope: Literal["active", "staged"],
) -> list[MonitoringSettingsCheckResponse]:
    """Build the operator-facing global monitoring settings rows."""
    snapshot = (
        monitoring_settings.active_snapshot()
        if scope == "active"
        else monitoring_settings.staged_snapshot()
    )
    snapshot_by_id = {check.check_id: check for check in snapshot.checks}
    defaults_by_id = {
        rule.check_id: rule for rule in default_monitoring_check_cadences()
    }
    return [
        MonitoringSettingsCheckResponse(
            check_id=entry.check_id,
            label=entry.label,
            description=entry.description,
            enabled=snapshot_by_id[entry.check_id].enabled,
            interval_seconds=snapshot_by_id[entry.check_id].interval_seconds,
            tls_warning_days=snapshot_by_id[entry.check_id].tls_warning_days,
            restart_delta_threshold=(
                snapshot_by_id[entry.check_id].restart_delta_threshold
            ),
            probe_timeout_seconds=snapshot_by_id[entry.check_id].probe_timeout_seconds,
            default_enabled=defaults_by_id[entry.check_id].enabled,
            default_interval_seconds=defaults_by_id[entry.check_id].interval_seconds,
            default_tls_warning_days=monitoring_threshold_defaults(entry.check_id)[0],
            default_restart_delta_threshold=monitoring_threshold_defaults(entry.check_id)[1],
            default_probe_timeout_seconds=monitoring_threshold_defaults(entry.check_id)[2],
        )
        for entry in monitoring_check_catalog()
    ]


def _monitoring_service_override_payloads(
    *,
    services: Sequence[Service],
    overrides: Sequence[ServiceCheckOverride],
) -> list[MonitoringSettingsServiceOverrideResponse]:
    """Build the operator-facing service override rows."""
    services_by_id = {service.id: service for service in services}
    payloads: list[MonitoringSettingsServiceOverrideResponse] = []
    for override in overrides:
        service = services_by_id.get(override.service_id)
        if service is None:
            continue
        entry = monitoring_check_entry(override.check_id)
        payloads.append(
            MonitoringSettingsServiceOverrideResponse(
                service_id=service.id,
                service_name=service.name,
                service_status=service.status,
                check_id=override.check_id,
                check_label=entry.label,
                enabled=override.enabled,
                interval_seconds=override.interval_seconds,
                tls_warning_days=override.tls_warning_days,
                restart_delta_threshold=override.restart_delta_threshold,
                probe_timeout_seconds=override.probe_timeout_seconds,
                updated_at=override.updated_at,
            )
        )
    return payloads


def _monitoring_effective_service_payloads(
    *,
    monitoring_settings: MonitoringSettingsService,
    scope: Literal["active", "staged"],
    services: Sequence[Service],
    service_overrides: Sequence[ServiceCheckOverride],
    incidents: Sequence[Incident],
    cadence: MonitoringCadenceConfig,
    now: datetime,
) -> list[MonitoringSettingsEffectiveServiceResponse]:
    """Build the effective cadence rows for each service."""
    default_rules_by_id = {
        rule.check_id: rule for rule in default_monitoring_check_cadences()
    }
    payloads: list[MonitoringSettingsEffectiveServiceResponse] = []
    for service in services:
        check_rows: list[MonitoringSettingsEffectiveCheckResponse] = []
        for entry in monitoring_check_catalog():
            if not check_applies_to_service(entry.check_id, service):
                continue
            execution = resolve_service_check_execution(
                config=cadence,
                service_id=service.id,
                check_id=entry.check_id,
                base_interval_seconds=default_rules_by_id[entry.check_id].interval_seconds,
            )
            decision = resolve_monitoring_cadence_decision(
                config=cadence,
                check_id=entry.check_id,
                services=list(services),
                now=now,
                incidents=list(incidents),
                base_interval_seconds=default_rules_by_id[entry.check_id].interval_seconds,
            )
            accelerated_now = decision.accelerated and service.id in decision.scoped_service_ids
            effective_interval_seconds = execution.interval_seconds
            if accelerated_now:
                effective_interval_seconds = min(
                    effective_interval_seconds,
                    decision.effective_interval_seconds,
                )
            thresholds = monitoring_settings.resolve_threshold_settings(
                scope=scope,
                service_overrides=service_overrides,
                service_id=service.id,
                check_id=entry.check_id,
            )
            check_rows.append(
                MonitoringSettingsEffectiveCheckResponse(
                    check_id=entry.check_id,
                    label=entry.label,
                    enabled=execution.enabled,
                    base_interval_seconds=execution.interval_seconds,
                    effective_interval_seconds=effective_interval_seconds,
                    source=_monitoring_resolution_source(execution.source),
                    tls_warning_days=thresholds.tls_warning_days,
                    restart_delta_threshold=thresholds.restart_delta_threshold,
                    probe_timeout_seconds=thresholds.probe_timeout_seconds,
                    threshold_source=(
                        None
                        if (
                            thresholds.tls_warning_days is None
                            and thresholds.restart_delta_threshold is None
                            and thresholds.probe_timeout_seconds is None
                        )
                        else _monitoring_resolution_source(thresholds.source)
                    ),
                    accelerated_now=accelerated_now,
                    incident_ids=decision.incident_ids if accelerated_now else [],
                )
            )
        if check_rows:
            payloads.append(
                MonitoringSettingsEffectiveServiceResponse(
                    service_id=service.id,
                    service_name=service.name,
                    service_status=service.status,
                    checks=check_rows,
                )
            )
    return payloads


def _monitoring_resolution_source(
    source: str,
) -> MonitoringSettingsResolutionSource:
    """Convert one internal monitoring-resolution source into the API enum."""
    if source == "service_override":
        return MonitoringSettingsResolutionSource.SERVICE_OVERRIDE
    return MonitoringSettingsResolutionSource.GLOBAL_DEFAULT


def _monitoring_apply_required(
    *,
    monitoring_settings: MonitoringSettingsService,
    database: KavalDatabase,
) -> bool:
    """Return whether the staged monitoring settings still need apply."""
    if monitoring_settings.apply_required():
        return True
    return not _service_check_override_sets_equal(
        database.list_service_check_overrides(scope=ServiceCheckOverrideScope.ACTIVE),
        database.list_service_check_overrides(scope=ServiceCheckOverrideScope.STAGED),
    )


def _service_check_override_sets_equal(
    left: Sequence[ServiceCheckOverride],
    right: Sequence[ServiceCheckOverride],
) -> bool:
    """Compare two service override snapshots while ignoring update timestamps."""
    def normalize(
        overrides: Sequence[ServiceCheckOverride],
    ) -> list[
        tuple[
            str,
            str,
            bool | None,
            int | None,
            int | None,
            int | None,
            float | None,
        ]
    ]:
        return sorted(
            (
                override.service_id,
                override.check_id,
                override.enabled,
                override.interval_seconds,
                override.tls_warning_days,
                override.restart_delta_threshold,
                override.probe_timeout_seconds,
            )
            for override in overrides
        )

    return normalize(left) == normalize(right)


def _validate_monitoring_settings_payload(
    *,
    payload: MonitoringSettingsUpdateRequest,
    services: Sequence[Service],
) -> None:
    """Reject unsupported check ids and meaningless service override targets."""
    supported_check_ids = {entry.check_id for entry in monitoring_check_catalog()}
    services_by_id = {service.id: service for service in services}
    seen_check_ids: set[str] = set()
    for check in payload.checks:
        if check.check_id in seen_check_ids:
            raise HTTPException(
                status_code=400,
                detail=f"duplicate monitoring check id: {check.check_id}",
            )
        seen_check_ids.add(check.check_id)
    provided_check_ids = seen_check_ids
    if provided_check_ids != supported_check_ids:
        missing = sorted(supported_check_ids - provided_check_ids)
        extra = sorted(provided_check_ids - supported_check_ids)
        detail_parts: list[str] = []
        if missing:
            detail_parts.append(f"missing checks: {', '.join(missing)}")
        if extra:
            detail_parts.append(f"unsupported checks: {', '.join(extra)}")
        raise HTTPException(status_code=400, detail="; ".join(detail_parts))
    seen_override_keys: set[tuple[str, str]] = set()
    for override in payload.service_overrides:
        key = (override.service_id, override.check_id)
        if key in seen_override_keys:
            raise HTTPException(
                status_code=400,
                detail=(
                    "duplicate service override key: "
                    f"{override.service_id}/{override.check_id}"
                ),
            )
        seen_override_keys.add(key)
        service = services_by_id.get(override.service_id)
        if service is None:
            raise HTTPException(status_code=404, detail="service not found")
        if override.check_id not in supported_check_ids:
            raise HTTPException(
                status_code=400,
                detail=f"unsupported monitoring check id: {override.check_id}",
            )
        if not check_applies_to_service(override.check_id, service):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"check {override.check_id} does not apply to service "
                    f"{override.service_id}"
                ),
            )


def _monitoring_service_overrides_from_payload(
    *,
    payload: MonitoringSettingsUpdateRequest,
    scope: ServiceCheckOverrideScope,
    now: datetime,
) -> list[ServiceCheckOverride]:
    """Convert the writable monitoring payload into persisted override records."""
    return [
        ServiceCheckOverride(
            scope=scope,
            service_id=override.service_id,
            check_id=override.check_id,
            enabled=override.enabled,
            interval_seconds=override.interval_seconds,
            tls_warning_days=override.tls_warning_days,
            restart_delta_threshold=override.restart_delta_threshold,
            probe_timeout_seconds=override.probe_timeout_seconds,
            updated_at=now,
        )
        for override in payload.service_overrides
    ]


def _service_check_override_for(
    *,
    overrides: Sequence[ServiceCheckOverride],
    service_id: str,
    check_id: str,
) -> ServiceCheckOverride | None:
    """Return the persisted override for one service/check pair if present."""
    for override in overrides:
        if override.service_id == service_id and override.check_id == check_id:
            return override
    return None


def _service_check_suppression_overrides(
    *,
    overrides: Sequence[ServiceCheckOverride],
    scope: ServiceCheckOverrideScope,
    service_id: str,
    check_id: str,
    suppressed: bool,
    now: datetime,
) -> list[ServiceCheckOverride]:
    """Apply one suppression toggle while preserving unrelated service overrides."""
    updated: list[ServiceCheckOverride] = []
    matched = False
    for override in overrides:
        if override.service_id != service_id or override.check_id != check_id:
            updated.append(override)
            continue
        matched = True
        if override.enabled is True:
            raise HTTPException(
                status_code=409,
                detail=(
                    "service check has an explicit enabled override; "
                    "edit monitoring settings instead"
                ),
            )
        if suppressed:
            updated.append(
                override.model_copy(
                    update={
                        "scope": scope,
                        "enabled": False,
                        "updated_at": now,
                    }
                )
            )
            continue
        if override.interval_seconds is None:
            continue
        updated.append(
            override.model_copy(
                update={
                    "scope": scope,
                    "enabled": None,
                    "updated_at": now,
                }
            )
        )
    if not matched and suppressed:
        updated.append(
            ServiceCheckOverride(
                scope=scope,
                service_id=service_id,
                check_id=check_id,
                enabled=False,
                interval_seconds=None,
                updated_at=now,
            )
        )
    return sorted(updated, key=lambda item: (item.service_id, item.check_id))


def _build_notification_routing_policy(
    payload: NotificationSettingsUpdateRequest,
) -> IncidentAlertRoutingPolicy:
    """Build a typed routing policy from the writable notification payload."""
    return IncidentAlertRoutingPolicy(
        critical=IncidentAlertRoute(payload.routing.critical),
        high=IncidentAlertRoute(payload.routing.high),
        medium=IncidentAlertRoute(payload.routing.medium),
        low=IncidentAlertRoute(payload.routing.low),
        dedup_window_minutes=payload.routing.dedup_window_minutes,
        digest_window_minutes=payload.routing.digest_window_minutes,
    )


def _build_notification_settings_test_payload(
    *,
    channel_name: str,
    checked_at: datetime,
) -> NotificationPayload:
    """Build one explicit operator-triggered notification test payload."""
    return NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id=f"notification-test:{channel_name}",
        incident_id=None,
        severity=Severity.LOW,
        title="Kaval notification settings test",
        summary=f"Explicit test for {channel_name}",
        body=(
            f"Explicit admin test for notification channel '{channel_name}' at "
            f"{checked_at.isoformat()}."
        ),
        evidence_lines=[],
        recommended_action=None,
        action_buttons=[],
        dedup_key=f"notification-test:{channel_name}",
        created_at=checked_at,
    )


def _apply_runtime_log_level(app: FastAPI, log_level: str) -> None:
    """Apply one explicit runtime log level to the process loggers."""
    level = _RUNTIME_LOG_LEVELS.get(log_level, logging.INFO)
    for logger_name in _RUNTIME_LOGGER_NAMES:
        logging.getLogger(logger_name).setLevel(level)
    app.state.runtime_log_level = log_level


def _active_local_model_configured_for_app(app: FastAPI) -> bool:
    """Return whether the app-scoped active local model path is configured."""
    model_settings = cast(ModelSettingsService, app.state.model_settings_service)
    return model_settings.active_local_configured()


def _runtime_local_model_config(
    *,
    model_settings: ModelSettingsService,
    vault: CredentialVault,
) -> LocalModelConfig | None:
    """Resolve the active local runtime config or suppress unusable states."""
    try:
        return model_settings.resolve_local_model_config(scope="active", vault=vault)
    except (CredentialVaultLockedError, ValueError):
        return None


def _runtime_cloud_model_config(
    *,
    model_settings: ModelSettingsService,
    vault: CredentialVault,
) -> CloudModelConfig | None:
    """Resolve the active cloud runtime config or suppress unusable states."""
    try:
        return model_settings.resolve_cloud_model_config(scope="active", vault=vault)
    except (CredentialVaultLockedError, ValueError):
        return None


def _build_model_settings_change(
    *,
    action: Literal["saved", "applied"],
    previous: ManagedModelSettings,
    current: ManagedModelSettings,
    config_path: Path,
    apply_required: bool,
) -> Change:
    """Build one auditable config-change entry for model-settings mutations."""
    action_prefix = "Saved staged" if action == "saved" else "Applied staged"
    apply_note = (
        " Apply is still required before runtime use."
        if action == "saved" and apply_required
        else ""
    )
    return Change(
        id=f"chg-model-settings-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"{action_prefix} model settings via {config_path}.{apply_note}",
        old_value=_model_settings_change_summary(previous),
        new_value=_model_settings_change_summary(current),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _model_settings_change_summary(snapshot: ManagedModelSettings) -> str:
    """Build a compact audit summary for one model-settings snapshot."""
    local_summary = (
        f"local=enabled:{snapshot.local.model}"
        if snapshot.local.enabled and snapshot.local.model
        else "local=disabled"
    )
    cloud_summary = (
        f"cloud=enabled:{snapshot.cloud.provider}:{snapshot.cloud.model}"
        if snapshot.cloud.enabled and snapshot.cloud.model
        else "cloud=disabled"
    )
    escalation_summary = (
        "escalation="
        f"finding>{snapshot.escalation.finding_count_gt},"
        f"confidence<{snapshot.escalation.local_confidence_lt:.2f},"
        f"daycap={snapshot.escalation.max_cloud_calls_per_day},"
        f"incidentcap={snapshot.escalation.max_cloud_calls_per_incident}"
    )
    return f"{local_summary}; {cloud_summary}; {escalation_summary}"


def _build_system_settings_change(
    *,
    action: Literal["saved", "applied"],
    previous: ManagedSystemSettings,
    current: ManagedSystemSettings,
    config_path: Path,
    apply_required: bool,
) -> Change:
    """Build one auditable config-change entry for system-settings mutations."""
    action_prefix = "Saved staged" if action == "saved" else "Applied staged"
    apply_note = (
        " Apply is still required before runtime use."
        if action == "saved" and apply_required
        else ""
    )
    return Change(
        id=f"chg-system-settings-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"{action_prefix} system settings via {config_path}.{apply_note}",
        old_value=_system_settings_change_summary(previous),
        new_value=_system_settings_change_summary(current),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _system_settings_change_summary(snapshot: ManagedSystemSettings) -> str:
    """Build a compact audit summary for one system-settings snapshot."""
    return (
        f"log_level={snapshot.log_level}; "
        f"audit_detail_retention_days={snapshot.audit_detail_retention_days}; "
        f"audit_summary_retention_days={snapshot.audit_summary_retention_days}"
    )


def _build_notification_settings_change(
    *,
    action: Literal["saved", "applied"],
    previous: ManagedNotificationSettings,
    current: ManagedNotificationSettings,
    config_path: Path,
    apply_required: bool,
) -> Change:
    """Build one auditable config-change entry for notification-settings mutations."""
    action_prefix = "Saved staged" if action == "saved" else "Applied staged"
    apply_note = (
        " Apply is still required before runtime use."
        if action == "saved" and apply_required
        else ""
    )
    return Change(
        id=f"chg-notification-settings-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"{action_prefix} notification settings via {config_path}.{apply_note}",
        old_value=_notification_settings_change_summary(previous),
        new_value=_notification_settings_change_summary(current),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_monitoring_settings_change(
    *,
    action: Literal["saved", "applied"],
    previous: ManagedMonitoringSettings,
    previous_service_overrides: Sequence[ServiceCheckOverride],
    current: ManagedMonitoringSettings,
    current_service_overrides: Sequence[ServiceCheckOverride],
    config_path: Path,
    apply_required: bool,
) -> Change:
    """Build one auditable config-change entry for monitoring-settings mutations."""
    action_prefix = "Saved staged" if action == "saved" else "Applied staged"
    apply_note = (
        " Apply is still required before runtime use."
        if action == "saved" and apply_required
        else ""
    )
    return Change(
        id=f"chg-monitoring-settings-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"{action_prefix} monitoring settings via {config_path}.{apply_note}",
        old_value=_monitoring_settings_change_summary(
            snapshot=previous,
            service_overrides=previous_service_overrides,
        ),
        new_value=_monitoring_settings_change_summary(
            snapshot=current,
            service_overrides=current_service_overrides,
        ),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_service_check_suppression_change(
    *,
    service: Service,
    check_label: str,
    check_id: str,
    previous_active_override: ServiceCheckOverride | None,
    previous_staged_override: ServiceCheckOverride | None,
    current_active_override: ServiceCheckOverride | None,
    current_staged_override: ServiceCheckOverride | None,
    suppressed: bool,
) -> Change:
    """Build one auditable config-change entry for a service suppression toggle."""
    action = "Suppressed" if suppressed else "Restored inherited monitoring for"
    return Change(
        id=f"chg-service-check-suppression-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=service.id,
        description=(
            f"{action} {check_label} ({check_id}) on {service.name} "
            "across active and staged monitoring overrides."
        ),
        old_value=(
            "active="
            f"{_service_check_override_change_summary(previous_active_override)}; "
            "staged="
            f"{_service_check_override_change_summary(previous_staged_override)}"
        ),
        new_value=(
            "active="
            f"{_service_check_override_change_summary(current_active_override)}; "
            "staged="
            f"{_service_check_override_change_summary(current_staged_override)}"
        ),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _service_check_override_change_summary(
    override: ServiceCheckOverride | None,
) -> str:
    """Build a compact audit summary for one service/check override state."""
    if override is None:
        return "inherit"
    enabled = "inherit" if override.enabled is None else str(override.enabled).lower()
    interval = (
        "inherit"
        if override.interval_seconds is None
        else str(override.interval_seconds)
    )
    threshold_summary = monitoring_threshold_summary(
        override.check_id,
        tls_warning_days=override.tls_warning_days,
        restart_delta_threshold=override.restart_delta_threshold,
        probe_timeout_seconds=override.probe_timeout_seconds,
    )
    if threshold_summary is None:
        return f"enabled={enabled},interval={interval}"
    return f"enabled={enabled},interval={interval},{threshold_summary}"


def _notification_settings_change_summary(
    snapshot: ManagedNotificationSettings,
) -> str:
    """Build a compact audit summary for one notification-settings snapshot."""
    enabled_channels = [
        f"{channel.name}:{channel.kind}"
        for channel in snapshot.channels
        if channel.enabled
    ]
    channels_summary = (
        f"channels={','.join(enabled_channels)}"
        if enabled_channels
        else "channels=none"
    )
    routing_summary = (
        "routing="
        f"critical:{snapshot.routing.critical},"
        f"high:{snapshot.routing.high},"
        f"medium:{snapshot.routing.medium},"
        f"low:{snapshot.routing.low},"
        f"dedup:{snapshot.routing.dedup_window_minutes},"
        f"digest:{snapshot.routing.digest_window_minutes}"
    )
    quiet_hours_summary = (
        "quiet_hours="
        f"{snapshot.quiet_hours.enabled}:"
        f"{snapshot.quiet_hours.start_time_local}-"
        f"{snapshot.quiet_hours.end_time_local}@"
        f"{snapshot.quiet_hours.timezone}"
    )
    return f"{channels_summary}; {routing_summary}; {quiet_hours_summary}"


def _monitoring_settings_change_summary(
    *,
    snapshot: ManagedMonitoringSettings,
    service_overrides: Sequence[ServiceCheckOverride],
) -> str:
    """Build a compact audit summary for one monitoring-settings snapshot."""
    checks_summary = ",".join(
        (
            f"{check.check_id}:{check.enabled}:{check.interval_seconds}"
            if monitoring_threshold_summary(
                check.check_id,
                tls_warning_days=check.tls_warning_days,
                restart_delta_threshold=check.restart_delta_threshold,
                probe_timeout_seconds=check.probe_timeout_seconds,
            )
            is None
            else (
                f"{check.check_id}:{check.enabled}:{check.interval_seconds}:"
                f"{monitoring_threshold_summary(
                    check.check_id,
                    tls_warning_days=check.tls_warning_days,
                    restart_delta_threshold=check.restart_delta_threshold,
                    probe_timeout_seconds=check.probe_timeout_seconds,
                )}"
            )
        )
        for check in snapshot.checks
    )
    overrides_summary = (
        ",".join(
            (
                f"{override.service_id}:{override.check_id}:"
                f"{_service_check_override_change_summary(override)}"
            )
            for override in sorted(
                service_overrides,
                key=lambda item: (item.service_id, item.check_id),
            )
        )
        if service_overrides
        else "none"
    )
    return f"checks={checks_summary}; service_overrides={overrides_summary}"


def build_credential_vault_response(
    *,
    request: Request,
    credential_material_service: CredentialMaterialService,
    model_settings: ModelSettingsService,
    notification_settings: NotificationSettingsService,
) -> CredentialVaultResponse:
    """Build the operator-facing vault-management payload."""
    request_map = {
        item.id: item for item in credential_material_service.request_manager.list_requests()
    }
    model_reference_map = _credential_vault_model_reference_map(model_settings)
    notification_channel_names = _credential_vault_notification_channel_names(
        notification_settings
    )
    credentials = [
        _build_credential_vault_credential_response(
            record=record,
            request_map=request_map,
            model_reference_map=model_reference_map,
            notification_channel_names=notification_channel_names,
        )
        for record in credential_material_service.list_vault_credentials()
    ]
    return CredentialVaultResponse(
        status=credential_material_service.vault_status(),
        auto_lock_minutes=cast(ApiSettings, request.app.state.api_settings).vault_auto_lock_minutes,
        credentials=credentials,
    )


def _build_credential_vault_credential_response(
    *,
    record: VaultCredentialRecord,
    request_map: dict[str, CredentialRequest],
    model_reference_map: dict[str, tuple[str, str]],
    notification_channel_names: dict[str, str],
) -> CredentialVaultCredentialResponse:
    """Build one secret-free stored-credential summary row."""
    request_record = request_map.get(record.request_id)
    if request_record is not None:
        service_name = request_record.service_name
        credential_description = request_record.credential_description
        source = CredentialVaultEntrySource.CREDENTIAL_REQUEST
    else:
        service_name, credential_description = _credential_vault_managed_labels(
            record=record,
            model_reference_map=model_reference_map,
            notification_channel_names=notification_channel_names,
        )
        source = CredentialVaultEntrySource.MANAGED_SETTING
    return CredentialVaultCredentialResponse(
        reference_id=record.reference_id,
        source=source,
        service_id=record.service_id,
        service_name=service_name,
        credential_key=record.credential_key,
        credential_description=credential_description,
        created_at=record.created_at,
        updated_at=record.updated_at,
        last_used_at=record.last_used_at,
        last_tested_at=record.last_tested_at,
        expires_at=record.expires_at,
    )


def _credential_vault_managed_labels(
    *,
    record: VaultCredentialRecord,
    model_reference_map: dict[str, tuple[str, str]],
    notification_channel_names: dict[str, str],
) -> tuple[str, str]:
    """Resolve display labels for managed settings secrets stored in the vault."""
    mapped_model_label = model_reference_map.get(record.reference_id)
    if mapped_model_label is not None:
        return mapped_model_label
    if record.service_id.startswith("settings.notifications."):
        channel_id = record.service_id.removeprefix("settings.notifications.")
        channel_name = notification_channel_names.get(channel_id)
        if channel_name:
            return (f"Notification channel: {channel_name}", "Destination URL")
        return ("Notification channel settings", "Destination URL")
    return (
        record.service_id.replace(".", " "),
        record.credential_key.replace("_", " "),
    )


def _credential_vault_model_reference_map(
    model_settings: ModelSettingsService,
) -> dict[str, tuple[str, str]]:
    """Resolve known model-secret references into stable display labels."""
    reference_map: dict[str, tuple[str, str]] = {}
    for snapshot in (
        model_settings.active_snapshot(),
        model_settings.staged_snapshot(),
    ):
        if snapshot.local.api_key_ref is not None:
            reference_map[snapshot.local.api_key_ref] = ("Local model settings", "API key")
        if snapshot.cloud.api_key_ref is not None:
            reference_map[snapshot.cloud.api_key_ref] = ("Cloud model settings", "API key")
    return reference_map


def _credential_vault_notification_channel_names(
    notification_settings: NotificationSettingsService,
) -> dict[str, str]:
    """Resolve notification channel ids into the most recent configured names."""
    names: dict[str, str] = {}
    for snapshot in (
        notification_settings.active_snapshot(),
        notification_settings.staged_snapshot(),
    ):
        for channel in snapshot.channels:
            names[channel.id] = channel.name
    return names


def _build_credential_vault_change(
    *,
    action: Literal["unlocked", "locked", "changed_password"],
    previous_status: VaultStatus,
    current_status: VaultStatus,
) -> Change:
    """Build one auditable change entry for an explicit vault mutation."""
    descriptions = {
        "unlocked": "Unlocked the credential vault via the admin settings panel.",
        "locked": "Locked the credential vault via the admin settings panel.",
        "changed_password": (
            "Changed the credential vault master passphrase via the admin settings panel."
        ),
    }
    return Change(
        id=f"chg-credential-vault-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=descriptions[action],
        old_value=_credential_vault_status_summary(previous_status),
        new_value=_credential_vault_status_summary(current_status),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_credential_vault_test_change(
    *,
    tested_credentials: int,
    readable_credentials: int,
) -> Change:
    """Build one auditable change entry for an explicit vault readability test."""
    return Change(
        id=f"chg-credential-vault-test-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=(
            "Ran an explicit credential vault readability test via the admin settings panel."
        ),
        old_value=None,
        new_value=(
            f"tested={tested_credentials}; readable={readable_credentials}; "
            f"unreadable={tested_credentials - readable_credentials}"
        ),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _credential_vault_status_summary(status: VaultStatus) -> str:
    """Build a compact audit summary for the current vault runtime state."""
    return (
        f"initialized={status.initialized}; "
        f"unlocked={status.unlocked}; "
        f"stored={status.stored_credentials}"
    )


def _build_credential_vault_test_item_response(
    result: VaultCredentialTestResult,
    *,
    checked_at: datetime,
    credential_map: dict[str, CredentialVaultCredentialResponse],
) -> CredentialVaultTestItemResponse:
    """Build one credential-vault test-result row from stored metadata."""
    credential = credential_map.get(result.record.reference_id)
    return CredentialVaultTestItemResponse(
        reference_id=result.record.reference_id,
        service_name=(
            credential.service_name
            if credential is not None
            else result.record.service_id.replace(".", " ")
        ),
        credential_description=(
            credential.credential_description
            if credential is not None
            else result.record.credential_key.replace("_", " ")
        ),
        ok=result.ok,
        message=result.message,
        checked_at=checked_at,
    )


@dataclass(slots=True)
class _ManagedNotificationSender:
    """Resolve active notification settings at send time without caching secrets."""

    settings_service: NotificationSettingsService
    vault: CredentialVault
    adapter_factory: Callable[[], AppriseAdapter] | None = None

    def send(self, payload: NotificationPayload) -> NotificationDeliveryResult:
        """Send one notification payload using the active notification settings."""
        try:
            config = self.settings_service.resolve_bus_config(
                scope="active",
                vault=self.vault,
            )
        except CredentialVaultLockedError:
            return NotificationDeliveryResult(
                status=NotificationDeliveryStatus.FAILED,
                attempted_channels=self.settings_service.configured_channel_count(
                    scope="active"
                ),
                delivered_channels=0,
                failed_channels=[],
                detail="Notification destinations are locked in the vault.",
            )
        return NotificationBus(
            config=config,
            adapter_factory=self.adapter_factory,
        ).send(payload)


def enrich_services_with_current_insight(
    services: Sequence[Service],
    *,
    local_model_configured: bool,
) -> list[Service]:
    """Attach current insight levels using the active runtime investigation capability."""
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


def _build_service_detail_monitoring_section(
    *,
    service: Service,
    monitoring_settings: MonitoringSettingsService,
    database: KavalDatabase,
) -> ServiceDetailMonitoringSectionResponse:
    """Build the service-detail monitoring rows using the active runtime state."""
    active_snapshot = monitoring_settings.active_snapshot()
    active_overrides = database.list_service_check_overrides(
        scope=ServiceCheckOverrideScope.ACTIVE
    )
    snapshot_by_id = {check.check_id: check for check in active_snapshot.checks}
    defaults_by_id = {
        rule.check_id: rule for rule in default_monitoring_check_cadences()
    }
    cadence = monitoring_settings.resolve_cadence_config(
        scope="active",
        service_overrides=active_overrides,
    )
    checks: list[ServiceDetailMonitoringCheckResponse] = []
    for entry in monitoring_check_catalog():
        if not check_applies_to_service(entry.check_id, service):
            continue
        override = _service_check_override_for(
            overrides=active_overrides,
            service_id=service.id,
            check_id=entry.check_id,
        )
        inherited = snapshot_by_id[entry.check_id]
        execution = resolve_service_check_execution(
            config=cadence,
            service_id=service.id,
            check_id=entry.check_id,
            base_interval_seconds=defaults_by_id[entry.check_id].interval_seconds,
            base_enabled=defaults_by_id[entry.check_id].enabled,
        )
        checks.append(
            ServiceDetailMonitoringCheckResponse(
                check_id=entry.check_id,
                label=entry.label,
                description=entry.description,
                inherited_enabled=inherited.enabled,
                inherited_interval_seconds=inherited.interval_seconds,
                effective_enabled=execution.enabled,
                effective_interval_seconds=execution.interval_seconds,
                source=_monitoring_resolution_source(execution.source),
                suppressed=override is not None and override.enabled is False,
                override_enabled=None if override is None else override.enabled,
                override_interval_seconds=(
                    None if override is None else override.interval_seconds
                ),
                override_updated_at=None if override is None else override.updated_at,
            )
        )
    return ServiceDetailMonitoringSectionResponse(checks=checks)


def build_service_detail_response(
    *,
    service: Service,
    credential_material_service: CredentialMaterialService,
    local_model_configured: bool,
    monitoring_settings: MonitoringSettingsService,
    database: KavalDatabase,
) -> ServiceDetailResponse:
    """Build the current service-detail response for one service."""
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
                local_model_configured=local_model_configured,
            ),
            fact_summary_available=False,
        ),
        monitoring_section=_build_service_detail_monitoring_section(
            service=service,
            monitoring_settings=monitoring_settings,
            database=database,
        ),
    )


def build_service_descriptor_view_response(
    loaded_descriptor: LoadedServiceDescriptor,
    *,
    services_dir: Path | str,
) -> ServiceDescriptorViewResponse:
    """Build the rendered descriptor view for one loaded descriptor."""
    descriptor = loaded_descriptor.descriptor
    return ServiceDescriptorViewResponse(
        descriptor_id=_loaded_descriptor_id(loaded_descriptor),
        file_path=_descriptor_view_path(loaded_descriptor.path),
        write_target_path=_descriptor_view_path(
            build_user_descriptor_path(services_dir, descriptor)
        ),
        name=descriptor.name,
        category=descriptor.category,
        source=descriptor.source,
        verified=descriptor.verified,
        generated_at=descriptor.generated_at,
        project_url=descriptor.project_url,
        icon=descriptor.icon,
        match=DescriptorViewMatchResponse(
            image_patterns=list(descriptor.match.image_patterns),
            container_name_patterns=list(descriptor.match.container_name_patterns),
        ),
        endpoints=[
            DescriptorViewEndpointResponse(
                name=name,
                port=endpoint.port,
                path=endpoint.path,
                auth=endpoint.auth,
                auth_header=endpoint.auth_header,
                healthy_when=endpoint.healthy_when,
            )
            for name, endpoint in sorted(descriptor.endpoints.items())
        ],
        dns_targets=list(descriptor.dns_targets),
        log_signals=DescriptorViewLogSignalsResponse(
            errors=list(descriptor.log_signals.errors),
            warnings=list(descriptor.log_signals.warnings),
        ),
        typical_dependency_containers=[
            _render_descriptor_container_dependency(container_dependency)
            for container_dependency in descriptor.typical_dependencies.containers
        ],
        typical_dependency_shares=list(descriptor.typical_dependencies.shares),
        common_failure_modes=[
            DescriptorViewFailureModeResponse(
                trigger=failure_mode.trigger,
                likely_cause=failure_mode.likely_cause,
                check_first=list(failure_mode.check_first),
            )
            for failure_mode in descriptor.common_failure_modes
        ],
        investigation_context=descriptor.investigation_context,
        inspection_surfaces=[
            _render_descriptor_inspection_surface(surface)
            for surface in descriptor.inspection.surfaces
        ],
        credential_hints=[
            DescriptorViewCredentialHintResponse(
                key=key,
                description=hint.description,
                location=hint.location,
                prompt=hint.prompt,
            )
            for key, hint in sorted(descriptor.credential_hints.items())
        ],
        raw_yaml=loaded_descriptor.path.read_text(encoding="utf-8"),
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


def _descriptor_view_path(path: Path) -> str:
    """Return a stable repo-relative descriptor path when possible."""
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def _build_descriptor_from_form_request(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
    match_request: DescriptorEditMatchRequest,
    endpoint_requests: list[DescriptorEditEndpointRequest],
    dependency_requests: list[DescriptorEditContainerDependencyRequest],
    share_dependencies: list[str],
) -> ServiceDescriptor:
    """Apply the bounded form editor fields to one existing descriptor."""
    _raise_for_duplicate_names(
        values=[endpoint.name for endpoint in endpoint_requests],
        label="descriptor endpoints",
    )
    _raise_for_duplicate_names(
        values=[dependency.name for dependency in dependency_requests],
        label="container dependencies",
    )

    try:
        descriptor_payload = loaded_descriptor.descriptor.model_dump(mode="python")
        descriptor_payload.update(
            {
                "match": DescriptorMatchRule(
                    image_patterns=_normalized_string_list(match_request.image_patterns),
                    container_name_patterns=_normalized_string_list(
                        match_request.container_name_patterns
                    ),
                ),
                "endpoints": {
                    normalized_name: DescriptorEndpoint(
                        port=endpoint.port,
                        path=_none_if_blank(endpoint.path),
                        auth=_none_if_blank(endpoint.auth),
                        auth_header=_none_if_blank(endpoint.auth_header),
                        healthy_when=_none_if_blank(endpoint.healthy_when),
                    )
                    for endpoint in endpoint_requests
                    if (normalized_name := _required_name(endpoint.name, "endpoint name"))
                    is not None
                },
                "typical_dependencies": DescriptorDependencies(
                    containers=[
                        DescriptorContainerDependency(
                            name=_required_name(dependency.name, "dependency name"),
                            alternatives=_normalized_string_list(
                                dependency.alternatives
                            ),
                        )
                        for dependency in dependency_requests
                    ],
                    shares=_normalized_string_list(share_dependencies),
                ),
                "source": DescriptorSource.USER,
                "verified": True,
            }
        )
        descriptor = ServiceDescriptor.model_validate(descriptor_payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=_descriptor_validation_error_message(exc),
        ) from exc
    _validate_stable_descriptor_identity(
        loaded_descriptor=loaded_descriptor,
        descriptor=descriptor,
    )
    return descriptor


def _proposed_descriptor_from_save_request(
    *,
    request: ServiceDescriptorSaveRequest,
    loaded_descriptor: LoadedServiceDescriptor,
) -> ServiceDescriptor:
    """Build one proposed descriptor from the shared save/validate contract."""
    if request.mode == DescriptorEditMode.FORM:
        return _build_descriptor_from_form_request(
            loaded_descriptor=loaded_descriptor,
            match_request=cast(DescriptorEditMatchRequest, request.match),
            endpoint_requests=cast(list[DescriptorEditEndpointRequest], request.endpoints),
            dependency_requests=cast(
                list[DescriptorEditContainerDependencyRequest],
                request.typical_dependency_containers,
            ),
            share_dependencies=cast(list[str], request.typical_dependency_shares),
        )
    return _build_descriptor_from_yaml_request(
        raw_yaml=str(request.raw_yaml),
        loaded_descriptor=loaded_descriptor,
    )


def _build_descriptor_from_yaml_request(
    *,
    raw_yaml: str,
    loaded_descriptor: LoadedServiceDescriptor,
) -> ServiceDescriptor:
    """Parse, validate, and normalize one advanced YAML descriptor edit."""
    descriptor = _descriptor_from_yaml_text(raw_yaml)
    _validate_stable_descriptor_identity(
        loaded_descriptor=loaded_descriptor,
        descriptor=descriptor,
    )
    return descriptor.model_copy(
        update={
            "source": DescriptorSource.USER,
            "verified": True,
        }
    )


def _descriptor_from_yaml_text(raw_yaml: str) -> ServiceDescriptor:
    """Parse and validate one raw descriptor YAML document."""
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail="descriptor YAML is invalid") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=400,
            detail="descriptor YAML must contain a mapping",
        )
    try:
        return ServiceDescriptor.model_validate(parsed)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=_descriptor_validation_error_message(exc),
        ) from exc


def _validate_stable_descriptor_identity(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
    descriptor: ServiceDescriptor,
) -> None:
    """Keep in-place edits bound to the current descriptor identity."""
    if descriptor.id != loaded_descriptor.descriptor.id:
        raise HTTPException(
            status_code=400,
            detail="descriptor id cannot change during edit mode",
        )
    if descriptor.category != loaded_descriptor.descriptor.category:
        raise HTTPException(
            status_code=400,
            detail="descriptor category cannot change during edit mode",
        )


def _descriptor_validation_error_message(exc: ValidationError) -> str:
    """Summarize the first validation errors for UI-safe save feedback."""
    parts: list[str] = []
    for error in exc.errors()[:3]:
        location = ".".join(str(part) for part in error["loc"])
        message = str(error["msg"])
        if message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        parts.append(message if not location else f"{location}: {message}")
    summary = "; ".join(parts)
    return f"descriptor validation failed: {summary}" if summary else "descriptor validation failed"


def _validate_auto_generated_descriptor_target(service: Service) -> None:
    """Reject generation targets that fall outside the Phase 3C contract."""
    if service.type is not ServiceType.CONTAINER:
        raise HTTPException(
            status_code=400,
            detail="only container services can generate quarantined descriptors",
        )
    if service.descriptor_id is not None:
        raise HTTPException(
            status_code=400,
            detail="service already has an active descriptor",
        )
    if service.image is None or not service.image.strip():
        raise HTTPException(
            status_code=400,
            detail="service is missing image metadata required for descriptor generation",
        )


def _load_quarantined_descriptor(
    *,
    services_dir: Path | str,
    category: str,
    descriptor_id: str,
) -> LoadedServiceDescriptor:
    """Load one quarantined descriptor candidate by its current path identity."""
    descriptor_path = build_auto_generated_descriptor_reference_path(
        services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    if not descriptor_path.exists():
        raise HTTPException(status_code=404, detail="quarantined descriptor not found")
    return load_service_descriptor(descriptor_path)


def _load_user_descriptor(
    *,
    services_dir: Path | str,
    category: str,
    descriptor_id: str,
) -> LoadedServiceDescriptor:
    """Load one reviewed user descriptor by its canonical path identity."""
    descriptor_path = build_user_descriptor_reference_path(
        services_dir,
        category=category,
        descriptor_id=descriptor_id,
    )
    if not descriptor_path.exists():
        raise HTTPException(status_code=404, detail="reviewed user descriptor not found")
    return load_service_descriptor(descriptor_path)


def _quarantined_descriptor_from_save_request(
    *,
    request: ServiceDescriptorSaveRequest,
    loaded_descriptor: LoadedServiceDescriptor,
) -> ServiceDescriptor:
    """Build one edited quarantined descriptor candidate from the review queue."""
    if request.mode is not DescriptorEditMode.YAML:
        raise HTTPException(
            status_code=400,
            detail="quarantined descriptor review currently supports YAML edit mode only",
        )
    descriptor = _descriptor_from_yaml_text(str(request.raw_yaml))
    descriptor = descriptor.model_copy(
        update={
            "source": DescriptorSource.AUTO_GENERATED,
            "verified": False,
            "generated_at": (
                loaded_descriptor.descriptor.generated_at or datetime.now(tz=UTC)
            ),
        }
    )
    try:
        validate_quarantined_descriptor_policy(descriptor)
    except DescriptorGenerationPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return descriptor


def _save_quarantined_descriptor_edit(
    *,
    services_dir: Path | str,
    previous_descriptor: LoadedServiceDescriptor,
    descriptor: ServiceDescriptor,
) -> LoadedServiceDescriptor:
    """Persist one edited quarantined descriptor candidate safely."""
    previous_path = previous_descriptor.path
    next_path = build_auto_generated_descriptor_path(services_dir, descriptor)
    if next_path.exists() and next_path != previous_path:
        raise HTTPException(
            status_code=409,
            detail="another quarantined descriptor already uses the edited descriptor id",
        )
    saved_descriptor = write_auto_generated_descriptor(
        services_dir=services_dir,
        descriptor=descriptor,
    )
    if previous_path != saved_descriptor.path and previous_path.exists():
        previous_path.unlink()
    delete_quarantined_descriptor_review_record(
        services_dir,
        category=previous_descriptor.descriptor.category,
        descriptor_id=previous_descriptor.descriptor.id,
    )
    delete_quarantined_descriptor_review_record(
        services_dir,
        category=saved_descriptor.descriptor.category,
        descriptor_id=saved_descriptor.descriptor.id,
    )
    return saved_descriptor


def _build_quarantined_descriptor_queue_item(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
    services: Sequence[Service],
    services_dir: Path | str,
) -> QuarantinedDescriptorQueueItemResponse:
    """Render one quarantined descriptor candidate for the review queue."""
    review_record = load_quarantined_descriptor_review_record(
        services_dir,
        category=loaded_descriptor.descriptor.category,
        descriptor_id=loaded_descriptor.descriptor.id,
    )
    matching_services = [
        service
        for service in services
        if service.type is ServiceType.CONTAINER
        and service.descriptor_id is None
        and _service_likely_matches_descriptor(service, loaded_descriptor.descriptor)
    ]
    updated_at = (
        review_record.updated_at
        if review_record is not None
        else loaded_descriptor.descriptor.generated_at or datetime.now(tz=UTC)
    )
    return QuarantinedDescriptorQueueItemResponse(
        descriptor=build_service_descriptor_view_response(
            loaded_descriptor,
            services_dir=services_dir,
        ),
        review_state=(
            review_record.review_state.value
            if review_record is not None
            else QuarantinedDescriptorReviewState.PENDING.value
        ),
        review_updated_at=updated_at,
        matching_services=matching_services,
    )


def _build_descriptor_save_change(
    *,
    service: Service,
    previous_descriptor: LoadedServiceDescriptor,
    saved_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for a descriptor edit."""
    descriptor_id = loaded_descriptor_identifier(saved_descriptor)
    previous_path = _descriptor_view_path(previous_descriptor.path)
    saved_path = _descriptor_view_path(saved_descriptor.path)
    action = (
        "Saved user override"
        if previous_descriptor.path != saved_descriptor.path
        else "Updated user override"
    )
    return Change(
        id=f"chg-descriptor-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=service.id,
        description=(
            f"{action} for descriptor {descriptor_id} on {service.name}."
        ),
        old_value=previous_path,
        new_value=saved_path,
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_quarantined_descriptor_edit_change(
    *,
    previous_descriptor: LoadedServiceDescriptor,
    saved_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for a quarantined descriptor edit."""
    descriptor_id = loaded_descriptor_identifier(saved_descriptor)
    action = (
        "Retitled quarantined descriptor candidate"
        if previous_descriptor.path != saved_descriptor.path
        else "Edited quarantined descriptor candidate"
    )
    return Change(
        id=f"chg-quarantined-descriptor-edit-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"{action} {descriptor_id}.",
        old_value=_descriptor_view_path(previous_descriptor.path),
        new_value=_descriptor_view_path(saved_descriptor.path),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_quarantined_descriptor_promote_change(
    *,
    previous_descriptor: LoadedServiceDescriptor,
    saved_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for descriptor promotion."""
    descriptor_id = loaded_descriptor_identifier(saved_descriptor)
    return Change(
        id=f"chg-quarantined-descriptor-promote-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=(
            "Promoted quarantined descriptor candidate "
            f"{descriptor_id} to the user descriptor tree."
        ),
        old_value=_descriptor_view_path(previous_descriptor.path),
        new_value=_descriptor_view_path(saved_descriptor.path),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_quarantined_descriptor_dismiss_change(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for descriptor dismissal."""
    descriptor_id = loaded_descriptor_identifier(loaded_descriptor)
    return Change(
        id=f"chg-quarantined-descriptor-dismiss-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"Dismissed quarantined descriptor candidate {descriptor_id}.",
        old_value=_descriptor_view_path(loaded_descriptor.path),
        new_value=None,
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_quarantined_descriptor_defer_change(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for descriptor defer actions."""
    descriptor_id = loaded_descriptor_identifier(loaded_descriptor)
    return Change(
        id=f"chg-quarantined-descriptor-defer-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None,
        description=f"Deferred review for quarantined descriptor candidate {descriptor_id}.",
        old_value=None,
        new_value=_descriptor_view_path(loaded_descriptor.path),
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_auto_generated_descriptor_change(
    *,
    service: Service,
    previous_descriptor: LoadedServiceDescriptor | None,
    saved_descriptor: LoadedServiceDescriptor,
) -> Change:
    """Build one auditable config-change record for quarantined descriptor generation."""
    descriptor_id = loaded_descriptor_identifier(saved_descriptor)
    descriptor_path = _descriptor_view_path(saved_descriptor.path)
    action = (
        "Updated quarantined descriptor candidate"
        if previous_descriptor is not None
        else "Generated quarantined descriptor candidate"
    )
    return Change(
        id=f"chg-auto-descriptor-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=service.id,
        description=f"{action} {descriptor_id} for unmatched service {service.name}.",
        old_value=(
            None
            if previous_descriptor is None
            else _descriptor_view_path(previous_descriptor.path)
        ),
        new_value=descriptor_path,
        timestamp=datetime.now(tz=UTC),
        correlated_incidents=[],
    )


def _build_descriptor_validation_preview(
    *,
    service: Service,
    services: Sequence[Service],
    loaded_descriptor: LoadedServiceDescriptor,
    proposed_descriptor: ServiceDescriptor,
    services_dir: Path | str,
) -> ServiceDescriptorValidationPreviewResponse:
    """Assemble a bounded likely-impact preview for a pending descriptor edit."""
    descriptor_id = loaded_descriptor_identifier(loaded_descriptor)
    affected_services = [
        DescriptorValidationAffectedServiceResponse(
            service_id=item.id,
            service_name=item.name,
            likely_matches=_service_likely_matches_descriptor(item, proposed_descriptor),
        )
        for item in services
        if item.descriptor_id == descriptor_id
    ]
    current_container_dependencies = _container_dependency_names(
        loaded_descriptor.descriptor.typical_dependencies.containers
    )
    proposed_container_dependencies = _container_dependency_names(
        proposed_descriptor.typical_dependencies.containers
    )
    current_share_dependencies = set(loaded_descriptor.descriptor.typical_dependencies.shares)
    proposed_share_dependencies = set(proposed_descriptor.typical_dependencies.shares)
    return ServiceDescriptorValidationPreviewResponse(
        descriptor_id=descriptor_id,
        write_target_path=_descriptor_view_path(
            build_user_descriptor_path(services_dir, proposed_descriptor)
        ),
        match=DescriptorValidationMatchPreviewResponse(
            current_service_likely_matches=_service_likely_matches_descriptor(
                service,
                proposed_descriptor,
            ),
            affected_services=affected_services,
        ),
        dependency_impact=DescriptorValidationDependencyImpactResponse(
            added_container_dependencies=sorted(
                proposed_container_dependencies - current_container_dependencies
            ),
            removed_container_dependencies=sorted(
                current_container_dependencies - proposed_container_dependencies
            ),
            added_share_dependencies=sorted(
                proposed_share_dependencies - current_share_dependencies
            ),
            removed_share_dependencies=sorted(
                current_share_dependencies - proposed_share_dependencies
            ),
        ),
    )


def _descriptor_policy_warnings(
    *,
    loaded_descriptor: LoadedServiceDescriptor,
    proposed_descriptor: ServiceDescriptor,
    preview: ServiceDescriptorValidationPreviewResponse,
) -> list[str]:
    """Return bounded operator-facing warnings for descriptor edit validation."""
    warnings: list[str] = []
    if loaded_descriptor.descriptor.source != DescriptorSource.USER:
        warnings.append(
            "Save will create or update a reviewed user override and "
            "leave the shipped descriptor unchanged."
        )
    if proposed_descriptor.source != DescriptorSource.USER:
        warnings.append("Save normalizes descriptor source to user for the active override.")
    if proposed_descriptor.verified is not True:
        warnings.append("Save normalizes verified to true for the reviewed user override.")
    if not preview.match.current_service_likely_matches:
        warnings.append(
            "Current service metadata no longer appears to match the edited descriptor patterns."
        )
    mismatched_services = [
        impacted_service.service_name
        for impacted_service in preview.match.affected_services
        if not impacted_service.likely_matches
    ]
    if mismatched_services:
        warnings.append(
            "Likely rematch review needed for currently bound services: "
            + ", ".join(sorted(mismatched_services))
            + "."
        )
    if (
        preview.dependency_impact.removed_container_dependencies
        or preview.dependency_impact.removed_share_dependencies
    ):
        warnings.append(
            "Removing declared dependencies can change graph edges and incident grouping context."
        )
    return warnings


def _service_likely_matches_descriptor(
    service: Service,
    descriptor: ServiceDescriptor,
) -> bool:
    """Estimate whether one current service still matches the edited descriptor."""
    image_matches = (
        service.image is not None
        and any(fnmatch(service.image, pattern) for pattern in descriptor.match.image_patterns)
    )
    candidate_names = [service.name, *service.lifecycle.previous_names]
    name_matches = any(
        fnmatch(candidate_name, pattern)
        for candidate_name in candidate_names
        for pattern in descriptor.match.container_name_patterns
    )
    return image_matches or name_matches


def _container_dependency_names(
    dependencies: Sequence[str | DescriptorContainerDependency],
) -> set[str]:
    """Normalize dependency entries into their primary container names."""
    return {
        dependency if isinstance(dependency, str) else dependency.name
        for dependency in dependencies
    }


def _required_name(value: str, label: str) -> str:
    """Return one required stripped name field for descriptor editor rows."""
    normalized = value.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail=f"{label} must not be empty")
    return normalized


def _none_if_blank(value: str | None) -> str | None:
    """Normalize optional text fields so empty UI values persist as null."""
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _normalized_string_list(values: Sequence[str]) -> list[str]:
    """Trim list input values and drop blank entries for deterministic saves."""
    return [normalized for value in values if (normalized := value.strip())]


def _raise_for_duplicate_names(*, values: Sequence[str], label: str) -> None:
    """Reject duplicate row names in bounded descriptor form mode."""
    normalized_values = [value.strip() for value in values if value.strip()]
    duplicates = sorted(
        {
            value
            for value in normalized_values
            if normalized_values.count(value) > 1
        }
    )
    if duplicates:
        formatted_duplicates = ", ".join(duplicates)
        raise HTTPException(
            status_code=400,
            detail=f"{label} require unique names: {formatted_duplicates}",
        )


def _http_exception_detail(exc: HTTPException) -> str:
    """Normalize FastAPI exception detail into a UI-safe message string."""
    return str(exc.detail)


def _render_descriptor_container_dependency(
    dependency: str | DescriptorContainerDependency,
) -> DescriptorViewContainerDependencyResponse:
    """Normalize one descriptor dependency entry for the UI."""
    if isinstance(dependency, str):
        return DescriptorViewContainerDependencyResponse(name=dependency, alternatives=[])
    return DescriptorViewContainerDependencyResponse(
        name=dependency.name,
        alternatives=list(dependency.alternatives),
    )


def _render_descriptor_inspection_surface(
    surface: DescriptorInspectionSurface,
) -> DescriptorViewInspectionSurfaceResponse:
    """Normalize one descriptor inspection surface for the UI."""
    return DescriptorViewInspectionSurfaceResponse(
        id=surface.id,
        type=surface.type.value,
        description=surface.description,
        endpoint=surface.endpoint,
        auth=None if surface.auth is None else surface.auth.value,
        auth_header=surface.auth_header,
        read_only=surface.read_only,
        facts_provided=list(surface.facts_provided),
        confidence_effect=(
            None
            if surface.confidence_effect is None
            else surface.confidence_effect.value
        ),
        version_range=surface.version_range,
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
    local_model_configured: bool,
) -> list[ServiceDetailImproveActionResponse]:
    """Build explicit improvement affordances for the minimum service detail view."""
    improve_actions: list[ServiceDetailImproveActionResponse] = []
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
    """Return the active descriptor record that matches the persisted service."""
    if service.descriptor_id is None:
        return None
    for loaded_descriptor in descriptors:
        if _loaded_descriptor_id(loaded_descriptor) == service.descriptor_id:
            return loaded_descriptor
    return None


def _loaded_descriptor_id(loaded_descriptor: LoadedServiceDescriptor) -> str:
    """Return the stable service descriptor identifier used in persisted services."""
    return loaded_descriptor_identifier(loaded_descriptor)


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


def build_maintenance_mode_response(
    *,
    database: KavalDatabase,
    now: datetime | None = None,
) -> MaintenanceModeResponse:
    """Build the operator-facing maintenance state from active DB-backed windows."""
    effective_now = now or datetime.now(tz=UTC)
    services_by_id = {service.id: service for service in database.list_services()}

    def service_window_sort_key(window: MaintenanceWindowRecord) -> str:
        """Return a stable display-oriented sort key for one service window."""
        service = services_by_id.get(window.service_id or "")
        if service is not None:
            return service.name
        return window.service_id or ""

    active_windows = active_maintenance_windows(
        database.list_maintenance_windows(),
        now=effective_now,
    )
    global_window = next(
        (window for window in active_windows if window.scope is MaintenanceScope.GLOBAL),
        None,
    )
    service_windows = sorted(
        (
            window
            for window in active_windows
            if window.scope is MaintenanceScope.SERVICE
        ),
        key=service_window_sort_key,
    )
    return MaintenanceModeResponse(
        global_window=(
            None
            if global_window is None
            else _build_maintenance_window_response(
                window=global_window,
                service=None,
                now=effective_now,
            )
        ),
        service_windows=[
            _build_maintenance_window_response(
                window=window,
                service=services_by_id.get(window.service_id or ""),
                now=effective_now,
            )
            for window in service_windows
        ],
        self_health_guardrail=(
            "Global maintenance suppresses normal findings and incident notifications, "
            "but critical Kaval self-health remains unsuppressed."
        ),
    )


def _build_maintenance_window_response(
    *,
    window: MaintenanceWindowRecord,
    service: Service | None,
    now: datetime,
) -> MaintenanceWindowResponse:
    """Build one active maintenance window response row."""
    return MaintenanceWindowResponse(
        scope=window.scope,
        service_id=window.service_id,
        service_name=None if service is None else service.name,
        started_at=window.started_at,
        expires_at=window.expires_at,
        minutes_remaining=_minutes_remaining(
            expires_at=window.expires_at,
            now=now,
        ),
    )


def _minutes_remaining(
    *,
    expires_at: datetime,
    now: datetime,
) -> int:
    """Return the rounded-up remaining window duration in minutes."""
    seconds_remaining = max(0.0, (expires_at - now).total_seconds())
    return int((seconds_remaining + 59) // 60)


def _active_global_maintenance_window(
    *,
    database: KavalDatabase,
    now: datetime | None = None,
) -> MaintenanceWindowRecord | None:
    """Return the active global maintenance window, if present."""
    effective_now = now or datetime.now(tz=UTC)
    return next(
        (
            window
            for window in active_maintenance_windows(
                database.list_maintenance_windows(),
                now=effective_now,
            )
            if window.scope is MaintenanceScope.GLOBAL
        ),
        None,
    )


def _active_service_maintenance_window(
    *,
    database: KavalDatabase,
    service_id: str,
    now: datetime | None = None,
) -> MaintenanceWindowRecord | None:
    """Return the active maintenance window for one service, if present."""
    effective_now = now or datetime.now(tz=UTC)
    return next(
        (
            window
            for window in active_maintenance_windows(
                database.list_maintenance_windows(),
                now=effective_now,
            )
            if window.scope is MaintenanceScope.SERVICE and window.service_id == service_id
        ),
        None,
    )


def _active_alert_maintenance_windows(
    *,
    database: KavalDatabase,
    now: datetime,
) -> list[AlertMaintenanceWindow]:
    """Return active maintenance windows converted for incident notification routing."""
    return [
        AlertMaintenanceWindow(
            service_id=window.service_id,
            expires_at=window.expires_at,
        )
        for window in active_maintenance_windows(
            database.list_maintenance_windows(),
            now=now,
        )
    ]


def _build_maintenance_change(
    *,
    scope: MaintenanceScope,
    service: Service | None,
    duration_minutes: int | None,
    enabled: bool,
    now: datetime,
) -> Change:
    """Build one auditable change record for maintenance mode actions."""
    target_label = "global maintenance" if service is None else f"{service.name} maintenance"
    if enabled:
        description = (
            f"Enabled {target_label} for {duration_minutes} minutes."
        )
        new_value = (
            f"scope={scope.value};duration_minutes={duration_minutes};"
            f"expires_at={(now + timedelta(minutes=duration_minutes or 0)).isoformat()}"
        )
        old_value = None
    else:
        description = f"Cleared {target_label}."
        old_value = f"scope={scope.value};active=true"
        new_value = f"scope={scope.value};active=false"
    return Change(
        id=f"chg-maintenance-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=None if service is None else service.id,
        description=description,
        old_value=old_value,
        new_value=new_value,
        timestamp=now,
        correlated_incidents=[],
    )


def build_proactive_recommendations_response(
    *,
    database: KavalDatabase,
    model_settings: ModelSettingsService,
    now: datetime | None = None,
) -> RecommendationsResponse:
    """Build ranked proactive admin recommendations from current persisted state."""
    effective_now = now or datetime.now(tz=UTC)
    services = database.list_services()
    services_by_id = {service.id: service for service in services}
    pattern_counts = Counter(
        (record.service_id, record.finding_domain)
        for record in database.list_finding_feedback_records()
    )
    noisy_patterns = [
        NoisyCheckPattern(
            service_id=suggestion.service_id,
            service_name=suggestion.service_name,
            check_id=suggestion.check_id,
            check_label=suggestion.check_label,
            dismissal_count=suggestion.dismissal_count,
            message=suggestion.message,
        )
        for suggestion in _build_finding_feedback_suggestions(
            services_by_id=services_by_id,
            pattern_counts=pattern_counts,
            database=database,
        )
    ]
    candidates = build_proactive_recommendations(
        services=services,
        vault_credentials=database.list_vault_credentials(),
        noisy_check_patterns=noisy_patterns,
        local_model_configured=model_settings.active_local_configured(),
        cloud_model_configured=model_settings.active_cloud_configured(),
        now=effective_now,
    )
    return RecommendationsResponse(
        items=[
            _build_recommendation_item_response(candidate)
            for candidate in candidates
        ]
    )


def _build_recommendation_item_response(
    candidate: RecommendationCandidate,
) -> RecommendationItemResponse:
    """Convert one internal recommendation candidate into the API contract."""
    return RecommendationItemResponse(
        id=candidate.id,
        kind=candidate.kind,
        title=candidate.title,
        detail=candidate.detail,
        action=RecommendationActionResponse(
            label=candidate.action.label,
            target=candidate.action.target,
            service_id=candidate.action.service_id,
        ),
    )


def build_finding_review_response(
    *,
    database: KavalDatabase,
) -> FindingReviewResponse:
    """Build the operator-facing finding review payload for noise control."""
    services = database.list_services()
    services_by_id = {service.id: service for service in services}
    feedback_records = database.list_finding_feedback_records()
    pattern_counts = Counter(
        (record.service_id, record.finding_domain) for record in feedback_records
    )
    latest_feedback_by_finding_id: dict[str, FindingFeedbackRecord] = {}
    for record in feedback_records:
        latest_feedback_by_finding_id[record.finding_id] = record
    suggestions = _build_finding_feedback_suggestions(
        services_by_id=services_by_id,
        pattern_counts=pattern_counts,
        database=database,
    )
    suggestion_by_pattern = {
        (suggestion.service_id, suggestion.check_id): suggestion for suggestion in suggestions
    }
    active_findings = [
        _build_finding_review_item(
            finding=finding,
            services_by_id=services_by_id,
            latest_feedback_by_finding_id=latest_feedback_by_finding_id,
            pattern_counts=pattern_counts,
            suggestion_by_pattern=suggestion_by_pattern,
        )
        for finding in sorted(
            database.list_findings(),
            key=lambda item: (item.created_at, item.id),
            reverse=True,
        )
        if finding.status in _ACTIVE_FINDING_STATUSES
    ]
    recently_dismissed = [
        _build_finding_review_item(
            finding=finding,
            services_by_id=services_by_id,
            latest_feedback_by_finding_id=latest_feedback_by_finding_id,
            pattern_counts=pattern_counts,
            suggestion_by_pattern=suggestion_by_pattern,
        )
        for finding in sorted(
            database.list_findings(),
            key=lambda item: (
                item.resolved_at if item.resolved_at is not None else item.created_at,
                item.id,
            ),
            reverse=True,
        )
        if finding.status == FindingStatus.DISMISSED
    ][:_RECENT_DISMISSED_FINDINGS_LIMIT]
    return FindingReviewResponse(
        active_findings=active_findings,
        recently_dismissed=recently_dismissed,
        suggestions=suggestions,
    )


def _build_finding_review_item(
    *,
    finding: Finding,
    services_by_id: dict[str, Service],
    latest_feedback_by_finding_id: dict[str, FindingFeedbackRecord],
    pattern_counts: Counter[tuple[str, str]],
    suggestion_by_pattern: dict[tuple[str, str], FindingFeedbackSuggestionResponse],
) -> FindingReviewItemResponse:
    """Build one finding review row with optional historical feedback context."""
    service = services_by_id.get(finding.service_id)
    feedback = latest_feedback_by_finding_id.get(finding.id)
    return FindingReviewItemResponse(
        finding=finding,
        service_name=finding.service_id if service is None else service.name,
        domain_label=_finding_domain_label(finding.domain),
        dismissal_reason=None if feedback is None else feedback.reason,
        dismissal_count_for_pattern=pattern_counts[(finding.service_id, finding.domain)],
        suggestion=suggestion_by_pattern.get((finding.service_id, finding.domain)),
    )


def _build_finding_feedback_suggestions(
    *,
    services_by_id: dict[str, Service],
    pattern_counts: Counter[tuple[str, str]],
    database: KavalDatabase,
) -> list[FindingFeedbackSuggestionResponse]:
    """Return advisory noise-control suggestions from repeated dismissal patterns."""
    active_overrides = {
        (override.service_id, override.check_id): override
        for override in database.list_service_check_overrides(
            scope=ServiceCheckOverrideScope.ACTIVE
        )
    }
    suggestions: list[FindingFeedbackSuggestionResponse] = []
    for service_id, check_id in sorted(pattern_counts):
        dismissal_count = pattern_counts[(service_id, check_id)]
        if dismissal_count < _FINDING_FEEDBACK_SUGGESTION_THRESHOLD:
            continue
        service = services_by_id.get(service_id)
        if service is None:
            continue
        try:
            entry = monitoring_check_entry(check_id)
        except ValueError:
            continue
        if not check_applies_to_service(check_id, service):
            continue
        override = active_overrides.get((service_id, check_id))
        if override is not None and override.enabled is False:
            continue
        action = _finding_feedback_action(check_id)
        suggestions.append(
            FindingFeedbackSuggestionResponse(
                service_id=service.id,
                service_name=service.name,
                check_id=check_id,
                check_label=entry.label,
                dismissal_count=dismissal_count,
                action=action,
                message=_finding_feedback_message(
                    service_name=service.name,
                    check_label=entry.label,
                    dismissal_count=dismissal_count,
                    action=action,
                ),
            )
        )
    return suggestions


def _finding_feedback_action(
    check_id: str,
) -> FindingFeedbackSuggestionAction:
    """Return the bounded advisory action for one repeatedly dismissed check."""
    if any(
        value is not None for value in monitoring_threshold_defaults(check_id)
    ):
        return FindingFeedbackSuggestionAction.ADJUST_THRESHOLD_OR_SUPPRESS
    return FindingFeedbackSuggestionAction.SUPPRESS_CHECK


def _finding_feedback_message(
    *,
    service_name: str,
    check_label: str,
    dismissal_count: int,
    action: FindingFeedbackSuggestionAction,
) -> str:
    """Build one deterministic operator-facing feedback suggestion message."""
    if action == FindingFeedbackSuggestionAction.ADJUST_THRESHOLD_OR_SUPPRESS:
        return (
            f"You've dismissed {dismissal_count} {check_label.casefold()} findings for "
            f"{service_name}. Consider adjusting the threshold or suppressing this check."
        )
    return (
        f"You've dismissed {dismissal_count} {check_label.casefold()} findings for "
        f"{service_name}. Consider suppressing this check."
    )


def _finding_domain_label(domain: str) -> str:
    """Return a compact human-readable label for one finding domain."""
    try:
        return monitoring_check_entry(domain).label
    except ValueError:
        return domain.replace(":", " / ").replace("_", " ").title()


def _incident_has_active_findings(
    *,
    database: KavalDatabase,
    incident_id: str,
) -> bool:
    """Return whether the incident still has any non-terminal findings."""
    return any(
        finding.incident_id == incident_id and finding.status in _ACTIVE_FINDING_STATUSES
        for finding in database.list_findings()
    )


def _build_finding_dismiss_change(
    *,
    finding: Finding,
    previous_status: FindingStatus,
    reason: FindingFeedbackReason,
    database: KavalDatabase,
) -> Change:
    """Build one auditable change record for explicit finding-noise dismissal."""
    dismissal_count = sum(
        1
        for record in database.list_finding_feedback_records()
        if record.service_id == finding.service_id and record.finding_domain == finding.domain
    )
    return Change(
        id=f"chg-finding-dismiss-{uuid4()}",
        type=ChangeType.CONFIG_CHANGE,
        service_id=finding.service_id,
        description=(
            f"Dismissed finding {finding.title!r} as {reason.value.replace('_', ' ')}."
        ),
        old_value=f"status={previous_status.value}",
        new_value=(
            f"status={FindingStatus.DISMISSED.value};"
            f"reason={reason.value};dismissals_for_pattern={dismissal_count}"
        ),
        timestamp=finding.resolved_at or datetime.now(tz=UTC),
        correlated_incidents=[] if finding.incident_id is None else [finding.incident_id],
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
    model_settings = cast(ModelSettingsService, request.app.state.model_settings_service)
    notification_settings = cast(
        NotificationSettingsService,
        request.app.state.notification_settings_service,
    )
    vault = cast(CredentialVault, request.app.state.credential_vault)
    for incident in _webhook_follow_up_incidents(pipeline_result):
        workflow_result = InvestigationWorkflow(
            database=database,
            local_model_transport=cast(
                RequestTransport | None,
                getattr(request.app.state, "local_model_transport", None),
            ),
            cloud_model_transport=cast(
                CloudTransport | None,
                getattr(request.app.state, "cloud_model_transport", None),
            ),
            local_model_config_loader=lambda: _runtime_local_model_config(
                model_settings=model_settings,
                vault=vault,
            ),
            cloud_model_config_loader=lambda: _runtime_cloud_model_config(
                model_settings=model_settings,
                vault=vault,
            ),
            cloud_escalation_policy_loader=model_settings.resolve_cloud_escalation_policy,
        ).run(
            incident_id=incident.id,
            trigger=InvestigationTrigger.AUTO,
            now=now,
        )
        router.route(
            incident=workflow_result.incident,
            investigation=workflow_result.investigation,
            now=now,
            context=notification_settings.build_routing_context(
                scope="active",
                now=now,
            ).model_copy(
                update={
                    "maintenance_windows": _active_alert_maintenance_windows(
                        database=database,
                        now=now,
                    )
                }
            ),
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


def _load_realtime_snapshot(app: FastAPI) -> RealtimeSnapshotResponse:
    """Load one complete Phase 1 UI snapshot from SQLite."""
    settings: ApiSettings = app.state.api_settings
    database = KavalDatabase(
        path=settings.database_path,
        migrations_dir=settings.migrations_dir,
    )
    try:
        services = enrich_services_with_current_insight(
            database.list_services(),
            local_model_configured=_active_local_model_configured_for_app(app),
        )
        incidents = database.list_incidents()
        investigations = database.list_investigations()
        manager = CredentialRequestManager(
            database=database,
            services_dir=settings.services_dir,
        )
        return RealtimeSnapshotResponse(
            kind="snapshot",
            graph=build_service_graph(services, descriptors=manager.descriptors),
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


def _resolve_settings_path(settings_path: Path | str | None) -> Path:
    """Resolve the persisted settings path from an explicit argument or environment."""
    if settings_path is not None:
        return Path(settings_path)
    environment_value = os.environ.get("KAVAL_SETTINGS_PATH")
    if environment_value:
        return Path(environment_value)
    return default_settings_path()


def _resolve_migrations_dir(migrations_dir: Path | str | None) -> Path | None:
    """Resolve the optional migrations directory override."""
    if migrations_dir is not None:
        return Path(migrations_dir)
    environment_value = os.environ.get("KAVAL_MIGRATIONS_DIR")
    return Path(environment_value) if environment_value else None


def _resolve_services_dir(services_dir: Path | str | None) -> Path:
    """Resolve the descriptor catalog directory for the current app instance."""
    if services_dir is not None:
        return Path(services_dir)
    environment_value = os.environ.get("KAVAL_SERVICES_DIR")
    if environment_value:
        return Path(environment_value)
    return Path(__file__).resolve().parents[3] / "services"


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
