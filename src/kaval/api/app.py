"""FastAPI application for the Kaval monitoring and operations surface."""

from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from collections.abc import AsyncIterator, Iterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, cast

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketDisconnect

from kaval.api.schemas import (
    CreateCredentialRequestRequest,
    CredentialRequestChoiceRequest,
    CredentialSecretSubmissionRequest,
    HealthResponse,
    RealtimeSnapshotResponse,
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
    AdapterRegistry,
    AuthentikAdapter,
    CloudflareAdapter,
    NginxProxyManagerAdapter,
    PiHoleAdapter,
    RadarrAdapter,
    ServiceAdapter,
)
from kaval.investigation.cloud_model import load_cloud_model_config_from_env
from kaval.investigation.local_model import load_local_model_config_from_env
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
    derive_service_insight,
)
from kaval.notifications import (
    load_notification_bus_config_from_env,
    load_telegram_config_from_env,
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
    return build_service_graph(enrich_services_with_current_insight(database.list_services()))


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


def _build_service_detail_adapter_statuses(
    *,
    service: Service,
    loaded_descriptor: LoadedServiceDescriptor | None,
    credential_material_service: CredentialMaterialService,
) -> list[ServiceDetailAdapterResponse]:
    """Build one adapter summary for each implemented deep-inspection adapter."""
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

    adapter_statuses: list[ServiceDetailAdapterResponse] = []
    for adapter_id, adapter in adapters_by_id.items():
        surfaces = surfaces_by_adapter_id[adapter_id]
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
                adapter_id=adapter_id,
                display_name=_adapter_display_name(adapter_id),
                configuration_state=configuration_state,
                configuration_summary=configuration_summary,
                health_state=health_state,
                health_summary=health_summary,
                missing_credentials=list(resolution.missing_keys),
                supported_fact_names=sorted(
                    {
                        fact_name
                        for surface in surfaces
                        for fact_name in surface.facts_provided
                    }
                ),
            )
        )
    return sorted(adapter_statuses, key=lambda status: status.display_name)


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
        services = enrich_services_with_current_insight(database.list_services())
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
