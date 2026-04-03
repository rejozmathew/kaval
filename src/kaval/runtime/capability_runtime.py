"""Runtime telemetry signals and report builders for capability health."""

from __future__ import annotations

import socket
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, TypeAdapter

from kaval.credentials.models import VaultStatus
from kaval.integrations import AdapterDiagnosticResult
from kaval.models import JsonValue, KavalModel
from kaval.runtime.capability_health import (
    CapabilityHealthLayer,
    CapabilityHealthStatus,
    CapabilityLayerHealth,
    CloudModelHealthInputs,
    DatabaseHealthInputs,
    LocalModelHealthInputs,
    WebhookReceiverHealthInputs,
    build_capability_health_snapshot,
    evaluate_cloud_model_health,
    evaluate_credential_vault_health,
    evaluate_database_health,
    evaluate_deep_inspection_adapters_health,
    evaluate_local_model_health,
    evaluate_webhook_receiver_health,
)

_DISPLAY_STATE_KEY = "display_state"


class CapabilityHealthDisplayState(StrEnum):
    """User-facing display states for the Kaval health panel."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STALE = "stale"
    DISABLED = "disabled"


class CapabilityRuntimeSignalSource(StrEnum):
    """Persisted runtime telemetry sources for P3A-19."""

    DISCOVERY_PIPELINE = "discovery_pipeline"
    CHECK_SCHEDULER = "check_scheduler"
    EXECUTOR_PROCESS = "executor_process"


class CapabilityRuntimePolicy(KavalModel):
    """Bounded freshness rules for minimum Phase 3A runtime signals."""

    discovery_stale_after_seconds: int = Field(default=1800, ge=1)
    scheduler_stale_after_seconds: int = Field(default=900, ge=1)


class DiscoveryPipelineRuntimeSignal(KavalModel):
    """Latest persisted runtime signal for the discovery pipeline."""

    source: Literal[CapabilityRuntimeSignalSource.DISCOVERY_PIPELINE] = (
        CapabilityRuntimeSignalSource.DISCOVERY_PIPELINE
    )
    recorded_at: datetime
    last_succeeded_at: datetime | None = None
    unraid_api_reachable: bool
    docker_api_reachable: bool
    trigger: str | None = None


class CheckSchedulerRuntimeSignal(KavalModel):
    """Latest persisted runtime signal for the deterministic check scheduler."""

    source: Literal[CapabilityRuntimeSignalSource.CHECK_SCHEDULER] = (
        CapabilityRuntimeSignalSource.CHECK_SCHEDULER
    )
    recorded_at: datetime
    last_completed_at: datetime | None = None
    executed_check_ids: list[str] = Field(default_factory=list)


class ExecutorProcessRuntimeSignal(KavalModel):
    """Latest persisted runtime signal for the internal executor process."""

    source: Literal[CapabilityRuntimeSignalSource.EXECUTOR_PROCESS] = (
        CapabilityRuntimeSignalSource.EXECUTOR_PROCESS
    )
    recorded_at: datetime
    listener_started_at: datetime
    socket_path: str
    socket_reachable: bool
    docker_socket_path: str
    docker_accessible: bool


CapabilityRuntimeSignal: TypeAlias = Annotated[
    DiscoveryPipelineRuntimeSignal
    | CheckSchedulerRuntimeSignal
    | ExecutorProcessRuntimeSignal,
    Field(discriminator="source"),
]

_RUNTIME_SIGNAL_ADAPTER: TypeAdapter[CapabilityRuntimeSignal] = TypeAdapter(
    CapabilityRuntimeSignal
)


class CapabilityLayerReport(KavalModel):
    """One user-facing capability-health layer record."""

    layer: CapabilityHealthLayer
    status: CapabilityHealthStatus
    display_state: CapabilityHealthDisplayState
    summary: str
    detail: str
    user_impact: str
    guidance: str
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @classmethod
    def from_layer(cls, layer: CapabilityLayerHealth) -> "CapabilityLayerReport":
        """Convert one internal layer result into a panel-facing record."""
        return cls(
            layer=layer.layer,
            status=layer.status,
            display_state=_display_state_for_layer(layer),
            summary=layer.summary,
            detail=layer.detail,
            user_impact=layer.user_impact,
            guidance=layer.guidance,
            metadata=dict(layer.metadata),
        )


class CapabilityHealthReport(KavalModel):
    """Typed API/UI report for the Kaval capability-health panel."""

    checked_at: datetime
    overall_status: CapabilityHealthStatus
    layers: list[CapabilityLayerReport]


def validate_capability_runtime_signal_json(payload: str) -> CapabilityRuntimeSignal:
    """Parse one persisted runtime signal payload."""
    return _RUNTIME_SIGNAL_ADAPTER.validate_json(payload)


def build_discovery_pipeline_runtime_signal(
    *,
    recorded_at: datetime,
    unraid_api_reachable: bool,
    docker_api_reachable: bool,
    last_succeeded_at: datetime | None = None,
    trigger: str | None = None,
) -> DiscoveryPipelineRuntimeSignal:
    """Build one persisted discovery-pipeline runtime signal."""
    return DiscoveryPipelineRuntimeSignal(
        recorded_at=recorded_at,
        last_succeeded_at=last_succeeded_at,
        unraid_api_reachable=unraid_api_reachable,
        docker_api_reachable=docker_api_reachable,
        trigger=trigger,
    )


def build_scheduler_runtime_signal(
    *,
    recorded_at: datetime,
    executed_check_ids: list[str] | tuple[str, ...],
    last_completed_at: datetime | None = None,
) -> CheckSchedulerRuntimeSignal:
    """Build one persisted scheduler runtime signal."""
    return CheckSchedulerRuntimeSignal(
        recorded_at=recorded_at,
        last_completed_at=last_completed_at,
        executed_check_ids=list(executed_check_ids),
    )


def build_executor_process_runtime_signal(
    *,
    recorded_at: datetime,
    listener_started_at: datetime,
    socket_path: Path,
    docker_socket_path: Path,
    socket_reachable: bool,
    docker_accessible: bool,
) -> ExecutorProcessRuntimeSignal:
    """Build one persisted executor-process runtime signal."""
    return ExecutorProcessRuntimeSignal(
        recorded_at=recorded_at,
        listener_started_at=listener_started_at,
        socket_path=str(socket_path),
        socket_reachable=socket_reachable,
        docker_socket_path=str(docker_socket_path),
        docker_accessible=docker_accessible,
    )


def probe_unix_socket(path: Path, *, timeout_seconds: float = 0.2) -> bool:
    """Return whether a Unix domain socket accepts a connection."""
    if not path.exists():
        return False
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout_seconds)
    try:
        client.connect(str(path))
    except OSError:
        return False
    finally:
        client.close()
    return True


def build_capability_health_report(
    *,
    checked_at: datetime,
    discovery_signal: DiscoveryPipelineRuntimeSignal | None,
    scheduler_signal: CheckSchedulerRuntimeSignal | None,
    executor_signal: ExecutorProcessRuntimeSignal | None,
    executor_socket_reachable: bool,
    local_model_configured: bool,
    cloud_model_configured: bool,
    notification_channel_count: int,
    vault_status: VaultStatus,
    database_reachable: bool,
    migrations_current: bool,
    database_corruption_detected: bool = False,
    webhook_receiver_configured: bool = False,
    adapter_diagnostics: list[AdapterDiagnosticResult] | tuple[AdapterDiagnosticResult, ...] = (),
    policy: CapabilityRuntimePolicy | None = None,
) -> CapabilityHealthReport:
    """Build the panel-facing capability-health report from runtime inputs."""
    effective_policy = policy or CapabilityRuntimePolicy()
    layers = [
        _build_discovery_pipeline_layer(
            checked_at=checked_at,
            signal=discovery_signal,
            policy=effective_policy,
        ),
        _build_check_scheduler_layer(
            checked_at=checked_at,
            signal=scheduler_signal,
            policy=effective_policy,
        ),
        _build_local_model_layer(local_model_configured=local_model_configured),
        _build_cloud_model_layer(cloud_model_configured=cloud_model_configured),
        _build_notification_channels_layer(
            notification_channel_count=notification_channel_count
        ),
        evaluate_credential_vault_health(vault_status),
        evaluate_deep_inspection_adapters_health(adapter_diagnostics),
        evaluate_webhook_receiver_health(
            WebhookReceiverHealthInputs(configured=webhook_receiver_configured)
        ),
        _build_executor_process_layer(
            signal=executor_signal,
            executor_socket_reachable=executor_socket_reachable,
        ),
        evaluate_database_health(
            DatabaseHealthInputs(
                reachable=database_reachable,
                migrations_current=migrations_current,
                corruption_detected=database_corruption_detected,
            )
        ),
    ]
    snapshot = build_capability_health_snapshot(checked_at=checked_at, layers=layers)
    return CapabilityHealthReport(
        checked_at=snapshot.checked_at,
        overall_status=snapshot.overall_status,
        layers=[CapabilityLayerReport.from_layer(layer) for layer in snapshot.layers],
    )


def _build_discovery_pipeline_layer(
    *,
    checked_at: datetime,
    signal: DiscoveryPipelineRuntimeSignal | None,
    policy: CapabilityRuntimePolicy,
) -> CapabilityLayerHealth:
    """Build the discovery-pipeline layer from persisted runtime telemetry."""
    if signal is None:
        return _reported_layer(
            layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.UNAVAILABLE,
            summary="Discovery pipeline telemetry is unavailable.",
            detail="No discovery refresh heartbeat has been recorded yet.",
            user_impact="Service topology may become stale without discovery confirmation.",
            guidance=(
                "Persist a successful discovery refresh to restore discovery "
                "health visibility."
            ),
        )

    last_success = signal.last_succeeded_at
    if last_success is None:
        return _reported_layer(
            layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.DEGRADED,
            summary="Discovery pipeline last run did not complete successfully.",
            detail=(
                "A discovery runtime signal exists, but no successful refresh "
                "has been recorded."
            ),
            user_impact="Service topology may be incomplete or outdated.",
            guidance=(
                "Restore Unraid and Docker discovery access, then persist a "
                "successful refresh."
            ),
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "trigger": signal.trigger,
                "unraid_api_reachable": signal.unraid_api_reachable,
                "docker_api_reachable": signal.docker_api_reachable,
            },
        )

    if checked_at - last_success > timedelta(seconds=policy.discovery_stale_after_seconds):
        return _reported_layer(
            layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.STALE,
            summary="Discovery pipeline data is stale.",
            detail=(
                "The last successful discovery refresh is older than the allowed freshness window."
            ),
            user_impact="Service map and topology may no longer match the live system.",
            guidance="Run or restore discovery refreshes on schedule.",
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "last_succeeded_at": last_success.isoformat(),
                "trigger": signal.trigger,
            },
        )

    if not signal.unraid_api_reachable or not signal.docker_api_reachable:
        return _reported_layer(
            layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.DEGRADED,
            summary="Discovery pipeline is degraded.",
            detail="The latest discovery refresh reported an upstream API reachability problem.",
            user_impact="Topology refresh may fail or return incomplete data.",
            guidance="Restore Unraid and Docker API reachability.",
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "last_succeeded_at": last_success.isoformat(),
                "trigger": signal.trigger,
                "unraid_api_reachable": signal.unraid_api_reachable,
                "docker_api_reachable": signal.docker_api_reachable,
            },
        )

    return _reported_layer(
        layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
        status=CapabilityHealthStatus.HEALTHY,
        display_state=CapabilityHealthDisplayState.HEALTHY,
        summary="Discovery pipeline is healthy.",
        detail="A recent successful discovery refresh is recorded.",
        user_impact="Service topology stays current.",
        guidance="No action required.",
        metadata={
            "recorded_at": signal.recorded_at.isoformat(),
            "last_succeeded_at": last_success.isoformat(),
            "trigger": signal.trigger,
        },
    )


def _build_check_scheduler_layer(
    *,
    checked_at: datetime,
    signal: CheckSchedulerRuntimeSignal | None,
    policy: CapabilityRuntimePolicy,
) -> CapabilityLayerHealth:
    """Build the check-scheduler layer from persisted runtime telemetry."""
    if signal is None:
        return _reported_layer(
            layer=CapabilityHealthLayer.CHECK_SCHEDULER,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.UNAVAILABLE,
            summary="Check scheduler telemetry is unavailable.",
            detail="No scheduler heartbeat has been recorded yet.",
            user_impact="Monitoring findings may be delayed or missing.",
            guidance="Persist scheduler ticks to restore scheduler health visibility.",
        )

    last_completed = signal.last_completed_at
    if last_completed is None:
        return _reported_layer(
            layer=CapabilityHealthLayer.CHECK_SCHEDULER,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.DEGRADED,
            summary="Check scheduler did not report a completed tick.",
            detail="A scheduler runtime signal exists, but no completed check cycle was recorded.",
            user_impact="Monitoring findings may be missing.",
            guidance="Restore scheduler execution and persist completed ticks.",
            metadata={"recorded_at": signal.recorded_at.isoformat()},
        )

    if checked_at - last_completed > timedelta(seconds=policy.scheduler_stale_after_seconds):
        return _reported_layer(
            layer=CapabilityHealthLayer.CHECK_SCHEDULER,
            status=CapabilityHealthStatus.DEGRADED,
            display_state=CapabilityHealthDisplayState.STALE,
            summary="Check scheduler heartbeat is stale.",
            detail=(
                "The last completed scheduler tick is older than the allowed freshness window."
            ),
            user_impact="Monitoring checks may no longer be running on schedule.",
            guidance="Restore scheduler execution and persist regular tick results.",
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "last_completed_at": last_completed.isoformat(),
                "executed_check_ids": list(signal.executed_check_ids),
            },
        )

    return _reported_layer(
        layer=CapabilityHealthLayer.CHECK_SCHEDULER,
        status=CapabilityHealthStatus.HEALTHY,
        display_state=CapabilityHealthDisplayState.HEALTHY,
        summary="Check scheduler is healthy.",
        detail="A recent scheduler tick completed successfully.",
        user_impact="Monitoring findings can arrive on schedule.",
        guidance="No action required.",
        metadata={
            "recorded_at": signal.recorded_at.isoformat(),
            "last_completed_at": last_completed.isoformat(),
            "executed_check_ids": list(signal.executed_check_ids),
        },
    )


def _build_local_model_layer(*, local_model_configured: bool) -> CapabilityLayerHealth:
    """Build the local-model layer without inventing an unrecorded probe result."""
    if not local_model_configured:
        return evaluate_local_model_health(LocalModelHealthInputs(configured=False))
    return _reported_layer(
        layer=CapabilityHealthLayer.LOCAL_MODEL,
        status=CapabilityHealthStatus.DEGRADED,
        display_state=CapabilityHealthDisplayState.UNAVAILABLE,
        summary="Local model health is unavailable.",
        detail="A local model is configured, but no runtime health probe has been recorded yet.",
        user_impact="Local investigation may be unavailable until the first successful model call.",
        guidance="Run a local investigation or add a bounded local-model probe later.",
    )


def _build_cloud_model_layer(*, cloud_model_configured: bool) -> CapabilityLayerHealth:
    """Build the cloud-model layer without inventing an unrecorded probe result."""
    if not cloud_model_configured:
        return evaluate_cloud_model_health(CloudModelHealthInputs(configured=False))
    return _reported_layer(
        layer=CapabilityHealthLayer.CLOUD_MODEL,
        status=CapabilityHealthStatus.DEGRADED,
        display_state=CapabilityHealthDisplayState.UNAVAILABLE,
        summary="Cloud model health is unavailable.",
        detail="A cloud model is configured, but no runtime health probe has been recorded yet.",
        user_impact="Cloud escalation may be unavailable until the first successful model call.",
        guidance="Run a cloud escalation or add a bounded cloud-model probe later.",
    )


def _build_notification_channels_layer(
    *,
    notification_channel_count: int,
) -> CapabilityLayerHealth:
    """Build notification-channel health from current configuration only."""
    if notification_channel_count == 0:
        return _reported_layer(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DISABLED,
            display_state=CapabilityHealthDisplayState.DISABLED,
            summary="Notification channels are not configured.",
            detail="No notification destinations are configured.",
            user_impact="Kaval will not push operational alerts until channels are configured.",
            guidance="Configure at least one notification channel if alert delivery is required.",
            metadata={"configured_channels": 0},
        )
    return _reported_layer(
        layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
        status=CapabilityHealthStatus.DEGRADED,
        display_state=CapabilityHealthDisplayState.UNAVAILABLE,
        summary="Notification channel health is unavailable.",
        detail=(
            f"{notification_channel_count} notification destinations are configured, "
            "but no delivery result has been recorded yet."
        ),
        user_impact="Alert delivery may fail silently until one send result is observed.",
        guidance="Record at least one successful or failed delivery to establish channel health.",
        metadata={"configured_channels": notification_channel_count},
    )


def _build_executor_process_layer(
    *,
    signal: ExecutorProcessRuntimeSignal | None,
    executor_socket_reachable: bool,
) -> CapabilityLayerHealth:
    """Build the executor-process layer from persisted and live socket signals."""
    if signal is None:
        return _reported_layer(
            layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
            status=CapabilityHealthStatus.CRITICAL,
            display_state=CapabilityHealthDisplayState.UNAVAILABLE,
            summary="Executor process telemetry is unavailable.",
            detail="No executor runtime signal has been recorded yet.",
            user_impact="Approved remediation actions cannot be trusted to execute.",
            guidance="Start the executor process so it can report startup health.",
        )

    if not executor_socket_reachable:
        return _reported_layer(
            layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
            status=CapabilityHealthStatus.CRITICAL,
            display_state=CapabilityHealthDisplayState.UNAVAILABLE,
            summary="Executor process is unavailable.",
            detail="The executor socket is not reachable from Core.",
            user_impact="Approved remediation actions are unavailable.",
            guidance="Restore the executor process or its Unix socket boundary.",
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "socket_path": signal.socket_path,
                "docker_accessible": signal.docker_accessible,
            },
        )

    if not signal.docker_accessible:
        return _reported_layer(
            layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
            status=CapabilityHealthStatus.CRITICAL,
            display_state=CapabilityHealthDisplayState.UNAVAILABLE,
            summary="Executor process cannot reach Docker.",
            detail="The executor is running, but its Docker socket check failed.",
            user_impact="Approved remediation actions are unavailable.",
            guidance=(
                "Restore executor-side Docker socket access within the existing "
                "trust boundary."
            ),
            metadata={
                "recorded_at": signal.recorded_at.isoformat(),
                "socket_path": signal.socket_path,
                "docker_socket_path": signal.docker_socket_path,
            },
        )

    return _reported_layer(
        layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
        status=CapabilityHealthStatus.HEALTHY,
        display_state=CapabilityHealthDisplayState.HEALTHY,
        summary="Executor process is healthy.",
        detail="The executor socket is reachable and the executor reported Docker access.",
        user_impact="Approved remediation actions can execute.",
        guidance="No action required.",
        metadata={
            "recorded_at": signal.recorded_at.isoformat(),
            "listener_started_at": signal.listener_started_at.isoformat(),
            "socket_path": signal.socket_path,
            "docker_socket_path": signal.docker_socket_path,
        },
    )


def _display_state_for_layer(
    layer: CapabilityLayerHealth,
) -> CapabilityHealthDisplayState:
    """Resolve the panel-facing display state for one capability layer."""
    raw_state = layer.metadata.get(_DISPLAY_STATE_KEY)
    if isinstance(raw_state, str):
        return CapabilityHealthDisplayState(raw_state)
    if layer.status == CapabilityHealthStatus.HEALTHY:
        return CapabilityHealthDisplayState.HEALTHY
    if layer.status == CapabilityHealthStatus.DISABLED:
        return CapabilityHealthDisplayState.DISABLED
    if layer.status == CapabilityHealthStatus.CRITICAL:
        return CapabilityHealthDisplayState.UNAVAILABLE
    return CapabilityHealthDisplayState.DEGRADED


def _reported_layer(
    *,
    layer: CapabilityHealthLayer,
    status: CapabilityHealthStatus,
    display_state: CapabilityHealthDisplayState,
    summary: str,
    detail: str,
    user_impact: str,
    guidance: str,
    metadata: dict[str, JsonValue] | None = None,
) -> CapabilityLayerHealth:
    """Build one capability layer and attach the panel display-state hint."""
    base_metadata: dict[str, JsonValue] = {_DISPLAY_STATE_KEY: display_state.value}
    if metadata:
        base_metadata.update(metadata)
    return CapabilityLayerHealth(
        layer=layer,
        status=status,
        summary=summary,
        detail=detail,
        user_impact=user_impact,
        guidance=guidance,
        metadata=base_metadata,
    )
