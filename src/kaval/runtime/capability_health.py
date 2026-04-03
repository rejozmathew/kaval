"""Typed Kaval self-health model across the runtime capability layers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self, Sequence

from pydantic import Field, model_validator

from kaval.credentials.models import VaultStatus
from kaval.integrations import AdapterDiagnosticResult, AdapterDiagnosticStatus
from kaval.models import JsonValue, KavalModel
from kaval.notifications import NotificationDeliveryStatus


class CapabilityHealthLayer(StrEnum):
    """The 10 Phase 3A capability-health layers."""

    DISCOVERY_PIPELINE = "discovery_pipeline"
    CHECK_SCHEDULER = "check_scheduler"
    LOCAL_MODEL = "local_model"
    CLOUD_MODEL = "cloud_model"
    NOTIFICATION_CHANNELS = "notification_channels"
    CREDENTIAL_VAULT = "credential_vault"
    DEEP_INSPECTION_ADAPTERS = "deep_inspection_adapters"
    WEBHOOK_RECEIVER = "webhook_receiver"
    EXECUTOR_PROCESS = "executor_process"
    DATABASE = "database"


class CapabilityHealthStatus(StrEnum):
    """Supported health states for Kaval capability layers."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    DISABLED = "disabled"


class CapabilityLayerHealth(KavalModel):
    """One capability-layer health record."""

    layer: CapabilityHealthLayer
    status: CapabilityHealthStatus
    summary: str
    detail: str
    user_impact: str
    guidance: str
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class CapabilityHealthSnapshot(KavalModel):
    """A full 10-layer runtime health snapshot for Kaval."""

    overall_status: CapabilityHealthStatus
    checked_at: datetime
    layers: list[CapabilityLayerHealth]

    @model_validator(mode="after")
    def validate_layers(self) -> Self:
        """Require exactly one record for each Phase 3A capability layer."""
        expected_layers = set(CapabilityHealthLayer)
        actual_layers = [layer.layer for layer in self.layers]
        if len(actual_layers) != len(set(actual_layers)):
            msg = "capability health snapshot contains duplicate layers"
            raise ValueError(msg)
        if set(actual_layers) != expected_layers:
            missing = sorted(
                layer.value for layer in expected_layers.difference(actual_layers)
            )
            unexpected = sorted(
                layer.value for layer in set(actual_layers).difference(expected_layers)
            )
            details: list[str] = []
            if missing:
                details.append(f"missing layers: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected layers: {', '.join(unexpected)}")
            raise ValueError(
                "capability health snapshot must include all 10 layers; "
                + "; ".join(details)
            )
        return self


class DiscoveryPipelineHealthInputs(KavalModel):
    """Signals used to evaluate discovery-pipeline health."""

    unraid_api_reachable: bool
    docker_api_reachable: bool
    running_on_schedule: bool
    data_stale: bool = False


class CheckSchedulerHealthInputs(KavalModel):
    """Signals used to evaluate check-scheduler health."""

    scheduler_running: bool
    overdue_checks: int = Field(default=0, ge=0)


class LocalModelHealthInputs(KavalModel):
    """Signals used to evaluate local-model availability."""

    configured: bool
    reachable: bool | None = None
    latency_ms: float | None = Field(default=None, ge=0.0)
    latency_target_ms: float = Field(default=5000.0, gt=0.0)


class CloudModelHealthInputs(KavalModel):
    """Signals used to evaluate optional cloud-model availability."""

    configured: bool
    api_key_valid: bool | None = None
    reachable: bool | None = None
    budget_available: bool | None = None


class NotificationChannelsHealthInputs(KavalModel):
    """Signals used to evaluate notification-channel health."""

    configured_channels: int = Field(default=0, ge=0)
    delivered_channels: int = Field(default=0, ge=0)
    failed_channels: int = Field(default=0, ge=0)
    last_delivery_status: NotificationDeliveryStatus | None = None


class WebhookReceiverHealthInputs(KavalModel):
    """Signals used to evaluate webhook-receiver health."""

    configured: bool
    listener_running: bool | None = None
    normalizers_healthy: bool | None = None
    source_auth_valid: bool | None = None


class ExecutorProcessHealthInputs(KavalModel):
    """Signals used to evaluate executor-process health."""

    listener_running: bool
    socket_reachable: bool
    docker_accessible: bool


class DatabaseHealthInputs(KavalModel):
    """Signals used to evaluate database health."""

    reachable: bool
    migrations_current: bool
    locked: bool = False
    corruption_detected: bool = False
    disk_ok: bool = True


def evaluate_discovery_pipeline_health(
    inputs: DiscoveryPipelineHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the discovery-pipeline capability layer."""
    if (
        inputs.unraid_api_reachable
        and inputs.docker_api_reachable
        and inputs.running_on_schedule
        and not inputs.data_stale
    ):
        return _layer(
            layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
            status=CapabilityHealthStatus.HEALTHY,
            summary="Discovery pipeline is healthy.",
            detail="Unraid and Docker are reachable and discovery data is current.",
            user_impact="Service topology stays current.",
            guidance="No action required.",
        )
    reasons: list[str] = []
    if not inputs.unraid_api_reachable:
        reasons.append("Unraid API is unreachable")
    if not inputs.docker_api_reachable:
        reasons.append("Docker API is unreachable")
    if not inputs.running_on_schedule:
        reasons.append("discovery is not running on schedule")
    if inputs.data_stale:
        reasons.append("discovery data is stale")
    return _layer(
        layer=CapabilityHealthLayer.DISCOVERY_PIPELINE,
        status=CapabilityHealthStatus.DEGRADED,
        summary="Discovery pipeline is degraded.",
        detail="; ".join(reasons) + ".",
        user_impact="Service map and topology may be outdated.",
        guidance="Restore API access and confirm discovery scheduling.",
    )


def evaluate_check_scheduler_health(
    inputs: CheckSchedulerHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the deterministic check-scheduler layer."""
    if inputs.scheduler_running and inputs.overdue_checks == 0:
        return _layer(
            layer=CapabilityHealthLayer.CHECK_SCHEDULER,
            status=CapabilityHealthStatus.HEALTHY,
            summary="Check scheduler is healthy.",
            detail="All registered checks are running on schedule.",
            user_impact="Findings arrive on time.",
            guidance="No action required.",
        )
    detail = (
        "Scheduler is not running."
        if not inputs.scheduler_running
        else f"{inputs.overdue_checks} checks are overdue."
    )
    return _layer(
        layer=CapabilityHealthLayer.CHECK_SCHEDULER,
        status=CapabilityHealthStatus.DEGRADED,
        summary="Check scheduler is degraded.",
        detail=detail,
        user_impact="Monitoring findings may be delayed or missing.",
        guidance="Restore scheduler execution and clear overdue checks.",
        metadata={"overdue_checks": inputs.overdue_checks},
    )


def evaluate_local_model_health(
    inputs: LocalModelHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the local-model capability layer."""
    if not inputs.configured:
        return _layer(
            layer=CapabilityHealthLayer.LOCAL_MODEL,
            status=CapabilityHealthStatus.DISABLED,
            summary="Local model is not configured.",
            detail="No local model endpoint is configured.",
            user_impact="Local-only investigation is unavailable until configured.",
            guidance="Configure a local model endpoint to enable local synthesis.",
        )
    if inputs.reachable is not True:
        return _layer(
            layer=CapabilityHealthLayer.LOCAL_MODEL,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Local model is unreachable.",
            detail="Configured local model endpoint did not respond successfully.",
            user_impact="Local investigation is unavailable or degraded.",
            guidance="Check the local model process and endpoint URL.",
        )
    if inputs.latency_ms is not None and inputs.latency_ms > inputs.latency_target_ms:
        return _layer(
            layer=CapabilityHealthLayer.LOCAL_MODEL,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Local model is slow.",
            detail=(
                f"Observed latency {inputs.latency_ms:.0f} ms exceeded the target "
                f"{inputs.latency_target_ms:.0f} ms."
            ),
            user_impact="Investigation latency is higher than expected.",
            guidance="Check local model performance or raise the latency target intentionally.",
            metadata={
                "latency_ms": inputs.latency_ms,
                "latency_target_ms": inputs.latency_target_ms,
            },
        )
    return _layer(
        layer=CapabilityHealthLayer.LOCAL_MODEL,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Local model is healthy.",
        detail="Configured local model endpoint is reachable within the latency target.",
        user_impact="Local investigation is available.",
        guidance="No action required.",
        metadata={"latency_ms": inputs.latency_ms},
    )


def evaluate_cloud_model_health(
    inputs: CloudModelHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the optional cloud-model capability layer."""
    if not inputs.configured:
        return _layer(
            layer=CapabilityHealthLayer.CLOUD_MODEL,
            status=CapabilityHealthStatus.DISABLED,
            summary="Cloud model is not configured.",
            detail="No cloud model provider is configured.",
            user_impact="Cloud escalation is unavailable until configured.",
            guidance="Configure a cloud model only if you want escalation beyond the local model.",
        )
    reasons: list[str] = []
    if inputs.api_key_valid is False:
        reasons.append("API key is invalid")
    if inputs.reachable is False:
        reasons.append("cloud endpoint is unreachable")
    if inputs.budget_available is False:
        reasons.append("cloud budget is exhausted")
    if reasons:
        return _layer(
            layer=CapabilityHealthLayer.CLOUD_MODEL,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Cloud model is degraded.",
            detail="; ".join(reasons) + ".",
            user_impact="Cloud escalation is unavailable or constrained.",
            guidance="Restore cloud credentials, endpoint access, or budget.",
        )
    return _layer(
        layer=CapabilityHealthLayer.CLOUD_MODEL,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Cloud model is healthy.",
        detail="Configured cloud model checks passed.",
        user_impact="Cloud escalation is available.",
        guidance="No action required.",
    )


def evaluate_notification_channels_health(
    inputs: NotificationChannelsHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate configured notification channels."""
    if inputs.configured_channels == 0:
        return _layer(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DISABLED,
            summary="Notification channels are not configured.",
            detail="No notification destinations are configured.",
            user_impact="Kaval will not push operational alerts until channels are configured.",
            guidance="Configure at least one notification channel if alert delivery is required.",
        )
    if (
        inputs.last_delivery_status == NotificationDeliveryStatus.FAILED
        or inputs.failed_channels > 0
        or inputs.delivered_channels < inputs.configured_channels
    ):
        return _layer(
            layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Notification channels are degraded.",
            detail=(
                f"{inputs.delivered_channels} of {inputs.configured_channels} channels "
                f"delivered successfully."
            ),
            user_impact="Users may miss notifications.",
            guidance="Check the configured notification destinations and transport health.",
            metadata={
                "configured_channels": inputs.configured_channels,
                "delivered_channels": inputs.delivered_channels,
                "failed_channels": inputs.failed_channels,
            },
        )
    return _layer(
        layer=CapabilityHealthLayer.NOTIFICATION_CHANNELS,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Notification channels are healthy.",
        detail="All configured notification channels are deliverable.",
        user_impact="Alerts can be delivered.",
        guidance="No action required.",
        metadata={"configured_channels": inputs.configured_channels},
    )


def evaluate_credential_vault_health(vault_status: VaultStatus) -> CapabilityLayerHealth:
    """Evaluate the credential-vault capability layer."""
    if not vault_status.initialized:
        return _layer(
            layer=CapabilityHealthLayer.CREDENTIAL_VAULT,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Credential vault is not initialized.",
            detail="Vault metadata has not been initialized yet.",
            user_impact="Vault-backed credentials are unavailable.",
            guidance="Unlock the vault once to initialize it before using vault mode.",
        )
    if not vault_status.unlocked:
        return _layer(
            layer=CapabilityHealthLayer.CREDENTIAL_VAULT,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Credential vault is locked.",
            detail="Vault is initialized but currently locked.",
            user_impact=(
                "Deep inspection and vault-backed UAC flows cannot access "
                "stored credentials."
            ),
            guidance="Unlock the vault to restore access to stored credentials.",
            metadata={"stored_credentials": vault_status.stored_credentials},
        )
    return _layer(
        layer=CapabilityHealthLayer.CREDENTIAL_VAULT,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Credential vault is healthy.",
        detail="Vault is initialized and unlocked.",
        user_impact="Stored credentials are available to authorized flows.",
        guidance="No action required.",
        metadata={"stored_credentials": vault_status.stored_credentials},
    )


def evaluate_deep_inspection_adapters_health(
    diagnostics: Sequence[AdapterDiagnosticResult],
) -> CapabilityLayerHealth:
    """Evaluate the deep-inspection adapter subsystem from diagnostic results."""
    if not diagnostics:
        return _layer(
            layer=CapabilityHealthLayer.DEEP_INSPECTION_ADAPTERS,
            status=CapabilityHealthStatus.DISABLED,
            summary="Deep inspection adapters have no diagnostics yet.",
            detail="No adapter diagnostic runs have been recorded.",
            user_impact="Adapter health is unknown until diagnostics run.",
            guidance=(
                "Run adapter diagnostics on their scheduled cadence or on "
                "investigation trigger."
            ),
        )
    degraded = [
        diagnostic
        for diagnostic in diagnostics
        if diagnostic.status != AdapterDiagnosticStatus.HEALTHY
    ]
    if degraded:
        return _layer(
            layer=CapabilityHealthLayer.DEEP_INSPECTION_ADAPTERS,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Deep inspection adapters are degraded.",
            detail=(
                f"{len(degraded)} of {len(diagnostics)} adapters are not healthy: "
                + ", ".join(diagnostic.adapter_id for diagnostic in degraded)
                + "."
            ),
            user_impact=(
                "Some services lose deep-inspection capability and fall back "
                "to base inference."
            ),
            guidance=(
                "Review adapter diagnostic failures and refresh credentials "
                "or compatibility logic as needed."
            ),
            metadata={
                "total_adapters": len(diagnostics),
                "healthy_adapters": len(diagnostics) - len(degraded),
                "degraded_adapters": len(degraded),
            },
        )
    return _layer(
        layer=CapabilityHealthLayer.DEEP_INSPECTION_ADAPTERS,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Deep inspection adapters are healthy.",
        detail="All diagnosed adapters are healthy.",
        user_impact="Deep inspection is available for configured services.",
        guidance="No action required.",
        metadata={
            "total_adapters": len(diagnostics),
            "healthy_adapters": len(diagnostics),
            "degraded_adapters": 0,
        },
    )


def evaluate_webhook_receiver_health(
    inputs: WebhookReceiverHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the webhook-receiver capability layer."""
    if not inputs.configured:
        return _layer(
            layer=CapabilityHealthLayer.WEBHOOK_RECEIVER,
            status=CapabilityHealthStatus.DISABLED,
            summary="Webhook receiver is not configured.",
            detail="No webhook sources are configured.",
            user_impact="External alert sources are not ingested until configured.",
            guidance="Configure webhook sources only if external ingestion is needed.",
        )
    if (
        inputs.listener_running is not True
        or inputs.normalizers_healthy is False
        or inputs.source_auth_valid is False
    ):
        reasons: list[str] = []
        if inputs.listener_running is not True:
            reasons.append("listener is not running")
        if inputs.normalizers_healthy is False:
            reasons.append("normalizers are unhealthy")
        if inputs.source_auth_valid is False:
            reasons.append("source authentication is failing")
        return _layer(
            layer=CapabilityHealthLayer.WEBHOOK_RECEIVER,
            status=CapabilityHealthStatus.DEGRADED,
            summary="Webhook receiver is degraded.",
            detail="; ".join(reasons) + ".",
            user_impact="External alerts may not be ingested reliably.",
            guidance="Restore listener health, normalizer behavior, and source authentication.",
        )
    return _layer(
        layer=CapabilityHealthLayer.WEBHOOK_RECEIVER,
        status=CapabilityHealthStatus.HEALTHY,
        summary="Webhook receiver is healthy.",
        detail="Configured webhook receiver checks passed.",
        user_impact="External alerts can be ingested.",
        guidance="No action required.",
    )


def evaluate_executor_process_health(
    inputs: ExecutorProcessHealthInputs,
) -> CapabilityLayerHealth:
    """Evaluate the executor-process capability layer."""
    if inputs.listener_running and inputs.socket_reachable and inputs.docker_accessible:
        return _layer(
            layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
            status=CapabilityHealthStatus.HEALTHY,
            summary="Executor process is healthy.",
            detail="Executor listener, socket, and docker access checks passed.",
            user_impact="Approved remediation actions can execute.",
            guidance="No action required.",
        )
    reasons: list[str] = []
    if not inputs.listener_running:
        reasons.append("listener is not running")
    if not inputs.socket_reachable:
        reasons.append("executor socket is unreachable")
    if not inputs.docker_accessible:
        reasons.append("docker access is unavailable")
    return _layer(
        layer=CapabilityHealthLayer.EXECUTOR_PROCESS,
        status=CapabilityHealthStatus.CRITICAL,
        summary="Executor process is critical.",
        detail="; ".join(reasons) + ".",
        user_impact="Approved remediation actions are unavailable.",
        guidance="Restore the executor process, socket path, and docker access boundary.",
    )


def evaluate_database_health(inputs: DatabaseHealthInputs) -> CapabilityLayerHealth:
    """Evaluate the database capability layer."""
    if (
        inputs.reachable
        and inputs.migrations_current
        and not inputs.locked
        and inputs.disk_ok
        and not inputs.corruption_detected
    ):
        return _layer(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.HEALTHY,
            summary="Database is healthy.",
            detail="Database is reachable and migrations are current.",
            user_impact="State persistence is available.",
            guidance="No action required.",
        )
    if (
        not inputs.reachable
        or inputs.locked
        or not inputs.disk_ok
        or inputs.corruption_detected
    ):
        reasons: list[str] = []
        if not inputs.reachable:
            reasons.append("database is unreachable")
        if inputs.locked:
            reasons.append("database is locked")
        if not inputs.disk_ok:
            reasons.append("database storage is exhausted")
        if inputs.corruption_detected:
            reasons.append("database corruption was detected")
        return _layer(
            layer=CapabilityHealthLayer.DATABASE,
            status=CapabilityHealthStatus.CRITICAL,
            summary="Database is critical.",
            detail="; ".join(reasons) + ".",
            user_impact="Persistence is unavailable or at risk.",
            guidance="Restore database availability and integrity immediately.",
        )
    return _layer(
        layer=CapabilityHealthLayer.DATABASE,
        status=CapabilityHealthStatus.DEGRADED,
        summary="Database is degraded.",
        detail="Database is reachable but migrations are not current.",
        user_impact="Persistence may behave inconsistently until migrations are current.",
        guidance="Run the expected database migrations before continuing normal operation.",
    )


def build_capability_health_snapshot(
    *,
    checked_at: datetime,
    layers: Sequence[CapabilityLayerHealth],
) -> CapabilityHealthSnapshot:
    """Aggregate one full capability-health snapshot across all 10 layers."""
    ordered_layers = sorted(layers, key=lambda item: item.layer.value)
    statuses = {layer.status for layer in ordered_layers}
    if CapabilityHealthStatus.CRITICAL in statuses:
        overall_status = CapabilityHealthStatus.CRITICAL
    elif CapabilityHealthStatus.DEGRADED in statuses:
        overall_status = CapabilityHealthStatus.DEGRADED
    else:
        overall_status = CapabilityHealthStatus.HEALTHY
    return CapabilityHealthSnapshot(
        overall_status=overall_status,
        checked_at=checked_at,
        layers=list(ordered_layers),
    )


def _layer(
    *,
    layer: CapabilityHealthLayer,
    status: CapabilityHealthStatus,
    summary: str,
    detail: str,
    user_impact: str,
    guidance: str,
    metadata: dict[str, JsonValue] | None = None,
) -> CapabilityLayerHealth:
    """Build one capability-layer health record."""
    return CapabilityLayerHealth(
        layer=layer,
        status=status,
        summary=summary,
        detail=detail,
        user_impact=user_impact,
        guidance=guidance,
        metadata=metadata or {},
    )
