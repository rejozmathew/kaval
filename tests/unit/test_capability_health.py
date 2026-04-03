"""Unit tests for the Kaval capability-health model."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.credentials.models import VaultStatus
from kaval.integrations import AdapterDiagnosticResult, AdapterDiagnosticStatus
from kaval.notifications import NotificationDeliveryStatus
from kaval.runtime import (
    CapabilityHealthLayer,
    CapabilityHealthStatus,
    CheckSchedulerHealthInputs,
    CloudModelHealthInputs,
    DatabaseHealthInputs,
    DiscoveryPipelineHealthInputs,
    ExecutorProcessHealthInputs,
    LocalModelHealthInputs,
    NotificationChannelsHealthInputs,
    WebhookReceiverHealthInputs,
    build_capability_health_snapshot,
    evaluate_check_scheduler_health,
    evaluate_cloud_model_health,
    evaluate_credential_vault_health,
    evaluate_database_health,
    evaluate_deep_inspection_adapters_health,
    evaluate_discovery_pipeline_health,
    evaluate_executor_process_health,
    evaluate_local_model_health,
    evaluate_notification_channels_health,
    evaluate_webhook_receiver_health,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for capability-health tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def healthy_layers() -> list[object]:
    """Build a full 10-layer set that should aggregate to healthy."""
    return [
        evaluate_discovery_pipeline_health(
            DiscoveryPipelineHealthInputs(
                unraid_api_reachable=True,
                docker_api_reachable=True,
                running_on_schedule=True,
            )
        ),
        evaluate_check_scheduler_health(
            CheckSchedulerHealthInputs(
                scheduler_running=True,
                overdue_checks=0,
            )
        ),
        evaluate_local_model_health(
            LocalModelHealthInputs(
                configured=False,
            )
        ),
        evaluate_cloud_model_health(
            CloudModelHealthInputs(
                configured=False,
            )
        ),
        evaluate_notification_channels_health(
            NotificationChannelsHealthInputs(
                configured_channels=0,
            )
        ),
        evaluate_credential_vault_health(
            VaultStatus(
                initialized=True,
                unlocked=True,
                unlock_expires_at=ts(13),
                stored_credentials=2,
            )
        ),
        evaluate_deep_inspection_adapters_health(
            [
                AdapterDiagnosticResult(
                    adapter_id="radarr_api",
                    status=AdapterDiagnosticStatus.HEALTHY,
                    checks=[],
                    checked_at=ts(12),
                    reason=None,
                )
            ]
        ),
        evaluate_webhook_receiver_health(
            WebhookReceiverHealthInputs(configured=False)
        ),
        evaluate_executor_process_health(
            ExecutorProcessHealthInputs(
                listener_running=True,
                socket_reachable=True,
                docker_accessible=True,
            )
        ),
        evaluate_database_health(
            DatabaseHealthInputs(
                reachable=True,
                migrations_current=True,
            )
        ),
    ]


def test_capability_health_snapshot_aggregates_all_layers() -> None:
    """A full 10-layer snapshot should aggregate degraded states correctly."""
    layers = healthy_layers()
    layers[6] = evaluate_deep_inspection_adapters_health(
        [
            AdapterDiagnosticResult(
                adapter_id="radarr_api",
                status=AdapterDiagnosticStatus.HEALTHY,
                checks=[],
                checked_at=ts(12, 0),
                reason=None,
            ),
            AdapterDiagnosticResult(
                adapter_id="cloudflare_api",
                status=AdapterDiagnosticStatus.AUTH_FAILED,
                checks=[],
                checked_at=ts(12, 5),
                reason="token expired",
            ),
        ]
    )

    snapshot = build_capability_health_snapshot(checked_at=ts(13), layers=layers)

    assert snapshot.overall_status == CapabilityHealthStatus.DEGRADED
    assert len(snapshot.layers) == 10
    assert {layer.layer for layer in snapshot.layers} == set(CapabilityHealthLayer)


def test_capability_health_snapshot_rejects_missing_layers() -> None:
    """Snapshots must include exactly one record for every capability layer."""
    with pytest.raises(ValueError, match="must include all 10 layers"):
        build_capability_health_snapshot(
            checked_at=ts(13),
            layers=healthy_layers()[:-1],
        )


def test_adapter_capability_health_aggregates_per_adapter_diagnostics() -> None:
    """Adapter subsystem health should expose degraded counts and IDs."""
    layer = evaluate_deep_inspection_adapters_health(
        [
            AdapterDiagnosticResult(
                adapter_id="radarr_api",
                status=AdapterDiagnosticStatus.HEALTHY,
                checks=[],
                checked_at=ts(12, 0),
                reason=None,
            ),
            AdapterDiagnosticResult(
                adapter_id="authentik_api",
                status=AdapterDiagnosticStatus.PARSE_ERROR,
                checks=[],
                checked_at=ts(12, 5),
                reason="schema changed",
            ),
        ]
    )

    assert layer.status == CapabilityHealthStatus.DEGRADED
    assert layer.metadata == {
        "total_adapters": 2,
        "healthy_adapters": 1,
        "degraded_adapters": 1,
    }
    assert "authentik_api" in layer.detail


def test_optional_disabled_layers_do_not_degrade_overall_health() -> None:
    """Disabled optional layers should not force overall degraded status."""
    snapshot = build_capability_health_snapshot(
        checked_at=ts(13, 30),
        layers=healthy_layers(),
    )

    assert snapshot.overall_status == CapabilityHealthStatus.HEALTHY
    disabled_layers = {
        layer.layer
        for layer in snapshot.layers
        if layer.status == CapabilityHealthStatus.DISABLED
    }
    assert disabled_layers == {
        CapabilityHealthLayer.LOCAL_MODEL,
        CapabilityHealthLayer.CLOUD_MODEL,
        CapabilityHealthLayer.NOTIFICATION_CHANNELS,
        CapabilityHealthLayer.WEBHOOK_RECEIVER,
    }


def test_executor_and_database_layers_can_be_critical() -> None:
    """Critical executor or database failures should raise overall critical health."""
    layers = healthy_layers()
    layers[8] = evaluate_executor_process_health(
        ExecutorProcessHealthInputs(
            listener_running=False,
            socket_reachable=False,
            docker_accessible=False,
        )
    )
    layers[9] = evaluate_database_health(
        DatabaseHealthInputs(
            reachable=False,
            migrations_current=False,
            locked=True,
            disk_ok=False,
        )
    )

    snapshot = build_capability_health_snapshot(checked_at=ts(14), layers=layers)

    assert snapshot.overall_status == CapabilityHealthStatus.CRITICAL
    assert layers[8].status == CapabilityHealthStatus.CRITICAL
    assert layers[9].status == CapabilityHealthStatus.CRITICAL


def test_notification_layer_degrades_on_delivery_failures() -> None:
    """Configured notification channels should degrade when delivery fails."""
    layer = evaluate_notification_channels_health(
        NotificationChannelsHealthInputs(
            configured_channels=2,
            delivered_channels=0,
            failed_channels=2,
            last_delivery_status=NotificationDeliveryStatus.FAILED,
        )
    )

    assert layer.status == CapabilityHealthStatus.DEGRADED
    assert layer.metadata == {
        "configured_channels": 2,
        "delivered_channels": 0,
        "failed_channels": 2,
    }
