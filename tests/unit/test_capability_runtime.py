"""Unit tests for Phase 3A capability runtime signals and panel reporting."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.credentials.models import VaultStatus
from kaval.database import KavalDatabase
from kaval.monitoring import SchedulerRunResult, persist_scheduler_runtime_signal
from kaval.runtime import (
    CapabilityHealthDisplayState,
    CapabilityHealthLayer,
    CapabilityHealthStatus,
    CapabilityRuntimeSignalSource,
    CheckSchedulerRuntimeSignal,
    build_capability_health_report,
    build_discovery_pipeline_runtime_signal,
    build_executor_process_runtime_signal,
    build_scheduler_runtime_signal,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for capability runtime tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def test_capability_health_report_distinguishes_stale_and_healthy_runtime_layers() -> None:
    """Discovery staleness should be distinct from recent scheduler and executor health."""
    report = build_capability_health_report(
        checked_at=ts(13, 0),
        discovery_signal=build_discovery_pipeline_runtime_signal(
            recorded_at=ts(11, 0),
            last_succeeded_at=ts(11, 0),
            unraid_api_reachable=True,
            docker_api_reachable=True,
            trigger="periodic_reconciliation",
        ),
        scheduler_signal=build_scheduler_runtime_signal(
            recorded_at=ts(12, 55),
            last_completed_at=ts(12, 55),
            executed_check_ids=["endpoint_probe"],
        ),
        executor_signal=build_executor_process_runtime_signal(
            recorded_at=ts(12, 58),
            listener_started_at=ts(12, 30),
            socket_path=Path("/tmp/executor.sock"),
            docker_socket_path=Path("/tmp/docker.sock"),
            socket_reachable=True,
            docker_accessible=True,
        ),
        executor_socket_reachable=True,
        local_model_configured=False,
        cloud_model_configured=False,
        notification_channel_count=0,
        vault_status=VaultStatus(
            initialized=True,
            unlocked=True,
            unlock_expires_at=ts(13, 30),
            stored_credentials=1,
        ),
        database_reachable=True,
        migrations_current=True,
    )
    layers = {layer.layer: layer for layer in report.layers}

    assert report.overall_status == CapabilityHealthStatus.DEGRADED
    assert layers[CapabilityHealthLayer.DISCOVERY_PIPELINE].display_state == (
        CapabilityHealthDisplayState.STALE
    )
    assert layers[CapabilityHealthLayer.CHECK_SCHEDULER].display_state == (
        CapabilityHealthDisplayState.HEALTHY
    )
    assert layers[CapabilityHealthLayer.EXECUTOR_PROCESS].display_state == (
        CapabilityHealthDisplayState.HEALTHY
    )


def test_capability_health_report_marks_missing_runtime_inputs_unavailable() -> None:
    """Missing runtime signals should remain explicitly unavailable instead of guessed."""
    report = build_capability_health_report(
        checked_at=ts(13, 0),
        discovery_signal=None,
        scheduler_signal=None,
        executor_signal=None,
        executor_socket_reachable=False,
        local_model_configured=True,
        cloud_model_configured=True,
        notification_channel_count=2,
        vault_status=VaultStatus(
            initialized=True,
            unlocked=True,
            unlock_expires_at=ts(13, 30),
            stored_credentials=1,
        ),
        database_reachable=True,
        migrations_current=True,
    )
    layers = {layer.layer: layer for layer in report.layers}

    assert layers[CapabilityHealthLayer.DISCOVERY_PIPELINE].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )
    assert layers[CapabilityHealthLayer.CHECK_SCHEDULER].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )
    assert layers[CapabilityHealthLayer.EXECUTOR_PROCESS].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )
    assert layers[CapabilityHealthLayer.LOCAL_MODEL].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )
    assert layers[CapabilityHealthLayer.CLOUD_MODEL].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )
    assert layers[CapabilityHealthLayer.NOTIFICATION_CHANNELS].display_state == (
        CapabilityHealthDisplayState.UNAVAILABLE
    )


def test_persist_scheduler_runtime_signal_records_completed_tick(tmp_path: Path) -> None:
    """Scheduler telemetry capture should persist one completed tick for later API queries."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    try:
        persist_scheduler_runtime_signal(
            database,
            run_at=ts(12, 15),
            result=SchedulerRunResult(
                executed_checks=("dns_resolution", "endpoint_probe"),
                findings=[],
            ),
        )

        signal = database.get_capability_runtime_signal(
            CapabilityRuntimeSignalSource.CHECK_SCHEDULER
        )

        assert isinstance(signal, CheckSchedulerRuntimeSignal)
        assert signal.last_completed_at == ts(12, 15)
        assert signal.executed_check_ids == ["dns_resolution", "endpoint_probe"]
    finally:
        database.close()
