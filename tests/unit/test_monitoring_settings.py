"""Unit tests for persisted monitoring settings."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.models import ServiceCheckOverride, ServiceCheckOverrideScope
from kaval.monitoring import resolve_service_check_execution
from kaval.settings.monitoring_config import (
    ManagedMonitoringCheckSettings,
    MonitoringSettingsService,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for monitoring-settings tests."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


def test_monitoring_settings_stage_apply_and_resolve_service_overrides(
    tmp_path: Path,
) -> None:
    """Monitoring settings should persist staged changes and build cadence config."""
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models:\n  local:\n    enabled: false\n", encoding="utf-8")
    service = MonitoringSettingsService(settings_path=settings_path)

    staged = service.update_staged(
        checks=[
            ManagedMonitoringCheckSettings(
                check_id="container_health",
                enabled=True,
                interval_seconds=75,
            ),
            ManagedMonitoringCheckSettings(
                check_id="restart_storm",
                enabled=True,
                interval_seconds=60,
                restart_delta_threshold=4,
            ),
            ManagedMonitoringCheckSettings(
                check_id="endpoint_probe",
                enabled=True,
                interval_seconds=180,
                probe_timeout_seconds=6.0,
            ),
            ManagedMonitoringCheckSettings(
                check_id="vm_health",
                enabled=True,
                interval_seconds=120,
            ),
            ManagedMonitoringCheckSettings(
                check_id="tls_cert",
                enabled=False,
                interval_seconds=21600,
                tls_warning_days=10,
            ),
            ManagedMonitoringCheckSettings(
                check_id="dns_resolution",
                enabled=True,
                interval_seconds=300,
            ),
            ManagedMonitoringCheckSettings(
                check_id="log_pattern",
                enabled=True,
                interval_seconds=300,
            ),
            ManagedMonitoringCheckSettings(
                check_id="unraid_system",
                enabled=True,
                interval_seconds=600,
            ),
            ManagedMonitoringCheckSettings(
                check_id="dependency_chain",
                enabled=True,
                interval_seconds=900,
            ),
        ]
    )

    assert service.apply_required() is True
    assert staged.checks[0].check_id == "container_health"
    assert "models:" in settings_path.read_text(encoding="utf-8")
    assert "monitoring:" in settings_path.read_text(encoding="utf-8")
    assert "check_id: endpoint_probe" in settings_path.read_text(encoding="utf-8")

    cadence = service.resolve_cadence_config(
        scope="staged",
        service_overrides=[
            ServiceCheckOverride(
                scope=ServiceCheckOverrideScope.STAGED,
                service_id="svc-delugevpn",
                check_id="endpoint_probe",
                enabled=True,
                interval_seconds=45,
                probe_timeout_seconds=2.5,
                updated_at=ts(10, 5),
            ),
            ServiceCheckOverride(
                scope=ServiceCheckOverrideScope.STAGED,
                service_id="svc-delugevpn",
                check_id="restart_storm",
                restart_delta_threshold=6,
                updated_at=ts(10, 6),
            ),
        ],
    )

    execution = resolve_service_check_execution(
        config=cadence,
        service_id="svc-delugevpn",
        check_id="endpoint_probe",
        base_interval_seconds=120,
    )
    assert execution.enabled is True
    assert execution.interval_seconds == 45
    assert execution.source == "service_override"
    restart_execution = resolve_service_check_execution(
        config=cadence,
        service_id="svc-delugevpn",
        check_id="restart_storm",
        base_interval_seconds=60,
    )
    assert restart_execution.enabled is True
    assert restart_execution.interval_seconds == 60
    assert restart_execution.source == "global_default"
    thresholds = service.resolve_threshold_settings(
        scope="staged",
        service_overrides=[
            ServiceCheckOverride(
                scope=ServiceCheckOverrideScope.STAGED,
                service_id="svc-delugevpn",
                check_id="endpoint_probe",
                enabled=True,
                interval_seconds=45,
                probe_timeout_seconds=2.5,
                updated_at=ts(10, 5),
            ),
            ServiceCheckOverride(
                scope=ServiceCheckOverrideScope.STAGED,
                service_id="svc-delugevpn",
                check_id="restart_storm",
                restart_delta_threshold=6,
                updated_at=ts(10, 6),
            ),
        ],
        service_id="svc-delugevpn",
        check_id="endpoint_probe",
    )
    assert thresholds.probe_timeout_seconds == 2.5
    assert thresholds.source == "service_override"

    tls_execution = resolve_service_check_execution(
        config=cadence,
        service_id="svc-delugevpn",
        check_id="tls_cert",
        base_interval_seconds=21600,
    )
    assert tls_execution.enabled is False
    assert tls_execution.interval_seconds == 21600
    tls_thresholds = service.resolve_threshold_settings(
        scope="staged",
        service_overrides=[],
        service_id="svc-delugevpn",
        check_id="tls_cert",
    )
    assert tls_thresholds.tls_warning_days == 10
    assert tls_thresholds.source == "global_default"

    applied = service.apply(now=ts(11, 0))
    assert applied.checks[2].interval_seconds == 180
    assert applied.checks[2].probe_timeout_seconds == 6.0
    assert service.apply_required() is False
    assert service.last_applied_at == ts(11, 0)
