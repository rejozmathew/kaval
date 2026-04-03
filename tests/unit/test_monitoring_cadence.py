"""Unit tests for Phase 3A monitoring cadence contracts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.models import Incident, IncidentStatus, Severity
from kaval.monitoring import (
    IncidentAccelerationPolicy,
    MonitoringCadenceConfig,
    MonitoringCheckCadenceRule,
    ServiceMonitoringCadenceOverride,
    default_monitoring_check_cadences,
    incident_acceleration_active,
    incident_service_scope,
    resolve_check_interval,
    resolve_monitoring_cadence_decision,
    resolve_service_check_interval,
)
from kaval.pipeline import build_mock_services


def ts(hour: int, minute: int = 0, second: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for cadence tests."""
    return datetime(2026, 4, 3, hour, minute, second, tzinfo=UTC)


def test_default_monitoring_cadence_defaults_match_phase_requirements() -> None:
    """The built-in defaults should cover the documented Phase 3A cadence table."""
    defaults = {
        rule.check_id: rule.interval_seconds
        for rule in default_monitoring_check_cadences()
    }

    assert defaults["container_health"] == 60
    assert defaults["endpoint_probe"] == 120
    assert defaults["tls_cert"] == 21600
    assert defaults["dns_resolution"] == 300
    assert defaults["unraid_system"] == 600
    assert defaults["log_pattern"] == 300
    assert defaults["change_detection"] == 300
    assert defaults["dependency_chain"] == 600
    assert defaults["plugin_health"] == 3600


def test_monitoring_cadence_config_rejects_duplicate_override_keys() -> None:
    """Duplicate check or service override keys should fail validation."""
    with pytest.raises(ValueError, match="duplicate check_id values"):
        MonitoringCadenceConfig(
            check_overrides=[
                MonitoringCheckCadenceRule(check_id="tls_cert", interval_seconds=3600),
                MonitoringCheckCadenceRule(check_id="tls_cert", interval_seconds=7200),
            ]
        )

    with pytest.raises(ValueError, match="duplicate \\(service_id, check_id\\) pairs"):
        MonitoringCadenceConfig(
            service_overrides=[
                ServiceMonitoringCadenceOverride(
                    service_id="svc-radarr",
                    check_id="endpoint_probe",
                    interval_seconds=30,
                ),
                ServiceMonitoringCadenceOverride(
                    service_id="svc-radarr",
                    check_id="endpoint_probe",
                    interval_seconds=45,
                ),
            ]
        )


def test_service_override_takes_precedence_over_check_override() -> None:
    """Per-service cadence should resolve ahead of coarser override layers."""
    config = MonitoringCadenceConfig(
        check_overrides=[
            MonitoringCheckCadenceRule(check_id="endpoint_probe", interval_seconds=90)
        ],
        service_overrides=[
            ServiceMonitoringCadenceOverride(
                service_id="svc-radarr",
                check_id="endpoint_probe",
                interval_seconds=30,
            )
        ],
    )

    assert resolve_check_interval(
        config=config,
        check_id="endpoint_probe",
        base_interval_seconds=120,
    ) == 90
    assert resolve_service_check_interval(
        config=config,
        service_id="svc-radarr",
        check_id="endpoint_probe",
        base_interval_seconds=120,
    ) == 30


def test_incident_service_scope_includes_upstream_dependencies() -> None:
    """Incident scope should expand to the affected service's dependency chain."""
    services = build_mock_services()
    incident = _build_incident(
        incident_id="inc-radarr",
        affected_services=["svc-radarr"],
        created_at=ts(12, 0, 0),
    )

    assert incident_service_scope(incident=incident, services=services) == [
        "svc-delugevpn",
        "svc-radarr",
    ]


def test_monitoring_cadence_decision_accelerates_related_checks() -> None:
    """Active incidents should accelerate checks for affected services and dependencies."""
    services = build_mock_services()
    incident = _build_incident(
        incident_id="inc-radarr",
        affected_services=["svc-radarr"],
        created_at=ts(12, 0, 0),
    )

    decision = resolve_monitoring_cadence_decision(
        config=MonitoringCadenceConfig(),
        check_id="dependency_chain",
        services=services,
        now=ts(12, 0, 31),
        incidents=[incident],
        base_interval_seconds=600,
    )

    assert decision.accelerated is True
    assert decision.base_interval_seconds == 600
    assert decision.effective_interval_seconds == 30
    assert decision.incident_ids == ["inc-radarr"]
    assert decision.scoped_service_ids == ["svc-delugevpn", "svc-radarr"]


def test_monitoring_cadence_decision_stops_accelerating_after_window() -> None:
    """Acceleration should stop once the bounded incident window expires."""
    services = build_mock_services()
    incident = _build_incident(
        incident_id="inc-radarr",
        affected_services=["svc-radarr"],
        created_at=ts(12, 0, 0),
    )

    decision = resolve_monitoring_cadence_decision(
        config=MonitoringCadenceConfig(),
        check_id="dependency_chain",
        services=services,
        now=ts(12, 15, 1),
        incidents=[incident],
        base_interval_seconds=600,
    )

    assert decision.accelerated is False
    assert decision.effective_interval_seconds == 600
    assert decision.incident_ids == []
    assert decision.scoped_service_ids == []


def test_incident_acceleration_ignores_resolved_incidents() -> None:
    """Resolved incidents should not keep checks in accelerated mode."""
    incident = _build_incident(
        incident_id="inc-radarr",
        affected_services=["svc-radarr"],
        created_at=ts(12, 0, 0),
        status=IncidentStatus.RESOLVED,
        resolved_at=ts(12, 5, 0),
    )

    assert incident_acceleration_active(
        incident=incident,
        now=ts(12, 5, 30),
        policy=IncidentAccelerationPolicy(),
    ) is False


def _build_incident(
    *,
    incident_id: str,
    affected_services: list[str],
    created_at: datetime,
    status: IncidentStatus = IncidentStatus.OPEN,
    resolved_at: datetime | None = None,
) -> Incident:
    """Build a minimal incident suitable for cadence tests."""
    return Incident(
        id=incident_id,
        title="Synthetic cadence incident",
        severity=Severity.HIGH,
        status=status,
        trigger_findings=["find-test"],
        all_findings=["find-test"],
        affected_services=affected_services,
        triggering_symptom="Synthetic cadence coverage.",
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.8,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=created_at,
        grouping_window_end=created_at,
        created_at=created_at,
        updated_at=resolved_at or created_at,
        resolved_at=resolved_at,
        mttr_seconds=None,
        journal_entry_id=None,
    )
