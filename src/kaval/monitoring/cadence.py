"""Typed monitoring-cadence contracts and scheduler helpers."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Literal, Self

from pydantic import Field, model_validator

from kaval.models import Incident, IncidentStatus, KavalModel, Service


class MonitoringCheckCadenceRule(KavalModel):
    """One named cadence rule for a monitoring check type."""

    check_id: str = Field(min_length=1)
    enabled: bool = True
    interval_seconds: int = Field(ge=1)
    rationale: str | None = None


class ServiceMonitoringCadenceOverride(KavalModel):
    """One per-service cadence override for a monitoring check."""

    service_id: str = Field(min_length=1)
    check_id: str = Field(min_length=1)
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_override(self) -> ServiceMonitoringCadenceOverride:
        """Require at least one explicit service-level override."""
        if self.enabled is None and self.interval_seconds is None:
            msg = "service cadence override requires enabled or interval_seconds"
            raise ValueError(msg)
        return self


class IncidentAccelerationPolicy(KavalModel):
    """Bounded scheduler acceleration for active incidents."""

    enabled: bool = True
    accelerated_interval_seconds: int = Field(default=30, ge=1)
    window_seconds: int = Field(default=900, ge=1)


class MonitoringCadenceConfig(KavalModel):
    """Global cadence defaults plus optional override layers."""

    global_defaults: list[MonitoringCheckCadenceRule] = Field(
        default_factory=lambda: list(default_monitoring_check_cadences())
    )
    check_overrides: list[MonitoringCheckCadenceRule] = Field(default_factory=list)
    service_overrides: list[ServiceMonitoringCadenceOverride] = Field(default_factory=list)
    incident_acceleration: IncidentAccelerationPolicy = Field(
        default_factory=IncidentAccelerationPolicy
    )

    @model_validator(mode="after")
    def validate_uniqueness(self) -> Self:
        """Reject duplicate override keys that would make resolution ambiguous."""
        _ensure_unique_check_rules(self.global_defaults, label="global_defaults")
        _ensure_unique_check_rules(self.check_overrides, label="check_overrides")
        seen_service_keys: set[tuple[str, str]] = set()
        for override in self.service_overrides:
            key = (override.service_id, override.check_id)
            if key in seen_service_keys:
                msg = (
                    "service_overrides must not contain duplicate "
                    f"(service_id, check_id) pairs: {override.service_id}/{override.check_id}"
                )
                raise ValueError(msg)
            seen_service_keys.add(key)
        return self


class MonitoringCadenceDecision(KavalModel):
    """Resolved cadence for one scheduler decision point."""

    check_id: str = Field(min_length=1)
    enabled: bool = True
    base_interval_seconds: int = Field(ge=1)
    effective_interval_seconds: int = Field(ge=1)
    accelerated: bool = False
    incident_ids: list[str] = Field(default_factory=list)
    scoped_service_ids: list[str] = Field(default_factory=list)


class MonitoringCheckExecution(KavalModel):
    """Resolved enabled-state and interval for one check scope."""

    check_id: str = Field(min_length=1)
    enabled: bool
    interval_seconds: int = Field(ge=1)
    source: Literal["global_default", "check_override", "service_override"]


_DEFAULT_MONITORING_CHECK_CADENCES: tuple[MonitoringCheckCadenceRule, ...] = (
    MonitoringCheckCadenceRule(
        check_id="container_health",
        interval_seconds=60,
        rationale="Fast detection of crashes and unhealthy container states.",
    ),
    MonitoringCheckCadenceRule(
        check_id="restart_storm",
        interval_seconds=60,
        rationale="Restart spikes should be detected as quickly as container outages.",
    ),
    MonitoringCheckCadenceRule(
        check_id="endpoint_probe",
        interval_seconds=120,
        rationale="Balance responsiveness with target load for repeated probes.",
    ),
    MonitoringCheckCadenceRule(
        check_id="vm_health",
        interval_seconds=120,
        rationale="Track VM state and hosted-service reachability without probe spam.",
    ),
    MonitoringCheckCadenceRule(
        check_id="tls_cert",
        interval_seconds=21600,
        rationale="Certificates change slowly; periodic expiry checks are sufficient.",
    ),
    MonitoringCheckCadenceRule(
        check_id="dns_resolution",
        interval_seconds=300,
        rationale="DNS changes are infrequent but impactful when they do occur.",
    ),
    MonitoringCheckCadenceRule(
        check_id="log_pattern",
        interval_seconds=300,
        rationale="Keep log signal freshness without re-reading logs every minute.",
    ),
    MonitoringCheckCadenceRule(
        check_id="change_detection",
        interval_seconds=300,
        rationale="Image/config change polling can run slower than health checks.",
    ),
    MonitoringCheckCadenceRule(
        check_id="unraid_system",
        interval_seconds=600,
        rationale="Array, disk, and cache state typically change on a slower cadence.",
    ),
    MonitoringCheckCadenceRule(
        check_id="dependency_chain",
        interval_seconds=600,
        rationale="Dependency validation is derived from other service-state signals.",
    ),
    MonitoringCheckCadenceRule(
        check_id="plugin_health",
        interval_seconds=3600,
        rationale="Plugin-state checks are low-churn and can run infrequently.",
    ),
)


def default_monitoring_check_cadences() -> tuple[MonitoringCheckCadenceRule, ...]:
    """Return the canonical built-in monitoring cadence defaults."""
    return _DEFAULT_MONITORING_CHECK_CADENCES


def default_monitoring_cadence_config() -> MonitoringCadenceConfig:
    """Build the default cadence configuration used by the scheduler."""
    return MonitoringCadenceConfig()


def resolve_check_interval(
    *,
    config: MonitoringCadenceConfig,
    check_id: str,
    base_interval_seconds: int | None = None,
) -> int:
    """Resolve the effective non-service-specific interval for one check."""
    return resolve_check_execution(
        config=config,
        check_id=check_id,
        base_interval_seconds=base_interval_seconds,
    ).interval_seconds


def resolve_service_check_interval(
    *,
    config: MonitoringCadenceConfig,
    service_id: str,
    check_id: str,
    base_interval_seconds: int | None = None,
) -> int:
    """Resolve the interval for one service-specific check execution."""
    return resolve_service_check_execution(
        config=config,
        service_id=service_id,
        check_id=check_id,
        base_interval_seconds=base_interval_seconds,
    ).interval_seconds


def resolve_check_execution(
    *,
    config: MonitoringCadenceConfig,
    check_id: str,
    base_interval_seconds: int | None = None,
    base_enabled: bool = True,
) -> MonitoringCheckExecution:
    """Resolve the enabled-state and interval for one check."""
    override = _check_rule(config.check_overrides, check_id=check_id)
    if override is not None:
        return MonitoringCheckExecution(
            check_id=check_id,
            enabled=override.enabled,
            interval_seconds=override.interval_seconds,
            source="check_override",
        )
    default_rule = _check_rule(config.global_defaults, check_id=check_id)
    if default_rule is not None:
        return MonitoringCheckExecution(
            check_id=check_id,
            enabled=default_rule.enabled,
            interval_seconds=default_rule.interval_seconds,
            source="global_default",
        )
    if base_interval_seconds is not None:
        return MonitoringCheckExecution(
            check_id=check_id,
            enabled=base_enabled,
            interval_seconds=base_interval_seconds,
            source="global_default",
        )
    msg = f"no cadence rule found for check_id={check_id!r}"
    raise ValueError(msg)


def resolve_service_check_execution(
    *,
    config: MonitoringCadenceConfig,
    service_id: str,
    check_id: str,
    base_interval_seconds: int | None = None,
    base_enabled: bool = True,
) -> MonitoringCheckExecution:
    """Resolve the enabled-state and interval for one service-specific check."""
    override = _service_rule(
        config.service_overrides,
        service_id=service_id,
        check_id=check_id,
    )
    if override is not None:
        parent = resolve_check_execution(
            config=config,
            check_id=check_id,
            base_interval_seconds=base_interval_seconds,
            base_enabled=base_enabled,
        )
        return MonitoringCheckExecution(
            check_id=check_id,
            enabled=parent.enabled if override.enabled is None else override.enabled,
            interval_seconds=(
                parent.interval_seconds
                if override.interval_seconds is None
                else override.interval_seconds
            ),
            source="service_override",
        )
    return resolve_check_execution(
        config=config,
        check_id=check_id,
        base_interval_seconds=base_interval_seconds,
        base_enabled=base_enabled,
    )


def incident_service_scope(
    *,
    incident: Incident,
    services: list[Service],
) -> list[str]:
    """Return the affected-service scope plus upstream dependencies for an incident."""
    services_by_id = {service.id: service for service in services}
    visited = set(incident.affected_services)
    queue: deque[str] = deque(incident.affected_services)

    while queue:
        service_id = queue.popleft()
        service = services_by_id.get(service_id)
        if service is None:
            continue
        for edge in service.dependencies:
            if edge.target_service_id in visited:
                continue
            visited.add(edge.target_service_id)
            queue.append(edge.target_service_id)

    return sorted(visited)


def resolve_monitoring_cadence_decision(
    *,
    config: MonitoringCadenceConfig,
    check_id: str,
    services: list[Service],
    now: datetime,
    incidents: list[Incident],
    base_interval_seconds: int,
) -> MonitoringCadenceDecision:
    """Resolve the scheduler cadence for one check at one point in time."""
    execution = resolve_check_execution(
        config=config,
        check_id=check_id,
        base_interval_seconds=base_interval_seconds,
    )
    base_interval = execution.interval_seconds
    applicable_incident_ids: list[str] = []
    scoped_service_ids: set[str] = set()
    current_service_ids = {service.id for service in services}

    for incident in incidents:
        if not incident_acceleration_active(
            incident=incident,
            now=now,
            policy=config.incident_acceleration,
        ):
            continue
        scope_ids = set(incident_service_scope(incident=incident, services=services))
        matching_service_ids = current_service_ids & scope_ids
        if not matching_service_ids:
            continue
        applicable_incident_ids.append(incident.id)
        scoped_service_ids.update(matching_service_ids)

    effective_interval = base_interval
    accelerated = bool(applicable_incident_ids)
    if accelerated:
        effective_interval = min(
            base_interval,
            config.incident_acceleration.accelerated_interval_seconds,
        )

    return MonitoringCadenceDecision(
        check_id=check_id,
        enabled=execution.enabled,
        base_interval_seconds=base_interval,
        effective_interval_seconds=effective_interval,
        accelerated=accelerated,
        incident_ids=applicable_incident_ids,
        scoped_service_ids=sorted(scoped_service_ids),
    )


def incident_acceleration_active(
    *,
    incident: Incident,
    now: datetime,
    policy: IncidentAccelerationPolicy,
) -> bool:
    """Return whether one incident should still accelerate related checks."""
    if not policy.enabled:
        return False
    if incident.status in {IncidentStatus.RESOLVED, IncidentStatus.DISMISSED}:
        return False
    window_expires_at = incident.created_at + timedelta(seconds=policy.window_seconds)
    return now < window_expires_at


def _check_rule(
    rules: list[MonitoringCheckCadenceRule] | tuple[MonitoringCheckCadenceRule, ...],
    *,
    check_id: str,
) -> MonitoringCheckCadenceRule | None:
    """Return the first cadence rule for one check ID, if any."""
    for rule in rules:
        if rule.check_id == check_id:
            return rule
    return None


def _service_rule(
    rules: list[ServiceMonitoringCadenceOverride],
    *,
    service_id: str,
    check_id: str,
) -> ServiceMonitoringCadenceOverride | None:
    """Return the first matching service-specific cadence override, if any."""
    for rule in rules:
        if rule.service_id == service_id and rule.check_id == check_id:
            return rule
    return None


def _ensure_unique_check_rules(
    rules: list[MonitoringCheckCadenceRule] | tuple[MonitoringCheckCadenceRule, ...],
    *,
    label: str,
) -> None:
    """Reject duplicate check IDs within one cadence rule list."""
    seen_check_ids: set[str] = set()
    for rule in rules:
        if rule.check_id in seen_check_ids:
            msg = f"{label} must not contain duplicate check_id values: {rule.check_id}"
            raise ValueError(msg)
        seen_check_ids.add(rule.check_id)
