"""Deterministic restart storm monitoring check."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from kaval.discovery.docker import DockerContainerSnapshot
from kaval.models import Evidence, EvidenceKind, Finding, Service, ServiceType, Severity
from kaval.monitoring.checks.base import CheckContext, MonitoringCheck, build_finding


@dataclass(frozen=True, slots=True)
class RestartObservation:
    """One recorded restart-count observation for a container service."""

    container_id: str
    restart_count: int
    observed_at: datetime


class RestartStormCheck(MonitoringCheck):
    """Emit findings when restart counts spike between observations."""

    def __init__(
        self,
        interval_seconds: int = 60,
        *,
        restart_delta_threshold: int = 3,
        window_seconds: int = 300,
    ) -> None:
        """Store the check identity, schedule interval, and restart threshold."""
        if restart_delta_threshold <= 0:
            msg = "restart_delta_threshold must be positive"
            raise ValueError(msg)
        if window_seconds <= 0:
            msg = "window_seconds must be positive"
            raise ValueError(msg)

        self.check_id = "restart_storm"
        self.interval_seconds = interval_seconds
        self._restart_delta_threshold = restart_delta_threshold
        self._window_seconds = window_seconds
        self._observations: dict[str, RestartObservation] = {}

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate restart-count deltas across scheduler observations."""
        if context.docker_snapshot is None:
            return []

        containers_by_id = {
            container.id: container for container in context.docker_snapshot.containers
        }
        active_service_ids: set[str] = set()
        findings: list[Finding] = []
        for service in sorted(context.services, key=lambda service: service.id):
            if service.type != ServiceType.CONTAINER or service.container_id is None:
                continue
            container = containers_by_id.get(service.container_id)
            if container is None:
                continue

            active_service_ids.add(service.id)
            observation = self._observations.get(service.id)
            if observation is not None:
                finding = _finding_for_restart_storm(
                    service=service,
                    container=container,
                    observation=observation,
                    now=context.now,
                    check_id=self.check_id,
                    restart_delta_threshold=self._restart_delta_threshold,
                    window_seconds=self._window_seconds,
                )
                if finding is not None:
                    findings.append(finding)

            self._observations[service.id] = RestartObservation(
                container_id=container.id,
                restart_count=container.restart_count,
                observed_at=context.now,
            )

        stale_service_ids = set(self._observations) - active_service_ids
        for service_id in stale_service_ids:
            del self._observations[service_id]
        return findings


def _finding_for_restart_storm(
    *,
    service: Service,
    container: DockerContainerSnapshot,
    observation: RestartObservation,
    now: datetime,
    check_id: str,
    restart_delta_threshold: int,
    window_seconds: int,
) -> Finding | None:
    """Return a finding when restart counts increase too quickly."""
    if observation.container_id != container.id:
        return None

    elapsed_seconds = int((now - observation.observed_at).total_seconds())
    if elapsed_seconds < 0 or elapsed_seconds > window_seconds:
        return None

    restart_delta = container.restart_count - observation.restart_count
    if restart_delta < restart_delta_threshold:
        return None

    return build_finding(
        check_id=check_id,
        service=service,
        title=f"{service.name} restart storm detected",
        severity=Severity.HIGH,
        summary=(
            f"{service.name} restarted {restart_delta} times in {elapsed_seconds} seconds "
            "according to Docker restart counters."
        ),
        impact=(
            "The service may be crash-looping and dependent services can experience "
            "repeated outages until the underlying fault is resolved."
        ),
        evidence=[
            _docker_restart_evidence(
                container=container,
                observation=observation,
                now=now,
                restart_delta=restart_delta,
                elapsed_seconds=elapsed_seconds,
                window_seconds=window_seconds,
            )
        ],
        now=now,
        confidence=0.98,
    )


def _docker_restart_evidence(
    *,
    container: DockerContainerSnapshot,
    observation: RestartObservation,
    now: datetime,
    restart_delta: int,
    elapsed_seconds: int,
    window_seconds: int,
) -> Evidence:
    """Build the Docker restart-counter evidence payload for a finding."""
    return Evidence(
        kind=EvidenceKind.API,
        source="docker_api",
        summary=(
            f"Docker restart count increased from {observation.restart_count} "
            f"to {container.restart_count} within {elapsed_seconds} seconds"
        ),
        observed_at=now,
        data={
            "container_id": container.id,
            "previous_restart_count": observation.restart_count,
            "current_restart_count": container.restart_count,
            "restart_delta": restart_delta,
            "elapsed_seconds": elapsed_seconds,
            "window_seconds": window_seconds,
            "state": container.state.status,
            "running": container.state.running,
            "restarting": container.state.restarting,
        },
    )
