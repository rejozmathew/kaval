"""Deterministic Unraid system monitoring checks."""

from __future__ import annotations

from datetime import datetime

from kaval.discovery.unraid import UnraidDiskSummary, UnraidShareSummary
from kaval.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)
from kaval.monitoring.checks.base import (
    CheckContext,
    MonitoringCheck,
    build_finding,
    service_selected,
)

_HEALTHY_ARRAY_STATES = {"STARTED", "OK"}
_HEALTHY_DISK_STATUSES = {"OK", "VALID"}


class UnraidSystemCheck(MonitoringCheck):
    """Emit findings for degraded Unraid array, disk, and share states."""

    def __init__(
        self,
        interval_seconds: int = 600,
        *,
        warning_share_usage_ratio: float = 0.8,
        critical_share_usage_ratio: float = 0.9,
    ) -> None:
        """Store the check identity, schedule interval, and capacity thresholds."""
        if not 0 < warning_share_usage_ratio <= 1:
            msg = "warning_share_usage_ratio must be between 0 and 1"
            raise ValueError(msg)
        if not 0 < critical_share_usage_ratio <= 1:
            msg = "critical_share_usage_ratio must be between 0 and 1"
            raise ValueError(msg)
        if critical_share_usage_ratio < warning_share_usage_ratio:
            msg = "critical_share_usage_ratio must be >= warning_share_usage_ratio"
            raise ValueError(msg)

        self.check_id = "unraid_system"
        self.interval_seconds = interval_seconds
        self._warning_share_usage_ratio = warning_share_usage_ratio
        self._critical_share_usage_ratio = critical_share_usage_ratio

    def run(self, context: CheckContext) -> list[Finding]:
        """Evaluate the current Unraid snapshot for degraded system conditions."""
        snapshot = context.unraid_snapshot
        if snapshot is None:
            return []

        findings: list[Finding] = []
        system_service = _system_service(context.services, snapshot.system_info.hostname)

        if snapshot.array is not None and snapshot.array.state not in _HEALTHY_ARRAY_STATES:
            if service_selected(context, system_service.id):
                findings.append(
                    _array_state_finding(
                        service=system_service,
                        state=snapshot.array.state,
                        now=context.now,
                        check_id=self.check_id,
                    )
                )

        if snapshot.array is not None:
            for disk in snapshot.array.disks:
                finding = (
                    _disk_health_finding(
                        service=system_service,
                        disk=disk,
                        now=context.now,
                        check_id=self.check_id,
                    )
                    if service_selected(context, system_service.id)
                    else None
                )
                if finding is not None:
                    findings.append(finding)

        for share in snapshot.shares:
            share_service = _share_service(context.services, share.name)
            finding = _share_capacity_finding(
                service=share_service,
                share=share,
                now=context.now,
                check_id=self.check_id,
                warning_share_usage_ratio=self._warning_share_usage_ratio,
                critical_share_usage_ratio=self._critical_share_usage_ratio,
            )
            if finding is not None and service_selected(context, share_service.id):
                findings.append(finding)
        return findings


def _array_state_finding(
    *,
    service: Service,
    state: str | None,
    now: datetime,
    check_id: str,
) -> Finding:
    """Build a finding for a degraded Unraid array state."""
    return build_finding(
        check_id=check_id,
        service=service,
        title="Unraid array is not healthy",
        severity=Severity.HIGH,
        summary=f"Unraid reports array state '{state or 'unknown'}'.",
        impact="Array operations may be degraded and dependent storage services can be affected.",
        evidence=[
            Evidence(
                kind=EvidenceKind.API,
                source="unraid_graphql",
                summary=f"Array state reported as {state or 'unknown'}",
                observed_at=now,
                data={"array_state": state},
            )
        ],
        now=now,
        confidence=0.97,
    )


def _disk_health_finding(
    *,
    service: Service,
    disk: UnraidDiskSummary,
    now: datetime,
    check_id: str,
) -> Finding | None:
    """Build a finding for a degraded Unraid disk status."""
    if disk.status in _HEALTHY_DISK_STATUSES:
        return None

    return build_finding(
        check_id=check_id,
        service=service,
        title=f"Unraid disk {disk.name} reports a degraded status",
        severity=Severity.HIGH,
        summary=(
            f"Disk {disk.name} reports Unraid status '{disk.status or 'unknown'}'."
        ),
        impact=(
            "Storage redundancy or data availability may be at risk until the "
            "disk is remediated."
        ),
        evidence=[
            Evidence(
                kind=EvidenceKind.API,
                source="unraid_graphql",
                summary=f"Disk {disk.name} status reported as {disk.status or 'unknown'}",
                observed_at=now,
                data={
                    "disk_name": disk.name,
                    "status": disk.status,
                    "temperature_c": disk.temp,
                    "size_bytes": disk.size,
                },
            )
        ],
        now=now,
        confidence=0.97,
    )


def _share_capacity_finding(
    *,
    service: Service,
    share: UnraidShareSummary,
    now: datetime,
    check_id: str,
    warning_share_usage_ratio: float,
    critical_share_usage_ratio: float,
) -> Finding | None:
    """Build a finding for a share that is nearing or at capacity."""
    if share.used_bytes is None or share.total_bytes in {None, 0}:
        return None

    used_bytes = share.used_bytes
    total_bytes = share.total_bytes
    assert total_bytes is not None
    usage_ratio = used_bytes / total_bytes
    if usage_ratio < warning_share_usage_ratio:
        return None

    severity = (
        Severity.HIGH
        if usage_ratio >= critical_share_usage_ratio
        else Severity.MEDIUM
    )
    return build_finding(
        check_id=check_id,
        service=service,
        title=f"Unraid share {share.name} is nearing capacity",
        severity=severity,
        summary=(
            f"Share {share.name} is using {usage_ratio * 100:.1f}% of its reported capacity."
        ),
        impact="Writes to this share may fail soon and dependent services can degrade.",
        evidence=[
            Evidence(
                kind=EvidenceKind.API,
                source="unraid_graphql",
                summary=f"Share {share.name} capacity usage is {usage_ratio * 100:.1f}%",
                observed_at=now,
                data={
                    "share_name": share.name,
                    "used_bytes": share.used_bytes,
                    "free_bytes": share.free_bytes,
                    "total_bytes": share.total_bytes,
                    "usage_ratio": round(usage_ratio, 4),
                    "primary_storage": share.primary_storage,
                    "secondary_storage": share.secondary_storage,
                },
            )
        ],
        now=now,
        confidence=0.95,
    )


def _system_service(services: list[Service], hostname: str | None) -> Service:
    """Return the existing or synthetic Unraid system service node."""
    for service in services:
        if service.type == ServiceType.SYSTEM:
            return service
    return Service(
        id="svc-system-unraid",
        name=hostname or "Unraid",
        type=ServiceType.SYSTEM,
        category="system",
        status=ServiceStatus.UNKNOWN,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def _share_service(services: list[Service], share_name: str) -> Service:
    """Return the existing or synthetic share service node for a named share."""
    normalized_name = share_name.lower()
    for service in services:
        if service.type == ServiceType.SHARE and service.name.lower() == normalized_name:
            return service
    return Service(
        id=f"svc-share-{normalized_name.replace(' ', '-')}",
        name=share_name,
        type=ServiceType.SHARE,
        category="storage",
        status=ServiceStatus.UNKNOWN,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
