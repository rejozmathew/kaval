"""Helpers for time-bound maintenance-mode behavior."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from kaval.models import Finding, MaintenanceWindowRecord


def active_maintenance_windows(
    windows: Sequence[MaintenanceWindowRecord],
    *,
    now: datetime,
) -> list[MaintenanceWindowRecord]:
    """Return only maintenance windows that are still active at the given time."""
    return [
        window
        for window in windows
        if window.started_at <= now < window.expires_at
    ]


def maintenance_active_for_service(
    *,
    service_id: str,
    windows: Sequence[MaintenanceWindowRecord],
    now: datetime,
) -> bool:
    """Return whether one service is currently covered by maintenance."""
    return any(
        window.service_id is None or window.service_id == service_id
        for window in active_maintenance_windows(windows, now=now)
    )


def filter_findings_for_maintenance(
    findings: Sequence[Finding],
    *,
    windows: Sequence[MaintenanceWindowRecord],
) -> list[Finding]:
    """Drop findings that fall within an active service or global maintenance window."""
    return [
        finding
        for finding in findings
        if not maintenance_active_for_service(
            service_id=finding.service_id,
            windows=windows,
            now=finding.created_at,
        )
    ]
