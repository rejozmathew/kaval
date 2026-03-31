"""Phase 1 read-only command-line interface."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from kaval.database import KavalDatabase
from kaval.models import Finding, FindingStatus, Incident, IncidentStatus, Service, ServiceStatus

_ACTIVE_FINDING_STATUSES = {
    FindingStatus.NEW,
    FindingStatus.GROUPED,
    FindingStatus.INVESTIGATING,
}
_ACTIVE_INCIDENT_STATUSES = {
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.REMEDIATING,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the Phase 1 CLI parser."""
    parser = argparse.ArgumentParser(prog="kaval", description="Kaval Phase 1 CLI")
    parser.add_argument(
        "--database",
        default=os.environ.get("KAVAL_DATABASE_PATH", "/data/kaval.db"),
        help="SQLite database path.",
    )
    parser.add_argument(
        "--migrations-dir",
        default=os.environ.get("KAVAL_MIGRATIONS_DIR"),
        help="Optional migrations directory override.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Show the current monitoring summary.")
    subparsers.add_parser("findings", help="List persisted findings.")
    subparsers.add_parser("incidents", help="List persisted incidents.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Phase 1 CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    database = KavalDatabase(
        path=Path(args.database),
        migrations_dir=Path(args.migrations_dir) if args.migrations_dir else None,
    )
    database.bootstrap()
    try:
        if args.command == "status":
            _print_status(database)
        elif args.command == "findings":
            _print_findings(database.list_findings())
        else:
            _print_incidents(database.list_incidents())
    finally:
        database.close()
    return 0


def _print_status(database: KavalDatabase) -> None:
    """Render the top-level monitoring summary."""
    services = database.list_services()
    findings = database.list_findings()
    incidents = database.list_incidents()
    system_profile = database.get_system_profile()
    active_finding_count = sum(
        1 for finding in findings if finding.status in _ACTIVE_FINDING_STATUSES
    )
    active_incident_count = sum(
        1 for incident in incidents if incident.status in _ACTIVE_INCIDENT_STATUSES
    )

    print(f"Services: {len(services)} total")
    print(
        "Service states: "
        f"{_count_services(services, ServiceStatus.HEALTHY)} healthy, "
        f"{_count_services(services, ServiceStatus.DEGRADED)} degraded, "
        f"{_count_services(services, ServiceStatus.DOWN)} down, "
        f"{_count_services(services, ServiceStatus.STOPPED)} stopped, "
        f"{_count_services(services, ServiceStatus.UNKNOWN)} unknown"
    )
    print(
        "Findings: "
        f"{active_finding_count} active / {len(findings)} total"
    )
    print(
        "Incidents: "
        f"{active_incident_count} active / {len(incidents)} total"
    )
    if system_profile is not None:
        print(
            "System profile: "
            f"{system_profile.hostname} (Unraid {system_profile.unraid_version})"
        )


def _print_findings(findings: Sequence[Finding]) -> None:
    """Render findings in reverse chronological order."""
    if not findings:
        print("No findings.")
        return

    for finding in sorted(
        findings,
        key=lambda finding: (finding.created_at, finding.id),
        reverse=True,
    ):
        print(
            f"{finding.id} "
            f"[{finding.severity.value}/{finding.status.value}] "
            f"{finding.service_id}: {finding.title}"
        )


def _print_incidents(incidents: Sequence[Incident]) -> None:
    """Render incidents in reverse update order."""
    if not incidents:
        print("No incidents.")
        return

    for incident in sorted(
        incidents,
        key=lambda incident: (incident.updated_at, incident.id),
        reverse=True,
    ):
        print(
            f"{incident.id} "
            f"[{incident.severity.value}/{incident.status.value}] "
            f"{incident.title}"
        )


def _count_services(services: Sequence[Service], status: ServiceStatus) -> int:
    """Count services in one specific health state."""
    return sum(1 for service in services if service.status == status)
