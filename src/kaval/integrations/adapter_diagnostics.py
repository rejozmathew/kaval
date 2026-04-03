"""Typed self-diagnostic helpers for deep-inspection adapters."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum

from pydantic import Field

from kaval.integrations.service_adapters import (
    AdapterResult,
    AdapterStatus,
    ServiceAdapter,
    execute_service_adapter,
)
from kaval.models import KavalModel, Service


class AdapterDiagnosticStatus(StrEnum):
    """High-level diagnostic statuses exposed by adapter self-checks."""

    HEALTHY = "healthy"
    AUTH_FAILED = "auth_failed"
    CONNECTION_FAILED = "connection_failed"
    VERSION_INCOMPATIBLE = "version_incompatible"
    PARSE_ERROR = "parse_error"
    DEGRADED = "degraded"


class AdapterDiagnosticCheck(StrEnum):
    """Named self-diagnostic checks performed for one adapter."""

    CONNECTION = "connection"
    AUTH = "auth"
    SCHEMA = "schema"
    VERSION = "version"


class AdapterDiagnosticOutcome(StrEnum):
    """Per-check outcomes for adapter self-diagnostics."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class AdapterDiagnosticCheckResult(KavalModel):
    """One check result within an adapter self-diagnostic run."""

    check: AdapterDiagnosticCheck
    outcome: AdapterDiagnosticOutcome
    detail: str | None = None


class AdapterDiagnosticResult(KavalModel):
    """Typed diagnostic output derived from one adapter execution attempt."""

    adapter_id: str = Field(min_length=1)
    status: AdapterDiagnosticStatus
    checks: list[AdapterDiagnosticCheckResult]
    checked_at: datetime
    reason: str | None = None


async def run_adapter_diagnostic(
    adapter: ServiceAdapter,
    *,
    service: Service,
    credentials: Mapping[str, str],
    now: datetime | None = None,
) -> AdapterDiagnosticResult:
    """Execute one adapter and normalize the outcome into diagnostic checks."""
    adapter_result = await execute_service_adapter(
        adapter,
        service=service,
        credentials=credentials,
        now=now,
    )
    return build_adapter_diagnostic_result(adapter=adapter, adapter_result=adapter_result)


def build_adapter_diagnostic_result(
    *,
    adapter: ServiceAdapter,
    adapter_result: AdapterResult,
) -> AdapterDiagnosticResult:
    """Convert one adapter execution result into a typed diagnostic result."""
    status = _diagnostic_status(adapter_result.status)
    return AdapterDiagnosticResult(
        adapter_id=adapter.adapter_id,
        status=status,
        checks=_diagnostic_checks(adapter=adapter, adapter_result=adapter_result),
        checked_at=adapter_result.timestamp,
        reason=adapter_result.reason,
    )


def _diagnostic_status(status: AdapterStatus) -> AdapterDiagnosticStatus:
    """Map an adapter execution status to its diagnostic equivalent."""
    return {
        AdapterStatus.SUCCESS: AdapterDiagnosticStatus.HEALTHY,
        AdapterStatus.AUTH_FAILED: AdapterDiagnosticStatus.AUTH_FAILED,
        AdapterStatus.CONNECTION_FAILED: AdapterDiagnosticStatus.CONNECTION_FAILED,
        AdapterStatus.VERSION_INCOMPATIBLE: AdapterDiagnosticStatus.VERSION_INCOMPATIBLE,
        AdapterStatus.PARSE_ERROR: AdapterDiagnosticStatus.PARSE_ERROR,
        AdapterStatus.DEGRADED: AdapterDiagnosticStatus.DEGRADED,
    }[status]


def _diagnostic_checks(
    *,
    adapter: ServiceAdapter,
    adapter_result: AdapterResult,
) -> list[AdapterDiagnosticCheckResult]:
    """Build per-check diagnostic results from one adapter execution outcome."""
    if adapter_result.status == AdapterStatus.SUCCESS:
        return [
            _check_result(
                AdapterDiagnosticCheck.CONNECTION,
                AdapterDiagnosticOutcome.PASS,
                "Adapter request completed successfully.",
            ),
            _auth_success_check(adapter),
            _check_result(
                AdapterDiagnosticCheck.SCHEMA,
                AdapterDiagnosticOutcome.PASS,
                "Adapter returned structured facts successfully.",
            ),
            _version_success_check(adapter),
        ]
    if adapter_result.status == AdapterStatus.AUTH_FAILED:
        return [
            _check_result(
                AdapterDiagnosticCheck.CONNECTION,
                AdapterDiagnosticOutcome.PASS,
                "Adapter reached the target service.",
            ),
            _check_result(
                AdapterDiagnosticCheck.AUTH,
                AdapterDiagnosticOutcome.FAIL,
                adapter_result.reason,
            ),
            _check_result(
                AdapterDiagnosticCheck.SCHEMA,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Schema validation was not reached because authentication failed.",
            ),
            _check_result(
                AdapterDiagnosticCheck.VERSION,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Version validation was not reached because authentication failed.",
            ),
        ]
    if adapter_result.status == AdapterStatus.CONNECTION_FAILED:
        return [
            _check_result(
                AdapterDiagnosticCheck.CONNECTION,
                AdapterDiagnosticOutcome.FAIL,
                adapter_result.reason,
            ),
            _check_result(
                AdapterDiagnosticCheck.AUTH,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Authentication was not attempted because the connection failed.",
            ),
            _check_result(
                AdapterDiagnosticCheck.SCHEMA,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Schema validation was not attempted because the connection failed.",
            ),
            _check_result(
                AdapterDiagnosticCheck.VERSION,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Version validation was not attempted because the connection failed.",
            ),
        ]
    if adapter_result.status == AdapterStatus.PARSE_ERROR:
        return [
            _check_result(
                AdapterDiagnosticCheck.CONNECTION,
                AdapterDiagnosticOutcome.PASS,
                "Adapter reached the target service.",
            ),
            _auth_success_check(adapter),
            _check_result(
                AdapterDiagnosticCheck.SCHEMA,
                AdapterDiagnosticOutcome.FAIL,
                adapter_result.reason,
            ),
            _check_result(
                AdapterDiagnosticCheck.VERSION,
                AdapterDiagnosticOutcome.UNKNOWN,
                "Version validation did not complete because parsing failed first.",
            ),
        ]
    if adapter_result.status == AdapterStatus.VERSION_INCOMPATIBLE:
        return [
            _check_result(
                AdapterDiagnosticCheck.CONNECTION,
                AdapterDiagnosticOutcome.PASS,
                "Adapter reached the target service.",
            ),
            _auth_success_check(adapter),
            _check_result(
                AdapterDiagnosticCheck.SCHEMA,
                AdapterDiagnosticOutcome.PASS,
                "Adapter returned enough structured data to evaluate version support.",
            ),
            _check_result(
                AdapterDiagnosticCheck.VERSION,
                AdapterDiagnosticOutcome.FAIL,
                adapter_result.reason,
            ),
        ]
    return [
        _check_result(
            AdapterDiagnosticCheck.CONNECTION,
            AdapterDiagnosticOutcome.UNKNOWN,
            "The adapter degraded before a diagnostic conclusion was reached.",
        ),
        _check_result(
            AdapterDiagnosticCheck.AUTH,
            AdapterDiagnosticOutcome.UNKNOWN,
            "The adapter degraded before a diagnostic conclusion was reached.",
        ),
        _check_result(
            AdapterDiagnosticCheck.SCHEMA,
            AdapterDiagnosticOutcome.UNKNOWN,
            "The adapter degraded before a diagnostic conclusion was reached.",
        ),
        _check_result(
            AdapterDiagnosticCheck.VERSION,
            AdapterDiagnosticOutcome.UNKNOWN,
            "The adapter degraded before a diagnostic conclusion was reached.",
        ),
    ]


def _auth_success_check(adapter: ServiceAdapter) -> AdapterDiagnosticCheckResult:
    """Return the auth-check result for a successful service adapter execution."""
    if adapter.credential_keys:
        return _check_result(
            AdapterDiagnosticCheck.AUTH,
            AdapterDiagnosticOutcome.PASS,
            "Adapter credentials were accepted.",
        )
    return _check_result(
        AdapterDiagnosticCheck.AUTH,
        AdapterDiagnosticOutcome.UNKNOWN,
        "Adapter does not declare required credentials.",
    )


def _version_success_check(adapter: ServiceAdapter) -> AdapterDiagnosticCheckResult:
    """Return the version-check result for a successful service adapter execution."""
    if adapter.supported_versions:
        return _check_result(
            AdapterDiagnosticCheck.VERSION,
            AdapterDiagnosticOutcome.PASS,
            f"Adapter supports the declared version range {adapter.supported_versions}.",
        )
    return _check_result(
        AdapterDiagnosticCheck.VERSION,
        AdapterDiagnosticOutcome.UNKNOWN,
        "Adapter does not declare a supported version range.",
    )


def _check_result(
    check: AdapterDiagnosticCheck,
    outcome: AdapterDiagnosticOutcome,
    detail: str | None,
) -> AdapterDiagnosticCheckResult:
    """Build one diagnostic check result."""
    return AdapterDiagnosticCheckResult(
        check=check,
        outcome=outcome,
        detail=detail,
    )
