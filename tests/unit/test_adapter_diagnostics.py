"""Unit tests for adapter self-diagnostic checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Mapping

from kaval.integrations import (
    AdapterDiagnosticCheck,
    AdapterDiagnosticOutcome,
    AdapterDiagnosticStatus,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
    run_adapter_diagnostic,
)
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for diagnostic tests."""
    return datetime(2026, 4, 3, hour, minute, tzinfo=UTC)


def build_service() -> Service:
    """Create a representative descriptor-backed service."""
    return Service(
        id="svc-radarr",
        name="Radarr",
        type=ServiceType.CONTAINER,
        category="arr",
        status=ServiceStatus.HEALTHY,
        descriptor_id="arr/radarr",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-radarr",
        vm_id=None,
        image="lscr.io/linuxserver/radarr:latest",
        endpoints=[],
        dependencies=[],
        dependents=[],
        last_check=ts(12),
        active_findings=0,
        active_incidents=0,
    )


class FakeAdapter:
    """Simple structural adapter double used by diagnostic tests."""

    def __init__(
        self,
        *,
        result: AdapterResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.adapter_id = "radarr_api"
        self.surface_bindings = (
            AdapterSurfaceBinding(
                descriptor_id="arr/radarr",
                surface_id="health_api",
            ),
        )
        self.credential_keys = ("api_key",)
        self.supported_versions = ">=3.0"
        self.read_only = True
        self._result = result
        self._error = error

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Return the configured result or raise the configured error."""
        del service, credentials
        if self._error is not None:
            raise self._error
        if self._result is None:
            raise AssertionError("test adapter requires result or error")
        return self._result


def check_outcomes(result: object) -> dict[str, str]:
    """Map diagnostic checks to their outcome values."""
    diagnostic = result
    assert hasattr(diagnostic, "checks")
    return {
        check.check.value: check.outcome.value
        for check in diagnostic.checks
    }


def test_run_adapter_diagnostic_reports_healthy_results() -> None:
    """Successful adapter execution should produce a healthy diagnostic."""
    adapter = FakeAdapter(
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.SUCCESS,
            facts={"health_issues": []},
            edges_discovered=[],
            timestamp=ts(13),
            reason=None,
        )
    )

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "secret"},
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.HEALTHY
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.PASS.value,
    }


def test_run_adapter_diagnostic_reports_auth_failed_results() -> None:
    """Authentication failures should map to auth_failed diagnostics."""
    adapter = FakeAdapter(
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.AUTH_FAILED,
            timestamp=ts(13, 5),
            reason="API key rejected",
        )
    )

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "wrong"},
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.AUTH_FAILED
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.FAIL.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.UNKNOWN.value,
    }


def test_run_adapter_diagnostic_reports_connection_failed_results() -> None:
    """Connection failures should map to connection_failed diagnostics."""
    adapter = FakeAdapter(
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.CONNECTION_FAILED,
            timestamp=ts(13, 10),
            reason="connection refused",
        )
    )

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "secret"},
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.CONNECTION_FAILED
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.FAIL.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.UNKNOWN.value,
    }


def test_run_adapter_diagnostic_reports_parse_error_results() -> None:
    """Parse failures should map to schema-failed diagnostics."""
    adapter = FakeAdapter(
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.PARSE_ERROR,
            timestamp=ts(13, 15),
            reason="unexpected response shape",
        )
    )

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "secret"},
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.PARSE_ERROR
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.FAIL.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.UNKNOWN.value,
    }


def test_run_adapter_diagnostic_reports_version_incompatible_results() -> None:
    """Version failures should map to version_incompatible diagnostics."""
    adapter = FakeAdapter(
        result=AdapterResult(
            adapter_id="radarr_api",
            status=AdapterStatus.VERSION_INCOMPATIBLE,
            timestamp=ts(13, 20),
            reason="unsupported version 2.0.0",
        )
    )

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "secret"},
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.VERSION_INCOMPATIBLE
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.PASS.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.FAIL.value,
    }


def test_run_adapter_diagnostic_reports_degraded_results_on_exception() -> None:
    """Unexpected adapter exceptions should degrade cleanly instead of raising."""
    adapter = FakeAdapter(error=RuntimeError("request timed out"))

    diagnostic = asyncio.run(
        run_adapter_diagnostic(
            adapter,
            service=build_service(),
            credentials={"api_key": "secret"},
            now=ts(13, 25),
        )
    )

    assert diagnostic.status == AdapterDiagnosticStatus.DEGRADED
    assert diagnostic.reason == "request timed out"
    assert check_outcomes(diagnostic) == {
        AdapterDiagnosticCheck.CONNECTION.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.AUTH.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.SCHEMA.value: AdapterDiagnosticOutcome.UNKNOWN.value,
        AdapterDiagnosticCheck.VERSION.value: AdapterDiagnosticOutcome.UNKNOWN.value,
    }
