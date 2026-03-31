"""Unit tests for the VM health monitoring check."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import (
    build_discovery_snapshot as build_unraid_discovery_snapshot,
)
from kaval.discovery.unraid import decode_graphql_data
from kaval.models import Endpoint, EndpointProtocol, Service, ServiceType, Severity
from kaval.monitoring.checks.base import CheckContext
from kaval.monitoring.checks.endpoint_probe import EndpointProbeResult
from kaval.monitoring.checks.vm_health import VMHealthCheck

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load a JSON fixture for VM health tests."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_vm_health_check_ignores_healthy_vms_without_hosted_endpoints() -> None:
    """Running VMs with no explicit hosted endpoints should not emit findings."""
    unraid_snapshot = _unraid_snapshot()
    services = _services(unraid_snapshot)

    findings = VMHealthCheck().run(
        CheckContext(services=services, unraid_snapshot=unraid_snapshot, now=ts(18, 0))
    )

    assert findings == []


def test_vm_health_check_flags_stopped_vms() -> None:
    """Stopped VMs should emit a high-severity finding."""
    unraid_snapshot = _unraid_snapshot(vm_state="stopped")
    services = _services(unraid_snapshot)

    findings = VMHealthCheck().run(
        CheckContext(services=services, unraid_snapshot=unraid_snapshot, now=ts(18, 5))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-vm-ubuntu"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].title == "Ubuntu Server VM is not running"
    assert findings[0].evidence[0].data["state"] == "stopped"


def test_vm_health_check_flags_paused_vms() -> None:
    """Paused VMs should emit a degraded-state finding."""
    unraid_snapshot = _unraid_snapshot(vm_state="paused")
    services = _services(unraid_snapshot)

    findings = VMHealthCheck().run(
        CheckContext(services=services, unraid_snapshot=unraid_snapshot, now=ts(18, 10))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-vm-ubuntu"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].title == "Ubuntu Server VM is paused"


def test_vm_health_check_probes_explicit_hosted_service_endpoints() -> None:
    """Running VMs should probe explicit hosted HTTP endpoints when present."""
    unraid_snapshot = _unraid_snapshot()
    services = _services(unraid_snapshot)
    vm_service = next(service for service in services if service.type == ServiceType.VM)
    vm_service = vm_service.model_copy(
        update={
            "endpoints": [
                Endpoint(
                    name="app",
                    protocol=EndpointProtocol.HTTP,
                    host="ubuntu-server.internal",
                    port=8123,
                    path="/health",
                    url=None,
                    auth_required=False,
                    expected_status=200,
                )
            ]
        }
    )
    services = [
        vm_service if service.id == vm_service.id else service
        for service in services
    ]

    def fake_probe(url: str, timeout_seconds: float) -> EndpointProbeResult:
        del timeout_seconds
        assert url == "http://ubuntu-server.internal:8123/health"
        return EndpointProbeResult(url=url, status_code=503)

    findings = VMHealthCheck(probe=fake_probe).run(
        CheckContext(services=services, unraid_snapshot=unraid_snapshot, now=ts(18, 15))
    )

    assert len(findings) == 1
    assert findings[0].service_id == "svc-vm-ubuntu"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].title == "Ubuntu Server hosted service returned an unhealthy status"


def _services(unraid_snapshot: object) -> list[Service]:
    """Build typed service nodes for the VM health tests."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot([], {})
    graph = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    )
    return graph.services


def _unraid_snapshot(*, vm_state: str = "running") -> object:
    """Build an Unraid snapshot fixture with one configurable VM state."""
    snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )
    vm = snapshot.vms[0].model_copy(update={"state": vm_state})
    return snapshot.model_copy(update={"vms": [vm]})
