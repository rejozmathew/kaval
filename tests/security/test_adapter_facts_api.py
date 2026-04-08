"""Security-focused tests for the adapter-facts read API."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.integrations import (
    AdapterRegistry,
    AdapterResult,
    AdapterStatus,
    AdapterSurfaceBinding,
)
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType

api_app_module = importlib.import_module("kaval.api.app")


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for adapter-facts security tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_adapter_facts_endpoint_redacts_secret_like_fields_without_echoing_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Adapter facts must stay prompt-safe and never reflect secret values."""
    monkeypatch.setattr(
        api_app_module,
        "_DEFAULT_ADAPTER_REGISTRY",
        AdapterRegistry(
            [
                StubSensitiveRadarrAdapter(
                    AdapterResult(
                        adapter_id="radarr_api",
                        status=AdapterStatus.SUCCESS,
                        facts={
                            "runtime_info": {"version": "5.0.3"},
                            "session": {"token": "nested-adapter-secret"},
                            "api_key": "top-level-adapter-secret",
                        },
                        edges_discovered=[],
                        timestamp=ts(14, 10),
                        reason=None,
                    )
                )
            ]
        ),
    )
    database_path = tmp_path / "kaval.db"
    seed_radarr_service(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        configure_vault_adapter_credential(client)
        response = client.get("/api/v1/services/svc-radarr/adapter-facts")

    assert response.status_code == 200
    payload = response.json()
    adapter_payload = payload["adapters"][0]
    assert adapter_payload["facts"] == {"runtime_info": {"version": "5.0.3"}}
    assert sorted(adapter_payload["excluded_paths"]) == ["api_key", "session"]
    assert "nested-adapter-secret" not in response.text
    assert "top-level-adapter-secret" not in response.text
    assert "radarr-vault-secret" not in response.text


class StubSensitiveRadarrAdapter:
    """Protocol-compatible adapter stub that returns secret-like fact fields."""

    adapter_id = "radarr_api"
    surface_bindings = (
        AdapterSurfaceBinding(descriptor_id="arr/radarr", surface_id="health_api"),
    )
    credential_keys = ("api_key",)
    supported_versions = ">=3.0"
    read_only = True

    def __init__(self, result: AdapterResult) -> None:
        """Store the deterministic adapter result to replay."""
        self._result = result

    async def inspect(
        self,
        service: Service,
        credentials: Mapping[str, str],
    ) -> AdapterResult:
        """Return the prebuilt result without performing network I/O."""
        del service, credentials
        return self._result.model_copy(deep=True)


def seed_radarr_service(database_path: Path) -> None:
    """Persist one descriptor-backed Radarr service for adapter-facts tests."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            Service(
                id="svc-radarr",
                name="Radarr",
                type=ServiceType.CONTAINER,
                category="arr",
                status=ServiceStatus.DEGRADED,
                descriptor_id="arr/radarr",
                descriptor_source=DescriptorSource.SHIPPED,
                container_id="container-radarr",
                vm_id=None,
                image="lscr.io/linuxserver/radarr:latest",
                endpoints=[],
                dns_targets=[],
                dependencies=[],
                dependents=[],
                last_check=ts(12, 1),
                active_findings=1,
                active_incidents=1,
            )
        )
    finally:
        database.close()


def configure_vault_adapter_credential(client: TestClient) -> None:
    """Store one Radarr API key through the existing credential flow."""
    create_response = client.post(
        "/api/v1/credential-requests",
        json={
            "incident_id": "inc-1",
            "investigation_id": "inv-1",
            "service_id": "svc-radarr",
            "credential_key": "api_key",
            "reason": "Need adapter facts.",
        },
    )
    request_id = create_response.json()["id"]
    client.post(
        f"/api/v1/credential-requests/{request_id}/choice",
        json={
            "mode": "vault",
            "decided_by": "security_test",
        },
    )
    client.post(
        "/api/v1/vault/unlock",
        json={"master_passphrase": "correct horse battery staple"},
    )
    client.post(
        f"/api/v1/credential-requests/{request_id}/submit",
        json={
            "secret_value": "radarr-vault-secret",
            "submitted_by": "security_test",
        },
    )
