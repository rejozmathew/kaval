"""Integration tests for the adapter-imported facts read API."""

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
    """Build a deterministic UTC timestamp for adapter-facts tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


class FrozenDateTime(datetime):
    """Deterministic datetime shim for adapter-facts endpoint tests."""

    @classmethod
    def now(cls, tz: object | None = None) -> datetime:
        """Return a fixed current time for endpoint freshness calculations."""
        frozen = ts(14, 30)
        if tz is None:
            return frozen.replace(tzinfo=None)
        return frozen.astimezone(tz)


def test_adapter_facts_endpoint_returns_redacted_fresh_facts_for_configured_adapter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Configured adapters should return prompt-safe facts with freshness metadata."""
    monkeypatch.setattr(api_app_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        api_app_module,
        "_DEFAULT_ADAPTER_REGISTRY",
        AdapterRegistry(
            [
                StubRadarrFactsAdapter(
                    AdapterResult(
                        adapter_id="radarr_api",
                        status=AdapterStatus.SUCCESS,
                        facts={
                            "health_issues": [
                                {
                                    "type": "error",
                                    "message": "Download client unavailable",
                                }
                            ],
                            "download_client_status": {
                                "available": False,
                                "configured_count": 1,
                            },
                            "api_key": "adapter-secret-should-not-leak",
                        },
                        edges_discovered=[],
                        timestamp=ts(14, 5),
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
    assert payload["service_id"] == "svc-radarr"
    assert payload["service_name"] == "Radarr"
    assert payload["facts_available"] is True
    assert payload["checked_at"]
    assert payload["adapters"] == [
        {
            "adapter_id": "radarr_api",
            "display_name": "Radarr API",
            "service_id": "svc-radarr",
            "service_name": "Radarr",
            "source": "deep_inspection_adapter",
            "read_only": True,
            "configuration_state": "configured",
            "configuration_summary": "Required adapter inputs are configured.",
            "health_state": "healthy",
            "health_summary": "Adapter returned prompt-safe facts successfully.",
            "missing_credentials": [],
            "supported_fact_names": [
                "download_client_status",
                "health_issues",
                "indexer_status",
            ],
            "execution_status": "success",
            "facts_available": True,
            "facts": {
                "health_issues": [
                    {
                        "type": "error",
                        "message": "Download client unavailable",
                    }
                ],
                "download_client_status": {
                    "available": False,
                    "configured_count": 1,
                },
            },
            "excluded_paths": ["api_key"],
            "applied_redaction_level": "redact_for_local",
            "facts_observed_at": "2026-04-07T14:05:00Z",
            "stale_at": "2026-04-07T15:05:00Z",
            "next_refresh_at": "2026-04-07T14:35:00Z",
            "refresh_interval_minutes": 30,
            "freshness": "current",
            "reason": None,
        }
    ]
    assert "adapter-secret-should-not-leak" not in response.text
    assert "radarr-vault-secret" not in response.text


def test_adapter_facts_endpoint_surfaces_unconfigured_and_locked_states_without_execution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Unavailable adapter credentials should return explicit state without any facts."""
    monkeypatch.setattr(api_app_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(
        api_app_module,
        "_DEFAULT_ADAPTER_REGISTRY",
        AdapterRegistry(
            [
                StubRadarrFactsAdapter(
                    AdapterResult(
                        adapter_id="radarr_api",
                        status=AdapterStatus.SUCCESS,
                        facts={"health_issues": [{"message": "should never run"}]},
                        edges_discovered=[],
                        timestamp=ts(14, 5),
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
        unconfigured_response = client.get("/api/v1/services/svc-radarr/adapter-facts")
        configure_vault_adapter_credential(client)
        client.post("/api/v1/vault/lock")
        locked_response = client.get("/api/v1/services/svc-radarr/adapter-facts")

    assert unconfigured_response.status_code == 200
    assert unconfigured_response.json()["adapters"] == [
        {
            "adapter_id": "radarr_api",
            "display_name": "Radarr API",
            "service_id": "svc-radarr",
            "service_name": "Radarr",
            "source": "deep_inspection_adapter",
            "read_only": True,
            "configuration_state": "unconfigured",
            "configuration_summary": "Required adapter inputs have not been configured yet.",
            "health_state": "unknown",
            "health_summary": "Health will remain unknown until the adapter is configured.",
            "missing_credentials": ["api_key"],
            "supported_fact_names": [
                "download_client_status",
                "health_issues",
                "indexer_status",
            ],
            "execution_status": None,
            "facts_available": False,
            "facts": {},
            "excluded_paths": [],
            "applied_redaction_level": None,
            "facts_observed_at": None,
            "stale_at": None,
            "next_refresh_at": None,
            "refresh_interval_minutes": 30,
            "freshness": "unavailable",
            "reason": "adapter credentials are not configured",
        }
    ]

    assert locked_response.status_code == 200
    assert locked_response.json()["adapters"] == [
        {
            "adapter_id": "radarr_api",
            "display_name": "Radarr API",
            "service_id": "svc-radarr",
            "service_name": "Radarr",
            "source": "deep_inspection_adapter",
            "read_only": True,
            "configuration_state": "locked",
            "configuration_summary": "Stored credentials exist, but the vault is currently locked.",
            "health_state": "unknown",
            "health_summary": "Unlock the vault before adapter diagnostics can evaluate health.",
            "missing_credentials": ["api_key"],
            "supported_fact_names": [
                "download_client_status",
                "health_issues",
                "indexer_status",
            ],
            "execution_status": None,
            "facts_available": False,
            "facts": {},
            "excluded_paths": [],
            "applied_redaction_level": None,
            "facts_observed_at": None,
            "stale_at": None,
            "next_refresh_at": None,
            "refresh_interval_minutes": 30,
            "freshness": "unavailable",
            "reason": "vault is locked",
        }
    ]


class StubRadarrFactsAdapter:
    """Protocol-compatible adapter stub for service facts API tests."""

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
            "decided_by": "integration_test",
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
            "submitted_by": "integration_test",
        },
    )
