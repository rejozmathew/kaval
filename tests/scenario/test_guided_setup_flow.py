"""Scenario coverage for the first-run guided setup flow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import DependencyConfidence, DependencyEdge, DependencySource
from tests.integration.test_fastapi_app import (
    FakeAppriseAdapter,
    add_radarr_service,
    add_unmatched_container_service,
    build_model_settings_payload,
    build_notification_settings_payload,
    seed_api_database,
)


def _add_low_confidence_dependency_edge(database_path: Path) -> None:
    """Persist one reviewable low-confidence edge for guided setup coverage."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        custom_app = database.get_service("svc-custom-app")
        downloads_share = database.get_service("svc-downloads-share")
        assert custom_app is not None
        assert downloads_share is not None

        database.upsert_service(
            custom_app.model_copy(
                update={
                    "dependencies": [
                        DependencyEdge(
                            target_service_id="svc-downloads-share",
                            confidence=DependencyConfidence.INFERRED,
                            source=DependencySource.DOCKER_NETWORK,
                            description=(
                                "Shared Docker network suggests this dependency path."
                            ),
                        )
                    ]
                }
            )
        )
        database.upsert_service(
            downloads_share.model_copy(
                update={"dependents": sorted({*downloads_share.dependents, custom_app.id})}
            )
        )
    finally:
        database.close()


def test_first_run_guided_setup_flow_covers_all_five_steps(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Guided setup should compose discovery, review, effectiveness, and settings flows."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_CLOUD_MODEL_ENABLED", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("KAVAL_NOTIFICATION_URLS", raising=False)

    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    seed_api_database(database_path)
    add_radarr_service(database_path)
    add_unmatched_container_service(database_path)
    _add_low_confidence_dependency_edge(database_path)

    notification_adapter = FakeAppriseAdapter()

    def local_transport(http_request, timeout_seconds):
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        assert timeout_seconds == 12.0
        assert http_request.full_url == "http://localhost:11434/v1/chat/completions"
        assert body["messages"][1]["content"] == '{"connection_ok": true}'
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"connection_ok": true}',
                        }
                    }
                ]
            }
        ).encode("utf-8")

    def cloud_transport(http_request, timeout_seconds):
        headers = {key.lower(): value for key, value in http_request.header_items()}
        body = json.loads(cast(bytes, http_request.data).decode("utf-8"))
        assert timeout_seconds == 25.0
        assert http_request.full_url == "https://api.anthropic.com/v1/messages"
        assert headers["x-api-key"] == "cloud-secret"
        assert body["system"] == "Return JSON only."
        assert body["messages"] == [{"role": "user", "content": '{"connection_ok": true}'}]
        return json.dumps(
            {
                "content": [
                    {
                        "type": "text",
                        "text": '{"connection_ok": true}',
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        settings_path=settings_path,
        local_model_transport=local_transport,
        cloud_model_transport=cloud_transport,
        notification_bus_adapter_factory=lambda: notification_adapter,
    )

    with TestClient(app) as client:
        unlock_response = client.post(
            "/api/v1/settings/vault/unlock",
            json={"master_passphrase": "correct horse battery staple"},
        )

        services_response = client.get("/api/v1/services")
        graph_before_confirmation = client.get("/api/v1/graph")
        custom_app_detail = client.get("/api/v1/services/svc-custom-app/detail")

        confirm_edge_response = client.put(
            "/api/v1/graph/edges",
            json={
                "source_service_id": "svc-custom-app",
                "target_service_id": "svc-downloads-share",
            },
        )
        graph_after_confirmation = client.get("/api/v1/graph")

        effectiveness_response = client.get("/api/v1/effectiveness")
        recommendations_response = client.get("/api/v1/recommendations")
        radarr_detail_before_model_setup = client.get("/api/v1/services/svc-radarr/detail")

        notification_save_response = client.put(
            "/api/v1/settings/notifications",
            json=build_notification_settings_payload(
                channels=[
                    {
                        "id": None,
                        "name": "Primary Discord",
                        "enabled": True,
                        "destination": "discord://tokenA/tokenB",
                    }
                ]
            ),
        )
        staged_channel_id = notification_save_response.json()["settings"]["staged"]["channels"][
            0
        ]["id"]
        notification_test_response = client.post(
            "/api/v1/settings/notifications/test",
            json={"channel_id": staged_channel_id, "scope": "staged"},
        )
        notification_apply_response = client.post("/api/v1/settings/notifications/apply")
        notification_settings_response = client.get("/api/v1/settings/notifications")

        model_save_response = client.put(
            "/api/v1/settings/models",
            json=build_model_settings_payload(
                local_enabled=True,
                local_model="qwen3:14b",
                local_api_key="local-secret",
                cloud_enabled=True,
                cloud_provider="anthropic",
                cloud_model="claude-sonnet-4-20250514",
                cloud_api_key="cloud-secret",
            ),
        )
        local_model_test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "local", "scope": "staged"},
        )
        cloud_model_test_response = client.post(
            "/api/v1/settings/models/test",
            json={"target": "cloud", "scope": "staged"},
        )
        model_apply_response = client.post("/api/v1/settings/models/apply")
        model_settings_response = client.get("/api/v1/settings/models")
        services_after_model_apply = client.get("/api/v1/services")
        radarr_detail_after_model_setup = client.get("/api/v1/services/svc-radarr/detail")
        changes_response = client.get("/api/v1/changes")

    assert unlock_response.status_code == 200

    assert services_response.status_code == 200
    services_by_id = {service["id"]: service for service in services_response.json()}
    assert services_by_id["svc-custom-app"]["descriptor_id"] is None
    assert services_by_id["svc-custom-app"]["descriptor_source"] is None

    assert graph_before_confirmation.status_code == 200
    low_confidence_edge = next(
        edge
        for edge in graph_before_confirmation.json()["edges"]
        if edge["source_service_id"] == "svc-custom-app"
        and edge["target_service_id"] == "svc-downloads-share"
    )
    assert low_confidence_edge["confidence"] == "inferred"
    assert low_confidence_edge["source"] == "docker_network"

    assert custom_app_detail.status_code == 200
    assert custom_app_detail.json()["service"]["id"] == "svc-custom-app"
    assert custom_app_detail.json()["service"]["descriptor_id"] is None

    assert confirm_edge_response.status_code == 200
    assert confirm_edge_response.json()["edge"] == {
        "source_service_id": "svc-custom-app",
        "target_service_id": "svc-downloads-share",
        "confidence": "user_confirmed",
        "source": "user",
        "description": "Shared Docker network suggests this dependency path.",
    }
    assert graph_after_confirmation.status_code == 200
    assert confirm_edge_response.json()["edge"] in graph_after_confirmation.json()["edges"]

    assert effectiveness_response.status_code == 200
    effectiveness_payload = effectiveness_response.json()
    assert effectiveness_payload["total_services"] == 4
    assert effectiveness_payload["improvable_services"] >= 2

    assert recommendations_response.status_code == 200
    recommendations_payload = recommendations_response.json()
    assert any(
        item["kind"] == "missing_descriptor"
        and item["action"] == {
            "label": "Review custom-app",
            "target": "service_detail",
            "service_id": "svc-custom-app",
        }
        for item in recommendations_payload["items"]
    )

    assert radarr_detail_before_model_setup.status_code == 200
    improve_action_kinds = {
        item["kind"]
        for item in radarr_detail_before_model_setup.json()["insight_section"][
            "improve_actions"
        ]
    }
    assert improve_action_kinds == {"configure_local_model", "configure_adapter"}

    assert notification_save_response.status_code == 200
    assert notification_test_response.status_code == 200
    assert notification_test_response.json()["ok"] is True
    assert notification_apply_response.status_code == 200
    assert notification_settings_response.status_code == 200
    assert (
        notification_settings_response.json()["active"]["configured_channel_count"] == 1
    )
    assert notification_adapter.added_urls == ["discord://tokenA/tokenB"]
    assert notification_adapter.notifications[0]["title"] == (
        "Kaval notification settings test"
    )

    assert model_save_response.status_code == 200
    assert local_model_test_response.status_code == 200
    assert local_model_test_response.json()["ok"] is True
    assert cloud_model_test_response.status_code == 200
    assert cloud_model_test_response.json()["ok"] is True
    assert model_apply_response.status_code == 200
    assert model_settings_response.status_code == 200
    assert model_settings_response.json()["active"]["local"]["configured"] is True
    assert model_settings_response.json()["active"]["cloud"]["configured"] is True

    assert services_after_model_apply.status_code == 200
    services_after_model = {
        service["id"]: service for service in services_after_model_apply.json()
    }
    assert services_after_model["svc-radarr"]["insight"] == {"level": 3}
    assert services_after_model["svc-delugevpn"]["insight"] == {"level": 3}

    assert radarr_detail_after_model_setup.status_code == 200
    assert radarr_detail_after_model_setup.json()["insight_section"]["current_level"] == 3
    assert [
        item["kind"]
        for item in radarr_detail_after_model_setup.json()["insight_section"][
            "improve_actions"
        ]
    ] == ["configure_adapter"]

    assert changes_response.status_code == 200
    change_ids = {change["id"] for change in changes_response.json()}
    assert confirm_edge_response.json()["audit_change"]["id"] in change_ids
    assert notification_save_response.json()["audit_change"]["id"] in change_ids
    assert notification_apply_response.json()["audit_change"]["id"] in change_ids
    assert model_save_response.json()["audit_change"]["id"] in change_ids
    assert model_apply_response.json()["audit_change"]["id"] in change_ids

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "local-secret" not in persisted_text
    assert "cloud-secret" not in persisted_text
    assert "discord://tokenA/tokenB" not in persisted_text
    assert "api_key_ref: vault:settings:models:local_api_key" in persisted_text
    assert "api_key_ref: vault:settings:models:cloud_api_key" in persisted_text
    assert "destination_ref: vault:settings:notifications:channels:" in persisted_text
