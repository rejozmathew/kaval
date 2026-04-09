"""Scenario coverage for descriptor promotion and post-promotion activation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.discovery.descriptors import (
    load_service_descriptors,
    loaded_descriptor_identifier,
)
from kaval.discovery.docker import (
    DockerContainerSnapshot,
    DockerContainerState,
    DockerPortBinding,
)
from kaval.discovery.matcher import build_service, match_service_descriptor
from tests.integration.test_fastapi_app import (
    add_unmatched_container_service,
    seed_api_database,
)

REPO_SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def _build_custom_app_snapshot() -> DockerContainerSnapshot:
    """Build the discovered container snapshot used for post-promotion rematching."""
    return DockerContainerSnapshot(
        Id="container-custom-app",
        name="custom-app",
        ConfigImage="ghcr.io/example/custom-app:1.0.0",
        Image="sha256:custom-app",
        command=[],
        state=DockerContainerState(
            Status="running",
            Running=True,
            Restarting=False,
            ExitCode=0,
            StartedAt="2026-04-09T12:00:00Z",
            FinishedAt="0001-01-01T00:00:00Z",
        ),
        RestartCount=0,
        env_names=[],
        labels={},
        mounts=[],
        networks=[],
        ports=[DockerPortBinding(container_port=8080, protocol="tcp")],
        image_details=None,
    )


def _rematch_custom_app_service(database_path: Path, services_dir: Path) -> None:
    """Apply the promoted descriptor on the next synthetic discovery pass."""
    descriptors = load_service_descriptors([services_dir])
    snapshot = _build_custom_app_snapshot()
    matched_descriptor = match_service_descriptor(snapshot, descriptors)
    assert matched_descriptor is not None
    assert loaded_descriptor_identifier(matched_descriptor) == "custom/custom_app"

    rematched_service = build_service(snapshot, matched_descriptor)
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        existing_service = database.get_service("svc-custom-app")
        assert existing_service is not None
        database.upsert_service(
            rematched_service.model_copy(
                update={
                    "active_findings": existing_service.active_findings,
                    "active_incidents": existing_service.active_incidents,
                    "last_check": existing_service.last_check,
                }
            )
        )
    finally:
        database.close()


def test_descriptor_auto_generation_review_promotion_and_activation_flow(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A promoted reviewed descriptor should stay inactive until the next rematch."""
    monkeypatch.setenv("KAVAL_LOCAL_MODEL_NAME", "qwen3:8b")
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)

    database_path = tmp_path / "kaval.db"
    services_dir = tmp_path / "services"
    shutil.copytree(REPO_SERVICES_DIR, services_dir)
    seed_api_database(database_path)
    add_unmatched_container_service(database_path)

    def local_transport(http_request, timeout_seconds):
        del http_request, timeout_seconds
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "id": "custom_app",
                                    "name": "Custom App",
                                    "category": "custom",
                                    "match": {
                                        "image_patterns": ["ghcr.io/example/custom-app*"],
                                        "container_name_patterns": ["custom-app"],
                                    },
                                    "endpoints": {
                                        "web_ui": {
                                            "port": 8080,
                                            "path": "/",
                                        }
                                    },
                                    "dns_targets": [],
                                    "log_signals": {"errors": [], "warnings": []},
                                    "typical_dependencies": {
                                        "containers": [],
                                        "shares": [],
                                    },
                                    "common_failure_modes": [],
                                    "investigation_context": "Custom App candidate",
                                }
                            )
                        }
                    }
                ]
            }
        ).encode("utf-8")

    app = create_app(
        database_path=database_path,
        services_dir=services_dir,
        local_model_transport=local_transport,
    )

    with TestClient(app) as client:
        generate_response = client.post(
            "/api/v1/services/svc-custom-app/descriptor/auto-generate"
        )
        active_descriptor_ids_after_generation = {
            loaded_descriptor_identifier(item)
            for item in load_service_descriptors([services_dir])
        }
        services_after_generation = client.get("/api/v1/services")
        descriptor_view_before_promotion = client.get("/api/v1/services/svc-custom-app/descriptor")
        queue_response = client.get("/api/v1/descriptors/auto-generated")
        edit_response = client.put(
            "/api/v1/descriptors/auto-generated/custom/custom_app",
            json={
                "mode": "yaml",
                "raw_yaml": (
                    "id: custom_app\n"
                    "name: Custom App Reviewed\n"
                    "category: custom\n"
                    "match:\n"
                    "  image_patterns:\n"
                    "    - ghcr.io/example/custom-app*\n"
                    "  container_name_patterns:\n"
                    "    - custom-app\n"
                    "endpoints:\n"
                    "  web_ui:\n"
                    "    port: 8080\n"
                    "    path: /\n"
                    "log_signals:\n"
                    "  errors: []\n"
                    "  warnings: []\n"
                    "typical_dependencies:\n"
                    "  containers: []\n"
                    "  shares: []\n"
                    "source: auto_generated\n"
                    "verified: false\n"
                    "generated_at: 2026-04-09T12:00:00Z\n"
                ),
            },
        )
        promote_response = client.post(
            "/api/v1/descriptors/auto-generated/custom/custom_app/promote"
        )
        active_descriptor_ids_after_promotion = {
            loaded_descriptor_identifier(item)
            for item in load_service_descriptors([services_dir])
        }
        queue_after_promotion = client.get("/api/v1/descriptors/auto-generated")
        services_after_promotion = client.get("/api/v1/services")
        descriptor_view_before_rematch = client.get("/api/v1/services/svc-custom-app/descriptor")
        recommendations_before_rematch = client.get("/api/v1/recommendations")

        _rematch_custom_app_service(database_path=database_path, services_dir=services_dir)

        services_after_rematch = client.get("/api/v1/services")
        graph_after_rematch = client.get("/api/v1/graph")
        descriptor_view_after_rematch = client.get("/api/v1/services/svc-custom-app/descriptor")
        recommendations_after_rematch = client.get("/api/v1/recommendations")
        changes_response = client.get("/api/v1/changes")

    assert generate_response.status_code == 200
    assert generate_response.json()["descriptor"]["source"] == "auto_generated"
    assert generate_response.json()["descriptor"]["verified"] is False

    assert "custom/custom_app" not in active_descriptor_ids_after_generation

    assert services_after_generation.status_code == 200
    custom_app_after_generation = next(
        service
        for service in services_after_generation.json()
        if service["id"] == "svc-custom-app"
    )
    assert custom_app_after_generation["descriptor_id"] is None
    assert custom_app_after_generation["descriptor_source"] is None

    assert descriptor_view_before_promotion.status_code == 404
    assert queue_response.status_code == 200
    assert [item["descriptor"]["descriptor_id"] for item in queue_response.json()] == [
        "custom/custom_app"
    ]
    assert edit_response.status_code == 200
    assert edit_response.json()["descriptor"]["name"] == "Custom App Reviewed"

    assert promote_response.status_code == 200
    assert promote_response.json()["action"] == "promoted"
    assert promote_response.json()["descriptor"]["source"] == "user"
    assert promote_response.json()["descriptor"]["verified"] is True
    assert "custom/custom_app" in active_descriptor_ids_after_promotion
    assert queue_after_promotion.status_code == 200
    assert queue_after_promotion.json() == []
    assert not (services_dir / "auto_generated" / "custom" / "custom_app.yaml").exists()
    assert (services_dir / "user" / "custom" / "custom_app.yaml").exists()

    assert services_after_promotion.status_code == 200
    custom_app_after_promotion = next(
        service
        for service in services_after_promotion.json()
        if service["id"] == "svc-custom-app"
    )
    assert custom_app_after_promotion["descriptor_id"] is None
    assert custom_app_after_promotion["descriptor_source"] is None
    assert descriptor_view_before_rematch.status_code == 404

    assert recommendations_before_rematch.status_code == 200
    assert any(
        item["kind"] == "missing_descriptor"
        for item in recommendations_before_rematch.json()["items"]
    )

    assert services_after_rematch.status_code == 200
    custom_app_after_rematch = next(
        service
        for service in services_after_rematch.json()
        if service["id"] == "svc-custom-app"
    )
    assert custom_app_after_rematch["descriptor_id"] == "custom/custom_app"
    assert custom_app_after_rematch["descriptor_source"] == "user"
    assert custom_app_after_rematch["endpoints"] == [
        {
            "name": "web_ui",
            "protocol": "http",
            "host": "custom-app",
            "port": 8080,
            "path": "/",
            "url": None,
            "auth_required": False,
            "expected_status": 200,
        }
    ]

    assert graph_after_rematch.status_code == 200
    graph_custom_app = next(
        service
        for service in graph_after_rematch.json()["services"]
        if service["id"] == "svc-custom-app"
    )
    assert graph_custom_app["descriptor_id"] == "custom/custom_app"
    assert graph_custom_app["descriptor_source"] == "user"

    assert descriptor_view_after_rematch.status_code == 200
    assert descriptor_view_after_rematch.json()["descriptor_id"] == "custom/custom_app"
    assert descriptor_view_after_rematch.json()["source"] == "user"
    assert descriptor_view_after_rematch.json()["verified"] is True

    assert recommendations_after_rematch.status_code == 200
    assert not any(
        item["kind"] == "missing_descriptor"
        for item in recommendations_after_rematch.json()["items"]
    )

    assert changes_response.status_code == 200
    change_ids = {change["id"] for change in changes_response.json()}
    assert generate_response.json()["audit_change"]["id"] in change_ids
    assert edit_response.json()["audit_change"]["id"] in change_ids
    assert promote_response.json()["audit_change"]["id"] in change_ids
