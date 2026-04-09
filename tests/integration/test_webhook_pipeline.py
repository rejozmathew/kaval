"""Integration tests for webhook-to-finding and incident pipeline wiring."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.integrations.webhooks.models import WebhookSourceType
from kaval.integrations.webhooks.pipeline import WebhookPipelineProcessor
from kaval.models import (
    Endpoint,
    EndpointProtocol,
    FindingStatus,
    IncidentStatus,
    MaintenanceScope,
    MaintenanceWindowRecord,
    Service,
    ServiceStatus,
    ServiceType,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for pipeline integration tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_pipeline_creates_finding_and_incident_for_single_service_match(
    tmp_path: Path,
) -> None:
    """Matched webhook alerts should create grouped findings and one incident."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.upsert_service(
        build_service(
            service_id="svc-immich",
            name="Immich",
            endpoint_host="immich.example.com",
            endpoint_port=443,
        )
    )

    try:
        result = WebhookPipelineProcessor().process(
            database=database,
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            payload=load_fixture("uptime_kuma_down.json"),
            received_at=ts(12, 0),
            raw_payload_retention_until=retention_until(ts(12, 0)),
        )

        findings = database.list_findings()
        incidents = database.list_incidents()
    finally:
        database.close()

    assert result.event.matching_outcome == "single"
    assert result.event.processing_status == "finding_created"
    assert len(result.findings) == 1
    assert len(result.created_services) == 0
    assert result.incident_result is not None
    assert len(result.incident_result.created_incidents) == 1
    assert len(findings) == 1
    assert findings[0].service_id == "svc-immich"
    assert findings[0].status is FindingStatus.GROUPED
    assert findings[0].incident_id == incidents[0].id
    assert findings[0].evidence[0].data["matched_service_ids"] == ["svc-immich"]
    assert len(incidents) == 1
    assert incidents[0].status is IncidentStatus.OPEN
    assert incidents[0].affected_services == ["svc-immich"]


def test_webhook_pipeline_routes_unmatched_alerts_to_external_pseudo_service(
    tmp_path: Path,
) -> None:
    """Unmatched webhook alerts should land on the generic external-alert service."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()

    try:
        result = WebhookPipelineProcessor().process(
            database=database,
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            payload=load_fixture("uptime_kuma_down.json"),
            received_at=ts(12, 5),
            raw_payload_retention_until=retention_until(ts(12, 5)),
        )

        findings = database.list_findings()
        incidents = database.list_incidents()
        external_service = database.get_service("svc-external-alerts")
    finally:
        database.close()

    assert result.event.matching_outcome == "unmatched"
    assert result.event.matched_service_ids == []
    assert len(result.findings) == 1
    assert len(result.created_services) == 1
    assert external_service is not None
    assert external_service.type is ServiceType.EXTERNAL
    assert findings[0].service_id == "svc-external-alerts"
    assert findings[0].status is FindingStatus.GROUPED
    assert len(incidents) == 1
    assert incidents[0].affected_services == ["svc-external-alerts"]


def test_webhook_pipeline_marks_maintenance_suppressed_matches_as_ignored(
    tmp_path: Path,
) -> None:
    """Matched webhook alerts under maintenance should not create findings or incidents."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.upsert_service(
        build_service(
            service_id="svc-immich",
            name="Immich",
            endpoint_host="immich.example.com",
            endpoint_port=443,
        )
    )
    database.upsert_maintenance_window(
        MaintenanceWindowRecord(
            scope=MaintenanceScope.SERVICE,
            service_id="svc-immich",
            started_at=ts(11, 45),
            expires_at=ts(12, 30),
        )
    )

    try:
        result = WebhookPipelineProcessor().process(
            database=database,
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            payload=load_fixture("uptime_kuma_down.json"),
            received_at=ts(12, 0),
            raw_payload_retention_until=retention_until(ts(12, 0)),
        )

        findings = database.list_findings()
        incidents = database.list_incidents()
    finally:
        database.close()

    assert result.event.matching_outcome == "single"
    assert result.event.processing_status == "ignored"
    assert result.findings == []
    assert result.incident_result is None
    assert findings == []
    assert incidents == []


def test_webhook_pipeline_uses_stable_group_service_for_multi_service_alerts(
    tmp_path: Path,
) -> None:
    """Multi-service webhook alerts should create one stable external alert-group service."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.upsert_service(build_service(service_id="svc-immich", name="Immich"))
    database.upsert_service(build_service(service_id="svc-redis", name="Redis"))

    try:
        result = WebhookPipelineProcessor().process(
            database=database,
            source_id="prometheus_alertmanager",
            source_type=WebhookSourceType.PROMETHEUS_ALERTMANAGER,
            payload=load_fixture("alertmanager_firing_group.json"),
            received_at=ts(12, 10),
            raw_payload_retention_until=retention_until(ts(12, 10)),
        )

        findings = database.list_findings()
        incidents = database.list_incidents()
    finally:
        database.close()

    group_service_id = stable_group_service_id(
        source_id="prometheus_alertmanager",
        dedup_key=result.event.dedup_key,
    )

    assert result.event.matching_outcome == "multi"
    assert result.event.processing_status == "finding_created"
    assert len(result.created_services) == 1
    assert result.created_services[0].id == group_service_id
    assert result.created_services[0].name == "Webhook group: Immich, Redis"
    assert len(findings) == 1
    assert findings[0].service_id == group_service_id
    assert findings[0].evidence[0].data["matched_service_ids"] == [
        "svc-immich",
        "svc-redis",
    ]
    assert len(incidents) == 1
    assert incidents[0].affected_services == [group_service_id]


def test_webhook_pipeline_resolves_existing_webhook_finding_and_incident(
    tmp_path: Path,
) -> None:
    """Resolved webhook alerts should close the corresponding finding and incident."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.upsert_service(build_service(service_id="svc-immich", name="Immich"))
    processor = WebhookPipelineProcessor()

    try:
        first_result = processor.process(
            database=database,
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            payload=load_fixture("uptime_kuma_down.json"),
            received_at=ts(12, 15),
            raw_payload_retention_until=retention_until(ts(12, 15)),
        )
        resolved_result = processor.process(
            database=database,
            source_id="uptime_kuma",
            source_type=WebhookSourceType.UPTIME_KUMA,
            payload=load_fixture("uptime_kuma_up.json"),
            received_at=ts(12, 20),
            raw_payload_retention_until=retention_until(ts(12, 20)),
        )

        findings = database.list_findings()
        incidents = database.list_incidents()
    finally:
        database.close()

    assert first_result.incident_id is not None
    assert len(resolved_result.resolved_findings) == 1
    assert len(resolved_result.resolved_incidents) == 1
    assert findings[0].status is FindingStatus.RESOLVED
    assert findings[0].resolved_at == ts(12, 20)
    assert incidents[0].status is IncidentStatus.RESOLVED
    assert incidents[0].resolved_at == ts(12, 20)
    assert incidents[0].resolution_mechanism == "Source alert resolved."


def retention_until(received_at: datetime) -> datetime:
    """Return a deterministic retention timestamp for test webhook events."""
    return received_at + timedelta(days=30)


def stable_group_service_id(*, source_id: str, dedup_key: str) -> str:
    """Return the expected pseudo-service identifier for one alert group."""
    group_hash = hashlib.sha1(
        f"{source_id}:{dedup_key}".encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()[:12]
    return f"svc-whkgrp-{group_hash}"


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def build_service(
    *,
    service_id: str,
    name: str,
    endpoint_host: str | None = None,
    endpoint_port: int | None = None,
) -> Service:
    """Build a minimal service record for webhook pipeline tests."""
    endpoints = []
    if endpoint_host is not None:
        endpoints.append(
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTPS,
                host=endpoint_host,
                port=endpoint_port,
                path="/",
                url=(
                    f"https://{endpoint_host}:{endpoint_port}/"
                    if endpoint_port not in {None, 443}
                    else f"https://{endpoint_host}/"
                ),
                auth_required=False,
                expected_status=200,
            )
        )
    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="app",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=endpoints,
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
