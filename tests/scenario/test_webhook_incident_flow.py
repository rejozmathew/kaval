"""Scenario test for webhook-driven incident opening and resolution."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.models import (
    Endpoint,
    EndpointProtocol,
    FindingStatus,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"
api_app_module = importlib.import_module("kaval.api.app")
notification_bus_module = importlib.import_module("kaval.notifications.bus")


def ts(hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for webhook scenario assertions."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_uptime_kuma_webhook_flow_opens_and_resolves_one_incident(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """One firing and one resolved webhook should drive investigation and notification."""
    monkeypatch.setenv("KAVAL_WEBHOOK_KEY_UPTIME_KUMA", "uptime-secret")
    monkeypatch.setenv("KAVAL_NOTIFICATION_URLS", "mailto://alerts@example.com")
    database_path = tmp_path / "kaval.db"
    seed_service_database(database_path)
    adapter = FakeAppriseAdapter()
    monkeypatch.setattr(
        notification_bus_module,
        "_default_adapter_factory",
        lambda: adapter,
    )
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        firing_response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=load_fixture("uptime_kuma_down.json"),
        )
        resolved_response = client.post(
            "/api/v1/webhooks/uptime_kuma",
            headers={"Authorization": "Bearer uptime-secret"},
            json=load_fixture("uptime_kuma_up.json"),
        )

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        findings = database.list_findings()
        incidents = database.list_incidents()
        investigations = database.list_investigations()
        payloads = database.list_webhook_payloads()
    finally:
        database.close()

    assert firing_response.status_code == 202
    assert resolved_response.status_code == 202
    assert len(findings) == 1
    assert findings[0].service_id == "svc-immich"
    assert findings[0].status is FindingStatus.RESOLVED
    assert len(incidents) == 1
    assert incidents[0].status is IncidentStatus.RESOLVED
    assert incidents[0].investigation_id is not None
    assert incidents[0].resolution_mechanism == "Source alert resolved."
    assert len(investigations) == 1
    assert investigations[0].incident_id == incidents[0].id
    assert investigations[0].root_cause == findings[0].summary
    assert len(payloads) == 2
    assert {payload.incident_id for payload in payloads} == {incidents[0].id}
    assert adapter.added_urls == ["mailto://alerts@example.com"]
    assert len(adapter.notifications) == 1
    assert adapter.notifications[0]["title"] == "Immich degraded"
    assert "Root cause: [Immich] [DOWN] PING immich.example.com failed after 3 retries." in (
        adapter.notifications[0]["body"]
    )
    assert "No restart recommended from the current evidence." in adapter.notifications[0]["body"]


def test_alertmanager_group_webhook_keeps_multi_service_context_and_digest_delivery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Grouped Alertmanager alerts should stay multi-service and release via digest later."""
    monkeypatch.setenv(
        "KAVAL_WEBHOOK_KEY_PROMETHEUS_ALERTMANAGER",
        "alertmanager-secret",
    )
    monkeypatch.setenv("KAVAL_NOTIFICATION_URLS", "mailto://alerts@example.com")
    database_path = tmp_path / "kaval.db"
    seed_group_service_database(database_path)
    adapter = FakeAppriseAdapter()
    monkeypatch.setattr(
        api_app_module,
        "datetime",
        SequencedDateTime(ts(17, 0), ts(17, 11), ts(18, 16)),
    )
    monkeypatch.setattr(
        notification_bus_module,
        "_default_adapter_factory",
        lambda: adapter,
    )
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        firing_response = client.post(
            "/api/v1/webhooks/prometheus_alertmanager",
            headers={"Authorization": "Bearer alertmanager-secret"},
            json=load_fixture("alertmanager_firing_group.json"),
        )
        replay_response = client.post(
            "/api/v1/webhooks/prometheus_alertmanager",
            headers={"Authorization": "Bearer alertmanager-secret"},
            json=load_fixture("alertmanager_firing_group_later.json"),
        )

    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        findings = database.list_findings()
        incidents = database.list_incidents()
        investigations = database.list_investigations()
    finally:
        database.close()

    expected_group_service_id = stable_group_service_id(
        source_id="prometheus_alertmanager",
        dedup_key=(
            'group:{}/{alertname="SharedStorageLatency",cluster="homelab"}:'
            '{alertname="SharedStorageLatency",cluster="homelab"}'
        ),
    )

    assert firing_response.status_code == 202
    assert replay_response.status_code == 202
    assert len(findings) == 2
    assert {finding.service_id for finding in findings} == {expected_group_service_id}
    assert all(
        finding.evidence[0].data["matched_service_ids"] == ["svc-immich", "svc-redis"]
        for finding in findings
    )
    assert len(incidents) == 2
    assert all(
        incident.affected_services == [expected_group_service_id]
        for incident in incidents
    )
    assert all(
        incident.title == "Webhook group: Immich, Redis degraded"
        for incident in incidents
    )
    assert {finding.incident_id for finding in findings} == {incident.id for incident in incidents}
    assert len(investigations) == 3
    assert {investigation.incident_id for investigation in investigations} == {
        incident.id for incident in incidents
    }
    assert adapter.added_urls == ["mailto://alerts@example.com"]
    assert len(adapter.notifications) == 1
    assert adapter.notifications[0]["title"] == "Webhook group: Immich, Redis degraded"
    assert "Shared storage latency is elevated for multiple services." in (
        adapter.notifications[0]["body"]
    )


class FakeAppriseAdapter:
    """Deterministic Apprise double for webhook scenario coverage."""

    def __init__(self) -> None:
        """Initialize captured sends."""
        self.added_urls: list[str] = []
        self.notifications: list[dict[str, str]] = []

    def add(self, servers: str) -> bool:
        """Record one configured notification destination."""
        self.added_urls.append(servers)
        return True

    def notify(self, *, title: str, body: str) -> bool:
        """Capture one rendered notification payload."""
        self.notifications.append({"title": title, "body": body})
        return True


class SequencedDateTime:
    """Deterministic datetime shim for sequential webhook-route timestamps."""

    def __init__(self, *timestamps: datetime) -> None:
        """Store the ordered timestamps the patched API module should return."""
        self._timestamps = iter(timestamps)

    def now(self, tz: object | None = None) -> datetime:
        """Return the next timestamp in sequence, preserving timezone handling."""
        resolved = next(self._timestamps)
        if tz is None:
            return resolved.replace(tzinfo=None)
        return resolved.astimezone(tz)


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def seed_service_database(database_path: Path) -> None:
    """Seed the database with the service required for the scenario flow."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            build_service(
                service_id="svc-immich",
                name="Immich",
                host="immich.example.com",
            )
        )
    finally:
        database.close()


def seed_group_service_database(database_path: Path) -> None:
    """Seed services required for the grouped Alertmanager scenario."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(
            build_service(
                service_id="svc-immich",
                name="Immich",
                host="immich.example.com",
            )
        )
        database.upsert_service(
            build_service(
                service_id="svc-redis",
                name="Redis",
                host="redis.example.com",
                port=6379,
            )
        )
    finally:
        database.close()


def build_service(
    *,
    service_id: str,
    name: str,
    host: str,
    port: int = 443,
) -> Service:
    """Build a minimal service record for webhook scenarios."""
    return Service(
        id=service_id,
        name=name,
        type=ServiceType.CONTAINER,
        category="media",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTPS if port == 443 else EndpointProtocol.TCP,
                host=host,
                port=port,
                path="/health" if port == 443 else None,
                url=(
                    f"https://{host}/health"
                    if port == 443
                    else f"tcp://{host}:{port}"
                ),
                auth_required=False,
                expected_status=200,
            )
        ],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def stable_group_service_id(*, source_id: str, dedup_key: str) -> str:
    """Return the expected pseudo-service identifier for one grouped alert."""
    group_hash = hashlib.sha1(
        f"{source_id}:{dedup_key}".encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()[:12]
    return f"svc-whkgrp-{group_hash}"
