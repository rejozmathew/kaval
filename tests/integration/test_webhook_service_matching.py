"""Integration tests for webhook service matching against persisted services."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.integrations.webhooks.matching import (
    WebhookServiceMatcher,
    WebhookServiceMatchMethod,
)
from kaval.integrations.webhooks.normalizers import (
    normalize_alertmanager_payload,
    normalize_uptime_kuma_payload,
)
from kaval.models import (
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for webhook-matching integration tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_matcher_matches_grouped_alerts_against_persisted_services(
    tmp_path: Path,
) -> None:
    """Grouped webhook events should multi-match against DB-backed service records."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    database.upsert_service(build_service(service_id="svc-immich", name="Immich"))
    database.upsert_service(build_service(service_id="svc-redis", name="Redis"))
    event = normalize_alertmanager_payload(
        source_id="prometheus_alertmanager",
        payload=load_fixture("alertmanager_firing_group.json"),
        received_at=ts(13, 0),
    )

    try:
        result = WebhookServiceMatcher().match(
            event=event,
            services=database.list_services(),
        )
    finally:
        database.close()

    assert result.method == WebhookServiceMatchMethod.EXACT
    assert result.event.matching_outcome == "multi"
    assert result.event.matched_service_ids == ["svc-immich", "svc-redis"]


def test_webhook_matcher_uses_tag_evidence_against_persisted_service_targets(
    tmp_path: Path,
) -> None:
    """Tag-based URL and host evidence should match persisted service endpoints."""
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
    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=load_fixture("uptime_kuma_down.json"),
        received_at=ts(13, 5),
    ).model_copy(update={"service_hints": []})

    try:
        result = WebhookServiceMatcher().match(
            event=event,
            services=database.list_services(),
        )
    finally:
        database.close()

    assert result.method == WebhookServiceMatchMethod.TAG
    assert result.event.matching_outcome == "single"
    assert result.event.matched_service_ids == ["svc-immich"]


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
    """Build a minimal persisted service record for matching integration tests."""
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
