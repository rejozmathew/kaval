"""Unit tests for deterministic webhook service matching."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.matching import (
    WebhookServiceMatcher,
    WebhookServiceMatchMethod,
)
from kaval.integrations.webhooks.normalizers import (
    normalize_alertmanager_payload,
    normalize_generic_json_payload,
    normalize_uptime_kuma_payload,
)
from kaval.integrations.webhooks.normalizers.generic_json import GenericJsonNormalizerConfig
from kaval.models import (
    Endpoint,
    EndpointProtocol,
    Service,
    ServiceStatus,
    ServiceType,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for webhook-matching tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_webhook_matcher_matches_single_service_by_exact_hint() -> None:
    """Exact service hints should produce one deterministic single-service match."""
    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=load_fixture("uptime_kuma_down.json"),
        received_at=ts(12, 0),
    )

    result = WebhookServiceMatcher().match(
        event=event,
        services=[
            build_service(
                service_id="svc-immich",
                name="Immich",
                descriptor_id="media/immich",
            ),
            build_service(
                service_id="svc-redis",
                name="Redis",
                descriptor_id="datastores/redis",
            ),
        ],
    )

    assert result.method == WebhookServiceMatchMethod.EXACT
    assert result.event.matching_outcome == "single"
    assert result.event.processing_status == "matched"
    assert result.event.matched_service_ids == ["svc-immich"]
    assert result.explanations == ("exact hint 'Immich' matched svc-immich",)


def test_webhook_matcher_matches_single_service_by_structured_tag() -> None:
    """Structured tag values should match services when exact hints are absent."""
    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=load_fixture("uptime_kuma_down.json"),
        received_at=ts(12, 5),
    ).model_copy(update={"service_hints": []})

    result = WebhookServiceMatcher().match(
        event=event,
        services=[
            build_service(
                service_id="svc-immich",
                name="Immich",
                descriptor_id="media/immich",
                endpoint_host="immich.example.com",
                endpoint_port=443,
            )
        ],
    )

    assert result.method == WebhookServiceMatchMethod.TAG
    assert result.event.matching_outcome == "single"
    assert result.event.matched_service_ids == ["svc-immich"]
    assert result.explanations[0] == (
        "structured tag value 'immich.example.com' matched svc-immich"
    )


def test_webhook_matcher_matches_single_service_by_fuzzy_text() -> None:
    """Fuzzy title/body text should only match when one service wins uniquely."""
    event = normalize_generic_json_payload(
        source_id="generic_json",
        payload=load_fixture("generic_json_firing.json"),
        config=GenericJsonNormalizerConfig(
            dedup_key_path="event.id",
            title_path="event.title",
            body_path="event.summary",
            alert_state_path="event.status",
            alert_state_mapping={"open": "firing", "closed": "resolved"},
        ),
        received_at=ts(12, 10),
    )

    result = WebhookServiceMatcher().match(
        event=event,
        services=[build_service(service_id="svc-plex", name="Plex")],
    )

    assert result.method == WebhookServiceMatchMethod.FUZZY
    assert result.event.matching_outcome == "single"
    assert result.event.matched_service_ids == ["svc-plex"]
    assert result.explanations == ("fuzzy text tokens plex matched svc-plex",)


def test_webhook_matcher_supports_multi_service_group_matches() -> None:
    """Grouped alerts should preserve multiple deterministic service matches."""
    event = normalize_alertmanager_payload(
        source_id="prometheus_alertmanager",
        payload=load_fixture("alertmanager_firing_group.json"),
        received_at=ts(12, 15),
    )

    result = WebhookServiceMatcher().match(
        event=event,
        services=[
            build_service(service_id="svc-immich", name="Immich"),
            build_service(service_id="svc-redis", name="Redis"),
        ],
    )

    assert result.method == WebhookServiceMatchMethod.EXACT
    assert result.event.matching_outcome == "multi"
    assert result.event.processing_status == "matched"
    assert result.event.matched_service_ids == ["svc-immich", "svc-redis"]


def test_webhook_matcher_returns_unmatched_when_no_deterministic_path_exists() -> None:
    """Events without exact, tag, or unique fuzzy evidence should remain unmatched."""
    event = normalize_uptime_kuma_payload(
        source_id="uptime_kuma",
        payload=load_fixture("uptime_kuma_down.json"),
        received_at=ts(12, 20),
    )

    result = WebhookServiceMatcher().match(
        event=event,
        services=[build_service(service_id="svc-radarr", name="Radarr")],
    )

    assert result.method == WebhookServiceMatchMethod.UNMATCHED
    assert result.event.matching_outcome == "unmatched"
    assert result.event.matched_service_ids == []
    assert result.explanations == ("no deterministic service match evidence was found",)


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def build_service(
    *,
    service_id: str,
    name: str,
    descriptor_id: str | None = None,
    endpoint_host: str | None = None,
    endpoint_port: int | None = None,
) -> Service:
    """Build a minimal service record for webhook-matching tests."""
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
        descriptor_id=descriptor_id,
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
