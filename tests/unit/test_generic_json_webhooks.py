"""Unit tests for generic JSON webhook normalization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.integrations.webhooks.models import (
    WebhookAlertState,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.integrations.webhooks.normalizers.generic_json import (
    GenericJsonNormalizerConfig,
    load_generic_json_normalizer_config_from_env,
    normalize_generic_json_payload,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for normalizer tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_generic_json_normalizer_uses_configured_field_mappings() -> None:
    """Configured paths should normalize nested generic JSON payloads."""
    payload = load_fixture("generic_json_firing.json")
    config = GenericJsonNormalizerConfig(
        dedup_key_path="event.id",
        source_event_id_path="debug.webhook_id",
        title_path="event.title",
        body_path="event.summary",
        url_path="event.url",
        alert_state_path="event.status",
        alert_state_mapping={
            "open": WebhookAlertState.FIRING,
            "closed": WebhookAlertState.RESOLVED,
        },
        severity_path="event.priority",
        severity_mapping={
            "p1": WebhookSeverity.CRITICAL,
            "p2": WebhookSeverity.HIGH,
            "p3": WebhookSeverity.MEDIUM,
            "p4": WebhookSeverity.LOW,
        },
        service_hint_paths=[
            "service.name",
            "service.host",
            "impacted_services[0].name",
        ],
        tag_paths={
            "team": "labels.team",
            "component": "labels.component",
        },
    )

    event = normalize_generic_json_payload(
        source_id="generic_json",
        payload=payload,
        config=config,
        received_at=ts(19, 2),
    )

    assert event.source_type == WebhookSourceType.GENERIC_JSON
    assert event.source_id == "generic_json"
    assert event.source_event_id == "whk-evt-42"
    assert event.dedup_key == "evt-42"
    assert event.received_at == ts(19, 2)
    assert event.alert_state == WebhookAlertState.FIRING
    assert event.severity == WebhookSeverity.HIGH
    assert event.title == "Plex transcoder queue backed up"
    assert event.body == "Multiple jobs have waited longer than 10 minutes."
    assert event.url == "https://alerts.example.com/events/evt-42?token=secret-abc"
    assert event.service_hints == ["plex", "plex.example.com", "tautulli"]
    assert event.tags == {
        "component": "transcoder",
        "team": "media",
    }
    assert event.raw_payload_redacted is True
    redacted_url = event.raw_payload["event"]["url"]
    assert isinstance(redacted_url, str)
    assert "secret-abc" not in redacted_url


def test_generic_json_normalizer_config_loads_from_env_and_defaults() -> None:
    """Env-loaded configs should normalize resolved payloads without extra code."""
    payload = load_fixture("generic_json_resolved.json")
    config = load_generic_json_normalizer_config_from_env(
        {
            "KAVAL_WEBHOOK_GENERIC_JSON_MAPPING": json.dumps(
                {
                    "dedup_key_path": "event.id",
                    "title_path": "event.title",
                    "url_path": "event.url",
                    "alert_state_path": "event.status",
                    "alert_state_mapping": {
                        "open": "firing",
                        "closed": "resolved",
                    },
                    "service_hint_paths": ["service.name", "service.host"],
                    "tag_paths": {"team": "labels.team"},
                }
            )
        }
    )

    assert config is not None
    event = normalize_generic_json_payload(
        source_id="generic_json",
        payload=payload,
        config=config,
        received_at=ts(19, 8),
    )

    assert event.source_event_id == "evt-42"
    assert event.alert_state == WebhookAlertState.RESOLVED
    assert event.severity == WebhookSeverity.INFO
    assert event.title == "Plex transcoder queue back to normal"
    assert event.body == "Plex transcoder queue back to normal"
    assert event.tags == {"team": "media"}


def load_fixture(name: str) -> dict[str, object]:
    """Load one webhook payload fixture from disk."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
