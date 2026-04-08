"""Unit tests for Prometheus metrics label-shape controls."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.api.metrics import (
    MetricFamily,
    MetricSample,
    _build_metric_label_policies,
    _validate_metric_families,
    render_prometheus_metrics,
)
from kaval.api.schemas import (
    ServiceDetailAdapterConfigurationState,
    ServiceDetailAdapterHealthState,
    ServiceDetailAdapterResponse,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for metrics unit tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_render_prometheus_metrics_emits_only_bounded_labels() -> None:
    """Rendering the metrics surface should not expose raw service or incident labels."""
    document = render_prometheus_metrics(
        services=[],
        findings=[],
        incidents=[],
        investigations=[],
        adapter_statuses=[
            ServiceDetailAdapterResponse(
                adapter_id="radarr_api",
                display_name="Radarr API",
                configuration_state=ServiceDetailAdapterConfigurationState.UNCONFIGURED,
                configuration_summary="Missing credentials.",
                health_state=ServiceDetailAdapterHealthState.UNKNOWN,
                health_summary="Health is unknown until configured.",
                missing_credentials=["api_key"],
                supported_fact_names=["queue_depth"],
            )
        ],
        known_adapter_ids=["radarr_api"],
        approval_tokens=[],
        webhook_payloads=[],
        webhook_event_states=[],
        database_size_bytes=0,
        uptime_seconds=42.0,
        now=ts(12, 0),
    )

    assert 'adapter="radarr_api"' in document
    assert "service_id=" not in document
    assert "incident_id=" not in document
    assert "container_id=" not in document


def test_metric_label_validation_rejects_unbounded_label_values() -> None:
    """Explicit label policy should reject ad-hoc source values."""
    family = MetricFamily(
        name="kaval_webhooks_received_total",
        help_text="Retained webhook payloads.",
        metric_type="gauge",
        samples=(
            MetricSample(
                metric_name="kaval_webhooks_received_total",
                value=1.0,
                labels=(("source", "custom-monitor"),),
            ),
        ),
    )

    with pytest.raises(ValueError, match="unexpected label value"):
        _validate_metric_families(
            families=[family],
            policies=_build_metric_label_policies(known_adapter_ids=["radarr_api"]),
        )


def test_metric_label_validation_rejects_raw_identifier_label_keys() -> None:
    """Explicit label policy should reject raw ID label keys even on known families."""
    family = MetricFamily(
        name="kaval_actions_total",
        help_text="Action attempts.",
        metric_type="gauge",
        samples=(
            MetricSample(
                metric_name="kaval_actions_total",
                value=1.0,
                labels=(
                    ("type", "restart_container"),
                    ("incident_id", "inc-123"),
                ),
            ),
        ),
    )

    with pytest.raises(ValueError, match="unexpected label keys"):
        _validate_metric_families(
            families=[family],
            policies=_build_metric_label_policies(known_adapter_ids=["radarr_api"]),
        )
