"""Integration tests for the Prometheus metrics endpoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app
from kaval.database import KavalDatabase
from kaval.integrations.webhooks import WebhookSourceType, WebhookStoredPayload
from kaval.integrations.webhooks.state import WebhookEventStateRecord
from kaval.models import (
    ActionType,
    ApprovalToken,
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    DescriptorSource,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    ModelUsed,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for metrics integration tests."""
    return datetime(2026, 4, 7, hour, minute, tzinfo=UTC)


def test_metrics_endpoint_exposes_prometheus_text_for_phase3b_signals(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The metrics endpoint should expose bounded aggregate families for Phase 3B."""
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_NAME", raising=False)
    monkeypatch.delenv("KAVAL_LOCAL_MODEL_ENABLED", raising=False)
    database_path = tmp_path / "kaval.db"
    seed_metrics_database(database_path)
    app = create_app(database_path=database_path)

    with TestClient(app) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    body = response.text

    assert "# TYPE kaval_services_total gauge" in body
    assert 'kaval_services_total{status="healthy"} 1' in body
    assert 'kaval_services_total{status="degraded"} 1' in body
    assert 'kaval_services_insight_level{level="0"} 1' in body
    assert 'kaval_services_insight_level{level="2"} 1' in body
    assert 'kaval_findings_active_total{severity="high"} 1' in body
    assert 'kaval_incidents_active_total{status="open"} 1' in body
    assert "# TYPE kaval_incident_mttr_seconds histogram" in body
    assert "kaval_incident_mttr_seconds_count 1" in body
    assert 'kaval_investigations_total{status="completed",model="none"} 1' in body
    assert 'kaval_investigations_total{status="completed",model="cloud"} 1' in body
    assert "# TYPE kaval_investigation_duration_seconds histogram" in body
    assert 'kaval_investigation_duration_seconds_count{model="cloud"} 1' in body
    assert "kaval_investigation_cloud_calls_total 3" in body
    assert 'kaval_adapters_total{status="unconfigured"} 1' in body
    assert (
        'kaval_adapter_inspections_total{adapter="radarr_api",status="unconfigured"} 1'
        in body
    )
    assert 'kaval_actions_total{type="restart_container",result="success"} 1' in body
    assert 'kaval_approval_tokens_total{status="used"} 1' in body
    assert 'kaval_webhooks_received_total{source="grafana"} 1' in body
    assert 'kaval_webhooks_matched_total{source="grafana"} 1' in body
    assert 'kaval_webhooks_duplicate_total{source="grafana"} 2' in body
    assert "# TYPE kaval_database_size_bytes gauge" in body
    assert "# TYPE kaval_uptime_seconds gauge" in body


def seed_metrics_database(database_path: Path) -> None:
    """Seed representative state for the metrics endpoint integration test."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        database.upsert_service(build_radarr_service())
        database.upsert_service(build_downloads_service())
        database.upsert_finding(build_webhook_finding())
        database.upsert_incident(build_open_incident())
        database.upsert_incident(build_resolved_incident())
        database.upsert_investigation(build_local_investigation())
        database.upsert_investigation(build_cloud_investigation())
        database.upsert_approval_token(build_used_approval_token())
        database.upsert_webhook_payload(build_webhook_payload())
        database.upsert_webhook_event_state(build_webhook_event_state())
    finally:
        database.close()


def build_radarr_service() -> Service:
    """Build the descriptor-backed service that exposes one adapter binding."""
    return Service(
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
        endpoints=[
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTP,
                host="radarr",
                port=7878,
                path="/",
                url="http://radarr:7878/",
                auth_required=False,
                expected_status=200,
            )
        ],
        dns_targets=[],
        dependencies=[
            DependencyEdge(
                target_service_id="svc-downloads",
                confidence=DependencyConfidence.CONFIGURED,
                source=DependencySource.SHARED_VOLUME,
                description="Mounted downloads share confirms dependency.",
            )
        ],
        dependents=[],
        last_check=ts(12, 0),
        active_findings=1,
        active_incidents=1,
    )


def build_downloads_service() -> Service:
    """Build one second service so the metrics output covers multiple statuses."""
    return Service(
        id="svc-downloads",
        name="downloads",
        type=ServiceType.SHARE,
        category="storage",
        status=ServiceStatus.HEALTHY,
        descriptor_id=None,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=["svc-radarr"],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )


def build_webhook_finding() -> Finding:
    """Build one active finding with webhook evidence for the metrics endpoint."""
    return Finding(
        id="find-radarr-latency",
        title="Radarr latency high",
        severity=Severity.HIGH,
        domain="webhook:grafana",
        service_id="svc-radarr",
        summary="Grafana reported sustained Radarr API latency.",
        evidence=[
            Evidence(
                kind=EvidenceKind.EVENT,
                source="webhook:grafana",
                summary="Grafana Radarr alert",
                observed_at=ts(12, 1),
                data={
                    "source_id": "grafana",
                    "dedup_key": "group:{alertname=\"RadarrLatency\"}",
                    "matching_outcome": "single",
                    "matched_service_ids": ["svc-radarr"],
                },
            )
        ],
        impact="Arr requests are delayed.",
        confidence=0.92,
        status=FindingStatus.NEW,
        incident_id="inc-radarr-open",
        related_changes=[],
        created_at=ts(12, 1),
        resolved_at=None,
    )


def build_open_incident() -> Incident:
    """Build one active incident for metrics assertions."""
    return Incident(
        id="inc-radarr-open",
        title="Radarr degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        trigger_findings=["find-radarr-latency"],
        all_findings=["find-radarr-latency"],
        affected_services=["svc-radarr"],
        triggering_symptom="Webhook alert reported sustained latency.",
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.88,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(12, 1),
        grouping_window_end=ts(12, 2),
        created_at=ts(12, 1),
        updated_at=ts(12, 2),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_resolved_incident() -> Incident:
    """Build one resolved incident so MTTR metrics have an observation."""
    return Incident(
        id="inc-old-resolved",
        title="Downloads recovered",
        severity=Severity.MEDIUM,
        status=IncidentStatus.RESOLVED,
        trigger_findings=[],
        all_findings=[],
        affected_services=["svc-downloads"],
        triggering_symptom="Share latency recovered.",
        suspected_cause=None,
        confirmed_cause=None,
        root_cause_service=None,
        resolution_mechanism="Manual recovery",
        cause_confirmation_source=None,
        confidence=0.71,
        investigation_id="inv-local",
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(11, 40),
        grouping_window_end=ts(11, 45),
        created_at=ts(11, 40),
        updated_at=ts(11, 50),
        resolved_at=ts(11, 50),
        mttr_seconds=600.0,
        journal_entry_id=None,
    )


def build_local_investigation() -> Investigation:
    """Build one completed local/no-cloud investigation."""
    return Investigation(
        id="inv-local",
        incident_id="inc-old-resolved",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[],
        research_steps=[],
        root_cause="Short-lived storage contention.",
        confidence=0.7,
        model_used=ModelUsed.NONE,
        cloud_model_calls=0,
        journal_entries_referenced=[],
        user_notes_referenced=[],
        recurrence_count=0,
        remediation=None,
        started_at=ts(11, 41),
        completed_at=ts(11, 43),
    )


def build_cloud_investigation() -> Investigation:
    """Build one completed cloud-backed investigation for model usage metrics."""
    return Investigation(
        id="inv-cloud",
        incident_id="inc-radarr-open",
        trigger=InvestigationTrigger.WEBHOOK,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[],
        research_steps=[],
        root_cause="Radarr API saturation.",
        confidence=0.84,
        model_used=ModelUsed.CLOUD,
        cloud_model_calls=3,
        journal_entries_referenced=[],
        user_notes_referenced=[],
        recurrence_count=0,
        remediation=None,
        started_at=ts(12, 2),
        completed_at=ts(12, 7),
    )


def build_used_approval_token() -> ApprovalToken:
    """Build one used approval token so action metrics are non-zero."""
    return ApprovalToken(
        token_id="tok-radarr-restart",
        incident_id="inc-radarr-open",
        action=ActionType.RESTART_CONTAINER,
        target="svc-radarr",
        approved_by="operator",
        issued_at=ts(12, 8),
        expires_at=ts(12, 18),
        nonce="nonce-radarr",
        hmac_signature="signature-radarr",
        used_at=ts(12, 9),
        result="success: restarted container",
    )


def build_webhook_payload() -> WebhookStoredPayload:
    """Build one retained webhook payload for webhook metrics."""
    return WebhookStoredPayload(
        id="whp-grafana-1",
        source_id="grafana",
        source_type=WebhookSourceType.GRAFANA,
        received_at=ts(12, 1),
        payload_size_bytes=512,
        raw_payload={"status": "firing"},
        raw_payload_redacted=True,
        raw_payload_retention_until=ts(12, 1) + timedelta(days=30),
        incident_id="inc-radarr-open",
    )


def build_webhook_event_state() -> WebhookEventStateRecord:
    """Build one webhook dedup-state record with duplicate-count data."""
    return WebhookEventStateRecord(
        state_key='grafana:group:{alertname="RadarrLatency"}',
        source_id="grafana",
        source_type=WebhookSourceType.GRAFANA,
        dedup_key='group:{alertname="RadarrLatency"}',
        last_event_id="whk-radarr-latency",
        last_source_event_id="group:{alertname=\"RadarrLatency\"}:firing:2026-04-07T12:01:00Z",
        last_received_at=ts(12, 3),
        last_alert_state="firing",
        active=True,
        active_since=ts(12, 1),
        resolved_at=None,
        last_processed_at=ts(12, 3),
        duplicate_count=2,
        flap_count=0,
    )
