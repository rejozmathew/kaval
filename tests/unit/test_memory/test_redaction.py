"""Unit tests for Operational Memory redaction helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.memory.redaction import (
    build_cloud_redaction_replacements,
    redact_for_cloud,
    redact_for_local,
)
from kaval.models import (
    DescriptorSource,
    Incident,
    IncidentStatus,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_redact_for_local_masks_secrets_but_keeps_internal_context() -> None:
    """Local-safe redaction should preserve internal topology while masking secrets."""
    text = (
        "Authorization: Bearer really-secret "
        "url=http://delugevpn:8112/api/status "
        "creds=https://user:pass@github.com/binhex/arch-delugevpn "
        "token=abc123"
    )

    redacted = redact_for_local(text)

    assert "really-secret" not in redacted
    assert "abc123" not in redacted
    assert "http://delugevpn:8112/api/status" in redacted
    assert "https://[REDACTED]@github.com/binhex/arch-delugevpn" in redacted


def test_redact_for_cloud_masks_internal_identifiers_and_urls() -> None:
    """Cloud-safe redaction should remove secrets and internal operational details."""
    incident = build_incident()
    service = build_service()
    text = (
        "incident=inc-delugevpn service=svc-delugevpn name=DelugeVPN "
        "container=container-delugevpn descriptor=downloads/delugevpn "
        "url=http://delugevpn:8112/api/status ip=192.168.1.50 "
        "share=/mnt/user/appdata/delugevpn "
        "auth=Authorization: Bearer really-secret"
    )

    redacted = redact_for_cloud(
        text,
        cloud_replacements=build_cloud_redaction_replacements(
            incident=incident,
            services=[service],
        ),
    )

    assert "inc-delugevpn" not in redacted
    assert "svc-delugevpn" not in redacted
    assert "DelugeVPN" not in redacted
    assert "container-delugevpn" not in redacted
    assert "downloads/delugevpn" not in redacted
    assert "http://delugevpn:8112/api/status" not in redacted
    assert "192.168.1.50" not in redacted
    assert "/mnt/user/appdata/delugevpn" not in redacted
    assert "really-secret" not in redacted
    assert "[INCIDENT_ID]" in redacted
    assert "[SERVICE_ID_1]" in redacted
    assert "[SERVICE_1]" in redacted
    assert "[CONTAINER_1]" in redacted
    assert "[DESCRIPTOR_1]" in redacted
    assert "http://[REDACTED_URL]" in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_PATH]" in redacted
    assert "Authorization: Bearer [REDACTED]" in redacted


def test_redact_for_local_masks_secret_query_params_and_cookie_headers() -> None:
    """Local-safe redaction should preserve structure while masking query and cookie secrets."""
    text = (
        "Cookie: sessionid=abc123; csrftoken=def456\n"
        "url=https://example.com/api?token=supersecret&view=full&password=hunter2"
    )

    redacted = redact_for_local(text)

    assert "abc123" not in redacted
    assert "def456" not in redacted
    assert "supersecret" not in redacted
    assert "hunter2" not in redacted
    assert "Cookie: [REDACTED]" in redacted
    assert (
        "https://example.com/api?token=%5BREDACTED%5D&view=full&password=%5BREDACTED%5D"
        in redacted
    )


def build_incident() -> Incident:
    """Build a minimal incident for redaction tests."""
    return Incident(
        id="inc-delugevpn",
        title="DelugeVPN degraded",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-delugevpn"],
        all_findings=["find-delugevpn"],
        affected_services=["svc-delugevpn"],
        triggering_symptom="VPN tunnel inactive",
        suspected_cause="VPN tunnel dropped",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.9,
        investigation_id=None,
        approved_actions=[],
        changes_correlated=[],
        grouping_window_start=ts(14, 0),
        grouping_window_end=ts(14, 5),
        created_at=ts(14, 0),
        updated_at=ts(14, 5),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_service() -> Service:
    """Build a minimal service for redaction tests."""
    return Service(
        id="svc-delugevpn",
        name="DelugeVPN",
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.DEGRADED,
        descriptor_id="downloads/delugevpn",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-delugevpn",
        vm_id=None,
        image="binhex/arch-delugevpn:latest",
        endpoints=[],
        dns_targets=[],
        dependencies=[],
        dependents=[],
        last_check=ts(14, 0),
        active_findings=1,
        active_incidents=1,
    )
