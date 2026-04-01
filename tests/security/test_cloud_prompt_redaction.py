"""Security tests for cloud-bound investigation prompt redaction."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.investigation.cloud_model import build_cloud_safe_prompt_bundle
from kaval.investigation.evidence import InvestigationEvidenceResult
from kaval.investigation.prompts import build_investigation_prompt_bundle
from kaval.models import (
    DescriptorSource,
    EvidenceStep,
    Incident,
    IncidentStatus,
    OperationalMemoryResult,
    RedactionLevel,
    Service,
    ServiceStatus,
    ServiceType,
    Severity,
    UserNote,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_cloud_safe_prompt_excludes_internal_ids_urls_and_secrets() -> None:
    """Cloud prompt assembly should remove sensitive internal prompt content before send."""
    incident = Incident(
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
    service = Service(
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
    evidence = InvestigationEvidenceResult(
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="inspect_service_state",
                target="svc-delugevpn",
                result_summary="DelugeVPN is degraded.",
                result_data={
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "container_id": "container-delugevpn",
                    "probe_url": "http://delugevpn:8112/api/status",
                    "auth": "Authorization: Bearer super-secret",
                },
                timestamp=ts(14, 1),
            )
        ],
        operational_memory=OperationalMemoryResult(
            system_profile=None,
            journal_entries=[],
            user_notes=[
                UserNote(
                    id="note-cloud",
                    service_id="svc-delugevpn",
                    note="check /mnt/user/appdata/delugevpn with token=abcd1234",
                    safe_for_model=True,
                    last_verified_at=ts(13, 0),
                    stale=False,
                    added_at=ts(13, 0),
                    updated_at=ts(13, 5),
                )
            ],
            recurrence_count=0,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ),
    )

    prompt_bundle = build_investigation_prompt_bundle(
        incident=incident,
        evidence=evidence,
        now=ts(14, 30),
    )
    cloud_prompt = build_cloud_safe_prompt_bundle(
        prompt_bundle=prompt_bundle,
        incident=incident,
        services=[service],
    )

    assert "inc-delugevpn" not in cloud_prompt.user_prompt
    assert "svc-delugevpn" not in cloud_prompt.user_prompt
    assert "DelugeVPN" not in cloud_prompt.user_prompt
    assert "container-delugevpn" not in cloud_prompt.user_prompt
    assert "http://delugevpn:8112/api/status" not in cloud_prompt.user_prompt
    assert "/mnt/user/appdata/delugevpn" not in cloud_prompt.user_prompt
    assert "super-secret" not in cloud_prompt.user_prompt
    assert "abcd1234" not in cloud_prompt.user_prompt
    assert "[SERVICE_1]" in cloud_prompt.user_prompt
    assert "[CONTAINER_1]" in cloud_prompt.user_prompt
    assert "http://[REDACTED_URL]" in cloud_prompt.user_prompt
    assert "[REDACTED_PATH]" in cloud_prompt.user_prompt
    assert "Authorization: Bearer [REDACTED]" in cloud_prompt.user_prompt
