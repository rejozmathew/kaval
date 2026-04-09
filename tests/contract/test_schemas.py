"""Contract tests for repository JSON schemas."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from jsonschema.validators import validator_for

from kaval.api.schemas import (
    AdapterFactSourceType,
    CredentialVaultChangePasswordRequest,
    CredentialVaultEntrySource,
    CredentialVaultMutationResponse,
    CredentialVaultResponse,
    CredentialVaultTestResponse,
    DescriptorCommunityExportResponse,
    DescriptorEditContainerDependencyRequest,
    DescriptorEditEndpointRequest,
    DescriptorEditMatchRequest,
    DescriptorEditMode,
    FindingDismissRequest,
    FindingDismissResponse,
    FindingFeedbackSuggestionAction,
    FindingReviewResponse,
    MaintenanceModeMutationResponse,
    MaintenanceModeResponse,
    MaintenanceWindowResponse,
    MaintenanceWindowUpdateRequest,
    ModelSettingsMutationResponse,
    ModelSettingsResponse,
    ModelSettingsSecretSource,
    ModelSettingsTestRequest,
    ModelSettingsTestResponse,
    ModelSettingsTestScope,
    ModelSettingsTestTarget,
    ModelSettingsUpdateRequest,
    MonitoringSettingsMutationResponse,
    MonitoringSettingsResolutionSource,
    MonitoringSettingsResponse,
    MonitoringSettingsUpdateRequest,
    NotificationSettingsMutationResponse,
    NotificationSettingsResponse,
    NotificationSettingsSecretSource,
    NotificationSettingsTestRequest,
    NotificationSettingsTestResponse,
    NotificationSettingsTestScope,
    NotificationSettingsUpdateRequest,
    QuarantinedDescriptorActionResponse,
    QuarantinedDescriptorQueueItemResponse,
    RecommendationActionResponse,
    RecommendationItemResponse,
    RecommendationsResponse,
    ServiceAdapterFactsItemResponse,
    ServiceAdapterFactsResponse,
    ServiceDescriptorGenerateResponse,
    ServiceDescriptorSaveRequest,
    ServiceDescriptorSaveResponse,
    ServiceDescriptorValidationResponse,
    ServiceDescriptorViewResponse,
    ServiceDetailCheckSuppressionMutationResponse,
    ServiceDetailCheckSuppressionUpdateRequest,
    ServiceDetailResponse,
    SystemSettingsLogLevel,
    SystemSettingsMutationResponse,
    SystemSettingsResponse,
    SystemSettingsUpdateRequest,
)
from kaval.discovery.descriptors import ServiceDescriptor
from kaval.integrations.adapter_fallback import AdapterFactFreshness
from kaval.integrations.service_adapters import (
    AdapterDiscoveredEdge,
    AdapterResult,
    AdapterStatus,
)
from kaval.integrations.webhooks import (
    WebhookAlertState,
    WebhookEvent,
    WebhookMatchingOutcome,
    WebhookProcessingStatus,
    WebhookSeverity,
    WebhookSourceType,
)
from kaval.models import (
    ActionType,
    ApprovalToken,
    ArrayProfile,
    Change,
    ChangeType,
    DescriptorSource,
    DnsRecordType,
    DnsTarget,
    Endpoint,
    EndpointProtocol,
    Evidence,
    EvidenceKind,
    EvidenceStep,
    ExecutorActionRequest,
    ExecutorActionResult,
    ExecutorActionStatus,
    Finding,
    FindingFeedbackReason,
    FindingStatus,
    HardwareProfile,
    Incident,
    IncidentLifecycleTransition,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    InvestigationTrigger,
    JournalConfidence,
    JournalEntry,
    MaintenanceScope,
    ModelUsed,
    NetworkingProfile,
    NotificationAction,
    NotificationActionStyle,
    NotificationActionType,
    NotificationPayload,
    NotificationSourceType,
    OperationalMemoryQuery,
    OperationalMemoryResult,
    PluginImpactService,
    PluginProfile,
    RedactionLevel,
    RemediationProposal,
    RemediationStatus,
    ResearchStep,
    RiskAssessment,
    RiskCheck,
    RiskCheckResult,
    RiskLevel,
    Service,
    ServiceInsight,
    ServiceLifecycle,
    ServiceLifecycleEvent,
    ServiceLifecycleEventType,
    ServiceLifecycleState,
    ServicesSummary,
    ServiceStatus,
    ServiceType,
    Severity,
    StorageProfile,
    SystemProfile,
    UserNote,
    VMProfile,
)
from kaval.schema_export import SCHEMA_MODELS, export_schemas

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for schema samples."""
    return datetime(2026, 3, 30, hour, minute, tzinfo=UTC)


def build_change() -> Change:
    """Create a reusable change record."""
    return Change(
        id="chg-1",
        type=ChangeType.IMAGE_UPDATE,
        service_id="svc-delugevpn",
        description="Updated DelugeVPN image",
        old_value="2.1.0",
        new_value="2.1.1",
        timestamp=ts(13, 45),
        correlated_incidents=["inc-1"],
    )


def build_adapter_result() -> AdapterResult:
    """Create a reusable adapter result sample."""
    return AdapterResult(
        adapter_id="radarr_api",
        status=AdapterStatus.SUCCESS,
        facts={
            "download_clients": [{"name": "DelugeVPN", "enabled": True}],
            "version": "5.0.3",
        },
        edges_discovered=[
            AdapterDiscoveredEdge(
                surface_id="download_clients",
                target_service_name="DelugeVPN",
                description="Radarr is configured to use DelugeVPN.",
            )
        ],
        timestamp=ts(14, 25),
        reason=None,
    )


def build_risk_assessment() -> RiskAssessment:
    """Create a reusable risk assessment record."""
    return RiskAssessment(
        overall_risk=RiskLevel.LOW,
        checks=[
            RiskCheck(
                check="container_exists",
                result=RiskCheckResult.PASS,
                detail="Container exists and is restartable.",
            )
        ],
        reversible=True,
        warnings=["Restart may briefly interrupt downloads."],
    )


def build_webhook_event() -> WebhookEvent:
    """Create a reusable normalized webhook event sample."""
    return WebhookEvent(
        source_type=WebhookSourceType.PROMETHEUS_ALERTMANAGER,
        source_id="primary-prometheus",
        source_event_id="group-7f3d8",
        dedup_key="prometheus:group-7f3d8:firing",
        received_at=ts(14, 27),
        alert_state=WebhookAlertState.FIRING,
        severity=WebhookSeverity.CRITICAL,
        title="Media pipeline degraded",
        body="Prometheus grouped alert for ARR download failures.",
        url="https://prometheus.example/graph?g0.expr=media_pipeline",
        tags={
            "alertname": "MediaPipelineDown",
            "environment": "homelab",
        },
        service_hints=["Radarr", "Sonarr"],
        matched_service_ids=["svc-radarr", "svc-sonarr"],
        matching_outcome=WebhookMatchingOutcome.MULTI,
        raw_payload={
            "status": "firing",
            "groupKey": "{}:{alertname=\"MediaPipelineDown\"}",
        },
        raw_payload_redacted=True,
        raw_payload_retention_until=ts(14, 27) + timedelta(days=30),
        processing_status=WebhookProcessingStatus.MATCHED,
    )


def build_finding() -> Finding:
    """Create a reusable finding sample."""
    return Finding(
        id="find-1",
        title="Radarr cannot reach download client",
        severity=Severity.HIGH,
        domain="arr",
        service_id="svc-radarr",
        summary="Radarr reports the download client is unavailable.",
        evidence=[
            Evidence(
                kind=EvidenceKind.LOG,
                source="radarr",
                summary="Download client not available",
                observed_at=ts(14, 24),
                data={"message": "Download client not available"},
            )
        ],
        impact="Download pipeline blocked.",
        confidence=0.88,
        status=FindingStatus.GROUPED,
        incident_id="inc-1",
        related_changes=[build_change()],
        created_at=ts(14, 24),
        resolved_at=None,
    )


def build_finding_review_response() -> FindingReviewResponse:
    """Create a reusable finding review payload sample."""
    return FindingReviewResponse(
        active_findings=[
            {
                "finding": build_finding().model_copy(
                    update={
                        "domain": "endpoint_probe",
                        "service_id": "svc-delugevpn",
                        "title": "DelugeVPN endpoint probe failed",
                        "summary": (
                            "The DelugeVPN web UI did not respond within the configured timeout."
                        ),
                        "impact": "The service may be down or timing out.",
                        "severity": Severity.MEDIUM,
                        "incident_id": None,
                        "created_at": ts(14, 30),
                        "related_changes": [],
                    }
                ),
                "service_name": "DelugeVPN",
                "domain_label": "Endpoint probe",
                "dismissal_reason": None,
                "dismissal_count_for_pattern": 5,
                "suggestion": {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "check_id": "endpoint_probe",
                    "check_label": "Endpoint probe",
                    "dismissal_count": 5,
                    "action": FindingFeedbackSuggestionAction.ADJUST_THRESHOLD_OR_SUPPRESS,
                    "message": (
                        "You've dismissed 5 endpoint probe findings for DelugeVPN. "
                        "Consider adjusting the threshold or suppressing this check."
                    ),
                },
            }
        ],
        recently_dismissed=[
            {
                "finding": build_finding().model_copy(
                    update={
                        "domain": "endpoint_probe",
                        "service_id": "svc-delugevpn",
                        "title": "DelugeVPN endpoint probe failed",
                        "summary": (
                            "The DelugeVPN web UI did not respond within the configured timeout."
                        ),
                        "impact": "The service may be down or timing out.",
                        "severity": Severity.MEDIUM,
                        "incident_id": None,
                        "status": FindingStatus.DISMISSED,
                        "created_at": ts(14, 20),
                        "resolved_at": ts(14, 25),
                        "related_changes": [],
                    }
                ),
                "service_name": "DelugeVPN",
                "domain_label": "Endpoint probe",
                "dismissal_reason": FindingFeedbackReason.FALSE_POSITIVE,
                "dismissal_count_for_pattern": 5,
                "suggestion": {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "check_id": "endpoint_probe",
                    "check_label": "Endpoint probe",
                    "dismissal_count": 5,
                    "action": FindingFeedbackSuggestionAction.ADJUST_THRESHOLD_OR_SUPPRESS,
                    "message": (
                        "You've dismissed 5 endpoint probe findings for DelugeVPN. "
                        "Consider adjusting the threshold or suppressing this check."
                    ),
                },
            }
        ],
        suggestions=[
            {
                "service_id": "svc-delugevpn",
                "service_name": "DelugeVPN",
                "check_id": "endpoint_probe",
                "check_label": "Endpoint probe",
                "dismissal_count": 5,
                "action": FindingFeedbackSuggestionAction.ADJUST_THRESHOLD_OR_SUPPRESS,
                "message": (
                    "You've dismissed 5 endpoint probe findings for DelugeVPN. "
                    "Consider adjusting the threshold or suppressing this check."
                ),
            }
        ],
    )


def build_finding_dismiss_request() -> FindingDismissRequest:
    """Create a reusable finding dismiss request payload sample."""
    return FindingDismissRequest(reason=FindingFeedbackReason.ALREADY_AWARE)


def build_finding_dismiss_response() -> FindingDismissResponse:
    """Create a reusable finding dismiss response payload sample."""
    return FindingDismissResponse(
        finding=build_finding().model_copy(
            update={
                "status": FindingStatus.DISMISSED,
                "resolved_at": ts(14, 40),
            }
        ),
        review=build_finding_review_response(),
        audit_change=build_change(),
    )


def build_maintenance_mode_response() -> MaintenanceModeResponse:
    """Create a reusable maintenance-mode payload sample."""
    return MaintenanceModeResponse(
        global_window=MaintenanceWindowResponse(
            scope=MaintenanceScope.GLOBAL,
            service_id=None,
            service_name=None,
            started_at=ts(14, 30),
            expires_at=ts(15, 0),
            minutes_remaining=30,
        ),
        service_windows=[
            MaintenanceWindowResponse(
                scope=MaintenanceScope.SERVICE,
                service_id="svc-delugevpn",
                service_name="DelugeVPN",
                started_at=ts(14, 35),
                expires_at=ts(16, 35),
                minutes_remaining=120,
            )
        ],
        self_health_guardrail=(
            "Global maintenance suppresses normal findings and incident notifications, "
            "but critical Kaval self-health remains unsuppressed."
        ),
    )


def build_maintenance_window_update_request() -> MaintenanceWindowUpdateRequest:
    """Create a reusable maintenance-window update payload sample."""
    return MaintenanceWindowUpdateRequest(duration_minutes=45)


def build_maintenance_mode_mutation_response() -> MaintenanceModeMutationResponse:
    """Create a reusable maintenance-mode mutation response sample."""
    return MaintenanceModeMutationResponse(
        maintenance=build_maintenance_mode_response(),
        audit_change=build_change(),
    )


def build_recommendations_response() -> RecommendationsResponse:
    """Create a reusable proactive recommendations payload sample."""
    return RecommendationsResponse(
        items=[
            RecommendationItemResponse(
                id="missing-descriptors",
                kind="missing_descriptor",
                title="2 services are missing descriptors",
                detail=(
                    "custom-app is the highest-impact unmatched service with 2 downstream "
                    "dependents. Local descriptor generation is available after review."
                ),
                action=RecommendationActionResponse(
                    label="Review custom-app",
                    target="service_detail",
                    service_id="svc-custom-app",
                ),
            ),
            RecommendationItemResponse(
                id="cloud-model",
                kind="cloud_model",
                title="Cloud escalation is not configured",
                detail=(
                    "Investigations are currently local-only. For complex multi-service "
                    "incidents, consider adding a bounded cloud escalation path."
                ),
                action=RecommendationActionResponse(
                    label="Open model settings",
                    target="model_settings",
                    service_id=None,
                ),
            ),
        ]
    )


def build_incident() -> Incident:
    """Create a reusable incident sample."""
    return Incident(
        id="inc-1",
        title="Radarr and Sonarr failing",
        severity=Severity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        trigger_findings=["find-1"],
        all_findings=["find-1", "find-2"],
        affected_services=["svc-radarr", "svc-sonarr", "svc-delugevpn"],
        triggering_symptom="Radarr health check failing",
        suspected_cause="DelugeVPN VPN tunnel inactive",
        confirmed_cause=None,
        root_cause_service="svc-delugevpn",
        resolution_mechanism=None,
        cause_confirmation_source=None,
        confidence=0.92,
        investigation_id="inv-1",
        approved_actions=[],
        changes_correlated=["chg-1"],
        grouping_window_start=ts(14, 23),
        grouping_window_end=ts(14, 28),
        created_at=ts(14, 23),
        updated_at=ts(14, 28),
        resolved_at=None,
        mttr_seconds=None,
        journal_entry_id=None,
    )


def build_investigation() -> Investigation:
    """Create a reusable investigation sample."""
    return Investigation(
        id="inv-1",
        incident_id="inc-1",
        trigger=InvestigationTrigger.AUTO,
        status=InvestigationStatus.COMPLETED,
        evidence_steps=[
            EvidenceStep(
                order=1,
                action="read_container_logs",
                target="delugevpn",
                result_summary="VPN tunnel inactive appears in recent logs.",
                result_data={"sample": "VPN tunnel inactive"},
                timestamp=ts(14, 25),
            )
        ],
        research_steps=[
            ResearchStep(
                order=1,
                action="query_operational_memory",
                source="sqlite://operational-memory",
                result_summary="Three matching recurrence entries found.",
                timestamp=ts(14, 26),
            )
        ],
        root_cause="DelugeVPN lost its VPN tunnel.",
        confidence=0.95,
        model_used=ModelUsed.LOCAL,
        cloud_model_calls=0,
        local_input_tokens=410,
        local_output_tokens=92,
        cloud_input_tokens=0,
        cloud_output_tokens=0,
        estimated_cloud_cost_usd=0.0,
        estimated_total_cost_usd=0.0,
        cloud_escalation_reason=None,
        journal_entries_referenced=["jrnl-1"],
        user_notes_referenced=["note-1"],
        recurrence_count=3,
        remediation=RemediationProposal(
            action_type=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            rationale="Restarting the VPN container restores the dependency chain.",
            risk_assessment=build_risk_assessment(),
            status=RemediationStatus.PROPOSED,
        ),
        started_at=ts(14, 24),
        completed_at=ts(14, 27),
    )


def build_service() -> Service:
    """Create a reusable service sample."""
    return Service(
        id="svc-delugevpn",
        name="DelugeVPN",
        type=ServiceType.CONTAINER,
        category="downloads",
        status=ServiceStatus.DEGRADED,
        descriptor_id="downloads/delugevpn",
        descriptor_source=DescriptorSource.SHIPPED,
        container_id="container-123",
        vm_id=None,
        image="binhex/arch-delugevpn:2.1.1",
        endpoints=[
            Endpoint(
                name="web",
                protocol=EndpointProtocol.HTTP,
                host="delugevpn",
                port=8112,
                path="/",
                url=None,
                auth_required=False,
                expected_status=200,
            )
        ],
        dns_targets=[
            DnsTarget(
                host="downloads.example.test",
                record_type=DnsRecordType.A,
                expected_values=["192.0.2.10"],
            )
        ],
        dependencies=[],
        dependents=["svc-radarr", "svc-sonarr"],
        last_check=ts(14, 24),
        active_findings=2,
        active_incidents=1,
    )


def build_service_insight() -> ServiceInsight:
    """Create a reusable service-insight sample."""
    return ServiceInsight(level=2)


def build_service_lifecycle() -> ServiceLifecycle:
    """Create a reusable service lifecycle sample."""
    return ServiceLifecycle(
        state=ServiceLifecycleState.MISSING,
        last_event=ServiceLifecycleEventType.SERVICE_REMOVED_UNEXPECTEDLY,
        changed_at=ts(14, 30),
        previous_names=["DelugeVPN"],
        previous_descriptor_ids=["downloads/delugevpn"],
    )


def build_service_lifecycle_event() -> ServiceLifecycleEvent:
    """Create a reusable lifecycle event sample."""
    return ServiceLifecycleEvent(
        service_id="svc-delugevpn",
        event_type=ServiceLifecycleEventType.SERVICE_REMOVED_UNEXPECTEDLY,
        timestamp=ts(14, 30),
        summary="Service unexpectedly disappeared and now requires confirmation: DelugeVPN.",
        change_id="chg-service_missing-svc-delugevpn-20260403T143000Z",
        related_service_ids=["svc-radarr", "svc-sonarr"],
    )


def build_system_profile() -> SystemProfile:
    """Create a reusable system profile sample."""
    return SystemProfile(
        hostname="zactower",
        unraid_version="7.2.1",
        hardware=HardwareProfile(
            cpu="Intel i3-12100T",
            memory_gb=32.0,
            gpu="NVIDIA",
            ups="APC Back-UPS",
        ),
        storage=StorageProfile(
            array=ArrayProfile(
                parity_drives=1,
                data_drives=4,
                cache="2x NVMe RAID 1",
                total_tb=12.0,
                used_tb=4.2,
            )
        ),
        networking=NetworkingProfile(
            domain="zactower.com",
            dns_provider="cloudflare",
            reverse_proxy="nginx_proxy_manager",
            tunnel="cloudflare_zero_trust",
            vpn="wireguard",
            dns_resolver="pihole",
            ssl_strategy="cloudflare_origin_certs",
        ),
        services_summary=ServicesSummary(
            total_containers=25,
            total_vms=3,
            matched_descriptors=22,
        ),
        vms=[
            VMProfile(
                name="Ubuntu Server",
                purpose="Hosts Moodle LMS + MariaDB",
                os="Ubuntu 22.04 LTS",
                quirks="LVM default partition is only ~10GB regardless of vdisk size",
            )
        ],
        plugins=[
            PluginProfile(
                name="community.applications",
                version="2026.03.30",
                enabled=True,
                update_available=False,
                impacted_services=[
                    PluginImpactService(
                        service_id="svc-radarr",
                        service_name="Radarr",
                        descriptor_id="arr/radarr",
                    )
                ],
            )
        ],
        last_updated=ts(14),
    )


def build_journal_entry() -> JournalEntry:
    """Create a reusable journal entry sample."""
    return JournalEntry(
        id="jrnl-1",
        incident_id="inc-1",
        date=date(2026, 3, 1),
        services=["svc-delugevpn", "svc-radarr", "svc-sonarr"],
        summary="VPN tunnel dropped after ISP IP change.",
        root_cause="ISP rotated public IP and the VPN tunnel did not reconnect.",
        resolution="Restarted DelugeVPN.",
        time_to_resolution_minutes=3.0,
        model_used="local",
        tags=["delugevpn", "vpn", "recurring"],
        lesson="Restart has consistently resolved this issue.",
        recurrence_count=3,
        confidence=JournalConfidence.CONFIRMED,
        user_confirmed=True,
        last_verified_at=ts(15),
        applies_to_version=None,
        superseded_by=None,
        stale_after_days=90,
    )


def build_user_note() -> UserNote:
    """Create a reusable user note sample."""
    return UserNote(
        id="note-1",
        service_id="svc-delugevpn",
        note="Restart has historically been safe for this container.",
        safe_for_model=True,
        last_verified_at=ts(15),
        stale=False,
        added_at=ts(12),
        updated_at=ts(15),
    )


def build_approval_token() -> ApprovalToken:
    """Create a reusable approval token sample."""
    return ApprovalToken(
        token_id="tok-1",
        incident_id="inc-1",
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approved_by="user_via_telegram",
        issued_at=ts(14, 30),
        expires_at=ts(14, 35),
        nonce="nonce-1",
        hmac_signature="deadbeef",
        used_at=None,
        result=None,
    )


def build_service_descriptor() -> ServiceDescriptor:
    """Create a reusable service descriptor sample."""
    return ServiceDescriptor(
        id="radarr",
        name="Radarr",
        category="arr",
        project_url="https://radarr.video",
        icon="radarr.svg",
        match={
            "image_patterns": [
                "lscr.io/linuxserver/radarr*",
                "hotio/radarr*",
                "*radarr*",
            ],
            "container_name_patterns": ["radarr*"],
        },
        endpoints={
            "web_ui": {"port": 7878, "path": "/"},
            "health_api": {
                "port": 7878,
                "path": "/api/v3/health",
                "auth": "api_key",
                "auth_header": "X-Api-Key",
                "healthy_when": "json_array_empty",
            },
        },
        dns_targets=[
            {
                "host": "radarr.example.test",
                "record_type": "A",
                "expected_values": ["192.0.2.20"],
            }
        ],
        log_signals={
            "errors": [
                "Unable to connect to indexer",
                "Download client .* not available",
            ],
            "warnings": ["No indexers available"],
        },
        typical_dependencies={
            "containers": [
                "prowlarr",
                {"name": "delugevpn", "alternatives": ["qbittorrent", "transmission"]},
            ],
            "shares": ["media", "downloads"],
        },
        common_failure_modes=[
            {
                "trigger": "Download client .* not available",
                "likely_cause": "Download client container is down or has lost VPN tunnel",
                "check_first": ["delugevpn", "qbittorrent"],
            }
        ],
        investigation_context="Radarr health returns an empty array when healthy.",
        inspection={
            "surfaces": [
                {
                    "id": "health_api",
                    "type": "api",
                    "description": "Radarr health diagnostics",
                    "endpoint": "/api/v3/health",
                    "auth": "api_key",
                    "auth_header": "X-Api-Key",
                    "read_only": True,
                    "facts_provided": [
                        "health_issues",
                        "download_client_status",
                        "indexer_status",
                    ],
                    "confidence_effect": "upgrade_to_runtime_observed",
                    "version_range": ">=3.0",
                }
            ]
        },
        credential_hints={
            "api_key": {
                "description": "Radarr API Key",
                "location": "Radarr Web UI → Settings → General → API Key",
                "prompt": "Provide the Radarr API key to enable deep inspection.",
            }
        },
    )


def build_service_adapter_facts_response() -> ServiceAdapterFactsResponse:
    """Create a reusable adapter-facts API response sample."""
    return ServiceAdapterFactsResponse(
        service_id="svc-radarr",
        service_name="Radarr",
        checked_at=ts(14, 30),
        facts_available=True,
        adapters=[
            ServiceAdapterFactsItemResponse(
                adapter_id="radarr_api",
                display_name="Radarr API",
                service_id="svc-radarr",
                service_name="Radarr",
                source=AdapterFactSourceType.DEEP_INSPECTION_ADAPTER,
                read_only=True,
                configuration_state="configured",
                configuration_summary="Required adapter inputs are configured.",
                health_state="healthy",
                health_summary="Adapter returned prompt-safe facts successfully.",
                missing_credentials=[],
                supported_fact_names=[
                    "download_client_status",
                    "health_issues",
                ],
                execution_status=AdapterStatus.SUCCESS,
                facts_available=True,
                facts={
                    "health_issues": [
                        {
                            "type": "error",
                            "message": "Download client unavailable",
                        }
                    ],
                    "download_client_status": {"available": False},
                },
                excluded_paths=["api_key"],
                applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
                facts_observed_at=ts(14, 25),
                stale_at=ts(15, 25),
                next_refresh_at=ts(14, 55),
                refresh_interval_minutes=30,
                freshness=AdapterFactFreshness.CURRENT,
                reason=None,
            )
        ],
    )


def build_service_detail_response() -> ServiceDetailResponse:
    """Create a reusable service-detail response sample."""
    return ServiceDetailResponse(
        service=build_service(),
        insight_section={
            "current_level": 2,
            "adapter_available": True,
            "adapters": [
                {
                    "adapter_id": "radarr_api",
                    "display_name": "Radarr API",
                    "configuration_state": "configured",
                    "configuration_summary": "Required adapter inputs are configured.",
                    "health_state": "healthy",
                    "health_summary": "Adapter returned prompt-safe facts successfully.",
                    "missing_credentials": [],
                    "supported_fact_names": ["health_issues"],
                }
            ],
            "improve_actions": [],
            "fact_summary_available": True,
        },
        monitoring_section={
            "checks": [
                {
                    "check_id": "endpoint_probe",
                    "label": "Endpoint probe",
                    "description": (
                        "Probe declared HTTP and HTTPS endpoints that do not require auth."
                    ),
                    "inherited_enabled": True,
                    "inherited_interval_seconds": 120,
                    "effective_enabled": False,
                    "effective_interval_seconds": 120,
                    "source": MonitoringSettingsResolutionSource.SERVICE_OVERRIDE,
                    "suppressed": True,
                    "override_enabled": False,
                    "override_interval_seconds": None,
                    "override_updated_at": ts(14, 40),
                }
            ]
        },
    )


def build_service_detail_check_suppression_update_request(
    *,
    suppressed: bool = True,
) -> ServiceDetailCheckSuppressionUpdateRequest:
    """Create a reusable suppression-toggle request sample."""
    return ServiceDetailCheckSuppressionUpdateRequest(suppressed=suppressed)


def build_service_detail_check_suppression_mutation_response(
    *,
    suppressed: bool = True,
) -> ServiceDetailCheckSuppressionMutationResponse:
    """Create a reusable suppression-toggle mutation response sample."""
    detail = build_service_detail_response()
    if not suppressed:
        check = detail.monitoring_section.checks[0]
        check.effective_enabled = True
        check.source = MonitoringSettingsResolutionSource.GLOBAL_DEFAULT
        check.suppressed = False
        check.override_enabled = None
        check.override_updated_at = None
    return ServiceDetailCheckSuppressionMutationResponse(
        detail=detail,
        audit_change=build_change(),
    )


def build_service_descriptor_view_response() -> ServiceDescriptorViewResponse:
    """Create a reusable rendered descriptor-view payload sample."""
    return ServiceDescriptorViewResponse(
        descriptor_id="arr/radarr",
        file_path="services/arr/radarr.yaml",
        write_target_path="services/user/arr/radarr.yaml",
        name="Radarr",
        category="arr",
        source=DescriptorSource.SHIPPED,
        verified=True,
        generated_at=None,
        project_url="https://github.com/Radarr/Radarr",
        icon="radarr",
        match={
            "image_patterns": [
                "lscr.io/linuxserver/radarr*",
                "hotio/radarr*",
            ],
            "container_name_patterns": [],
        },
        endpoints=[
            {
                "name": "health_api",
                "port": 7878,
                "path": "/api/v3/health",
                "auth": "api_key",
                "auth_header": "X-Api-Key",
                "healthy_when": "json_status_ok",
            }
        ],
        dns_targets=[
            {
                "host": "radarr.example.test",
                "record_type": "A",
                "expected_values": ["192.0.2.20"],
            }
        ],
        log_signals={
            "errors": ["Download client .* not available"],
            "warnings": ["No indexers available"],
        },
        typical_dependency_containers=[
            {
                "name": "prowlarr",
                "alternatives": [],
            }
        ],
        typical_dependency_shares=["downloads"],
        common_failure_modes=[
            {
                "trigger": "Download client .* not available",
                "likely_cause": "Download client container is down or unreachable.",
                "check_first": ["delugevpn"],
            }
        ],
        investigation_context="Radarr health returns an empty array when healthy.",
        inspection_surfaces=[
            {
                "id": "health_api",
                "type": "api",
                "description": "Radarr health diagnostics",
                "endpoint": "/api/v3/health",
                "auth": "api_key",
                "auth_header": "X-Api-Key",
                "read_only": True,
                "facts_provided": ["health_issues"],
                "confidence_effect": "upgrade_to_runtime_observed",
                "version_range": ">=3.0",
            }
        ],
        credential_hints=[
            {
                "key": "api_key",
                "description": "Radarr API Key",
                "location": "Radarr Web UI -> Settings -> General -> API Key",
                "prompt": "Provide the Radarr API key to enable deep inspection.",
            }
        ],
        raw_yaml=(
            "id: radarr\n"
            "name: Radarr\n"
            "category: arr\n"
            "source: shipped\n"
            "verified: true\n"
        ),
    )


def build_service_descriptor_save_request() -> ServiceDescriptorSaveRequest:
    """Create a reusable descriptor-save request payload sample."""
    return ServiceDescriptorSaveRequest(
        mode=DescriptorEditMode.FORM,
        match=DescriptorEditMatchRequest(
            image_patterns=["lscr.io/linuxserver/radarr*"],
            container_name_patterns=[],
        ),
        endpoints=[
            DescriptorEditEndpointRequest(
                name="health_api",
                port=7878,
                path="/api/v3/health",
                auth="api_key",
                auth_header="X-Api-Key",
                healthy_when="json_status_ok",
            )
        ],
        typical_dependency_containers=[
            DescriptorEditContainerDependencyRequest(
                name="prowlarr",
                alternatives=[],
            )
        ],
        typical_dependency_shares=["downloads"],
    )


def build_service_descriptor_save_response() -> ServiceDescriptorSaveResponse:
    """Create a reusable descriptor-save response payload sample."""
    return ServiceDescriptorSaveResponse(
        descriptor=build_service_descriptor_view_response(),
        audit_change=build_change(),
    )


def build_service_descriptor_generate_response() -> ServiceDescriptorGenerateResponse:
    """Create a reusable auto-generated descriptor trigger response payload sample."""
    return ServiceDescriptorGenerateResponse(
        service_id="svc-custom-app",
        service_name="custom-app",
        descriptor=build_service_descriptor_view_response().model_copy(
            update={
                "descriptor_id": "custom/custom_app",
                "file_path": "services/auto_generated/custom/custom_app.yaml",
                "write_target_path": "services/user/custom/custom_app.yaml",
                "name": "Custom App",
                "category": "custom",
                "source": DescriptorSource.AUTO_GENERATED,
                "verified": False,
                "generated_at": ts(14, 30),
                "inspection_surfaces": [],
                "credential_hints": [],
                "raw_yaml": (
                    "id: custom_app\n"
                    "name: Custom App\n"
                    "category: custom\n"
                    "source: auto_generated\n"
                    "verified: false\n"
                    "generated_at: 2026-03-31T14:30:00Z\n"
                ),
            }
        ),
        audit_change=build_change(),
        warnings=[
            "Quarantined auto-generated descriptors stay inactive until review and promotion."
        ],
    )


def build_quarantined_descriptor_queue_item_response() -> QuarantinedDescriptorQueueItemResponse:
    """Create a reusable quarantined descriptor queue item payload sample."""
    return QuarantinedDescriptorQueueItemResponse(
        descriptor=build_service_descriptor_generate_response().descriptor,
        review_state="deferred",
        review_updated_at=ts(14, 35),
        matching_services=[
            build_service().model_copy(
                update={
                    "id": "svc-custom-app",
                    "name": "custom-app",
                    "descriptor_id": None,
                    "descriptor_source": None,
                    "image": "ghcr.io/example/custom-app:1.0.0",
                }
            )
        ],
    )


def build_quarantined_descriptor_action_response() -> QuarantinedDescriptorActionResponse:
    """Create a reusable quarantined descriptor action payload sample."""
    return QuarantinedDescriptorActionResponse(
        descriptor_id="custom/custom_app",
        action="deferred",
        review_state="deferred",
        descriptor=build_service_descriptor_generate_response().descriptor,
        audit_change=build_change(),
    )


def build_descriptor_community_export_response() -> DescriptorCommunityExportResponse:
    """Create a reusable community descriptor export payload sample."""
    return DescriptorCommunityExportResponse(
        descriptor_id="custom/custom_app",
        target_path="services/custom/custom_app.yaml",
        yaml_text=(
            "id: custom_app\n"
            "name: Custom App\n"
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
        ),
        omitted_fields=["source", "verified", "generated_at"],
    )


def build_model_settings_response() -> ModelSettingsResponse:
    """Create a reusable staged/active model settings payload sample."""
    return ModelSettingsResponse(
        config_path="/data/kaval.yaml",
        load_error=None,
        apply_required=True,
        last_applied_at=ts(14, 50),
        active={
            "local": {
                "enabled": False,
                "provider": "openai_compatible",
                "model": None,
                "base_url": "http://localhost:11434",
                "timeout_seconds": 30.0,
                "api_key_ref": None,
                "api_key_source": ModelSettingsSecretSource.UNSET,
                "api_key_configured": False,
                "configured": False,
            },
            "cloud": {
                "enabled": False,
                "provider": "anthropic",
                "model": None,
                "base_url": "https://api.anthropic.com",
                "timeout_seconds": 45.0,
                "max_output_tokens": 1600,
                "api_key_ref": None,
                "api_key_source": ModelSettingsSecretSource.UNSET,
                "api_key_configured": False,
                "configured": False,
            },
            "escalation": {
                "finding_count_gt": 3,
                "local_confidence_lt": 0.6,
                "escalate_on_multiple_domains": True,
                "escalate_on_changelog_research": True,
                "escalate_on_user_request": False,
                "max_cloud_calls_per_day": 20,
                "max_cloud_calls_per_incident": 3,
            },
        },
        staged={
            "local": {
                "enabled": True,
                "provider": "openai_compatible",
                "model": "qwen3:14b",
                "base_url": "http://localhost:11434",
                "timeout_seconds": 12.0,
                "api_key_ref": "vault:settings:models:local_api_key",
                "api_key_source": ModelSettingsSecretSource.VAULT,
                "api_key_configured": True,
                "configured": True,
            },
            "cloud": {
                "enabled": True,
                "provider": "anthropic",
                "model": "claude-sonnet-4-20250514",
                "base_url": "https://api.anthropic.com",
                "timeout_seconds": 25.0,
                "max_output_tokens": 800,
                "api_key_ref": "vault:settings:models:cloud_api_key",
                "api_key_source": ModelSettingsSecretSource.VAULT,
                "api_key_configured": True,
                "configured": True,
            },
            "escalation": {
                "finding_count_gt": 4,
                "local_confidence_lt": 0.55,
                "escalate_on_multiple_domains": True,
                "escalate_on_changelog_research": True,
                "escalate_on_user_request": False,
                "max_cloud_calls_per_day": 20,
                "max_cloud_calls_per_incident": 3,
            },
        },
    )


def build_model_settings_update_request() -> ModelSettingsUpdateRequest:
    """Create a reusable model settings update payload sample."""
    return ModelSettingsUpdateRequest(
        local={
            "enabled": True,
            "model": "qwen3:14b",
            "base_url": "http://localhost:11434",
            "timeout_seconds": 12.0,
            "api_key": "write-only-local-secret",
            "clear_stored_api_key": False,
        },
        cloud={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "base_url": "https://api.anthropic.com",
            "timeout_seconds": 25.0,
            "max_output_tokens": 800,
            "api_key": "write-only-cloud-secret",
            "clear_stored_api_key": False,
        },
        escalation={
            "finding_count_gt": 4,
            "local_confidence_lt": 0.55,
            "escalate_on_multiple_domains": True,
            "escalate_on_changelog_research": True,
            "escalate_on_user_request": False,
            "max_cloud_calls_per_day": 20,
            "max_cloud_calls_per_incident": 3,
        },
    )


def build_model_settings_mutation_response() -> ModelSettingsMutationResponse:
    """Create a reusable model settings mutation response payload sample."""
    return ModelSettingsMutationResponse(
        settings=build_model_settings_response(),
        audit_change=build_change(),
    )


def build_model_settings_test_request() -> ModelSettingsTestRequest:
    """Create a reusable model settings test request payload sample."""
    return ModelSettingsTestRequest(
        target=ModelSettingsTestTarget.LOCAL,
        scope=ModelSettingsTestScope.STAGED,
    )


def build_model_settings_test_response() -> ModelSettingsTestResponse:
    """Create a reusable model settings test response payload sample."""
    return ModelSettingsTestResponse(
        target=ModelSettingsTestTarget.CLOUD,
        scope=ModelSettingsTestScope.STAGED,
        ok=True,
        checked_at=ts(14, 55),
        message="Cloud model endpoint accepted the explicit settings test.",
    )


def build_notification_settings_response() -> NotificationSettingsResponse:
    """Create a reusable staged/active notification settings payload sample."""
    return NotificationSettingsResponse(
        config_path="/data/kaval.yaml",
        load_error=None,
        apply_required=True,
        last_applied_at=ts(15, 0),
        active={
            "channels": [],
            "routing": {
                "critical": "immediate",
                "high": "immediate_with_dedup",
                "medium": "hourly_digest",
                "low": "dashboard_only",
                "dedup_window_minutes": 15,
                "digest_window_minutes": 60,
            },
            "quiet_hours": {
                "enabled": False,
                "start_time_local": "22:00",
                "end_time_local": "07:00",
                "timezone": "UTC",
                "active_now": False,
                "quiet_until": None,
            },
            "configured_channel_count": 0,
        },
        staged={
            "channels": [
                {
                    "id": "channel-1",
                    "name": "Primary Discord",
                    "kind": "discord",
                    "enabled": True,
                    "destination_ref": (
                        "vault:settings:notifications:channels:channel-1:destination"
                    ),
                    "destination_source": NotificationSettingsSecretSource.VAULT,
                    "destination_configured": True,
                }
            ],
            "routing": {
                "critical": "immediate",
                "high": "immediate_with_dedup",
                "medium": "hourly_digest",
                "low": "dashboard_only",
                "dedup_window_minutes": 20,
                "digest_window_minutes": 30,
            },
            "quiet_hours": {
                "enabled": True,
                "start_time_local": "22:00",
                "end_time_local": "07:00",
                "timezone": "UTC",
                "active_now": True,
                "quiet_until": ts(23, 0),
            },
            "configured_channel_count": 1,
        },
    )


def build_notification_settings_update_request() -> NotificationSettingsUpdateRequest:
    """Create a reusable notification settings update payload sample."""
    return NotificationSettingsUpdateRequest(
        channels=[
            {
                "id": None,
                "name": "Primary Discord",
                "enabled": True,
                "destination": "write-only-discord-destination",
            }
        ],
        routing={
            "critical": "immediate",
            "high": "immediate_with_dedup",
            "medium": "hourly_digest",
            "low": "dashboard_only",
            "dedup_window_minutes": 20,
            "digest_window_minutes": 30,
        },
        quiet_hours={
            "enabled": True,
            "start_time_local": "22:00",
            "end_time_local": "07:00",
            "timezone": "UTC",
        },
    )


def build_notification_settings_mutation_response() -> NotificationSettingsMutationResponse:
    """Create a reusable notification settings mutation response payload sample."""
    return NotificationSettingsMutationResponse(
        settings=build_notification_settings_response(),
        audit_change=build_change(),
    )


def build_notification_settings_test_request() -> NotificationSettingsTestRequest:
    """Create a reusable notification settings test request payload sample."""
    return NotificationSettingsTestRequest(
        channel_id="channel-1",
        scope=NotificationSettingsTestScope.STAGED,
    )


def build_notification_settings_test_response() -> NotificationSettingsTestResponse:
    """Create a reusable notification settings test response payload sample."""
    return NotificationSettingsTestResponse(
        channel_id="channel-1",
        scope=NotificationSettingsTestScope.ACTIVE,
        ok=True,
        checked_at=ts(15, 5),
        message="Explicit notification channel test delivered successfully.",
    )


def build_system_settings_response() -> SystemSettingsResponse:
    """Create a reusable staged/active system settings payload sample."""
    return SystemSettingsResponse(
        config_path="/data/kaval.yaml",
        load_error=None,
        apply_required=True,
        last_applied_at=ts(15, 15),
        active={
            "log_level": "warning",
            "audit_detail_retention_days": 90,
            "audit_summary_retention_days": 365,
        },
        staged={
            "log_level": "debug",
            "audit_detail_retention_days": 120,
            "audit_summary_retention_days": 400,
        },
        database={
            "path": "/data/kaval.db",
            "exists": True,
            "size_bytes": 1048576,
            "migrations_current": True,
            "quick_check_ok": True,
            "quick_check_result": "ok",
            "journal_mode": "wal",
        },
        transfer_guidance={
            "phase_guardrail": (
                "Phase 3C exposes warnings and scope only. Automated backup, export, "
                "and import execution stays out of scope until Phase 4."
            ),
            "exports": [
                {
                    "target": "operational_memory",
                    "label": "Operational memory",
                    "available": False,
                    "sensitivity": "high",
                    "warning": (
                        "Operational-memory exports can contain sensitive incident context, "
                        "user notes, system topology, and credential references."
                    ),
                }
            ],
            "imports": [
                {
                    "target": "descriptors",
                    "label": "Descriptor import",
                    "available": False,
                    "warning": (
                        "Descriptor imports can activate sensitive topology assumptions. "
                        "Review and promote descriptors explicitly before runtime use."
                    ),
                }
            ],
        },
        about={
            "api_title": "Kaval API",
            "api_version": "0.1.0",
            "api_summary": "Phase 2 monitoring, investigation, and UAC API.",
            "checked_at": ts(15, 16),
            "started_at": ts(15, 0),
            "uptime_seconds": 960.0,
            "runtime_log_level": "warning",
            "settings_path": "/data/kaval.yaml",
            "database_path": "/data/kaval.db",
            "services_dir": "/opt/kaval/services",
            "web_dist_dir": "/opt/kaval/web/dist",
            "web_bundle_present": True,
            "model_status": {
                "local_model_enabled": True,
                "local_model_configured": True,
                "local_model_summary": "Enabled · qwen3:14b · http://localhost:11434",
                "cloud_model_enabled": False,
                "cloud_model_configured": False,
                "cloud_model_summary": "Disabled",
                "escalation_summary": "Finding>4, confidence<0.55, caps 20/day and 3/incident",
            },
        },
    )


def build_system_settings_update_request() -> SystemSettingsUpdateRequest:
    """Create a reusable system settings update payload sample."""
    return SystemSettingsUpdateRequest(
        log_level=SystemSettingsLogLevel.DEBUG,
        audit_detail_retention_days=120,
        audit_summary_retention_days=400,
    )


def build_system_settings_mutation_response() -> SystemSettingsMutationResponse:
    """Create a reusable system settings mutation response payload sample."""
    return SystemSettingsMutationResponse(
        settings=build_system_settings_response(),
        audit_change=build_change(),
    )


def build_monitoring_settings_response() -> MonitoringSettingsResponse:
    """Create a reusable staged/active monitoring settings payload sample."""
    return MonitoringSettingsResponse(
        config_path="/data/kaval.yaml",
        load_error=None,
        apply_required=True,
        last_applied_at=ts(15, 10),
        active={
            "checks": [
                {
                    "check_id": "endpoint_probe",
                    "label": "Endpoint probe",
                    "description": (
                        "Probe declared HTTP and HTTPS endpoints that do not require auth."
                    ),
                    "enabled": True,
                    "interval_seconds": 120,
                    "tls_warning_days": None,
                    "restart_delta_threshold": None,
                    "probe_timeout_seconds": 5.0,
                    "default_enabled": True,
                    "default_interval_seconds": 120,
                    "default_tls_warning_days": None,
                    "default_restart_delta_threshold": None,
                    "default_probe_timeout_seconds": 5.0,
                }
            ],
            "service_overrides": [],
            "effective_services": [
                {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "service_status": "degraded",
                    "checks": [
                        {
                            "check_id": "endpoint_probe",
                            "label": "Endpoint probe",
                            "enabled": True,
                            "base_interval_seconds": 120,
                            "effective_interval_seconds": 120,
                            "source": MonitoringSettingsResolutionSource.GLOBAL_DEFAULT,
                            "tls_warning_days": None,
                            "restart_delta_threshold": None,
                            "probe_timeout_seconds": 5.0,
                            "threshold_source": MonitoringSettingsResolutionSource.GLOBAL_DEFAULT,
                            "accelerated_now": False,
                            "incident_ids": [],
                        }
                    ],
                }
            ],
        },
        staged={
            "checks": [
                {
                    "check_id": "endpoint_probe",
                    "label": "Endpoint probe",
                    "description": (
                        "Probe declared HTTP and HTTPS endpoints that do not require auth."
                    ),
                    "enabled": True,
                    "interval_seconds": 75,
                    "tls_warning_days": None,
                    "restart_delta_threshold": None,
                    "probe_timeout_seconds": 2.5,
                    "default_enabled": True,
                    "default_interval_seconds": 120,
                    "default_tls_warning_days": None,
                    "default_restart_delta_threshold": None,
                    "default_probe_timeout_seconds": 5.0,
                }
            ],
            "service_overrides": [
                {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "service_status": "degraded",
                    "check_id": "endpoint_probe",
                    "check_label": "Endpoint probe",
                    "enabled": False,
                    "interval_seconds": 45,
                    "tls_warning_days": None,
                    "restart_delta_threshold": None,
                    "probe_timeout_seconds": 2.5,
                    "updated_at": ts(15, 12),
                }
            ],
            "effective_services": [
                {
                    "service_id": "svc-delugevpn",
                    "service_name": "DelugeVPN",
                    "service_status": "degraded",
                    "checks": [
                        {
                            "check_id": "endpoint_probe",
                            "label": "Endpoint probe",
                            "enabled": False,
                            "base_interval_seconds": 45,
                            "effective_interval_seconds": 45,
                            "source": MonitoringSettingsResolutionSource.SERVICE_OVERRIDE,
                            "tls_warning_days": None,
                            "restart_delta_threshold": None,
                            "probe_timeout_seconds": 2.5,
                            "threshold_source": MonitoringSettingsResolutionSource.SERVICE_OVERRIDE,
                            "accelerated_now": False,
                            "incident_ids": [],
                        }
                    ],
                }
            ],
        },
    )


def build_monitoring_settings_update_request() -> MonitoringSettingsUpdateRequest:
    """Create a reusable monitoring settings update payload sample."""
    return MonitoringSettingsUpdateRequest(
        checks=[
            {
                "check_id": "endpoint_probe",
                "enabled": True,
                "interval_seconds": 75,
                "probe_timeout_seconds": 2.5,
            }
        ],
        service_overrides=[
            {
                "service_id": "svc-delugevpn",
                "check_id": "endpoint_probe",
                "enabled": False,
                "interval_seconds": 45,
                "probe_timeout_seconds": 2.5,
            }
        ],
    )


def build_monitoring_settings_mutation_response() -> MonitoringSettingsMutationResponse:
    """Create a reusable monitoring settings mutation response payload sample."""
    return MonitoringSettingsMutationResponse(
        settings=build_monitoring_settings_response(),
        audit_change=build_change(),
    )


def build_credential_vault_response() -> CredentialVaultResponse:
    """Create a reusable credential-vault management payload sample."""
    return CredentialVaultResponse(
        status={
            "initialized": True,
            "unlocked": True,
            "unlock_expires_at": ts(15, 45),
            "stored_credentials": 2,
        },
        auto_lock_minutes=5,
        credentials=[
            {
                "reference_id": "vault:settings:models:local_api_key",
                "source": CredentialVaultEntrySource.MANAGED_SETTING,
                "service_id": "settings.models.local",
                "service_name": "Local model settings",
                "credential_key": "api_key",
                "credential_description": "API key",
                "created_at": ts(15, 20),
                "updated_at": ts(15, 20),
                "last_used_at": ts(15, 25),
                "last_tested_at": ts(15, 30),
                "expires_at": None,
            },
            {
                "reference_id": "vault:cred-1",
                "source": CredentialVaultEntrySource.CREDENTIAL_REQUEST,
                "service_id": "svc-radarr",
                "service_name": "Radarr",
                "credential_key": "api_key",
                "credential_description": "Radarr API Key",
                "created_at": ts(15, 21),
                "updated_at": ts(15, 21),
                "last_used_at": None,
                "last_tested_at": None,
                "expires_at": None,
            },
        ],
    )


def build_credential_vault_mutation_response() -> CredentialVaultMutationResponse:
    """Create a reusable credential-vault mutation response payload sample."""
    return CredentialVaultMutationResponse(
        vault=build_credential_vault_response(),
        audit_change=build_change(),
    )


def build_credential_vault_test_response() -> CredentialVaultTestResponse:
    """Create a reusable credential-vault test response payload sample."""
    return CredentialVaultTestResponse(
        vault=build_credential_vault_response(),
        ok=True,
        checked_at=ts(15, 35),
        tested_credentials=2,
        readable_credentials=2,
        results=[
            {
                "reference_id": "vault:settings:models:local_api_key",
                "service_name": "Local model settings",
                "credential_description": "API key",
                "ok": True,
                "message": "Stored credential decrypted successfully.",
                "checked_at": ts(15, 35),
            }
        ],
        message="Explicit vault readability test passed for all stored credentials.",
        audit_change=build_change(),
    )


def build_credential_vault_change_password_request() -> CredentialVaultChangePasswordRequest:
    """Create a reusable credential-vault change-password request payload sample."""
    return CredentialVaultChangePasswordRequest(
        current_master_passphrase="correct horse battery staple",
        new_master_passphrase="correct horse battery stable",
    )


def build_service_descriptor_validation_response() -> ServiceDescriptorValidationResponse:
    """Create a reusable descriptor-validation preview payload sample."""
    return ServiceDescriptorValidationResponse(
        valid=True,
        errors=[],
        warnings=[
            "Save will create or update a reviewed user override and "
            "leave the shipped descriptor unchanged."
        ],
        preview={
            "descriptor_id": "arr/radarr",
            "write_target_path": "services/user/arr/radarr.yaml",
            "match": {
                "current_service_likely_matches": True,
                "affected_services": [
                    {
                        "service_id": "svc-radarr",
                        "service_name": "Radarr",
                        "likely_matches": True,
                    }
                ],
            },
            "dependency_impact": {
                "added_container_dependencies": ["bazarr"],
                "removed_container_dependencies": ["delugevpn"],
                "added_share_dependencies": [],
                "removed_share_dependencies": ["downloads"],
            },
        },
    )


def load_schema(schema_name: str) -> dict[str, object]:
    """Load a checked-in schema file from the repository."""
    schema_path = SCHEMAS_DIR / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_with_schema(schema_name: str, instance: object) -> None:
    """Validate a model payload against the checked-in schema."""
    schema = load_schema(schema_name)
    validator_cls = validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    validator.validate(instance)


def test_checked_in_schemas_match_exported_models(tmp_path: Path) -> None:
    """Checked-in schema artifacts should stay synchronized with the exporter."""
    exported_paths = export_schemas(tmp_path)
    expected_names = {filename for filename, _ in SCHEMA_MODELS}
    actual_names = {path.name for path in exported_paths}

    assert actual_names == expected_names

    for exported_path in exported_paths:
        checked_in = json.loads((SCHEMAS_DIR / exported_path.name).read_text(encoding="utf-8"))
        generated = json.loads(exported_path.read_text(encoding="utf-8"))
        assert generated == checked_in


def test_sample_payloads_validate_against_schemas() -> None:
    """Representative payloads should validate against checked-in schemas."""
    adapter_result = build_adapter_result()
    incident = build_incident()
    finding = build_finding()
    investigation = build_investigation()
    service = build_service()
    service_insight = build_service_insight()
    service_lifecycle = build_service_lifecycle()
    service_lifecycle_event = build_service_lifecycle_event()
    system_profile = build_system_profile()
    journal_entry = build_journal_entry()
    user_note = build_user_note()
    webhook_event = build_webhook_event()
    approval_token = build_approval_token()
    service_descriptor = build_service_descriptor()
    service_adapter_facts_response = build_service_adapter_facts_response()
    finding_review_response = build_finding_review_response()
    finding_dismiss_request = build_finding_dismiss_request()
    finding_dismiss_response = build_finding_dismiss_response()
    maintenance_mode_response = build_maintenance_mode_response()
    maintenance_window_update_request = build_maintenance_window_update_request()
    maintenance_mode_mutation_response = build_maintenance_mode_mutation_response()
    recommendations_response = build_recommendations_response()
    service_detail_response = build_service_detail_response()
    service_detail_check_suppression_update_request = (
        build_service_detail_check_suppression_update_request()
    )
    service_detail_check_suppression_mutation_response = (
        build_service_detail_check_suppression_mutation_response()
    )
    service_descriptor_view_response = build_service_descriptor_view_response()
    service_descriptor_generate_response = build_service_descriptor_generate_response()
    descriptor_community_export_response = build_descriptor_community_export_response()
    model_settings_response = build_model_settings_response()
    model_settings_update_request = build_model_settings_update_request()
    model_settings_mutation_response = build_model_settings_mutation_response()
    model_settings_test_request = build_model_settings_test_request()
    model_settings_test_response = build_model_settings_test_response()
    monitoring_settings_response = build_monitoring_settings_response()
    monitoring_settings_update_request = build_monitoring_settings_update_request()
    monitoring_settings_mutation_response = build_monitoring_settings_mutation_response()
    credential_vault_response = build_credential_vault_response()
    credential_vault_mutation_response = build_credential_vault_mutation_response()
    credential_vault_test_response = build_credential_vault_test_response()
    credential_vault_change_password_request = (
        build_credential_vault_change_password_request()
    )
    notification_settings_response = build_notification_settings_response()
    notification_settings_update_request = build_notification_settings_update_request()
    notification_settings_mutation_response = build_notification_settings_mutation_response()
    notification_settings_test_request = build_notification_settings_test_request()
    notification_settings_test_response = build_notification_settings_test_response()
    system_settings_response = build_system_settings_response()
    system_settings_update_request = build_system_settings_update_request()
    system_settings_mutation_response = build_system_settings_mutation_response()
    quarantined_descriptor_queue_item_response = (
        build_quarantined_descriptor_queue_item_response()
    )
    quarantined_descriptor_action_response = build_quarantined_descriptor_action_response()
    service_descriptor_save_request = build_service_descriptor_save_request()
    service_descriptor_save_response = build_service_descriptor_save_response()
    service_descriptor_validation_response = build_service_descriptor_validation_response()

    validate_with_schema("adapter_result.json", adapter_result.model_dump(mode="json"))
    validate_with_schema("incident.json", incident.model_dump(mode="json"))
    validate_with_schema("finding.json", finding.model_dump(mode="json"))
    validate_with_schema("investigation.json", investigation.model_dump(mode="json"))
    validate_with_schema("service.json", service.model_dump(mode="json"))
    validate_with_schema(
        "service_insight.json",
        service_insight.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_lifecycle.json",
        service_lifecycle.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_lifecycle_event.json",
        service_lifecycle_event.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor.json",
        service_descriptor.model_dump(mode="json"),
    )
    validate_with_schema("system_profile.json", system_profile.model_dump(mode="json"))
    validate_with_schema("journal_entry.json", journal_entry.model_dump(mode="json"))
    validate_with_schema(
        "service_adapter_facts_response.json",
        service_adapter_facts_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "finding_review_response.json",
        finding_review_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "finding_dismiss_request.json",
        finding_dismiss_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "finding_dismiss_response.json",
        finding_dismiss_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "maintenance_mode_response.json",
        maintenance_mode_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "maintenance_window_update_request.json",
        maintenance_window_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "maintenance_mode_mutation_response.json",
        maintenance_mode_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "recommendations_response.json",
        recommendations_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_detail_response.json",
        service_detail_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_detail_check_suppression_update_request.json",
        service_detail_check_suppression_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_detail_check_suppression_mutation_response.json",
        service_detail_check_suppression_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor_view_response.json",
        service_descriptor_view_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor_generate_response.json",
        service_descriptor_generate_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "descriptor_community_export_response.json",
        descriptor_community_export_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "model_settings_response.json",
        model_settings_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "model_settings_update_request.json",
        model_settings_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "model_settings_mutation_response.json",
        model_settings_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "model_settings_test_request.json",
        model_settings_test_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "model_settings_test_response.json",
        model_settings_test_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "monitoring_settings_response.json",
        monitoring_settings_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "monitoring_settings_update_request.json",
        monitoring_settings_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "monitoring_settings_mutation_response.json",
        monitoring_settings_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "credential_vault_response.json",
        credential_vault_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "credential_vault_mutation_response.json",
        credential_vault_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "credential_vault_test_response.json",
        credential_vault_test_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "credential_vault_change_password_request.json",
        credential_vault_change_password_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_settings_response.json",
        notification_settings_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_settings_update_request.json",
        notification_settings_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_settings_mutation_response.json",
        notification_settings_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_settings_test_request.json",
        notification_settings_test_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_settings_test_response.json",
        notification_settings_test_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "system_settings_response.json",
        system_settings_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "system_settings_update_request.json",
        system_settings_update_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "system_settings_mutation_response.json",
        system_settings_mutation_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "quarantined_descriptor_queue_item_response.json",
        quarantined_descriptor_queue_item_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "quarantined_descriptor_action_response.json",
        quarantined_descriptor_action_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor_save_request.json",
        service_descriptor_save_request.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor_save_response.json",
        service_descriptor_save_response.model_dump(mode="json"),
    )
    validate_with_schema(
        "service_descriptor_validation_response.json",
        service_descriptor_validation_response.model_dump(mode="json"),
    )
    validate_with_schema("user_note.json", user_note.model_dump(mode="json"))
    validate_with_schema("webhook_event.json", webhook_event.model_dump(mode="json"))
    validate_with_schema("approval_token.json", approval_token.model_dump(mode="json"))
    validate_with_schema(
        "executor_action_request.json",
        ExecutorActionRequest(
            action=ActionType.RESTART_CONTAINER,
            target="delugevpn",
            approval_token=approval_token,
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "executor_action_result.json",
        ExecutorActionResult(
            token_id=approval_token.token_id,
            incident_id=approval_token.incident_id,
            action=approval_token.action,
            target=approval_token.target,
            status=ExecutorActionStatus.SUCCESS,
            detail="Container restarted successfully.",
            executed_at=ts(14, 31),
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "incident_lifecycle_transition.json",
        IncidentLifecycleTransition(
            from_status=IncidentStatus.INVESTIGATING,
            to_status=IncidentStatus.AWAITING_APPROVAL,
            reason="Approval required for restart.",
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "notification_payload.json",
        NotificationPayload(
            source_type=NotificationSourceType.INCIDENT,
            source_id=incident.id,
            incident_id=incident.id,
            severity=incident.severity,
            title=incident.title,
            summary="Root cause points to DelugeVPN.",
            body="Restarting DelugeVPN is recommended based on repeated history.",
            evidence_lines=[
                'DelugeVPN logs: "VPN tunnel inactive"',
                'Radarr logs: "Download client not available"',
            ],
            recommended_action="Restart DelugeVPN",
            action_buttons=[
                NotificationAction(
                    label="Approve restart",
                    action=NotificationActionType.APPROVE,
                    style=NotificationActionStyle.PRIMARY,
                    callback_id="approve-inc-1",
                    url=None,
                    expires_at=ts(14, 35),
                )
            ],
            dedup_key="incident-inc-1",
            created_at=ts(14, 29),
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "operational_memory_query.json",
        OperationalMemoryQuery(
            incident_id=incident.id,
            service_ids=["svc-delugevpn"],
            tags=["vpn"],
            include_system_profile=True,
            include_journal=True,
            include_user_notes=True,
            max_journal_entries=5,
            redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
        ).model_dump(mode="json"),
    )
    validate_with_schema(
        "operational_memory_result.json",
        OperationalMemoryResult(
            system_profile=system_profile,
            journal_entries=[journal_entry],
            user_notes=[user_note],
            recurrence_count=3,
            applied_redaction_level=RedactionLevel.REDACT_FOR_LOCAL,
            warnings=[],
        ).model_dump(mode="json"),
    )
