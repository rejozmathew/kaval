"""Unit tests for proactive admin recommendations."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.credentials.models import VaultCredentialRecord
from kaval.models import (
    DependencyConfidence,
    DependencyEdge,
    DependencySource,
    Service,
    ServiceStatus,
    ServiceType,
)
from kaval.recommendations import (
    NoisyCheckPattern,
    RecommendationActionTarget,
    RecommendationKind,
    build_proactive_recommendations,
)


def ts(day: int, hour: int, minute: int = 0) -> datetime:
    """Build deterministic UTC timestamps for recommendation tests."""
    return datetime(2026, 4, day, hour, minute, tzinfo=UTC)


def test_proactive_recommendations_rank_real_state_in_a_stable_order() -> None:
    """Ranking should stay understandable and deterministic across suggestion kinds."""
    services = [
        build_service(
            service_id="svc-unknown-app",
            name="Unknown App",
            descriptor_id=None,
            dependents=["svc-radarr", "svc-sonarr"],
        ),
        build_service(
            service_id="svc-delugevpn",
            name="DelugeVPN",
            descriptor_id="downloads/delugevpn",
        ),
        build_service(
            service_id="svc-radarr",
            name="Radarr",
            descriptor_id="arr/radarr",
            dependencies=[
                DependencyEdge(
                    target_service_id="svc-delugevpn",
                    confidence=DependencyConfidence.CONFIGURED,
                    source=DependencySource.DESCRIPTOR,
                    description="Radarr uses DelugeVPN as its download client.",
                )
            ],
        ),
    ]

    recommendations = build_proactive_recommendations(
        services=services,
        vault_credentials=[
            VaultCredentialRecord(
                reference_id="vault:auth",
                request_id="credreq-auth",
                incident_id="inc-auth",
                service_id="svc-delugevpn",
                credential_key="api_key",
                ciphertext="ciphertext",
                submitted_by="user_via_telegram",
                created_at=ts(2, 9).replace(month=2),
                updated_at=ts(2, 9).replace(month=2),
                last_used_at=ts(6, 10),
                last_tested_at=ts(3, 10).replace(month=2),
            )
        ],
        noisy_check_patterns=[
            NoisyCheckPattern(
                service_id="svc-delugevpn",
                service_name="DelugeVPN",
                check_id="endpoint_probe",
                check_label="Endpoint probe",
                dismissal_count=6,
                message="Repeated endpoint probe dismissals suggest tuning or suppression.",
            )
        ],
        local_model_configured=True,
        cloud_model_configured=False,
        now=ts(8, 12),
    )

    assert [item.kind for item in recommendations] == [
        RecommendationKind.MISSING_DESCRIPTOR,
        RecommendationKind.STALE_CREDENTIAL,
        RecommendationKind.NOISY_CHECK,
        RecommendationKind.CLOUD_MODEL,
    ]
    assert recommendations[0].action.target == RecommendationActionTarget.SERVICE_DETAIL
    assert recommendations[0].action.service_id == "svc-unknown-app"
    assert recommendations[1].action.target == RecommendationActionTarget.CREDENTIAL_VAULT
    assert recommendations[2].action.target == RecommendationActionTarget.FINDING_REVIEW
    assert recommendations[3].action.target == RecommendationActionTarget.MODEL_SETTINGS


def test_proactive_recommendations_ignore_non_descriptor_services_and_fresh_credentials() -> None:
    """Fresh credentials and non-container services should not create recommendations."""
    recommendations = build_proactive_recommendations(
        services=[
            build_service(
                service_id="svc-downloads-share",
                name="downloads",
                service_type=ServiceType.SHARE,
                descriptor_id=None,
            )
        ],
        vault_credentials=[
            VaultCredentialRecord(
                reference_id="vault:fresh",
                request_id="credreq-fresh",
                incident_id="inc-fresh",
                service_id="svc-downloads-share",
                credential_key="api_key",
                ciphertext="ciphertext",
                submitted_by="user_via_telegram",
                created_at=ts(7, 8),
                updated_at=ts(7, 8),
                last_used_at=None,
                last_tested_at=ts(7, 9),
            )
        ],
        noisy_check_patterns=[],
        local_model_configured=False,
        cloud_model_configured=False,
        now=ts(8, 12),
    )

    assert recommendations == []


def build_service(
    *,
    service_id: str,
    name: str,
    descriptor_id: str | None,
    service_type: ServiceType = ServiceType.CONTAINER,
    dependencies: list[DependencyEdge] | None = None,
    dependents: list[str] | None = None,
) -> Service:
    """Build a minimal service record for recommendation tests."""
    return Service(
        id=service_id,
        name=name,
        type=service_type,
        category="app",
        status=ServiceStatus.HEALTHY,
        descriptor_id=descriptor_id,
        descriptor_source=None,
        container_id=None,
        vm_id=None,
        image=None,
        endpoints=[],
        dns_targets=[],
        dependencies=dependencies or [],
        dependents=dependents or [],
        last_check=None,
        active_findings=0,
        active_incidents=0,
    )
