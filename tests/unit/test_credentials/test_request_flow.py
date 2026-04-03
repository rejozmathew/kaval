"""Unit tests for the Phase 2B credential-request flow."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.credentials import (
    CredentialRequestConflictError,
    CredentialRequestManager,
    CredentialRequestMode,
    CredentialRequestStatus,
)
from kaval.database import KavalDatabase
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for credential-request tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_create_request_uses_descriptor_credential_hint(tmp_path: Path) -> None:
    """Creating a request should copy the shipped credential hint into the audit record."""
    database = seed_database(tmp_path / "credential-requests.db")
    try:
        manager = CredentialRequestManager(database=database)

        credential_request = manager.create_request(
            incident_id="inc-1",
            investigation_id="inv-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Logs are vague and the diagnostics API would narrow the fault.",
            now=ts(18, 10),
        )

        assert credential_request.status == CredentialRequestStatus.PENDING
        assert credential_request.service_name == "Radarr"
        assert credential_request.credential_description == "Radarr API Key"
        assert "Settings" in credential_request.credential_location
        persisted = database.get_credential_request(credential_request.id)
        assert persisted == credential_request
    finally:
        database.close()


def test_resolve_choice_marks_request_awaiting_input_for_volatile_mode(
    tmp_path: Path,
) -> None:
    """Choosing a storage mode should move the request into awaiting_input."""
    database = seed_database(tmp_path / "credential-choice.db")
    try:
        manager = CredentialRequestManager(database=database)
        credential_request = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics.",
            now=ts(18, 10),
        )

        updated = manager.resolve_choice(
            request_id=credential_request.id,
            mode=CredentialRequestMode.VOLATILE,
            decided_by="user_via_telegram",
            now=ts(18, 12),
        )

        assert updated.status == CredentialRequestStatus.AWAITING_INPUT
        assert updated.selected_mode == CredentialRequestMode.VOLATILE
        assert updated.decided_by == "user_via_telegram"
        assert updated.decided_at == ts(18, 12)
        assert updated.credential_reference is None
    finally:
        database.close()


def test_resolve_choice_marks_request_skipped(tmp_path: Path) -> None:
    """Skip decisions should complete the request without creating secret state."""
    database = seed_database(tmp_path / "credential-skip.db")
    try:
        manager = CredentialRequestManager(database=database)
        credential_request = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics.",
            now=ts(18, 10),
        )

        updated = manager.resolve_choice(
            request_id=credential_request.id,
            mode=CredentialRequestMode.SKIP,
            decided_by="user_via_telegram",
            now=ts(18, 13),
        )

        assert updated.status == CredentialRequestStatus.SKIPPED
        assert updated.selected_mode == CredentialRequestMode.SKIP
        assert updated.credential_reference is None
    finally:
        database.close()


def test_list_requests_expires_pending_requests(tmp_path: Path) -> None:
    """Expired requests should become explicit expired records when listed."""
    database = seed_database(tmp_path / "credential-expire.db")
    try:
        manager = CredentialRequestManager(database=database)
        credential_request = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics.",
            now=ts(18, 10),
            ttl_seconds=60,
        )

        listed = manager.list_requests(now=ts(18, 12))

        assert listed[0].status == CredentialRequestStatus.EXPIRED
        persisted = database.get_credential_request(credential_request.id)
        assert persisted is not None
        assert persisted.status == CredentialRequestStatus.EXPIRED
    finally:
        database.close()


def test_resolve_choice_rejects_already_decided_requests(tmp_path: Path) -> None:
    """Requests should not accept a second decision once one mode is already recorded."""
    database = seed_database(tmp_path / "credential-conflict.db")
    try:
        manager = CredentialRequestManager(database=database)
        credential_request = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics.",
            now=ts(18, 10),
        )
        manager.resolve_choice(
            request_id=credential_request.id,
            mode=CredentialRequestMode.VAULT,
            decided_by="user_via_telegram",
            now=ts(18, 12),
        )

        with pytest.raises(CredentialRequestConflictError, match="already has a selected mode"):
            manager.resolve_choice(
                request_id=credential_request.id,
                mode=CredentialRequestMode.SKIP,
                decided_by="user_via_telegram",
                now=ts(18, 13),
            )
    finally:
        database.close()


def test_find_satisfied_request_returns_latest_matching_credential(tmp_path: Path) -> None:
    """Adapters should be able to look up the newest satisfied credential request."""
    database = seed_database(tmp_path / "credential-latest.db")
    try:
        manager = CredentialRequestManager(database=database)
        first_request = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics.",
            now=ts(18, 0),
        )
        manager.resolve_choice(
            request_id=first_request.id,
            mode=CredentialRequestMode.VOLATILE,
            decided_by="user_via_telegram",
            now=ts(18, 1),
        )
        manager.mark_satisfied(
            request_id=first_request.id,
            credential_reference="volatile:first",
            now=ts(18, 2),
        )

        second_request = manager.create_request(
            incident_id="inc-2",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need API diagnostics again.",
            now=ts(18, 10),
        )
        manager.resolve_choice(
            request_id=second_request.id,
            mode=CredentialRequestMode.VAULT,
            decided_by="user_via_web",
            now=ts(18, 11),
        )
        satisfied = manager.mark_satisfied(
            request_id=second_request.id,
            credential_reference="vault:second",
            now=ts(18, 12),
        )

        resolved = manager.find_satisfied_request(
            service_id="svc-radarr",
            credential_key="api_key",
            now=ts(18, 13),
        )

        assert resolved == satisfied
    finally:
        database.close()


def seed_database(database_path: Path) -> KavalDatabase:
    """Create one temporary database with a descriptor-backed Radarr service."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.upsert_service(
        Service(
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
            endpoints=[],
            dns_targets=[],
            dependencies=[],
            dependents=[],
            last_check=ts(18, 0),
            active_findings=1,
            active_incidents=1,
        )
    )
    return database
