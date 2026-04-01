"""Unit tests for the Phase 2B credential vault."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.credentials import (
    CredentialMaterialService,
    CredentialRequestManager,
    CredentialRequestMode,
    CredentialRequestStatus,
    CredentialVault,
    CredentialVaultLockedError,
    VolatileCredentialStore,
)
from kaval.database import KavalDatabase
from kaval.models import DescriptorSource, Service, ServiceStatus, ServiceType


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for vault tests."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_vault_unlock_initializes_and_locks_cleanly(tmp_path: Path) -> None:
    """Unlocking should initialize the vault and locking should clear the runtime key."""
    database_path = seed_database(tmp_path / "vault-init.db")
    vault = CredentialVault(database_path=database_path, auto_lock_minutes=5)

    initial_status = vault.status(now=ts(18, 0))
    unlocked_status = vault.unlock("correct horse battery staple", now=ts(18, 1))
    locked_status = vault.lock()

    assert initial_status.initialized is False
    assert initial_status.unlocked is False
    assert unlocked_status.initialized is True
    assert unlocked_status.unlocked is True
    assert locked_status.initialized is True
    assert locked_status.unlocked is False


def test_vault_encrypts_and_retrieves_secret_after_unlock(tmp_path: Path) -> None:
    """Vault-backed secrets should round-trip only while the vault is unlocked."""
    database_path = seed_database(tmp_path / "vault-store.db")
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        manager = CredentialRequestManager(database=database)
        request_record = manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need diagnostics API access.",
            now=ts(18, 0),
        )
        request_record = manager.resolve_choice(
            request_id=request_record.id,
            mode=CredentialRequestMode.VAULT,
            decided_by="user_via_telegram",
            now=ts(18, 1),
        )

        vault = CredentialVault(database_path=database_path, auto_lock_minutes=5)
        vault.unlock("correct horse battery staple", now=ts(18, 2))
        reference_id = vault.store_secret(
            request_record=request_record,
            secret_value="radarr-secret-value",
            submitted_by="user_via_telegram",
            now=ts(18, 2),
        )
        stored_record = database.get_vault_credential(reference_id)

        assert reference_id.startswith("vault:")
        assert stored_record is not None
        assert "radarr-secret-value" not in stored_record.ciphertext
        assert vault.get_secret(reference_id, now=ts(18, 3)) == "radarr-secret-value"
    finally:
        database.close()


def test_vault_auto_locks_after_timeout(tmp_path: Path) -> None:
    """The vault should forget its in-memory key once the autolock window expires."""
    database_path = seed_database(tmp_path / "vault-autolock.db")
    vault = CredentialVault(database_path=database_path, auto_lock_minutes=5)

    vault.unlock("correct horse battery staple", now=ts(18, 0))
    status = vault.status(now=ts(18, 6))

    assert status.unlocked is False


def test_material_service_satisfies_volatile_request(tmp_path: Path) -> None:
    """Volatile-mode submissions should satisfy the request without touching the vault."""
    database_path = seed_database(tmp_path / "volatile-submit.db")
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        service = CredentialMaterialService(
            request_manager=CredentialRequestManager(database=database),
            volatile_store=VolatileCredentialStore(default_ttl_seconds=1800),
            vault=CredentialVault(database_path=database_path, auto_lock_minutes=5),
        )
        request_record = service.request_manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need diagnostics API access.",
            now=ts(18, 0),
        )
        service.request_manager.resolve_choice(
            request_id=request_record.id,
            mode=CredentialRequestMode.VOLATILE,
            decided_by="user_via_telegram",
            now=ts(18, 1),
        )

        satisfied = service.submit_secret(
            request_id=request_record.id,
            secret_value="radarr-secret-value",
            submitted_by="user_via_telegram",
            now=ts(18, 2),
        )

        assert satisfied.status == CredentialRequestStatus.SATISFIED
        assert satisfied.credential_reference is not None
        assert satisfied.credential_reference.startswith("volatile:")
        assert (
            service.get_secret(satisfied.credential_reference, now=ts(18, 3))
            == "radarr-secret-value"
        )
    finally:
        database.close()


def test_material_service_requires_unlocked_vault_for_vault_mode(tmp_path: Path) -> None:
    """Vault-mode submissions should fail until the vault is explicitly unlocked."""
    database_path = seed_database(tmp_path / "vault-submit.db")
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
        service = CredentialMaterialService(
            request_manager=CredentialRequestManager(database=database),
            volatile_store=VolatileCredentialStore(default_ttl_seconds=1800),
            vault=CredentialVault(database_path=database_path, auto_lock_minutes=5),
        )
        request_record = service.request_manager.create_request(
            incident_id="inc-1",
            service_id="svc-radarr",
            credential_key="api_key",
            reason="Need diagnostics API access.",
            now=ts(18, 0),
        )
        service.request_manager.resolve_choice(
            request_id=request_record.id,
            mode=CredentialRequestMode.VAULT,
            decided_by="user_via_telegram",
            now=ts(18, 1),
        )

        with pytest.raises(CredentialVaultLockedError, match="vault is locked"):
            service.submit_secret(
                request_id=request_record.id,
                secret_value="radarr-secret-value",
                submitted_by="user_via_telegram",
                now=ts(18, 2),
            )

        service.unlock_vault("correct horse battery staple", now=ts(18, 2))
        satisfied = service.submit_secret(
            request_id=request_record.id,
            secret_value="radarr-secret-value",
            submitted_by="user_via_telegram",
            now=ts(18, 3),
        )

        assert satisfied.status == CredentialRequestStatus.SATISFIED
        assert satisfied.credential_reference is not None
        assert satisfied.credential_reference.startswith("vault:")
        assert (
            service.get_secret(satisfied.credential_reference, now=ts(18, 4))
            == "radarr-secret-value"
        )
    finally:
        database.close()


def seed_database(database_path: Path) -> Path:
    """Seed one database with a descriptor-backed Radarr service."""
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    try:
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
    finally:
        database.close()
    return database_path
