"""Encrypted vault and volatile credential storage for Phase 2B."""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from secrets import token_bytes
from sqlite3 import Connection
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from kaval.credentials.models import (
    CredentialRequest,
    CredentialRequestMode,
    CredentialRequestStatus,
    VaultConfigRecord,
    VaultCredentialRecord,
    VaultStatus,
)
from kaval.credentials.request_flow import (
    CredentialRequestConflictError,
    CredentialRequestManager,
    CredentialRequestNotFoundError,
)
from kaval.database import KavalDatabase

_DERIVED_KEY_LENGTH = 32
_ARGON2_ITERATIONS = 3
_ARGON2_LANES = 4
_ARGON2_MEMORY_COST = 65536
_VERIFIER_PLAINTEXT = b"kaval-vault-verifier"


class CredentialVaultError(RuntimeError):
    """Base error raised by credential storage backends."""


class CredentialVaultLockedError(CredentialVaultError):
    """Raised when a vault operation requires an unlocked master key."""


class CredentialVaultPassphraseError(CredentialVaultError):
    """Raised when the supplied master passphrase is invalid."""


class CredentialVaultNotInitializedError(CredentialVaultError):
    """Raised when a vault mutation requires prior initialization."""


class CredentialMaterialNotFoundError(CredentialVaultError):
    """Raised when a stored credential reference does not exist or has expired."""


class AdapterCredentialState(StrEnum):
    """Availability states for adapter-facing credential resolution."""

    AVAILABLE = "available"
    UNCONFIGURED = "unconfigured"
    LOCKED = "locked"


@dataclass(slots=True)
class VolatileCredentialRecord:
    """One volatile in-memory credential lease."""

    reference_id: str
    request_id: str
    service_id: str
    credential_key: str
    secret_value: str = field(repr=False)
    submitted_by: str
    created_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class AdapterCredentialResolution:
    """Resolved adapter credential state without exposing secret material in reprs."""

    state: AdapterCredentialState
    missing_keys: tuple[str, ...] = ()
    detail: str | None = None
    credentials: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass(slots=True)
class VaultCredentialTestResult:
    """Result of one explicit vault readability test."""

    record: VaultCredentialRecord
    ok: bool
    message: str


@dataclass(slots=True)
class VolatileCredentialStore:
    """In-memory storage for volatile session credentials."""

    default_ttl_seconds: int = 1800
    _records: dict[str, VolatileCredentialRecord] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Validate volatile credential TTL values."""
        if self.default_ttl_seconds <= 0:
            msg = "default_ttl_seconds must be positive"
            raise ValueError(msg)

    def store(
        self,
        *,
        request_record: CredentialRequest,
        secret_value: str,
        submitted_by: str,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        """Store one secret in-memory and return its opaque reference."""
        effective_now = now or datetime.now(tz=UTC)
        effective_ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if effective_ttl <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)
        reference_id = f"volatile:{uuid4()}"
        self._records[reference_id] = VolatileCredentialRecord(
            reference_id=reference_id,
            request_id=request_record.id,
            service_id=request_record.service_id,
            credential_key=request_record.credential_key,
            secret_value=secret_value,
            submitted_by=submitted_by,
            created_at=effective_now,
            expires_at=effective_now + timedelta(seconds=effective_ttl),
        )
        self._purge_expired(effective_now)
        return reference_id

    def get_secret(self, reference_id: str, *, now: datetime | None = None) -> str:
        """Return one still-valid volatile secret by opaque reference."""
        effective_now = now or datetime.now(tz=UTC)
        self._purge_expired(effective_now)
        record = self._records.get(reference_id)
        if record is None:
            msg = f"credential material not found: {reference_id}"
            raise CredentialMaterialNotFoundError(msg)
        return record.secret_value

    def _purge_expired(self, now: datetime) -> None:
        """Drop expired volatile secrets before lookups or inserts."""
        expired_references = [
            reference_id
            for reference_id, record in self._records.items()
            if record.expires_at <= now
        ]
        for reference_id in expired_references:
            self._records.pop(reference_id, None)


@dataclass(slots=True)
class CredentialVault:
    """Encrypted-at-rest vault storage with explicit lock/unlock boundaries."""

    database_path: Path | str
    migrations_dir: Path | str | None = None
    auto_lock_minutes: int = 5
    _unlock_key: bytes | None = field(default=None, init=False, repr=False)
    _unlock_expires_at: datetime | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize database paths and validate autolock settings."""
        self.database_path = Path(self.database_path)
        self.migrations_dir = None if self.migrations_dir is None else Path(self.migrations_dir)
        if self.auto_lock_minutes <= 0:
            msg = "auto_lock_minutes must be positive"
            raise ValueError(msg)

    def status(self, *, now: datetime | None = None) -> VaultStatus:
        """Return current initialization and lock state for the vault."""
        effective_now = now or datetime.now(tz=UTC)
        self._apply_auto_lock(effective_now)
        database = self._database()
        try:
            return VaultStatus(
                initialized=database.get_vault_config() is not None,
                unlocked=self._unlock_key is not None,
                unlock_expires_at=self._unlock_expires_at,
                stored_credentials=len(database.list_vault_credentials()),
            )
        finally:
            database.close()

    def unlock(self, master_passphrase: str, *, now: datetime | None = None) -> VaultStatus:
        """Initialize or unlock the vault with the supplied master passphrase."""
        effective_now = now or datetime.now(tz=UTC)
        if not master_passphrase:
            msg = "master_passphrase must not be empty"
            raise ValueError(msg)
        database = self._database()
        try:
            config = database.get_vault_config()
            if config is None:
                config = self._initialize_vault(database, master_passphrase, now=effective_now)
            derived_key = _verified_fernet_key(
                master_passphrase,
                config=config,
            )
        finally:
            database.close()

        self._unlock_key = derived_key
        self._unlock_expires_at = effective_now + timedelta(minutes=self.auto_lock_minutes)
        return self.status(now=effective_now)

    def lock(self) -> VaultStatus:
        """Forget the in-memory unlock key immediately."""
        self._unlock_key = None
        self._unlock_expires_at = None
        return self.status()

    def store_secret(
        self,
        *,
        request_record: CredentialRequest,
        secret_value: str,
        submitted_by: str,
        now: datetime | None = None,
    ) -> str:
        """Encrypt and persist one secret in the vault."""
        effective_now = now or datetime.now(tz=UTC)
        fernet = self._active_fernet(effective_now)
        reference_id = f"vault:{uuid4()}"
        record = VaultCredentialRecord(
            reference_id=reference_id,
            request_id=request_record.id,
            incident_id=request_record.incident_id,
            service_id=request_record.service_id,
            credential_key=request_record.credential_key,
            ciphertext=fernet.encrypt(secret_value.encode("utf-8")).decode("utf-8"),
            submitted_by=submitted_by,
            created_at=effective_now,
            updated_at=effective_now,
        )
        database = self._database()
        try:
            database.upsert_vault_credential(record)
        finally:
            database.close()
        return reference_id

    def list_credentials(self) -> list[VaultCredentialRecord]:
        """List stored vault credentials without decrypting their secret values."""
        database = self._database()
        try:
            return database.list_vault_credentials()
        finally:
            database.close()

    def upsert_managed_secret(
        self,
        *,
        reference_id: str,
        secret_value: str,
        service_id: str,
        credential_key: str,
        submitted_by: str,
        request_id: str | None = None,
        incident_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        """Encrypt and persist one stable-reference managed secret."""
        effective_now = now or datetime.now(tz=UTC)
        fernet = self._active_fernet(effective_now)
        database = self._database()
        try:
            existing_record = database.get_vault_credential(reference_id)
            created_at = (
                effective_now if existing_record is None else existing_record.created_at
            )
            record = VaultCredentialRecord(
                reference_id=reference_id,
                request_id=request_id or f"managed:{service_id}:{credential_key}",
                incident_id=incident_id or "managed",
                service_id=service_id,
                credential_key=credential_key,
                ciphertext=fernet.encrypt(secret_value.encode("utf-8")).decode("utf-8"),
                submitted_by=submitted_by,
                created_at=created_at,
                updated_at=effective_now,
            )
            database.upsert_vault_credential(record)
        finally:
            database.close()
        return reference_id

    def get_secret(self, reference_id: str, *, now: datetime | None = None) -> str:
        """Decrypt one stored vault credential by opaque reference."""
        effective_now = now or datetime.now(tz=UTC)
        fernet = self._active_fernet(effective_now)
        database = self._database()
        try:
            record = database.get_vault_credential(reference_id)
            if record is None:
                msg = f"credential material not found: {reference_id}"
                raise CredentialMaterialNotFoundError(msg)
            try:
                secret_value = fernet.decrypt(record.ciphertext.encode("utf-8")).decode(
                    "utf-8"
                )
            except InvalidToken as exc:
                raise CredentialVaultPassphraseError(
                    "stored vault credential could not be decrypted"
                ) from exc
            updated_record = record.model_copy(update={"last_used_at": effective_now})
            connection = database.connection()
            with connection:
                _upsert_vault_credential_record(connection, updated_record)
            return secret_value
        finally:
            database.close()

    def delete_secret(self, reference_id: str) -> None:
        """Delete one stored vault secret reference without decrypting it."""
        database = self._database()
        try:
            database.delete_vault_credential(reference_id)
        finally:
            database.close()

    def test_credentials(
        self,
        *,
        now: datetime | None = None,
    ) -> list[VaultCredentialTestResult]:
        """Test whether each stored credential can be decrypted with the current key."""
        effective_now = now or datetime.now(tz=UTC)
        fernet = self._active_fernet(effective_now)
        database = self._database()
        try:
            records = database.list_vault_credentials()
            results: list[VaultCredentialTestResult] = []
            connection = database.connection()
            with connection:
                for record in records:
                    ok = True
                    message = "Stored credential decrypted successfully."
                    try:
                        fernet.decrypt(record.ciphertext.encode("utf-8"))
                    except InvalidToken:
                        ok = False
                        message = "Stored credential could not be decrypted."
                    tested_record = record.model_copy(update={"last_tested_at": effective_now})
                    _upsert_vault_credential_record(connection, tested_record)
                    results.append(
                        VaultCredentialTestResult(
                            record=tested_record,
                            ok=ok,
                            message=message,
                        )
                    )
            return results
        finally:
            database.close()

    def change_master_passphrase(
        self,
        *,
        current_master_passphrase: str,
        new_master_passphrase: str,
        now: datetime | None = None,
    ) -> VaultStatus:
        """Re-encrypt all stored credentials under a new master passphrase."""
        effective_now = now or datetime.now(tz=UTC)
        if not current_master_passphrase:
            msg = "current_master_passphrase must not be empty"
            raise ValueError(msg)
        if not new_master_passphrase:
            msg = "new_master_passphrase must not be empty"
            raise ValueError(msg)

        database = self._database()
        try:
            config = database.get_vault_config()
            if config is None:
                raise CredentialVaultNotInitializedError("vault is not initialized")
            current_key = _verified_fernet_key(
                current_master_passphrase,
                config=config,
            )
            next_config, next_key = _build_vault_config_record(
                new_master_passphrase,
                now=effective_now,
            )
            current_fernet = Fernet(current_key)
            next_fernet = Fernet(next_key)
            rotated_records: list[VaultCredentialRecord] = []
            for record in database.list_vault_credentials():
                try:
                    secret_value = current_fernet.decrypt(
                        record.ciphertext.encode("utf-8")
                    ).decode("utf-8")
                except InvalidToken as exc:
                    raise CredentialVaultError(
                        "stored vault credential could not be decrypted"
                    ) from exc
                rotated_records.append(
                    record.model_copy(
                        update={
                            "ciphertext": next_fernet.encrypt(
                                secret_value.encode("utf-8")
                            ).decode("utf-8"),
                            "updated_at": effective_now,
                        }
                    )
                )
            connection = database.connection()
            with connection:
                _upsert_vault_config_record(connection, next_config)
                for record in rotated_records:
                    _upsert_vault_credential_record(connection, record)
        finally:
            database.close()

        self._unlock_key = next_key
        self._unlock_expires_at = effective_now + timedelta(minutes=self.auto_lock_minutes)
        return self.status(now=effective_now)

    def _initialize_vault(
        self,
        database: KavalDatabase,
        master_passphrase: str,
        *,
        now: datetime,
    ) -> VaultConfigRecord:
        """Create the initial vault metadata using the supplied passphrase."""
        config, _ = _build_vault_config_record(master_passphrase, now=now)
        database.upsert_vault_config(config)
        return config

    def _active_fernet(self, now: datetime) -> Fernet:
        """Return the active Fernet instance or reject when the vault is locked."""
        self._apply_auto_lock(now)
        if self._unlock_key is None:
            raise CredentialVaultLockedError("vault is locked")
        return Fernet(self._unlock_key)

    def _apply_auto_lock(self, now: datetime) -> None:
        """Auto-lock the vault once the unlock lease has expired."""
        if self._unlock_expires_at is not None and self._unlock_expires_at <= now:
            self._unlock_key = None
            self._unlock_expires_at = None

    def _database(self) -> KavalDatabase:
        """Open one short-lived database handle for vault operations."""
        database = KavalDatabase(
            path=self.database_path,
            migrations_dir=self.migrations_dir,
        )
        database.bootstrap()
        return database


@dataclass(slots=True)
class CredentialMaterialService:
    """Resolve approved credential requests into volatile or vault-backed material."""

    request_manager: CredentialRequestManager
    volatile_store: VolatileCredentialStore
    vault: CredentialVault
    default_volatile_ttl_seconds: int = 1800

    def submit_secret(
        self,
        *,
        request_id: str,
        secret_value: str,
        submitted_by: str,
        now: datetime | None = None,
    ) -> CredentialRequest:
        """Store secret material for one awaiting-input credential request."""
        effective_now = now or datetime.now(tz=UTC)
        if not secret_value:
            msg = "secret_value must not be empty"
            raise ValueError(msg)
        request_record = self.request_manager.get_request(request_id, now=effective_now)
        if request_record is None:
            msg = f"credential request not found: {request_id}"
            raise CredentialRequestNotFoundError(msg)
        if request_record.status != CredentialRequestStatus.AWAITING_INPUT:
            msg = "credential request is not ready to accept secret material"
            raise CredentialRequestConflictError(msg)
        if request_record.selected_mode == CredentialRequestMode.VOLATILE:
            reference_id = self.volatile_store.store(
                request_record=request_record,
                secret_value=secret_value,
                submitted_by=submitted_by,
                now=effective_now,
                ttl_seconds=self.default_volatile_ttl_seconds,
            )
        elif request_record.selected_mode == CredentialRequestMode.VAULT:
            reference_id = self.vault.store_secret(
                request_record=request_record,
                secret_value=secret_value,
                submitted_by=submitted_by,
                now=effective_now,
            )
        else:
            msg = "credential request does not have a storable mode"
            raise CredentialRequestConflictError(msg)
        return self.request_manager.mark_satisfied(
            request_id=request_id,
            credential_reference=reference_id,
            now=effective_now,
        )

    def get_secret(self, reference_id: str, *, now: datetime | None = None) -> str:
        """Resolve one opaque credential reference into its raw secret value."""
        if reference_id.startswith("volatile:"):
            return self.volatile_store.get_secret(reference_id, now=now)
        if reference_id.startswith("vault:"):
            return self.vault.get_secret(reference_id, now=now)
        msg = f"unsupported credential reference: {reference_id}"
        raise CredentialMaterialNotFoundError(msg)

    def resolve_adapter_credentials(
        self,
        *,
        service_id: str,
        credential_keys: Sequence[str],
        now: datetime | None = None,
    ) -> AdapterCredentialResolution:
        """Resolve adapter credential keys into an internal, non-logging bundle."""
        effective_now = now or datetime.now(tz=UTC)
        unique_keys = tuple(dict.fromkeys(credential_keys))
        if not unique_keys:
            return AdapterCredentialResolution(state=AdapterCredentialState.AVAILABLE)

        missing_keys: list[str] = []
        resolved_credentials: dict[str, str] = {}
        for credential_key in unique_keys:
            request_record = self.request_manager.find_satisfied_request(
                service_id=service_id,
                credential_key=credential_key,
                now=effective_now,
            )
            if request_record is None or request_record.credential_reference is None:
                missing_keys.append(credential_key)
                continue
            try:
                resolved_credentials[credential_key] = self.get_secret(
                    request_record.credential_reference,
                    now=effective_now,
                )
            except CredentialVaultLockedError:
                return AdapterCredentialResolution(
                    state=AdapterCredentialState.LOCKED,
                    missing_keys=tuple(unique_keys),
                    detail="vault is locked",
                )
            except CredentialMaterialNotFoundError:
                missing_keys.append(credential_key)

        if missing_keys:
            return AdapterCredentialResolution(
                state=AdapterCredentialState.UNCONFIGURED,
                missing_keys=tuple(missing_keys),
                detail="adapter credentials are not configured",
            )
        return AdapterCredentialResolution(
            state=AdapterCredentialState.AVAILABLE,
            credentials=resolved_credentials,
        )

    def vault_status(self, *, now: datetime | None = None) -> VaultStatus:
        """Return current vault initialization and lock state."""
        return self.vault.status(now=now)

    def unlock_vault(
        self,
        master_passphrase: str,
        *,
        now: datetime | None = None,
    ) -> VaultStatus:
        """Initialize or unlock the vault with the supplied passphrase."""
        return self.vault.unlock(master_passphrase, now=now)

    def lock_vault(self) -> VaultStatus:
        """Explicitly lock the vault and forget the in-memory unlock key."""
        return self.vault.lock()

    def list_vault_credentials(self) -> list[VaultCredentialRecord]:
        """List stored vault credentials without exposing their values."""
        return self.vault.list_credentials()

    def test_vault_credentials(
        self,
        *,
        now: datetime | None = None,
    ) -> list[VaultCredentialTestResult]:
        """Run an explicit readability test across all stored vault credentials."""
        return self.vault.test_credentials(now=now)

    def change_vault_master_passphrase(
        self,
        *,
        current_master_passphrase: str,
        new_master_passphrase: str,
        now: datetime | None = None,
    ) -> VaultStatus:
        """Rotate the vault master passphrase and re-encrypt stored secrets."""
        return self.vault.change_master_passphrase(
            current_master_passphrase=current_master_passphrase,
            new_master_passphrase=new_master_passphrase,
            now=now,
        )


def _build_vault_config_record(
    master_passphrase: str,
    *,
    now: datetime,
) -> tuple[VaultConfigRecord, bytes]:
    """Build one persisted vault config record and its derived Fernet key."""
    salt_b64 = base64.b64encode(token_bytes(16)).decode("ascii")
    derived_key = _derive_fernet_key(master_passphrase, salt_b64)
    return (
        VaultConfigRecord(
            salt_b64=salt_b64,
            verifier_token=Fernet(derived_key)
            .encrypt(_VERIFIER_PLAINTEXT)
            .decode("utf-8"),
            created_at=now,
            updated_at=now,
        ),
        derived_key,
    )


def _verified_fernet_key(
    master_passphrase: str,
    *,
    config: VaultConfigRecord,
) -> bytes:
    """Validate one passphrase against persisted config and return the derived key."""
    derived_key = _derive_fernet_key(master_passphrase, config.salt_b64)
    try:
        Fernet(derived_key).decrypt(config.verifier_token.encode("utf-8"))
    except InvalidToken as exc:
        raise CredentialVaultPassphraseError("master passphrase is invalid") from exc
    return derived_key


def _upsert_vault_config_record(connection: Connection, record: VaultConfigRecord) -> None:
    """Persist one vault config record on an existing transaction."""
    connection.execute(
        """
        INSERT INTO vault_config (singleton_key, updated_at, payload)
        VALUES (?, ?, ?)
        ON CONFLICT(singleton_key) DO UPDATE SET
            updated_at = excluded.updated_at,
            payload = excluded.payload
        """,
        (
            1,
            record.updated_at.isoformat(),
            record.model_dump_json(),
        ),
    )


def _upsert_vault_credential_record(
    connection: Connection,
    record: VaultCredentialRecord,
) -> None:
    """Persist one vault credential record on an existing transaction."""
    connection.execute(
        """
        INSERT INTO vault_credentials (
            reference_id,
            request_id,
            service_id,
            updated_at,
            payload
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(reference_id) DO UPDATE SET
            request_id = excluded.request_id,
            service_id = excluded.service_id,
            updated_at = excluded.updated_at,
            payload = excluded.payload
        """,
        (
            record.reference_id,
            record.request_id,
            record.service_id,
            record.updated_at.isoformat(),
            record.model_dump_json(),
        ),
    )


def _derive_fernet_key(master_passphrase: str, salt_b64: str) -> bytes:
    """Derive one Fernet-compatible key from the supplied master passphrase."""
    salt = base64.b64decode(salt_b64.encode("ascii"))
    derived_key = Argon2id(
        salt=salt,
        length=_DERIVED_KEY_LENGTH,
        iterations=_ARGON2_ITERATIONS,
        lanes=_ARGON2_LANES,
        memory_cost=_ARGON2_MEMORY_COST,
    ).derive(master_passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(derived_key)
