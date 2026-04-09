"""SQLite persistence layer for Kaval Phase 0."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar, cast

from kaval.credentials.models import (
    CredentialRequest,
    VaultConfigRecord,
    VaultCredentialRecord,
)
from kaval.integrations.webhooks import WebhookStoredPayload
from kaval.integrations.webhooks.state import WebhookEventStateRecord
from kaval.memory.note_models import UserNoteVersion
from kaval.models import (
    ApprovalToken,
    Change,
    DependencyConfidence,
    DependencyEdge,
    DependencyOverride,
    DependencyOverrideState,
    DependencySource,
    DescriptorSource,
    Finding,
    FindingFeedbackRecord,
    Incident,
    Investigation,
    JournalEntry,
    KavalModel,
    MaintenanceScope,
    MaintenanceWindowRecord,
    Service,
    ServiceCheckOverride,
    ServiceCheckOverrideScope,
    SystemProfile,
    UserNote,
)
from kaval.runtime.capability_runtime import (
    CapabilityRuntimeSignal,
    CapabilityRuntimeSignalSource,
    validate_capability_runtime_signal_json,
)

ModelT = TypeVar("ModelT", bound=KavalModel)


def default_migrations_dir() -> Path:
    """Return the default migrations directory for the repository."""
    return Path(__file__).resolve().parents[2] / "migrations"


def _maintenance_scope_key(
    *,
    scope: MaintenanceScope,
    service_id: str | None,
) -> str:
    """Return the stable database key for one maintenance window scope."""
    if scope is MaintenanceScope.GLOBAL:
        return "global"
    if service_id is None:
        msg = "service maintenance windows require service_id"
        raise ValueError(msg)
    return service_id


@dataclass(slots=True)
class KavalDatabase:
    """SQLite-backed persistence for Phase 0 entities and contracts."""

    path: Path | str
    migrations_dir: Path | str | None = None
    _connection: sqlite3.Connection | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize constructor paths."""
        self.path = Path(self.path)
        self.migrations_dir = (
            default_migrations_dir() if self.migrations_dir is None else Path(self.migrations_dir)
        )

    def connection(self) -> sqlite3.Connection:
        """Return an open SQLite connection."""
        if self._connection is None:
            database_path = Path(self.path)
            database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(database_path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            self._connection = connection
        return self._connection

    def close(self) -> None:
        """Close the underlying SQLite connection if it is open."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def bootstrap(self) -> None:
        """Create the migrations table and apply any pending SQL migrations."""
        connection = self.connection()
        migrations_dir = (
            default_migrations_dir()
            if self.migrations_dir is None
            else Path(self.migrations_dir)
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        applied_versions = set(self.applied_migrations())
        migration_paths = sorted(migrations_dir.glob("*.sql"))
        for migration_path in migration_paths:
            version = migration_path.stem
            if version in applied_versions:
                continue
            sql = migration_path.read_text(encoding="utf-8")
            with connection:
                connection.executescript(sql)
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, self._now_iso()),
                )

    def applied_migrations(self) -> list[str]:
        """Return applied migration versions in ascending order."""
        rows = self.connection().execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        return [str(row["version"]) for row in rows]

    def upsert_finding(self, finding: Finding) -> None:
        """Insert or update a finding record."""
        self._upsert_record(
            table="findings",
            key_column="id",
            key_value=finding.id,
            payload=finding,
            columns={
                "status": finding.status.value,
                "severity": finding.severity.value,
                "service_id": finding.service_id,
                "incident_id": finding.incident_id,
                "created_at": finding.created_at.isoformat(),
            },
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        """Fetch a finding by identifier."""
        return self._get_record("findings", "id", finding_id, Finding)

    def list_findings(self) -> list[Finding]:
        """List findings ordered by creation time and identifier."""
        return self._list_records("findings", "created_at, id", Finding)

    def delete_finding(self, finding_id: str) -> None:
        """Delete a finding by identifier."""
        self._delete_record("findings", "id", finding_id)

    def upsert_finding_feedback_record(
        self,
        finding_feedback_record: FindingFeedbackRecord,
    ) -> None:
        """Insert or update one persisted finding-feedback record."""
        self._upsert_record(
            table="finding_feedback_records",
            key_column="id",
            key_value=finding_feedback_record.id,
            payload=finding_feedback_record,
            columns={
                "finding_id": finding_feedback_record.finding_id,
                "service_id": finding_feedback_record.service_id,
                "finding_domain": finding_feedback_record.finding_domain,
                "reason": finding_feedback_record.reason.value,
                "recorded_at": finding_feedback_record.recorded_at.isoformat(),
            },
        )

    def list_finding_feedback_records(self) -> list[FindingFeedbackRecord]:
        """List finding-feedback records ordered by time and identifier."""
        return self._list_records(
            "finding_feedback_records",
            "recorded_at, id",
            FindingFeedbackRecord,
        )

    def upsert_maintenance_window(
        self,
        maintenance_window: MaintenanceWindowRecord,
    ) -> None:
        """Insert or update one persisted maintenance window."""
        self._upsert_record(
            table="maintenance_windows",
            key_column="scope_key",
            key_value=_maintenance_scope_key(
                scope=maintenance_window.scope,
                service_id=maintenance_window.service_id,
            ),
            payload=maintenance_window,
            columns={
                "scope": maintenance_window.scope.value,
                "service_id": maintenance_window.service_id,
                "expires_at": maintenance_window.expires_at.isoformat(),
            },
        )

    def list_maintenance_windows(self) -> list[MaintenanceWindowRecord]:
        """List persisted maintenance windows ordered by scope and expiry."""
        return self._list_records(
            "maintenance_windows",
            "scope, service_id, expires_at, scope_key",
            MaintenanceWindowRecord,
        )

    def delete_maintenance_window(
        self,
        *,
        scope: MaintenanceScope,
        service_id: str | None = None,
    ) -> None:
        """Delete one persisted maintenance window by scope identity."""
        self._delete_record(
            "maintenance_windows",
            "scope_key",
            _maintenance_scope_key(scope=scope, service_id=service_id),
        )

    def upsert_incident(self, incident: Incident) -> None:
        """Insert or update an incident record."""
        self._upsert_record(
            table="incidents",
            key_column="id",
            key_value=incident.id,
            payload=incident,
            columns={
                "status": incident.status.value,
                "severity": incident.severity.value,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
            },
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        """Fetch an incident by identifier."""
        return self._get_record("incidents", "id", incident_id, Incident)

    def list_incidents(self) -> list[Incident]:
        """List incidents ordered by creation time and identifier."""
        return self._list_records("incidents", "created_at, id", Incident)

    def delete_incident(self, incident_id: str) -> None:
        """Delete an incident by identifier."""
        self._delete_record("incidents", "id", incident_id)

    def upsert_investigation(self, investigation: Investigation) -> None:
        """Insert or update an investigation record."""
        self._upsert_record(
            table="investigations",
            key_column="id",
            key_value=investigation.id,
            payload=investigation,
            columns={
                "incident_id": investigation.incident_id,
                "status": investigation.status.value,
                "started_at": investigation.started_at.isoformat(),
            },
        )

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        """Fetch an investigation by identifier."""
        return self._get_record("investigations", "id", investigation_id, Investigation)

    def list_investigations(self) -> list[Investigation]:
        """List investigations ordered by start time and identifier."""
        return self._list_records("investigations", "started_at, id", Investigation)

    def delete_investigation(self, investigation_id: str) -> None:
        """Delete an investigation by identifier."""
        self._delete_record("investigations", "id", investigation_id)

    def upsert_service(self, service: Service) -> None:
        """Insert or update a service record."""
        self._upsert_record(
            table="services",
            key_column="id",
            key_value=service.id,
            payload=service,
            columns={
                "type": service.type.value,
                "status": service.status.value,
                "last_check": service.last_check.isoformat() if service.last_check else None,
            },
        )

    def get_service(self, service_id: str) -> Service | None:
        """Fetch a service by identifier."""
        return next(
            (service for service in self.list_services() if service.id == service_id),
            None,
        )

    def list_services(self) -> list[Service]:
        """List services ordered by type and identifier."""
        services = self._list_records("services", "type, id", Service)
        return _apply_dependency_overrides(
            services,
            self.list_dependency_overrides(),
        )

    def delete_service(self, service_id: str) -> None:
        """Delete a service by identifier."""
        self._delete_record("services", "id", service_id)

    def update_descriptor_source_for_services(
        self,
        *,
        descriptor_id: str,
        descriptor_source: DescriptorSource,
    ) -> None:
        """Persist a new descriptor source for all services using one descriptor."""
        rows = self.connection().execute("SELECT payload FROM services").fetchall()
        for row in rows:
            service = Service.model_validate_json(str(row["payload"]))
            if (
                service.descriptor_id != descriptor_id
                or service.descriptor_source == descriptor_source
            ):
                continue
            self.upsert_service(
                service.model_copy(update={"descriptor_source": descriptor_source})
            )

    def upsert_dependency_override(self, override: DependencyOverride) -> None:
        """Insert or update one persisted dependency override."""
        with self.connection():
            self.connection().execute(
                """
                INSERT INTO dependency_overrides (
                    source_service_id,
                    target_service_id,
                    state,
                    updated_at,
                    payload
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_service_id, target_service_id) DO UPDATE SET
                    state = excluded.state,
                    updated_at = excluded.updated_at,
                    payload = excluded.payload
                """,
                (
                    override.source_service_id,
                    override.target_service_id,
                    override.state.value,
                    override.updated_at.isoformat(),
                    override.model_dump_json(),
                ),
            )

    def get_dependency_override(
        self,
        source_service_id: str,
        target_service_id: str,
    ) -> DependencyOverride | None:
        """Fetch one dependency override by its source and target pair."""
        row = self.connection().execute(
            """
            SELECT payload
            FROM dependency_overrides
            WHERE source_service_id = ? AND target_service_id = ?
            """,
            (source_service_id, target_service_id),
        ).fetchone()
        if row is None:
            return None
        return DependencyOverride.model_validate_json(str(row["payload"]))

    def list_dependency_overrides(self) -> list[DependencyOverride]:
        """List dependency overrides ordered by update time and edge key."""
        rows = self.connection().execute(
            """
            SELECT payload
            FROM dependency_overrides
            ORDER BY updated_at, source_service_id, target_service_id
            """
        ).fetchall()
        return [
            DependencyOverride.model_validate_json(str(row["payload"]))
            for row in rows
        ]

    def delete_dependency_override(
        self,
        source_service_id: str,
        target_service_id: str,
    ) -> None:
        """Delete one persisted dependency override."""
        with self.connection():
            self.connection().execute(
                """
                DELETE FROM dependency_overrides
                WHERE source_service_id = ? AND target_service_id = ?
                """,
                (source_service_id, target_service_id),
            )

    def replace_service_check_overrides(
        self,
        *,
        scope: ServiceCheckOverrideScope,
        overrides: list[ServiceCheckOverride],
    ) -> None:
        """Replace the full override set for one monitoring-settings scope."""
        if any(item.scope is not scope for item in overrides):
            msg = f"all service check overrides must use scope={scope.value}"
            raise ValueError(msg)
        with self.connection():
            self.connection().execute(
                "DELETE FROM service_check_overrides WHERE scope = ?",
                (scope.value,),
            )
            for override in overrides:
                self.connection().execute(
                    """
                    INSERT INTO service_check_overrides (
                        scope,
                        service_id,
                        check_id,
                        updated_at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        override.scope.value,
                        override.service_id,
                        override.check_id,
                        override.updated_at.isoformat(),
                        override.model_dump_json(),
                    ),
                )

    def list_service_check_overrides(
        self,
        *,
        scope: ServiceCheckOverrideScope,
    ) -> list[ServiceCheckOverride]:
        """List service-scoped monitoring overrides for one apply scope."""
        rows = self.connection().execute(
            """
            SELECT payload
            FROM service_check_overrides
            WHERE scope = ?
            ORDER BY service_id, check_id
            """,
            (scope.value,),
        ).fetchall()
        return [
            ServiceCheckOverride.model_validate_json(str(row["payload"]))
            for row in rows
        ]

    def upsert_change(self, change: Change) -> None:
        """Insert or update a change record."""
        self._upsert_record(
            table="changes",
            key_column="id",
            key_value=change.id,
            payload=change,
            columns={
                "type": change.type.value,
                "service_id": change.service_id,
                "timestamp": change.timestamp.isoformat(),
            },
        )

    def get_change(self, change_id: str) -> Change | None:
        """Fetch a change by identifier."""
        return self._get_record("changes", "id", change_id, Change)

    def list_changes(self) -> list[Change]:
        """List changes ordered by timestamp and identifier."""
        return self._list_records("changes", "timestamp, id", Change)

    def delete_change(self, change_id: str) -> None:
        """Delete a change by identifier."""
        self._delete_record("changes", "id", change_id)

    def upsert_approval_token(self, token: ApprovalToken) -> None:
        """Insert or update an approval token."""
        self._upsert_record(
            table="approval_tokens",
            key_column="token_id",
            key_value=token.token_id,
            payload=token,
            columns={
                "incident_id": token.incident_id,
                "action": token.action.value,
                "target": token.target,
                "expires_at": token.expires_at.isoformat(),
                "used_at": token.used_at.isoformat() if token.used_at else None,
            },
        )

    def get_approval_token(self, token_id: str) -> ApprovalToken | None:
        """Fetch an approval token by identifier."""
        return self._get_record("approval_tokens", "token_id", token_id, ApprovalToken)

    def delete_approval_token(self, token_id: str) -> None:
        """Delete an approval token by identifier."""
        self._delete_record("approval_tokens", "token_id", token_id)

    def upsert_credential_request(self, credential_request: CredentialRequest) -> None:
        """Insert or update a credential request."""
        self._upsert_record(
            table="credential_requests",
            key_column="id",
            key_value=credential_request.id,
            payload=credential_request,
            columns={
                "incident_id": credential_request.incident_id,
                "service_id": credential_request.service_id,
                "status": credential_request.status.value,
                "requested_at": credential_request.requested_at.isoformat(),
                "expires_at": credential_request.expires_at.isoformat(),
            },
        )

    def get_credential_request(self, request_id: str) -> CredentialRequest | None:
        """Fetch a credential request by identifier."""
        return self._get_record("credential_requests", "id", request_id, CredentialRequest)

    def list_credential_requests(self) -> list[CredentialRequest]:
        """List credential requests ordered by request time and identifier."""
        return self._list_records(
            "credential_requests",
            "requested_at, id",
            CredentialRequest,
        )

    def delete_credential_request(self, request_id: str) -> None:
        """Delete a credential request by identifier."""
        self._delete_record("credential_requests", "id", request_id)

    def upsert_vault_config(self, vault_config: VaultConfigRecord) -> None:
        """Insert or update the singleton vault config record."""
        payload = vault_config.model_dump_json()
        with self.connection():
            self.connection().execute(
                """
                INSERT INTO vault_config (singleton_key, updated_at, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(singleton_key) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    payload = excluded.payload
                """,
                (1, vault_config.updated_at.isoformat(), payload),
            )

    def get_vault_config(self) -> VaultConfigRecord | None:
        """Fetch the singleton vault config record."""
        row = self.connection().execute(
            "SELECT payload FROM vault_config WHERE singleton_key = 1"
        ).fetchone()
        if row is None:
            return None
        return VaultConfigRecord.model_validate_json(str(row["payload"]))

    def clear_vault_config(self) -> None:
        """Delete the singleton vault config record."""
        with self.connection():
            self.connection().execute("DELETE FROM vault_config WHERE singleton_key = 1")

    def upsert_vault_credential(self, record: VaultCredentialRecord) -> None:
        """Insert or update one encrypted vault credential."""
        self._upsert_record(
            table="vault_credentials",
            key_column="reference_id",
            key_value=record.reference_id,
            payload=record,
            columns={
                "request_id": record.request_id,
                "service_id": record.service_id,
                "updated_at": record.updated_at.isoformat(),
            },
        )

    def get_vault_credential(self, reference_id: str) -> VaultCredentialRecord | None:
        """Fetch one encrypted vault credential by opaque reference."""
        return self._get_record(
            "vault_credentials",
            "reference_id",
            reference_id,
            VaultCredentialRecord,
        )

    def list_vault_credentials(self) -> list[VaultCredentialRecord]:
        """List encrypted vault credentials ordered by update time and reference."""
        return self._list_records(
            "vault_credentials",
            "updated_at, reference_id",
            VaultCredentialRecord,
        )

    def delete_vault_credential(self, reference_id: str) -> None:
        """Delete one encrypted vault credential by opaque reference."""
        self._delete_record("vault_credentials", "reference_id", reference_id)

    def upsert_system_profile(self, system_profile: SystemProfile) -> None:
        """Insert or update the singleton system profile record."""
        payload = system_profile.model_dump_json()
        with self.connection():
            self.connection().execute(
                """
                INSERT INTO system_profiles (singleton_key, last_updated, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(singleton_key) DO UPDATE SET
                    last_updated = excluded.last_updated,
                    payload = excluded.payload
                """,
                (1, system_profile.last_updated.isoformat(), payload),
            )

    def get_system_profile(self) -> SystemProfile | None:
        """Fetch the singleton system profile record."""
        row = self.connection().execute(
            "SELECT payload FROM system_profiles WHERE singleton_key = 1"
        ).fetchone()
        if row is None:
            return None
        return SystemProfile.model_validate_json(str(row["payload"]))

    def clear_system_profile(self) -> None:
        """Delete the singleton system profile record."""
        with self.connection():
            self.connection().execute("DELETE FROM system_profiles WHERE singleton_key = 1")

    def upsert_capability_runtime_signal(self, signal: CapabilityRuntimeSignal) -> None:
        """Insert or update one runtime telemetry signal for capability health."""
        self._upsert_record(
            table="capability_runtime_signals",
            key_column="source",
            key_value=str(signal.source),
            payload=cast(KavalModel, signal),
            columns={
                "recorded_at": signal.recorded_at.isoformat(),
            },
        )

    def get_capability_runtime_signal(
        self,
        source: CapabilityRuntimeSignalSource,
    ) -> CapabilityRuntimeSignal | None:
        """Fetch one runtime telemetry signal by capability source."""
        row = self.connection().execute(
            "SELECT payload FROM capability_runtime_signals WHERE source = ?",
            (source.value,),
        ).fetchone()
        if row is None:
            return None
        return validate_capability_runtime_signal_json(str(row["payload"]))

    def list_capability_runtime_signals(self) -> list[CapabilityRuntimeSignal]:
        """List runtime telemetry signals ordered by source."""
        rows = self.connection().execute(
            "SELECT payload FROM capability_runtime_signals ORDER BY source"
        ).fetchall()
        return [
            validate_capability_runtime_signal_json(str(row["payload"]))
            for row in rows
        ]

    def delete_capability_runtime_signal(
        self,
        source: CapabilityRuntimeSignalSource,
    ) -> None:
        """Delete one capability runtime signal by source."""
        self._delete_record("capability_runtime_signals", "source", source.value)

    def migrations_current(self) -> bool:
        """Return whether all checked-in SQL migrations are applied."""
        applied = set(self.applied_migrations())
        migrations_dir = (
            default_migrations_dir()
            if self.migrations_dir is None
            else Path(self.migrations_dir)
        )
        available = {
            migration_path.stem
            for migration_path in migrations_dir.glob("*.sql")
        }
        return applied == available

    def upsert_journal_entry(self, journal_entry: JournalEntry) -> None:
        """Insert or update a journal entry."""
        self._upsert_record(
            table="journal_entries",
            key_column="id",
            key_value=journal_entry.id,
            payload=journal_entry,
            columns={
                "incident_id": journal_entry.incident_id,
                "entry_date": journal_entry.date.isoformat(),
            },
        )

    def get_journal_entry(self, journal_entry_id: str) -> JournalEntry | None:
        """Fetch a journal entry by identifier."""
        return self._get_record("journal_entries", "id", journal_entry_id, JournalEntry)

    def list_journal_entries(self) -> list[JournalEntry]:
        """List journal entries ordered by entry date and identifier."""
        return self._list_records("journal_entries", "entry_date, id", JournalEntry)

    def delete_journal_entry(self, journal_entry_id: str) -> None:
        """Delete a journal entry by identifier."""
        self._delete_record("journal_entries", "id", journal_entry_id)

    def upsert_user_note(self, user_note: UserNote) -> None:
        """Insert or update a user note."""
        self._upsert_record(
            table="user_notes",
            key_column="id",
            key_value=user_note.id,
            payload=user_note,
            columns={
                "service_id": user_note.service_id,
                "updated_at": user_note.updated_at.isoformat(),
            },
        )

    def get_user_note(self, user_note_id: str) -> UserNote | None:
        """Fetch a user note by identifier."""
        return self._get_record("user_notes", "id", user_note_id, UserNote)

    def list_user_notes(self) -> list[UserNote]:
        """List user notes ordered by update time and identifier."""
        return self._list_records("user_notes", "updated_at, id", UserNote)

    def delete_user_note(self, user_note_id: str) -> None:
        """Delete a user note by identifier."""
        self._delete_record("user_notes", "id", user_note_id)

    def upsert_user_note_version(self, user_note_version: UserNoteVersion) -> None:
        """Insert or update one retained user-note version snapshot."""
        with self.connection():
            self.connection().execute(
                """
                INSERT INTO user_note_versions (
                    id,
                    note_id,
                    version_number,
                    recorded_at,
                    archived,
                    payload
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    note_id = excluded.note_id,
                    version_number = excluded.version_number,
                    recorded_at = excluded.recorded_at,
                    archived = excluded.archived,
                    payload = excluded.payload
                """,
                (
                    user_note_version.id,
                    user_note_version.note_id,
                    user_note_version.version_number,
                    user_note_version.recorded_at.isoformat(),
                    "1" if user_note_version.archived else "0",
                    user_note_version.model_dump_json(),
                ),
            )

    def list_user_note_versions(self, note_id: str) -> list[UserNoteVersion]:
        """List version snapshots for one note in ascending version order."""
        rows = self.connection().execute(
            """
            SELECT payload
            FROM user_note_versions
            WHERE note_id = ?
            ORDER BY version_number, recorded_at, id
            """,
            (note_id,),
        ).fetchall()
        return [
            UserNoteVersion.model_validate_json(str(row["payload"]))
            for row in rows
        ]

    def delete_user_note_versions(self, note_id: str) -> None:
        """Delete all retained version snapshots for one note."""
        with self.connection():
            self.connection().execute(
                "DELETE FROM user_note_versions WHERE note_id = ?",
                (note_id,),
            )

    def upsert_webhook_payload(self, webhook_payload: WebhookStoredPayload) -> None:
        """Insert or update one retained redacted webhook payload."""
        self._upsert_record(
            table="webhook_payloads",
            key_column="id",
            key_value=webhook_payload.id,
            payload=webhook_payload,
            columns={
                "source_id": webhook_payload.source_id,
                "source_type": webhook_payload.source_type.value,
                "received_at": webhook_payload.received_at.isoformat(),
                "retention_until": webhook_payload.raw_payload_retention_until.isoformat(),
                "incident_id": webhook_payload.incident_id,
            },
        )

    def get_webhook_payload(self, webhook_payload_id: str) -> WebhookStoredPayload | None:
        """Fetch one retained webhook payload by identifier."""
        return self._get_record("webhook_payloads", "id", webhook_payload_id, WebhookStoredPayload)

    def list_webhook_payloads(self) -> list[WebhookStoredPayload]:
        """List retained webhook payloads ordered by receive time and identifier."""
        return self._list_records("webhook_payloads", "received_at, id", WebhookStoredPayload)

    def delete_webhook_payload(self, webhook_payload_id: str) -> None:
        """Delete one retained webhook payload by identifier."""
        self._delete_record("webhook_payloads", "id", webhook_payload_id)

    def purge_expired_webhook_payloads(
        self,
        *,
        now: datetime,
        open_incident_ids: set[str] | frozenset[str] = frozenset(),
    ) -> int:
        """Delete expired webhook payloads unless they are tied to active incidents."""
        rows = self.connection().execute(
            """
            SELECT id, incident_id
            FROM webhook_payloads
            WHERE retention_until < ?
            """,
            (now.isoformat(),),
        ).fetchall()
        expired_ids = [
            str(row["id"])
            for row in rows
            if row["incident_id"] is None or str(row["incident_id"]) not in open_incident_ids
        ]
        if not expired_ids:
            return 0
        placeholders = ", ".join("?" for _ in expired_ids)
        with self.connection():
            self.connection().execute(
                f"DELETE FROM webhook_payloads WHERE id IN ({placeholders})",
                expired_ids,
            )
        return len(expired_ids)

    def upsert_webhook_event_state(self, state_record: WebhookEventStateRecord) -> None:
        """Insert or update one normalized webhook dedup-state record."""
        self._upsert_record(
            table="webhook_event_states",
            key_column="state_key",
            key_value=state_record.state_key,
            payload=state_record,
            columns={
                "source_id": state_record.source_id,
                "dedup_key": state_record.dedup_key,
                "active": "1" if state_record.active else "0",
                "last_received_at": state_record.last_received_at.isoformat(),
            },
        )

    def get_webhook_event_state(self, state_key: str) -> WebhookEventStateRecord | None:
        """Fetch one normalized webhook dedup-state record by key."""
        return self._get_record(
            "webhook_event_states",
            "state_key",
            state_key,
            WebhookEventStateRecord,
        )

    def list_webhook_event_states(self) -> list[WebhookEventStateRecord]:
        """List normalized webhook dedup-state records ordered by receive time and key."""
        return self._list_records(
            "webhook_event_states",
            "last_received_at, state_key",
            WebhookEventStateRecord,
        )

    def delete_webhook_event_state(self, state_key: str) -> None:
        """Delete one normalized webhook dedup-state record by key."""
        self._delete_record("webhook_event_states", "state_key", state_key)

    def _upsert_record(
        self,
        *,
        table: str,
        key_column: str,
        key_value: str,
        payload: ModelT,
        columns: dict[str, str | None],
    ) -> None:
        """Insert or update a model payload with a small indexed projection."""
        ordered_columns = [key_column, *columns.keys(), "payload"]
        placeholders = ", ".join("?" for _ in ordered_columns)
        update_columns = ", ".join(
            f"{column} = excluded.{column}" for column in [*columns.keys(), "payload"]
        )
        sql = f"""
            INSERT INTO {table} ({", ".join(ordered_columns)})
            VALUES ({placeholders})
            ON CONFLICT({key_column}) DO UPDATE SET
                {update_columns}
        """
        values = [key_value, *columns.values(), payload.model_dump_json()]
        with self.connection():
            self.connection().execute(sql, values)

    def _get_record(
        self,
        table: str,
        key_column: str,
        key_value: str,
        model_type: type[ModelT],
    ) -> ModelT | None:
        """Fetch and deserialize a stored model payload."""
        row = self.connection().execute(
            f"SELECT payload FROM {table} WHERE {key_column} = ?",
            (key_value,),
        ).fetchone()
        if row is None:
            return None
        return model_type.model_validate_json(str(row["payload"]))

    def _list_records(self, table: str, order_by: str, model_type: type[ModelT]) -> list[ModelT]:
        """List records from a table and deserialize their payloads."""
        rows = self.connection().execute(
            f"SELECT payload FROM {table} ORDER BY {order_by}"
        ).fetchall()
        return [model_type.model_validate_json(str(row["payload"])) for row in rows]

    def _delete_record(self, table: str, key_column: str, key_value: str) -> None:
        """Delete a record from a table by identifier."""
        with self.connection():
            self.connection().execute(
                f"DELETE FROM {table} WHERE {key_column} = ?",
                (key_value,),
            )

    @staticmethod
    def _now_iso() -> str:
        """Return the current UTC timestamp in ISO 8601 format."""
        return datetime.now(tz=UTC).isoformat()


def _apply_dependency_overrides(
    services: list[Service],
    overrides: list[DependencyOverride],
) -> list[Service]:
    """Return services with persisted dependency overrides merged into the graph."""
    services_by_id = {
        service.id: service.model_copy(
            deep=True,
            update={
                "dependencies": list(service.dependencies),
                "dependents": [],
            },
        )
        for service in services
    }

    for override in overrides:
        source = services_by_id.get(override.source_service_id)
        if source is None or override.target_service_id not in services_by_id:
            continue

        edges_by_target = {
            edge.target_service_id: edge
            for edge in source.dependencies
        }
        if override.state is DependencyOverrideState.ABSENT:
            edges_by_target.pop(override.target_service_id, None)
        else:
            existing_edge = edges_by_target.get(override.target_service_id)
            edges_by_target[override.target_service_id] = DependencyEdge(
                target_service_id=override.target_service_id,
                confidence=DependencyConfidence.USER_CONFIRMED,
                source=DependencySource.USER,
                description=(
                    override.description
                    if override.description is not None
                    else existing_edge.description
                    if existing_edge is not None
                    else "Dependency confirmed by the local admin."
                ),
            )
        services_by_id[source.id] = source.model_copy(
            update={
                "dependencies": sorted(
                    edges_by_target.values(),
                    key=lambda edge: edge.target_service_id,
                )
            }
        )

    dependents_by_id = {
        service.id: {
            dependent
            for dependent in service.dependents
            if dependent not in services_by_id
        }
        for service in services
    }
    for service in services_by_id.values():
        for edge in service.dependencies:
            dependents = dependents_by_id.get(edge.target_service_id)
            if dependents is not None:
                dependents.add(service.id)

    return [
        services_by_id[service.id].model_copy(
            update={"dependents": sorted(dependents_by_id[service.id])}
        )
        for service in services
    ]
