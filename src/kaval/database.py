"""SQLite persistence layer for Kaval Phase 0."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from kaval.models import (
    ApprovalToken,
    Change,
    Finding,
    Incident,
    Investigation,
    JournalEntry,
    KavalModel,
    Service,
    SystemProfile,
    UserNote,
)

ModelT = TypeVar("ModelT", bound=KavalModel)


def default_migrations_dir() -> Path:
    """Return the default migrations directory for the repository."""
    return Path(__file__).resolve().parents[2] / "migrations"


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
        return self._get_record("services", "id", service_id, Service)

    def delete_service(self, service_id: str) -> None:
        """Delete a service by identifier."""
        self._delete_record("services", "id", service_id)

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

    def delete_user_note(self, user_note_id: str) -> None:
        """Delete a user note by identifier."""
        self._delete_record("user_notes", "id", user_note_id)

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
