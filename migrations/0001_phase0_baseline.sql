CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    service_id TEXT NOT NULL,
    incident_id TEXT,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_status_created_at
    ON findings (status, created_at);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_created_at
    ON incidents (status, created_at);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_incident_id
    ON investigations (incident_id);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    last_check TEXT,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_services_type_status
    ON services (type, status);

CREATE TABLE IF NOT EXISTS changes (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    service_id TEXT,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changes_service_timestamp
    ON changes (service_id, timestamp);

CREATE TABLE IF NOT EXISTS approval_tokens (
    token_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_tokens_incident_id
    ON approval_tokens (incident_id);

CREATE TABLE IF NOT EXISTS system_profiles (
    singleton_key INTEGER PRIMARY KEY CHECK (singleton_key = 1),
    last_updated TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS journal_entries (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    entry_date TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_journal_entries_incident_date
    ON journal_entries (incident_id, entry_date);

CREATE TABLE IF NOT EXISTS user_notes (
    id TEXT PRIMARY KEY,
    service_id TEXT,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_notes_service_updated_at
    ON user_notes (service_id, updated_at);
