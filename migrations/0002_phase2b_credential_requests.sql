CREATE TABLE IF NOT EXISTS credential_requests (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_requests_incident_requested_at
    ON credential_requests (incident_id, requested_at);

CREATE INDEX IF NOT EXISTS idx_credential_requests_status_expires_at
    ON credential_requests (status, expires_at);
