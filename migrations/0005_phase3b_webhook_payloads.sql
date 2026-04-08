CREATE TABLE IF NOT EXISTS webhook_payloads (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    received_at TEXT NOT NULL,
    retention_until TEXT NOT NULL,
    incident_id TEXT,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_payloads_source_received_at
    ON webhook_payloads (source_id, received_at);

CREATE INDEX IF NOT EXISTS idx_webhook_payloads_retention_until
    ON webhook_payloads (retention_until);

CREATE INDEX IF NOT EXISTS idx_webhook_payloads_incident_id
    ON webhook_payloads (incident_id);
