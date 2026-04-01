CREATE TABLE IF NOT EXISTS vault_config (
    singleton_key INTEGER PRIMARY KEY CHECK (singleton_key = 1),
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_credentials (
    reference_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_credentials_request_id
    ON vault_credentials (request_id);

CREATE INDEX IF NOT EXISTS idx_vault_credentials_service_updated_at
    ON vault_credentials (service_id, updated_at);
