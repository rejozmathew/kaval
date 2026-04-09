CREATE TABLE IF NOT EXISTS maintenance_windows (
    scope_key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    service_id TEXT,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_maintenance_windows_scope_expires
    ON maintenance_windows (scope, service_id, expires_at, scope_key);
