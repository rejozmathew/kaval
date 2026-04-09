CREATE TABLE IF NOT EXISTS service_check_overrides (
    scope TEXT NOT NULL,
    service_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (scope, service_id, check_id)
);

CREATE INDEX IF NOT EXISTS idx_service_check_overrides_scope_service
    ON service_check_overrides (scope, service_id, check_id);
