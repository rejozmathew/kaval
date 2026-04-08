CREATE TABLE IF NOT EXISTS dependency_overrides (
    source_service_id TEXT NOT NULL,
    target_service_id TEXT NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (source_service_id, target_service_id)
);

CREATE INDEX IF NOT EXISTS idx_dependency_overrides_source_updated_at
    ON dependency_overrides (source_service_id, updated_at);
