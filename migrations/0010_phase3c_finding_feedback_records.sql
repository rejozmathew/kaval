CREATE TABLE IF NOT EXISTS finding_feedback_records (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    finding_domain TEXT NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_feedback_records_pattern
    ON finding_feedback_records (service_id, finding_domain, recorded_at, id);

CREATE INDEX IF NOT EXISTS idx_finding_feedback_records_finding
    ON finding_feedback_records (finding_id, recorded_at, id);
