CREATE TABLE IF NOT EXISTS capability_runtime_signals (
    source TEXT PRIMARY KEY,
    recorded_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_capability_runtime_signals_recorded_at
    ON capability_runtime_signals (recorded_at);
