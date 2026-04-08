CREATE TABLE IF NOT EXISTS webhook_event_states (
    state_key TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    active TEXT NOT NULL,
    last_received_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_event_states_source_dedup
    ON webhook_event_states (source_id, dedup_key);

CREATE INDEX IF NOT EXISTS idx_webhook_event_states_last_received_at
    ON webhook_event_states (last_received_at);
