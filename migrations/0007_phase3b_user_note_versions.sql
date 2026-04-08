CREATE TABLE IF NOT EXISTS user_note_versions (
    id TEXT PRIMARY KEY,
    note_id TEXT NOT NULL,
    version_number INTEGER NOT NULL,
    recorded_at TEXT NOT NULL,
    archived TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(note_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_user_note_versions_note_version
    ON user_note_versions (note_id, version_number);
