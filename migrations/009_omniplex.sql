CREATE TABLE IF NOT EXISTS omniplex_changelogs (
    version TEXT PRIMARY KEY,
    entry_id TEXT,
    posted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
