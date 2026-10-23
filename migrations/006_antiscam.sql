ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_links BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_mentions BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_mention_limit INTEGER NOT NULL DEFAULT 6;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_timeout_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_link_rule_id TEXT;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_mention_rule_id TEXT;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_synced_at TIMESTAMPTZ;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS antiscam_error TEXT;

ALTER TABLE audit_trail DROP CONSTRAINT IF EXISTS audit_trail_source_check;
ALTER TABLE audit_trail ADD CONSTRAINT audit_trail_source_check CHECK (source IN ('dashboard', 'command', 'guard', 'lockdown', 'recovery', 'system', 'antiscam'));
