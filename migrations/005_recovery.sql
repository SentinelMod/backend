ALTER TABLE limits ADD COLUMN IF NOT EXISTS limit_scope TEXT NOT NULL DEFAULT 'moderator';
ALTER TABLE limits ADD COLUMN IF NOT EXISTS dry_run BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE past_hit_limits ADD COLUMN IF NOT EXISTS dry_run BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS guard_webhooks BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS guard_vanity BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS auto_lockdown BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS auto_lockdown_threshold INTEGER NOT NULL DEFAULT 2;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS auto_lockdown_window_secs INTEGER NOT NULL DEFAULT 300;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS snapshots_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS digest_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS digest_last_sent TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    trigger TEXT NOT NULL,
    created_by TEXT,
    roles JSONB NOT NULL,
    channels JSONB NOT NULL,
    role_count INTEGER NOT NULL,
    channel_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS snapshots_guild_idx ON snapshots (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS past_hit_limits_recent_idx ON past_hit_limits (guild_id, dry_run, created_at DESC);
CREATE INDEX IF NOT EXISTS user_actions_created_idx ON user_actions (created_at);

ALTER TABLE audit_trail DROP CONSTRAINT IF EXISTS audit_trail_source_check;
ALTER TABLE audit_trail ADD CONSTRAINT audit_trail_source_check CHECK (source IN ('dashboard', 'command', 'guard', 'lockdown', 'recovery', 'system'));
