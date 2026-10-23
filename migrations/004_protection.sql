ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS alert_role_id TEXT;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS alert_dm_owner BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS guard_bot_add BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE guild_settings ADD COLUMN IF NOT EXISTS guard_dangerous_perms BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE past_hit_limits ADD COLUMN IF NOT EXISTS action_taken TEXT;

CREATE TABLE IF NOT EXISTS quarantines (
    id TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    user_id TEXT NOT NULL,
    roles TEXT[] NOT NULL DEFAULT '{}',
    hit_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    restored_at TIMESTAMPTZ,
    restored_by TEXT
);

CREATE INDEX IF NOT EXISTS quarantines_guild_idx ON quarantines (guild_id, created_at DESC);

CREATE TABLE IF NOT EXISTS lockdowns (
    guild_id TEXT PRIMARY KEY REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_by TEXT NOT NULL,
    removed_permissions JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    user_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('dashboard', 'command', 'guard', 'lockdown')),
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_trail_guild_idx ON audit_trail (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS user_actions_guild_idx ON user_actions (guild_id, created_at DESC);
CREATE INDEX IF NOT EXISTS past_hit_limits_guild_idx ON past_hit_limits (guild_id, created_at DESC);
