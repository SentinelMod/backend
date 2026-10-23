CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS guilds (
    guild_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS guild_admins (
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    user_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS limits (
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    limit_id TEXT PRIMARY KEY DEFAULT uuid_generate_v4(),
    limit_name TEXT NOT NULL DEFAULT 'Untitled',
    limit_type TEXT NOT NULL,
    limit_action TEXT NOT NULL,
    limit_per INTEGER NOT NULL,
    limit_time INTERVAL NOT NULL
);

CREATE TABLE IF NOT EXISTS user_actions (
    action_id TEXT PRIMARY KEY,
    limit_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id TEXT NOT NULL,
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    action_target TEXT NOT NULL,
    limits_hit TEXT[] NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS past_hit_limits (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    guild_id TEXT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE ON UPDATE CASCADE,
    limit_id TEXT NOT NULL REFERENCES limits(limit_id) ON DELETE CASCADE ON UPDATE CASCADE,
    cause TEXT[] NOT NULL DEFAULT '{}',
    notes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
