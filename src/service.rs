use std::fmt;

use poise::serenity_prelude::{GuildId, UserId};
use sqlx::PgPool;

use crate::core::{UserLimitActions, UserLimitTypes};

pub const MAX_LIMIT_NAME: usize = 64;
pub const MAX_THRESHOLD: i32 = 1000;
pub const MAX_WINDOW_SECS: i64 = 30 * 86400;
pub const MIN_TIMEOUT_SECS: i64 = 60;
pub const MAX_TIMEOUT_SECS: i64 = 28 * 86400;
pub const DEFAULT_TIMEOUT_SECS: i64 = 3600;

#[derive(Debug)]
pub enum ServiceError {
    Invalid(String),
    NotFound(&'static str),
    Db,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::NotFound(msg) => f.write_str(msg),
            Self::Db => f.write_str("Database error"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<sqlx::Error> for ServiceError {
    fn from(e: sqlx::Error) -> Self {
        log::error!("service query failed: {}", e);
        Self::Db
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

fn invalid<T>(msg: impl Into<String>) -> ServiceResult<T> {
    Err(ServiceError::Invalid(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitScope {
    Moderator,
    Server,
}

impl LimitScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Moderator => "moderator",
            Self::Server => "server",
        }
    }

    pub fn parse(raw: &str) -> ServiceResult<Self> {
        match raw {
            "moderator" => Ok(Self::Moderator),
            "server" => Ok(Self::Server),
            _ => invalid("Scope must be moderator or server"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LimitInput {
    pub name: String,
    pub event: UserLimitTypes,
    pub action: UserLimitActions,
    pub per: i32,
    pub window_secs: i64,
    pub timeout_secs: Option<i64>,
    pub scope: LimitScope,
    pub dry_run: bool,
}

#[derive(Debug, Default, Clone)]
pub struct LimitPatch {
    pub name: Option<String>,
    pub event: Option<UserLimitTypes>,
    pub action: Option<UserLimitActions>,
    pub per: Option<i32>,
    pub window_secs: Option<i64>,
    pub timeout_secs: Option<i64>,
    pub scope: Option<LimitScope>,
    pub dry_run: Option<bool>,
}

impl LimitInput {
    pub fn validated(mut self) -> ServiceResult<Self> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() {
            return invalid("Give the limit a name");
        }
        if self.name.chars().count() > MAX_LIMIT_NAME {
            return invalid(format!("Limit names can be at most {} characters", MAX_LIMIT_NAME));
        }
        if !(1..=MAX_THRESHOLD).contains(&self.per) {
            return invalid(format!("The threshold must be between 1 and {}", MAX_THRESHOLD));
        }
        if !(1..=MAX_WINDOW_SECS).contains(&self.window_secs) {
            return invalid("The time window must be between 1 second and 30 days");
        }
        self.timeout_secs = if self.action == UserLimitActions::TimeoutUser {
            let secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
            if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) {
                return invalid("Timeouts must be between 1 minute and 28 days");
            }
            Some(secs)
        } else {
            None
        };
        Ok(self)
    }
}

pub async fn ensure_guild(pool: &PgPool, guild_id: GuildId) -> ServiceResult<()> {
    sqlx::query("INSERT INTO guilds (guild_id) VALUES ($1) ON CONFLICT (guild_id) DO NOTHING")
        .bind(guild_id.to_string())
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO guild_settings (guild_id) VALUES ($1) ON CONFLICT (guild_id) DO NOTHING")
        .bind(guild_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn is_setup(pool: &PgPool, guild_id: GuildId) -> ServiceResult<bool> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM guilds WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

pub async fn create_limit(pool: &PgPool, guild_id: GuildId, input: LimitInput) -> ServiceResult<String> {
    let input = input.validated()?;
    let (id,): (String,) = sqlx::query_as(
        "INSERT INTO limits (guild_id, limit_name, limit_type, limit_action, limit_per, limit_time, limit_timeout_duration, limit_scope, dry_run)
         VALUES ($1, $2, $3, $4, $5, make_interval(secs => $6),
                 CASE WHEN $7::double precision IS NULL THEN NULL ELSE make_interval(secs => $7) END, $8, $9)
         RETURNING limit_id",
    )
    .bind(guild_id.to_string())
    .bind(&input.name)
    .bind(input.event.to_string())
    .bind(input.action.to_string())
    .bind(input.per)
    .bind(input.window_secs as f64)
    .bind(input.timeout_secs.map(|s| s as f64))
    .bind(input.scope.as_str())
    .bind(input.dry_run)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

type LimitRow = (String, String, String, i32, i64, Option<i64>, String, bool);

pub async fn get_limit(pool: &PgPool, guild_id: GuildId, limit_id: &str) -> ServiceResult<LimitInput> {
    let row: Option<LimitRow> = sqlx::query_as(
        "SELECT limit_name, limit_type, limit_action, limit_per,
                EXTRACT(EPOCH FROM limit_time)::BIGINT, EXTRACT(EPOCH FROM limit_timeout_duration)::BIGINT,
                limit_scope, dry_run
         FROM limits WHERE guild_id = $1 AND limit_id = $2",
    )
    .bind(guild_id.to_string())
    .bind(limit_id)
    .fetch_optional(pool)
    .await?;

    let (name, event, action, per, window_secs, timeout_secs, scope, dry_run) =
        row.ok_or(ServiceError::NotFound("Could not find that limit"))?;
    Ok(LimitInput {
        name,
        event: event.parse().map_err(|_| ServiceError::Invalid("Stored limit has an unknown event".into()))?,
        action: action.parse().map_err(|_| ServiceError::Invalid("Stored limit has an unknown action".into()))?,
        per,
        window_secs,
        timeout_secs,
        scope: LimitScope::parse(&scope).unwrap_or(LimitScope::Moderator),
        dry_run,
    })
}

pub async fn update_limit(pool: &PgPool, guild_id: GuildId, limit_id: &str, patch: LimitPatch) -> ServiceResult<LimitInput> {
    let current = get_limit(pool, guild_id, limit_id).await?;
    let merged = LimitInput {
        name: patch.name.unwrap_or(current.name),
        event: patch.event.unwrap_or(current.event),
        action: patch.action.unwrap_or(current.action),
        per: patch.per.unwrap_or(current.per),
        window_secs: patch.window_secs.unwrap_or(current.window_secs),
        timeout_secs: patch.timeout_secs.or(current.timeout_secs),
        scope: patch.scope.unwrap_or(current.scope),
        dry_run: patch.dry_run.unwrap_or(current.dry_run),
    }
    .validated()?;

    sqlx::query(
        "UPDATE limits SET limit_name = $3, limit_type = $4, limit_action = $5, limit_per = $6,
                limit_time = make_interval(secs => $7),
                limit_timeout_duration = CASE WHEN $8::double precision IS NULL THEN NULL ELSE make_interval(secs => $8) END,
                limit_scope = $9, dry_run = $10
         WHERE guild_id = $1 AND limit_id = $2",
    )
    .bind(guild_id.to_string())
    .bind(limit_id)
    .bind(&merged.name)
    .bind(merged.event.to_string())
    .bind(merged.action.to_string())
    .bind(merged.per)
    .bind(merged.window_secs as f64)
    .bind(merged.timeout_secs.map(|s| s as f64))
    .bind(merged.scope.as_str())
    .bind(merged.dry_run)
    .execute(pool)
    .await?;
    Ok(merged)
}

pub async fn delete_limit(pool: &PgPool, guild_id: GuildId, limit_id: &str) -> ServiceResult<String> {
    let row: Option<(String,)> = sqlx::query_as("DELETE FROM limits WHERE guild_id = $1 AND limit_id = $2 RETURNING limit_name")
        .bind(guild_id.to_string())
        .bind(limit_id)
        .fetch_optional(pool)
        .await?;
    row.map(|(name,)| name).ok_or(ServiceError::NotFound("Could not find that limit"))
}

pub async fn limit_names(pool: &PgPool, guild_id: GuildId) -> ServiceResult<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT limit_name FROM limits WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(name,)| name.to_lowercase()).collect())
}

pub async fn whitelist_add(pool: &PgPool, guild_id: GuildId, entity_id: &str, kind: &str) -> ServiceResult<()> {
    if !matches!(kind, "user" | "role") {
        return invalid("Whitelist entries must be a user or a role");
    }
    if entity_id.parse::<u64>().is_err() {
        return invalid("That is not a valid Discord id");
    }
    sqlx::query("INSERT INTO guild_whitelist (guild_id, entity_id, entity_type) VALUES ($1, $2, $3) ON CONFLICT (guild_id, entity_id) DO NOTHING")
        .bind(guild_id.to_string())
        .bind(entity_id)
        .bind(kind)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn whitelist_remove(pool: &PgPool, guild_id: GuildId, entity_id: &str) -> ServiceResult<()> {
    let result = sqlx::query("DELETE FROM guild_whitelist WHERE guild_id = $1 AND entity_id = $2")
        .bind(guild_id.to_string())
        .bind(entity_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ServiceError::NotFound("That entry is not on the whitelist"));
    }
    Ok(())
}

pub async fn admin_add(pool: &PgPool, guild_id: GuildId, user_id: UserId) -> ServiceResult<()> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM guild_admins WHERE guild_id = $1 AND user_id = $2")
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await?;
    if count > 0 {
        return invalid("That user is already a Sentinel admin");
    }
    sqlx::query("INSERT INTO guild_admins (guild_id, user_id) VALUES ($1, $2)")
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn admin_remove(pool: &PgPool, guild_id: GuildId, user_id: UserId) -> ServiceResult<()> {
    let result = sqlx::query("DELETE FROM guild_admins WHERE guild_id = $1 AND user_id = $2")
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ServiceError::NotFound("That user is not a Sentinel admin"));
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
#[serde(default)]
pub struct GuildSettings {
    pub logs_channel_id: Option<String>,
    pub logs_enabled: bool,
    pub logs_color: i32,
    pub alert_role_id: Option<String>,
    pub alert_dm_owner: bool,
    pub guard_bot_add: bool,
    pub guard_dangerous_perms: bool,
    pub guard_webhooks: bool,
    pub guard_vanity: bool,
    pub auto_lockdown: bool,
    pub auto_lockdown_threshold: i32,
    pub auto_lockdown_window_secs: i32,
    pub snapshots_enabled: bool,
    pub digest_enabled: bool,
    pub antiscam_links: bool,
    pub antiscam_mentions: bool,
    pub antiscam_mention_limit: i32,
    pub antiscam_timeout_secs: i32,
}

impl Default for GuildSettings {
    fn default() -> Self {
        Self {
            logs_channel_id: None,
            logs_enabled: true,
            logs_color: 65280,
            alert_role_id: None,
            alert_dm_owner: true,
            guard_bot_add: false,
            guard_dangerous_perms: false,
            guard_webhooks: false,
            guard_vanity: false,
            auto_lockdown: false,
            auto_lockdown_threshold: 2,
            auto_lockdown_window_secs: 300,
            snapshots_enabled: true,
            digest_enabled: false,
            antiscam_links: false,
            antiscam_mentions: false,
            antiscam_mention_limit: 6,
            antiscam_timeout_secs: 0,
        }
    }
}

const SETTINGS_COLUMNS: &str = "logs_channel_id, logs_enabled, logs_color, alert_role_id, alert_dm_owner, guard_bot_add,
    guard_dangerous_perms, guard_webhooks, guard_vanity, auto_lockdown, auto_lockdown_threshold, auto_lockdown_window_secs,
    snapshots_enabled, digest_enabled, antiscam_links, antiscam_mentions, antiscam_mention_limit, antiscam_timeout_secs";

pub async fn settings(pool: &PgPool, guild_id: GuildId) -> ServiceResult<GuildSettings> {
    let row: Option<GuildSettings> = sqlx::query_as(&format!("SELECT {} FROM guild_settings WHERE guild_id = $1", SETTINGS_COLUMNS))
        .bind(guild_id.to_string())
        .fetch_optional(pool)
        .await?;
    Ok(row.unwrap_or_default())
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct SettingsPatch {
    #[serde(default, deserialize_with = "double_option")]
    pub logs_channel_id: Option<Option<String>>,
    pub logs_enabled: Option<bool>,
    pub logs_color: Option<i64>,
    #[serde(default, deserialize_with = "double_option")]
    pub alert_role_id: Option<Option<String>>,
    pub alert_dm_owner: Option<bool>,
    pub guard_bot_add: Option<bool>,
    pub guard_dangerous_perms: Option<bool>,
    pub guard_webhooks: Option<bool>,
    pub guard_vanity: Option<bool>,
    pub auto_lockdown: Option<bool>,
    pub auto_lockdown_threshold: Option<i32>,
    pub auto_lockdown_window_secs: Option<i32>,
    pub snapshots_enabled: Option<bool>,
    pub digest_enabled: Option<bool>,
    pub antiscam_links: Option<bool>,
    pub antiscam_mentions: Option<bool>,
    pub antiscam_mention_limit: Option<i32>,
    pub antiscam_timeout_secs: Option<i32>,
}

fn double_option<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Ok(Some(<Option<String> as serde::Deserialize>::deserialize(deserializer)?))
}

impl SettingsPatch {
    pub fn changed(&self) -> Vec<&'static str> {
        let mut changed = vec![];
        if self.logs_channel_id.is_some() { changed.push("log channel"); }
        if self.logs_enabled.is_some() { changed.push("routine notifications"); }
        if self.logs_color.is_some() { changed.push("embed colour"); }
        if self.alert_role_id.is_some() { changed.push("alert role"); }
        if self.alert_dm_owner.is_some() { changed.push("owner DMs"); }
        if self.guard_bot_add.is_some() { changed.push("bot-add guard"); }
        if self.guard_dangerous_perms.is_some() { changed.push("permission guard"); }
        if self.guard_webhooks.is_some() { changed.push("webhook guard"); }
        if self.guard_vanity.is_some() { changed.push("vanity guard"); }
        if self.auto_lockdown.is_some() || self.auto_lockdown_threshold.is_some() || self.auto_lockdown_window_secs.is_some() {
            changed.push("auto-lockdown");
        }
        if self.snapshots_enabled.is_some() { changed.push("snapshots"); }
        if self.digest_enabled.is_some() { changed.push("weekly digest"); }
        if self.antiscam_links.is_some() { changed.push("scam link filter"); }
        if self.antiscam_mentions.is_some() || self.antiscam_mention_limit.is_some() { changed.push("mass mention filter"); }
        if self.antiscam_timeout_secs.is_some() { changed.push("scam timeout"); }
        changed
    }

    pub fn touches_antiscam(&self) -> bool {
        self.antiscam_links.is_some()
            || self.antiscam_mentions.is_some()
            || self.antiscam_mention_limit.is_some()
            || self.antiscam_timeout_secs.is_some()
            || self.logs_channel_id.is_some()
    }
}

fn valid_snowflake(value: &Option<Option<String>>) -> bool {
    match value {
        Some(Some(id)) => id.parse::<u64>().is_ok(),
        _ => true,
    }
}

pub async fn update_settings(pool: &PgPool, guild_id: GuildId, patch: SettingsPatch) -> ServiceResult<GuildSettings> {
    if !valid_snowflake(&patch.logs_channel_id) || !valid_snowflake(&patch.alert_role_id) {
        return invalid("That is not a valid Discord id");
    }
    if let Some(color) = patch.logs_color {
        if !(0..=0xFFFFFF).contains(&color) {
            return invalid("Colours must be between #000000 and #FFFFFF");
        }
    }
    if let Some(threshold) = patch.auto_lockdown_threshold {
        if !(1..=20).contains(&threshold) {
            return invalid("The auto-lockdown threshold must be between 1 and 20");
        }
    }
    if let Some(window) = patch.auto_lockdown_window_secs {
        if !(60..=3600).contains(&window) {
            return invalid("The auto-lockdown window must be between 1 and 60 minutes");
        }
    }
    if let Some(limit) = patch.antiscam_mention_limit {
        if !(3..=50).contains(&limit) {
            return invalid("The mention limit must be between 3 and 50");
        }
    }
    if let Some(timeout) = patch.antiscam_timeout_secs {
        if !(0..=2_419_200).contains(&timeout) {
            return invalid("The scam timeout must be between 0 seconds and 28 days");
        }
    }

    ensure_guild(pool, guild_id).await?;
    let current = settings(pool, guild_id).await?;
    let next = GuildSettings {
        logs_channel_id: patch.logs_channel_id.unwrap_or(current.logs_channel_id),
        logs_enabled: patch.logs_enabled.unwrap_or(current.logs_enabled),
        logs_color: patch.logs_color.map(|c| c as i32).unwrap_or(current.logs_color),
        alert_role_id: patch.alert_role_id.unwrap_or(current.alert_role_id),
        alert_dm_owner: patch.alert_dm_owner.unwrap_or(current.alert_dm_owner),
        guard_bot_add: patch.guard_bot_add.unwrap_or(current.guard_bot_add),
        guard_dangerous_perms: patch.guard_dangerous_perms.unwrap_or(current.guard_dangerous_perms),
        guard_webhooks: patch.guard_webhooks.unwrap_or(current.guard_webhooks),
        guard_vanity: patch.guard_vanity.unwrap_or(current.guard_vanity),
        auto_lockdown: patch.auto_lockdown.unwrap_or(current.auto_lockdown),
        auto_lockdown_threshold: patch.auto_lockdown_threshold.unwrap_or(current.auto_lockdown_threshold),
        auto_lockdown_window_secs: patch.auto_lockdown_window_secs.unwrap_or(current.auto_lockdown_window_secs),
        snapshots_enabled: patch.snapshots_enabled.unwrap_or(current.snapshots_enabled),
        digest_enabled: patch.digest_enabled.unwrap_or(current.digest_enabled),
        antiscam_links: patch.antiscam_links.unwrap_or(current.antiscam_links),
        antiscam_mentions: patch.antiscam_mentions.unwrap_or(current.antiscam_mentions),
        antiscam_mention_limit: patch.antiscam_mention_limit.unwrap_or(current.antiscam_mention_limit),
        antiscam_timeout_secs: patch.antiscam_timeout_secs.unwrap_or(current.antiscam_timeout_secs),
    };

    sqlx::query(
        "UPDATE guild_settings SET logs_channel_id = $2, logs_enabled = $3, logs_color = $4, alert_role_id = $5,
                alert_dm_owner = $6, guard_bot_add = $7, guard_dangerous_perms = $8, guard_webhooks = $9, guard_vanity = $10,
                auto_lockdown = $11, auto_lockdown_threshold = $12, auto_lockdown_window_secs = $13,
                snapshots_enabled = $14, digest_enabled = $15, antiscam_links = $16, antiscam_mentions = $17,
                antiscam_mention_limit = $18, antiscam_timeout_secs = $19
         WHERE guild_id = $1",
    )
    .bind(guild_id.to_string())
    .bind(&next.logs_channel_id)
    .bind(next.logs_enabled)
    .bind(next.logs_color)
    .bind(&next.alert_role_id)
    .bind(next.alert_dm_owner)
    .bind(next.guard_bot_add)
    .bind(next.guard_dangerous_perms)
    .bind(next.guard_webhooks)
    .bind(next.guard_vanity)
    .bind(next.auto_lockdown)
    .bind(next.auto_lockdown_threshold)
    .bind(next.auto_lockdown_window_secs)
    .bind(next.snapshots_enabled)
    .bind(next.digest_enabled)
    .bind(next.antiscam_links)
    .bind(next.antiscam_mentions)
    .bind(next.antiscam_mention_limit)
    .bind(next.antiscam_timeout_secs)
    .execute(pool)
    .await?;
    Ok(next)
}

pub async fn record_audit(pool: &PgPool, guild_id: GuildId, user_id: UserId, source: &str, action: &str, detail: &str) {
    if let Err(e) = sqlx::query("INSERT INTO audit_trail (guild_id, user_id, source, action, detail) VALUES ($1, $2, $3, $4, $5)")
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .bind(source)
        .bind(action)
        .bind(detail)
        .execute(pool)
        .await
    {
        log::error!("could not record audit entry: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(per: i32, window_secs: i64, action: UserLimitActions, timeout_secs: Option<i64>) -> LimitInput {
        LimitInput {
            name: "  Ban spree  ".into(),
            event: UserLimitTypes::Ban,
            action,
            per,
            window_secs,
            timeout_secs,
            scope: LimitScope::Moderator,
            dry_run: false,
        }
    }

    #[test]
    fn trims_name_and_accepts_valid_limit() {
        let ok = input(3, 600, UserLimitActions::BanUser, Some(120)).validated().unwrap();
        assert_eq!(ok.name, "Ban spree");
        assert_eq!(ok.timeout_secs, None);
    }

    #[test]
    fn rejects_out_of_range_values() {
        assert!(input(0, 600, UserLimitActions::BanUser, None).validated().is_err());
        assert!(input(MAX_THRESHOLD + 1, 600, UserLimitActions::BanUser, None).validated().is_err());
        assert!(input(3, 0, UserLimitActions::BanUser, None).validated().is_err());
        assert!(input(3, MAX_WINDOW_SECS + 1, UserLimitActions::BanUser, None).validated().is_err());
        assert!(LimitInput { name: "   ".into(), ..input(3, 600, UserLimitActions::BanUser, None) }.validated().is_err());
    }

    #[test]
    fn timeout_defaults_and_bounds() {
        let ok = input(3, 600, UserLimitActions::TimeoutUser, None).validated().unwrap();
        assert_eq!(ok.timeout_secs, Some(DEFAULT_TIMEOUT_SECS));
        assert!(input(3, 600, UserLimitActions::TimeoutUser, Some(10)).validated().is_err());
        assert!(input(3, 600, UserLimitActions::TimeoutUser, Some(MAX_TIMEOUT_SECS + 1)).validated().is_err());
    }

    #[test]
    fn severity_orders_responses() {
        let mut actions = UserLimitActions::ALL.to_vec();
        actions.reverse();
        actions.sort_by_key(|a| a.severity());
        assert_eq!(actions.first(), Some(&UserLimitActions::NotifyOnly));
        assert_eq!(actions.last(), Some(&UserLimitActions::BanUser));
    }

    #[test]
    fn scope_round_trips() {
        assert_eq!(LimitScope::parse("server").unwrap(), LimitScope::Server);
        assert_eq!(LimitScope::parse(LimitScope::Moderator.as_str()).unwrap(), LimitScope::Moderator);
        assert!(LimitScope::parse("everyone").is_err());
    }
}
