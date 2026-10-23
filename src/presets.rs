use std::collections::HashSet;

use poise::serenity_prelude::GuildId;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::core::{UserLimitActions as A, UserLimitTypes as E};
use crate::service::{self, GuildSettings, LimitInput, LimitScope, ServiceError, ServiceResult};

pub struct Preset {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub limits: fn() -> Vec<LimitInput>,
}

fn limit(name: &str, event: E, per: i32, window_secs: i64, action: A) -> LimitInput {
    LimitInput {
        name: name.to_string(),
        event,
        action,
        per,
        window_secs,
        timeout_secs: None,
        scope: LimitScope::Moderator,
        dry_run: false,
    }
}

fn small() -> Vec<LimitInput> {
    vec![
        limit("Ban warning", E::Ban, 3, 600, A::NotifyOnly),
        limit("Ban spree", E::Ban, 5, 600, A::RemoveAllRoles),
        limit("Kick warning", E::Kick, 4, 600, A::NotifyOnly),
        limit("Kick spree", E::Kick, 8, 600, A::RemoveAllRoles),
        limit("Channel deletions", E::ChannelRemove, 3, 300, A::RemoveAllRoles),
        limit("Role deletions", E::RoleRemove, 3, 300, A::RemoveAllRoles),
        limit("Webhook creation", E::WebhookAdd, 3, 600, A::NotifyOnly),
        limit("Dangerous grants", E::DangerousPermission, 2, 600, A::RemoveAllRoles),
        limit("Mass prune", E::MemberPrune, 1, 3600, A::NotifyOnly),
    ]
}

fn large() -> Vec<LimitInput> {
    vec![
        limit("Ban warning", E::Ban, 8, 600, A::NotifyOnly),
        limit("Ban spree", E::Ban, 15, 600, A::RemoveAllRoles),
        limit("Kick warning", E::Kick, 10, 600, A::NotifyOnly),
        limit("Kick spree", E::Kick, 20, 600, A::RemoveAllRoles),
        limit("Channel deletions", E::ChannelRemove, 4, 300, A::RemoveAllRoles),
        limit("Role deletions", E::RoleRemove, 4, 300, A::RemoveAllRoles),
        limit("Webhook creation", E::WebhookAdd, 5, 600, A::NotifyOnly),
        limit("Dangerous grants", E::DangerousPermission, 3, 600, A::RemoveAllRoles),
        limit("Server-wide channel deletions", E::ChannelRemove, 8, 300, A::NotifyOnly),
    ]
    .into_iter()
    .map(|mut l| {
        if l.name.starts_with("Server-wide") {
            l.scope = LimitScope::Server;
        }
        l
    })
    .collect()
}

fn strict() -> Vec<LimitInput> {
    vec![
        limit("Ban warning", E::Ban, 2, 600, A::NotifyOnly),
        limit("Ban spree", E::Ban, 3, 600, A::RemoveAllRoles),
        limit("Ban lockout", E::Ban, 5, 600, A::BanUser),
        limit("Kick spree", E::Kick, 3, 600, A::RemoveAllRoles),
        limit("Channel deletions", E::ChannelRemove, 2, 300, A::RemoveAllRoles),
        limit("Role deletions", E::RoleRemove, 2, 300, A::RemoveAllRoles),
        limit("Webhook creation", E::WebhookAdd, 2, 600, A::RemoveAllRoles),
        limit("Bot added", E::BotAdd, 1, 3600, A::NotifyOnly),
        limit("Dangerous grants", E::DangerousPermission, 1, 600, A::RemoveAllRoles),
        limit("Mass prune", E::MemberPrune, 1, 3600, A::RemoveAllRoles),
    ]
}

pub const PRESETS: [Preset; 3] = [
    Preset { key: "small", name: "Small community", description: "Warn early, quarantine on clear sprees. Good for servers under a few thousand members.", limits: small },
    Preset { key: "large", name: "Large server", description: "Higher thresholds for busy moderation teams, plus a server-wide channel deletion alert.", limits: large },
    Preset { key: "strict", name: "Strict", description: "Low thresholds and a ban at the top of the ban ladder. For servers that have been targeted before.", limits: strict },
];

pub fn find(key: &str) -> ServiceResult<&'static Preset> {
    PRESETS.iter().find(|p| p.key == key).ok_or(ServiceError::NotFound("Unknown preset"))
}

#[derive(Serialize)]
pub struct PresetLimit {
    pub name: String,
    pub event: String,
    pub event_label: String,
    pub action: String,
    pub action_label: String,
    pub per: i32,
    pub window_seconds: i64,
    pub scope: LimitScope,
}

#[derive(Serialize)]
pub struct PresetView {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub limits: Vec<PresetLimit>,
}

pub fn catalog() -> Vec<PresetView> {
    PRESETS
        .iter()
        .map(|p| PresetView {
            key: p.key,
            name: p.name,
            description: p.description,
            limits: (p.limits)()
                .into_iter()
                .map(|l| PresetLimit {
                    event_label: l.event.to_cond(),
                    action_label: l.action.to_cond(),
                    event: l.event.to_string(),
                    action: l.action.to_string(),
                    name: l.name,
                    per: l.per,
                    window_seconds: l.window_secs,
                    scope: l.scope,
                })
                .collect(),
        })
        .collect()
}

pub async fn apply(pool: &PgPool, guild_id: GuildId, key: &str) -> ServiceResult<(usize, usize)> {
    let preset = find(key)?;
    let existing: HashSet<String> = service::limit_names(pool, guild_id).await?.into_iter().collect();
    let mut created = 0;
    let mut skipped = 0;
    for input in (preset.limits)() {
        if existing.contains(&input.name.to_lowercase()) {
            skipped += 1;
            continue;
        }
        service::create_limit(pool, guild_id, input).await?;
        created += 1;
    }
    Ok((created, skipped))
}

#[derive(Serialize, Deserialize)]
pub struct ExportedLimit {
    pub name: String,
    pub event: String,
    pub action: String,
    pub per: i32,
    pub window_seconds: i64,
    pub timeout_seconds: Option<i64>,
    #[serde(default = "default_scope")]
    pub scope: LimitScope,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_scope() -> LimitScope {
    LimitScope::Moderator
}

#[derive(Serialize, Deserialize)]
pub struct ExportedEntity {
    pub id: String,
    pub kind: String,
}

#[derive(Serialize, Deserialize)]
pub struct ExportedConfig {
    pub version: u32,
    pub exported_at: String,
    pub limits: Vec<ExportedLimit>,
    pub whitelist: Vec<ExportedEntity>,
    pub settings: GuildSettings,
}

type ExportRow = (String, String, String, i32, i64, Option<i64>, String, bool);

pub async fn export(pool: &PgPool, guild_id: GuildId) -> ServiceResult<ExportedConfig> {
    let rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT limit_name, limit_type, limit_action, limit_per, EXTRACT(EPOCH FROM limit_time)::BIGINT,
                EXTRACT(EPOCH FROM limit_timeout_duration)::BIGINT, limit_scope, dry_run
         FROM limits WHERE guild_id = $1 ORDER BY limit_name",
    )
    .bind(guild_id.to_string())
    .fetch_all(pool)
    .await?;

    let whitelist: Vec<(String, String)> = sqlx::query_as("SELECT entity_id, entity_type FROM guild_whitelist WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?;

    Ok(ExportedConfig {
        version: 1,
        exported_at: sqlx::types::chrono::Utc::now().to_rfc3339(),
        limits: rows
            .into_iter()
            .map(|(name, event, action, per, window_seconds, timeout_seconds, scope, dry_run)| ExportedLimit {
                name,
                event,
                action,
                per,
                window_seconds,
                timeout_seconds,
                scope: LimitScope::parse(&scope).unwrap_or(LimitScope::Moderator),
                dry_run,
            })
            .collect(),
        whitelist: whitelist.into_iter().map(|(id, kind)| ExportedEntity { id, kind }).collect(),
        settings: service::settings(pool, guild_id).await?,
    })
}

#[derive(Serialize)]
pub struct ImportReport {
    pub limits_created: usize,
    pub limits_replaced: usize,
    pub whitelist_added: usize,
    pub settings_applied: bool,
}

pub async fn import(
    pool: &PgPool,
    guild_id: GuildId,
    config: ExportedConfig,
    replace_limits: bool,
    known_roles: &HashSet<String>,
    known_channels: &HashSet<String>,
) -> ServiceResult<ImportReport> {
    if config.version != 1 {
        return Err(ServiceError::Invalid("Unsupported config version".into()));
    }
    if config.limits.len() > 100 {
        return Err(ServiceError::Invalid("A config can contain at most 100 limits".into()));
    }

    let inputs = config
        .limits
        .into_iter()
        .map(|l| {
            LimitInput {
                event: l.event.parse().map_err(|_| ServiceError::Invalid(format!("Unknown event {}", l.event)))?,
                action: l.action.parse().map_err(|_| ServiceError::Invalid(format!("Unknown response {}", l.action)))?,
                name: l.name,
                per: l.per,
                window_secs: l.window_seconds,
                timeout_secs: l.timeout_seconds,
                scope: l.scope,
                dry_run: l.dry_run,
            }
            .validated()
        })
        .collect::<ServiceResult<Vec<_>>>()?;

    service::ensure_guild(pool, guild_id).await?;

    let mut replaced = 0;
    if replace_limits {
        let result = sqlx::query("DELETE FROM limits WHERE guild_id = $1")
            .bind(guild_id.to_string())
            .execute(pool)
            .await?;
        replaced = result.rows_affected() as usize;
    }

    let existing: HashSet<String> = service::limit_names(pool, guild_id).await?.into_iter().collect();
    let mut created = 0;
    for input in inputs {
        if existing.contains(&input.name.to_lowercase()) {
            continue;
        }
        service::create_limit(pool, guild_id, input).await?;
        created += 1;
    }

    let mut whitelist_added = 0;
    for entry in config.whitelist {
        if entry.kind == "role" && !known_roles.contains(&entry.id) {
            continue;
        }
        if service::whitelist_add(pool, guild_id, &entry.id, &entry.kind).await.is_ok() {
            whitelist_added += 1;
        }
    }

    let s = config.settings;
    service::update_settings(
        pool,
        guild_id,
        service::SettingsPatch {
            logs_channel_id: Some(s.logs_channel_id.filter(|id| known_channels.contains(id))),
            logs_enabled: Some(s.logs_enabled),
            logs_color: Some(s.logs_color as i64),
            alert_role_id: Some(s.alert_role_id.filter(|id| known_roles.contains(id))),
            alert_dm_owner: Some(s.alert_dm_owner),
            guard_bot_add: Some(s.guard_bot_add),
            guard_dangerous_perms: Some(s.guard_dangerous_perms),
            guard_webhooks: Some(s.guard_webhooks),
            guard_vanity: Some(s.guard_vanity),
            auto_lockdown: Some(s.auto_lockdown),
            auto_lockdown_threshold: Some(s.auto_lockdown_threshold),
            auto_lockdown_window_secs: Some(s.auto_lockdown_window_secs),
            snapshots_enabled: Some(s.snapshots_enabled),
            digest_enabled: Some(s.digest_enabled),
            antiscam_links: Some(s.antiscam_links),
            antiscam_mentions: Some(s.antiscam_mentions),
            antiscam_mention_limit: Some(s.antiscam_mention_limit.clamp(3, 50)),
            antiscam_timeout_secs: Some(s.antiscam_timeout_secs.clamp(0, 2_419_200)),
        },
    )
    .await?;

    Ok(ImportReport { limits_created: created, limits_replaced: replaced, whitelist_added, settings_applied: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_limit_is_valid() {
        for preset in PRESETS.iter() {
            let limits = (preset.limits)();
            assert!(!limits.is_empty());
            let mut names = HashSet::new();
            for l in limits {
                assert!(names.insert(l.name.to_lowercase()), "duplicate name in {}", preset.key);
                l.validated().unwrap();
            }
        }
    }
}
