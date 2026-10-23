use std::collections::{HashMap, HashSet};
use std::time::Duration;

use nonmax::NonMaxU16;
use poise::serenity_prelude::{
    ChannelId, ChannelType, CreateChannel, EditRole, GuildId, PermissionOverwrite, PermissionOverwriteType, Permissions, RoleId,
    UserId,
};
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::protect::Bot;
use crate::service::{self, ServiceError, ServiceResult};

const KEEP_PER_GUILD: i64 = 10;
const STEP_DELAY: Duration = Duration::from_millis(350);

#[derive(Clone, Serialize, Deserialize)]
pub struct SnapRole {
    pub id: String,
    pub name: String,
    pub color: u32,
    pub hoist: bool,
    pub mentionable: bool,
    pub permissions: u64,
    pub position: i16,
    pub managed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnapOverwrite {
    pub id: String,
    pub kind: String,
    pub allow: u64,
    pub deny: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SnapChannel {
    pub id: String,
    pub name: String,
    pub kind: ChannelType,
    pub position: u16,
    pub parent_id: Option<String>,
    pub topic: Option<String>,
    pub nsfw: bool,
    pub rate_limit: Option<u16>,
    pub bitrate: Option<u32>,
    pub user_limit: Option<u16>,
    pub overwrites: Vec<SnapOverwrite>,
}

fn capture(bot: Bot<'_>, guild_id: GuildId) -> ServiceResult<(Vec<SnapRole>, Vec<SnapChannel>)> {
    let guild = bot.cache.guild(guild_id).ok_or(ServiceError::NotFound("Sentinel cannot see this server"))?;

    let roles = guild
        .roles
        .iter()
        .filter(|r| r.id.get() != guild_id.get())
        .map(|r| SnapRole {
            id: r.id.to_string(),
            name: r.name.to_string(),
            color: r.colour.0,
            hoist: r.hoist(),
            mentionable: r.mentionable(),
            permissions: r.permissions.bits(),
            position: r.position,
            managed: r.managed(),
        })
        .collect();

    let channels = guild
        .channels
        .iter()
        .map(|c| SnapChannel {
            id: c.id.to_string(),
            name: c.name.to_string(),
            kind: c.kind,
            position: c.position,
            parent_id: c.parent_id.map(|p| p.to_string()),
            topic: c.topic.as_ref().map(|t| t.to_string()),
            nsfw: c.nsfw,
            rate_limit: c.rate_limit_per_user.map(|r| r.get()),
            bitrate: c.bitrate.map(|b| b.get()),
            user_limit: c.user_limit.map(|u| u.get()),
            overwrites: c
                .permission_overwrites
                .iter()
                .map(|o| {
                    let (id, kind) = match o.kind {
                        PermissionOverwriteType::Role(id) => (id.to_string(), "role"),
                        PermissionOverwriteType::Member(id) => (id.to_string(), "member"),
                        _ => (String::new(), "unknown"),
                    };
                    SnapOverwrite { id, kind: kind.to_string(), allow: o.allow.bits(), deny: o.deny.bits() }
                })
                .filter(|o| o.kind != "unknown")
                .collect(),
        })
        .collect();

    Ok((roles, channels))
}

pub async fn take(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, trigger: &str, by: Option<UserId>) -> ServiceResult<String> {
    let (roles, channels) = capture(bot, guild_id)?;
    let (id,): (String,) = sqlx::query_as(
        "INSERT INTO snapshots (guild_id, trigger, created_by, roles, channels, role_count, channel_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(guild_id.to_string())
    .bind(trigger)
    .bind(by.map(|u| u.to_string()))
    .bind(serde_json::to_value(&roles).unwrap_or_default())
    .bind(serde_json::to_value(&channels).unwrap_or_default())
    .bind(roles.len() as i32)
    .bind(channels.len() as i32)
    .fetch_one(pool)
    .await?;

    sqlx::query(
        "DELETE FROM snapshots WHERE guild_id = $1 AND id NOT IN
            (SELECT id FROM snapshots WHERE guild_id = $1 ORDER BY created_at DESC LIMIT $2)",
    )
    .bind(guild_id.to_string())
    .bind(KEEP_PER_GUILD)
    .execute(pool)
    .await?;

    Ok(id)
}

#[derive(Serialize)]
pub struct SnapshotMeta {
    pub id: String,
    pub trigger: String,
    pub created_by: Option<String>,
    pub role_count: i32,
    pub channel_count: i32,
    pub created_at: String,
}

pub async fn list(pool: &PgPool, guild_id: GuildId) -> ServiceResult<Vec<SnapshotMeta>> {
    let rows: Vec<(String, String, Option<String>, i32, i32, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, trigger, created_by, role_count, channel_count, created_at FROM snapshots WHERE guild_id = $1 ORDER BY created_at DESC",
    )
    .bind(guild_id.to_string())
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, trigger, created_by, role_count, channel_count, created_at)| SnapshotMeta {
            id,
            trigger,
            created_by,
            role_count,
            channel_count,
            created_at: created_at.to_rfc3339(),
        })
        .collect())
}

async fn load(pool: &PgPool, guild_id: GuildId, snapshot_id: &str) -> ServiceResult<(Vec<SnapRole>, Vec<SnapChannel>)> {
    let row: Option<(serde_json::Value, serde_json::Value)> =
        sqlx::query_as("SELECT roles, channels FROM snapshots WHERE guild_id = $1 AND id = $2")
            .bind(guild_id.to_string())
            .bind(snapshot_id)
            .fetch_optional(pool)
            .await?;
    let (roles, channels) = row.ok_or(ServiceError::NotFound("That snapshot was not found"))?;
    let roles = serde_json::from_value(roles).map_err(|_| ServiceError::Invalid("Snapshot roles are unreadable".into()))?;
    let channels = serde_json::from_value(channels).map_err(|_| ServiceError::Invalid("Snapshot channels are unreadable".into()))?;
    Ok((roles, channels))
}

#[derive(Serialize)]
pub struct PermissionChange {
    pub id: String,
    pub name: String,
    pub added: String,
    pub removed: String,
}

#[derive(Serialize)]
pub struct RestorePlan {
    pub missing_roles: Vec<SnapRole>,
    pub missing_channels: Vec<SnapChannel>,
    pub changed_roles: Vec<PermissionChange>,
}

fn permission_list(perms: Permissions) -> String {
    let names: Vec<String> = perms.iter_names().map(|(name, _)| name.replace('_', " ").to_lowercase()).collect();
    names.join(", ")
}

pub async fn plan(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, snapshot_id: &str) -> ServiceResult<RestorePlan> {
    let (roles, channels) = load(pool, guild_id, snapshot_id).await?;
    let guild = bot.cache.guild(guild_id).ok_or(ServiceError::NotFound("Sentinel cannot see this server"))?;

    let current_roles: HashMap<String, Permissions> = guild.roles.iter().map(|r| (r.id.to_string(), r.permissions)).collect();
    let current_channels: HashSet<String> = guild.channels.iter().map(|c| c.id.to_string()).collect();

    let missing_roles = roles.iter().filter(|r| !r.managed && !current_roles.contains_key(&r.id)).cloned().collect();
    let missing_channels = channels.iter().filter(|c| !current_channels.contains(&c.id)).cloned().collect();
    let changed_roles = roles
        .iter()
        .filter_map(|r| {
            let now = *current_roles.get(&r.id)?;
            let then = Permissions::from_bits_truncate(r.permissions);
            (now != then).then(|| PermissionChange {
                id: r.id.clone(),
                name: r.name.clone(),
                added: permission_list(now & !then),
                removed: permission_list(then & !now),
            })
        })
        .collect();

    Ok(RestorePlan { missing_roles, missing_channels, changed_roles })
}

#[derive(Deserialize, Default, Clone, Copy)]
pub struct RestoreOptions {
    #[serde(default = "yes")]
    pub roles: bool,
    #[serde(default = "yes")]
    pub channels: bool,
    #[serde(default)]
    pub permissions: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Default)]
pub struct RestoreReport {
    pub roles_created: usize,
    pub channels_created: usize,
    pub roles_reset: usize,
    pub failures: Vec<String>,
}

fn overwrites(snap: &SnapChannel, role_map: &HashMap<String, RoleId>, existing_roles: &HashSet<String>) -> Vec<PermissionOverwrite> {
    snap.overwrites
        .iter()
        .filter_map(|o| {
            let kind = if o.kind == "role" {
                let id = role_map.get(&o.id).copied().or_else(|| existing_roles.contains(&o.id).then(|| o.id.parse().ok()).flatten())?;
                PermissionOverwriteType::Role(id)
            } else {
                PermissionOverwriteType::Member(o.id.parse().ok()?)
            };
            Some(PermissionOverwrite {
                allow: Permissions::from_bits_truncate(o.allow),
                deny: Permissions::from_bits_truncate(o.deny),
                kind,
            })
        })
        .collect()
}

pub async fn restore(
    bot: Bot<'_>,
    pool: &PgPool,
    guild_id: GuildId,
    snapshot_id: &str,
    by: UserId,
    source: &str,
    options: RestoreOptions,
) -> ServiceResult<RestoreReport> {
    let (_, snap_channels) = load(pool, guild_id, snapshot_id).await?;
    let plan = plan(bot, pool, guild_id, snapshot_id).await?;
    let reason = "Sentinel: restoring from snapshot";
    let mut report = RestoreReport::default();
    let mut role_map: HashMap<String, RoleId> = HashMap::new();

    if options.roles {
        let mut missing = plan.missing_roles.clone();
        missing.sort_by_key(|r| r.position);
        for role in missing.iter().take(100) {
            let builder = EditRole::new()
                .name(role.name.clone())
                .colour(role.color)
                .hoist(role.hoist)
                .mentionable(role.mentionable)
                .permissions(Permissions::from_bits_truncate(role.permissions))
                .audit_log_reason(reason);
            match guild_id.create_role(bot.http, builder).await {
                Ok(created) => {
                    role_map.insert(role.id.clone(), created.id);
                    report.roles_created += 1;
                    let _ = guild_id.edit_role_position(bot.http, created.id, role.position, Some(reason)).await;
                }
                Err(e) => report.failures.push(format!("Role {}: {}", role.name, e)),
            }
            tokio::time::sleep(STEP_DELAY).await;
        }
    }

    if options.permissions {
        for change in &plan.changed_roles {
            let Some(snap) = snap_role(pool, guild_id, snapshot_id, &change.id).await else { continue };
            let Ok(role_id) = change.id.parse::<RoleId>() else { continue };
            match guild_id
                .edit_role(bot, role_id, EditRole::new().permissions(Permissions::from_bits_truncate(snap)).audit_log_reason(reason))
                .await
            {
                Ok(_) => report.roles_reset += 1,
                Err(e) => report.failures.push(format!("Permissions for {}: {}", change.name, e)),
            }
            tokio::time::sleep(STEP_DELAY).await;
        }
    }

    if options.channels {
        let existing_roles: HashSet<String> = bot
            .cache
            .guild(guild_id)
            .map(|g| g.roles.iter().map(|r| r.id.to_string()).collect())
            .unwrap_or_default();
        let existing_channels: HashSet<String> = bot
            .cache
            .guild(guild_id)
            .map(|g| g.channels.iter().map(|c| c.id.to_string()).collect())
            .unwrap_or_default();

        let missing: HashSet<String> = plan.missing_channels.iter().map(|c| c.id.clone()).collect();
        let mut ordered: Vec<&SnapChannel> = snap_channels.iter().filter(|c| missing.contains(&c.id)).collect();
        ordered.sort_by_key(|c| (c.kind != ChannelType::Category, c.position));

        let mut channel_map: HashMap<String, ChannelId> = HashMap::new();
        for snap in ordered.into_iter().take(200) {
            let mut builder = CreateChannel::new(snap.name.clone())
                .kind(snap.kind)
                .position(snap.position)
                .nsfw(snap.nsfw)
                .permissions(overwrites(snap, &role_map, &existing_roles))
                .audit_log_reason(reason);
            if let Some(topic) = &snap.topic {
                builder = builder.topic(topic.clone());
            }
            if let Some(rate) = snap.rate_limit.and_then(NonMaxU16::new) {
                builder = builder.rate_limit_per_user(rate);
            }
            if matches!(snap.kind, ChannelType::Voice | ChannelType::Stage) {
                if let Some(bitrate) = snap.bitrate {
                    builder = builder.bitrate(bitrate);
                }
                if let Some(limit) = snap.user_limit.and_then(NonMaxU16::new) {
                    builder = builder.user_limit(limit);
                }
            }
            if let Some(parent) = &snap.parent_id {
                let parent_id = channel_map
                    .get(parent)
                    .copied()
                    .or_else(|| existing_channels.contains(parent).then(|| parent.parse().ok()).flatten());
                if let Some(parent_id) = parent_id {
                    builder = builder.category(parent_id);
                }
            }

            match guild_id.create_channel(bot, builder).await {
                Ok(created) => {
                    channel_map.insert(snap.id.clone(), created.id);
                    report.channels_created += 1;
                }
                Err(e) => report.failures.push(format!("Channel #{}: {}", snap.name, e)),
            }
            tokio::time::sleep(STEP_DELAY).await;
        }
    }

    let detail = format!(
        "<@{}> restored a snapshot: {} role{} and {} channel{} recreated, {} role permission{} reset{}",
        by,
        report.roles_created,
        if report.roles_created == 1 { "" } else { "s" },
        report.channels_created,
        if report.channels_created == 1 { "" } else { "s" },
        report.roles_reset,
        if report.roles_reset == 1 { "" } else { "s" },
        if report.failures.is_empty() { String::new() } else { format!(", {} failed", report.failures.len()) }
    );
    service::record_audit(pool, guild_id, by, source, "snapshot_restored", &detail).await;
    if let Ok(settings) = service::settings(pool, guild_id).await {
        crate::protect::alert(bot, &settings, guild_id, "Snapshot restored", &detail, "recovery").await;
    }

    Ok(report)
}

async fn snap_role(pool: &PgPool, guild_id: GuildId, snapshot_id: &str, role_id: &str) -> Option<u64> {
    let (roles, _) = load(pool, guild_id, snapshot_id).await.ok()?;
    roles.into_iter().find(|r| r.id == role_id).map(|r| r.permissions)
}

pub async fn take_scheduled(bot: Bot<'_>, pool: &PgPool) {
    let rows: Vec<(String,)> = match sqlx::query_as(
        "SELECT g.guild_id FROM guilds g JOIN guild_settings s ON s.guild_id = g.guild_id
         WHERE s.snapshots_enabled AND NOT EXISTS (
            SELECT 1 FROM snapshots n WHERE n.guild_id = g.guild_id AND n.created_at > NOW() - INTERVAL '6 hours'
         )",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            log::error!("could not list guilds for snapshots: {}", e);
            return;
        }
    };

    let mut taken = 0;
    for (guild_id,) in rows {
        let Ok(guild_id) = guild_id.parse::<GuildId>() else { continue };
        if bot.cache.guild(guild_id).is_none() {
            continue;
        }
        match take(bot, pool, guild_id, "scheduled", None).await {
            Ok(_) => taken += 1,
            Err(e) => log::warn!("snapshot failed for {}: {}", guild_id, e),
        }
    }
    if taken > 0 {
        log::info!("Took {} scheduled snapshot(s)", taken);
    }
}
