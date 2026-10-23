use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use poise::serenity_prelude::{
    Cache, CacheHttp, ChannelId, CreateAllowedMentions, CreateEmbed, CreateMessage, EditMember, EditRole, GuildId, Http,
    Permissions, RoleId, Timestamp, UserId,
};
use serenity::model::guild::audit_log::Change;
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::core::UserLimitActions;
use crate::service::{self, GuildSettings, ServiceError, ServiceResult};

pub const ALERT_COLOR: u32 = 0xf26d7d;

pub fn guarded_permissions() -> Permissions {
    Permissions::ADMINISTRATOR
        | Permissions::MANAGE_GUILD
        | Permissions::MANAGE_ROLES
        | Permissions::MANAGE_CHANNELS
        | Permissions::BAN_MEMBERS
        | Permissions::KICK_MEMBERS
        | Permissions::MANAGE_WEBHOOKS
}

pub fn lockdown_permissions() -> Permissions {
    guarded_permissions() | Permissions::MENTION_EVERYONE
}

#[derive(Clone, Copy)]
pub struct Bot<'a> {
    pub cache: &'a Arc<Cache>,
    pub http: &'a Http,
}

impl CacheHttp for Bot<'_> {
    fn http(&self) -> &Http {
        self.http
    }

    fn cache(&self) -> Option<&Arc<Cache>> {
        Some(self.cache)
    }
}

impl<'a> Bot<'a> {
    pub fn from_ctx(ctx: &'a serenity::all::Context) -> Self {
        Self { cache: &ctx.cache, http: &ctx.http }
    }

    pub fn from_cache_http(cache_http: &'a botox::cache::CacheHttpImpl) -> Self {
        Self { cache: &cache_http.cache, http: &cache_http.http }
    }

    pub fn me(&self) -> UserId {
        self.cache.current_user().id
    }

    fn owner(&self, guild_id: GuildId) -> Option<UserId> {
        self.cache.guild(guild_id).map(|g| g.owner_id)
    }

    fn guild_name(&self, guild_id: GuildId) -> String {
        self.cache.guild(guild_id).map(|g| g.name.to_string()).unwrap_or_else(|| guild_id.to_string())
    }
}

pub fn dashboard_link(guild_id: GuildId, tab: &str) -> String {
    format!("{}/dashboard/{}?tab={}", crate::config::CONFIG.frontend_url.trim_end_matches('/'), guild_id, tab)
}

pub async fn is_exempt(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId) -> bool {
    if actor == bot.me() || Some(actor) == bot.owner(guild_id) {
        return true;
    }
    let roles = guild_id.member(bot, actor).await.map(|m| m.roles.to_vec()).unwrap_or_default();
    crate::core::is_whitelisted(pool, guild_id, actor, &roles).await.unwrap_or(false)
}

pub async fn alert(bot: Bot<'_>, settings: &GuildSettings, guild_id: GuildId, title: &str, body: &str, tab: &str) {
    let link = dashboard_link(guild_id, tab);
    let embed = CreateEmbed::new()
        .title(title.to_string())
        .description(format!("{}\n\n[Open in dashboard]({})", body, link))
        .color(ALERT_COLOR)
        .footer(serenity::all::CreateEmbedFooter::new(bot.guild_name(guild_id)))
        .timestamp(Timestamp::now());

    if let Some(channel_id) = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<ChannelId>().ok()) {
        let mut message = CreateMessage::new().embed(embed.clone());
        if let Some(role_id) = settings.alert_role_id.as_deref().and_then(|id| id.parse::<RoleId>().ok()) {
            message = message
                .content(format!("<@&{}>", role_id))
                .allowed_mentions(CreateAllowedMentions::new().roles(vec![role_id]));
        }
        if let Err(e) = channel_id.send_message(bot.http, message).await {
            log::warn!("could not send alert to log channel: {}", e);
        }
    }

    if settings.alert_dm_owner {
        if let Some(owner) = bot.owner(guild_id) {
            if let Err(e) = owner.direct_message(bot.http, CreateMessage::new().embed(embed)).await {
                log::warn!("could not DM owner: {}", e);
            }
        }
    }
}

pub async fn notice(bot: Bot<'_>, settings: &GuildSettings, guild_id: GuildId, title: &str, body: &str, tab: &str) {
    let Some(channel_id) = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<ChannelId>().ok()) else { return };
    let embed = CreateEmbed::new()
        .title(title.to_string())
        .description(format!("{}

[Open in dashboard]({})", body, dashboard_link(guild_id, tab)))
        .color(settings.logs_color.clamp(0, 0xFFFFFF) as u32)
        .timestamp(Timestamp::now());
    if let Err(e) = channel_id.send_message(bot.http, CreateMessage::new().embed(embed)).await {
        log::warn!("could not send notice to log channel: {}", e);
    }
}

pub async fn respond(
    bot: Bot<'_>,
    pool: &PgPool,
    guild_id: GuildId,
    user_id: UserId,
    action: &UserLimitActions,
    timeout_secs: Option<i64>,
    hit_id: &str,
) -> String {
    let reason = "Sentinel: configured limit reached";
    match action {
        UserLimitActions::NotifyOnly => "Alert sent".to_string(),
        UserLimitActions::KickUser => match guild_id.kick(bot.http, user_id, Some(reason)).await {
            Ok(()) => "Kicked".to_string(),
            Err(e) => format!("Kick failed: {}", e),
        },
        UserLimitActions::BanUser => match guild_id.ban(bot.http, user_id, 0, Some(reason)).await {
            Ok(()) => "Banned".to_string(),
            Err(e) => format!("Ban failed: {}", e),
        },
        UserLimitActions::TimeoutUser => {
            let secs = timeout_secs.unwrap_or(service::DEFAULT_TIMEOUT_SECS);
            let until = match Timestamp::from_unix_timestamp(Utc::now().timestamp() + secs) {
                Ok(t) => t,
                Err(e) => return format!("Timeout failed: {}", e),
            };
            match guild_id.edit_member(bot.http, user_id, EditMember::new().disable_communication_until(until).audit_log_reason(reason)).await {
                Ok(_) => format!("Timed out for {}", crate::utils::format_duration(secs)),
                Err(e) => format!("Timeout failed: {}", e),
            }
        }
        UserLimitActions::RemoveAllRoles => match quarantine(bot, pool, guild_id, user_id, Some(hit_id)).await {
            Ok(0) => "Quarantined (no roles to remove)".to_string(),
            Ok(n) => format!("Quarantined: removed {} role{}", n, if n == 1 { "" } else { "s" }),
            Err(e) => format!("Quarantine failed: {}", e),
        },
    }
}

fn managed_roles(bot: Bot<'_>, guild_id: GuildId) -> HashSet<RoleId> {
    bot.cache
        .guild(guild_id)
        .map(|g| g.roles.iter().filter(|r| r.managed()).map(|r| r.id).collect())
        .unwrap_or_default()
}

pub async fn quarantine(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, user_id: UserId, hit_id: Option<&str>) -> Result<usize, crate::Error> {
    let member = guild_id.member(bot, user_id).await?;
    let managed = managed_roles(bot, guild_id);
    let (kept, removed): (Vec<RoleId>, Vec<RoleId>) = member.roles.iter().copied().partition(|r| managed.contains(r));

    if removed.is_empty() {
        return Ok(0);
    }

    guild_id
        .edit_member(bot.http, user_id, EditMember::new().roles(kept).audit_log_reason("Sentinel: quarantined after reaching a limit"))
        .await?;

    sqlx::query("INSERT INTO quarantines (guild_id, user_id, roles, hit_id) VALUES ($1, $2, $3, $4)")
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .bind(removed.iter().map(|r| r.to_string()).collect::<Vec<_>>())
        .bind(hit_id)
        .execute(pool)
        .await?;

    Ok(removed.len())
}

pub async fn restore_quarantine(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, quarantine_id: &str, by: UserId) -> ServiceResult<usize> {
    let row: Option<(String, Vec<String>)> = sqlx::query_as(
        "SELECT user_id, roles FROM quarantines WHERE guild_id = $1 AND id = $2 AND restored_at IS NULL",
    )
    .bind(guild_id.to_string())
    .bind(quarantine_id)
    .fetch_optional(pool)
    .await?;

    let (user_id, roles) = row.ok_or(ServiceError::NotFound("That quarantine was not found or is already restored"))?;
    let user_id: UserId = user_id.parse().map_err(|_| ServiceError::Invalid("Stored user id is invalid".into()))?;

    let member = guild_id
        .member(bot, user_id)
        .await
        .map_err(|_| ServiceError::Invalid("That member is no longer in the server".into()))?;

    let existing: HashSet<RoleId> = bot.cache.guild(guild_id).map(|g| g.roles.iter().map(|r| r.id).collect()).unwrap_or_default();
    let mut next: Vec<RoleId> = member.roles.to_vec();
    let mut restored = 0;
    for role in roles.iter().filter_map(|r| r.parse::<RoleId>().ok()) {
        if existing.contains(&role) && !next.contains(&role) {
            next.push(role);
            restored += 1;
        }
    }

    guild_id
        .edit_member(bot.http, user_id, EditMember::new().roles(next).audit_log_reason("Sentinel: quarantine restored"))
        .await
        .map_err(|e| ServiceError::Invalid(format!("Discord refused the change: {}", e)))?;

    sqlx::query("UPDATE quarantines SET restored_at = NOW(), restored_by = $3 WHERE guild_id = $1 AND id = $2")
        .bind(guild_id.to_string())
        .bind(quarantine_id)
        .bind(by.to_string())
        .execute(pool)
        .await?;

    Ok(restored)
}

pub async fn guard_bot_add(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId, added_bot: UserId) {
    let Ok(settings) = service::settings(pool, guild_id).await else { return };
    if !settings.guard_bot_add || is_exempt(bot, pool, guild_id, actor).await {
        return;
    }

    let outcome = match guild_id.kick(bot.http, added_bot, Some("Sentinel: bot added by a non-whitelisted member")).await {
        Ok(()) => "removed".to_string(),
        Err(e) => format!("could not be removed ({})", e),
    };

    let detail = format!("<@{}> added bot <@{}>; the bot {}", actor, added_bot, outcome);
    service::record_audit(pool, guild_id, actor, "guard", "bot_add_blocked", &detail).await;
    alert(bot, &settings, guild_id, "Bot-add guard triggered", &detail, "audit").await;
    maybe_auto_lockdown(bot, pool, guild_id).await;
}

pub fn added_dangerous_permissions(changes: &[Change]) -> Permissions {
    changes
        .iter()
        .find_map(|change| match change {
            Change::Permissions { old, new } => {
                let old = old.unwrap_or_default();
                let new = new.unwrap_or_default();
                Some(new & !old & guarded_permissions())
            }
            _ => None,
        })
        .unwrap_or_default()
}

pub async fn guard_role_permissions(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId, role_id: RoleId, changes: &[Change]) -> bool {
    let added = added_dangerous_permissions(changes);
    if added.is_empty() {
        return false;
    }

    let Ok(settings) = service::settings(pool, guild_id).await else { return true };
    if !settings.guard_dangerous_perms || is_exempt(bot, pool, guild_id, actor).await {
        return true;
    }

    let current = bot.cache.guild(guild_id).and_then(|g| g.roles.get(&role_id).map(|r| r.permissions));
    let outcome = match current {
        Some(perms) => match guild_id
            .edit_role(bot, role_id, EditRole::new().permissions(perms & !added).audit_log_reason("Sentinel: dangerous permission reverted"))
            .await
        {
            Ok(_) => "reverted".to_string(),
            Err(e) => format!("could not be reverted ({})", e),
        },
        None => "could not be reverted (role not cached)".to_string(),
    };

    let detail = format!("<@{}> granted {} to <@&{}>; the change was {}", actor, permission_names(added), role_id, outcome);
    service::record_audit(pool, guild_id, actor, "guard", "dangerous_permission_blocked", &detail).await;
    alert(bot, &settings, guild_id, "Dangerous permission guard triggered", &detail, "audit").await;
    maybe_auto_lockdown(bot, pool, guild_id).await;
    true
}

pub async fn guard_member_roles(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId, target: UserId, changes: &[Change]) -> bool {
    let added: Vec<RoleId> = changes
        .iter()
        .filter_map(|change| match change {
            Change::RolesAdded { new: Some(roles), .. } => Some(roles.iter().map(|r| r.id).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();

    let dangerous: Vec<RoleId> = bot
        .cache
        .guild(guild_id)
        .map(|g| {
            added
                .iter()
                .copied()
                .filter(|id| g.roles.get(id).map_or(false, |r| !(r.permissions & guarded_permissions()).is_empty()))
                .collect()
        })
        .unwrap_or_default();

    if dangerous.is_empty() {
        return false;
    }

    let Ok(settings) = service::settings(pool, guild_id).await else { return true };
    if !settings.guard_dangerous_perms || is_exempt(bot, pool, guild_id, actor).await {
        return true;
    }

    let outcome = match guild_id.member(bot, target).await {
        Ok(member) => {
            let next: Vec<RoleId> = member.roles.iter().copied().filter(|r| !dangerous.contains(r)).collect();
            match guild_id
                .edit_member(bot.http, target, EditMember::new().roles(next).audit_log_reason("Sentinel: dangerous role grant reverted"))
                .await
            {
                Ok(_) => "reverted".to_string(),
                Err(e) => format!("could not be reverted ({})", e),
            }
        }
        Err(e) => format!("could not be reverted ({})", e),
    };

    let roles = dangerous.iter().map(|r| format!("<@&{}>", r)).collect::<Vec<_>>().join(", ");
    let detail = format!("<@{}> gave <@{}> {}; the grant was {}", actor, target, roles, outcome);
    service::record_audit(pool, guild_id, actor, "guard", "dangerous_role_blocked", &detail).await;
    alert(bot, &settings, guild_id, "Dangerous permission guard triggered", &detail, "audit").await;
    maybe_auto_lockdown(bot, pool, guild_id).await;
    true
}

pub fn permission_names(perms: Permissions) -> String {
    let names = [
        (Permissions::ADMINISTRATOR, "Administrator"),
        (Permissions::MANAGE_GUILD, "Manage Server"),
        (Permissions::MANAGE_ROLES, "Manage Roles"),
        (Permissions::MANAGE_CHANNELS, "Manage Channels"),
        (Permissions::BAN_MEMBERS, "Ban Members"),
        (Permissions::KICK_MEMBERS, "Kick Members"),
        (Permissions::MANAGE_WEBHOOKS, "Manage Webhooks"),
        (Permissions::MENTION_EVERYONE, "Mention Everyone"),
    ];
    names.iter().filter(|(p, _)| perms.contains(*p)).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

#[derive(serde::Serialize)]
pub struct LockdownStatus {
    pub active: bool,
    pub started_at: Option<String>,
    pub started_by: Option<String>,
    pub roles_locked: usize,
}

pub async fn lockdown_status(pool: &PgPool, guild_id: GuildId) -> ServiceResult<LockdownStatus> {
    let row: Option<(DateTime<Utc>, String, serde_json::Value)> =
        sqlx::query_as("SELECT started_at, started_by, removed_permissions FROM lockdowns WHERE guild_id = $1")
            .bind(guild_id.to_string())
            .fetch_optional(pool)
            .await?;

    Ok(match row {
        Some((started_at, started_by, removed)) => LockdownStatus {
            active: true,
            started_at: Some(started_at.to_rfc3339()),
            started_by: Some(started_by),
            roles_locked: removed.as_object().map_or(0, |m| m.len()),
        },
        None => LockdownStatus { active: false, started_at: None, started_by: None, roles_locked: 0 },
    })
}

async fn set_invites_paused(guild_id: GuildId, paused: bool) -> bool {
    let until = paused.then(|| (Utc::now() + std::time::Duration::from_secs(86400)).to_rfc3339());
    let result = reqwest::Client::new()
        .put(format!("https://discord.com/api/v10/guilds/{}/incident-actions", guild_id))
        .header("Authorization", format!("Bot {}", crate::config::CONFIG.token))
        .json(&serde_json::json!({ "invites_disabled_until": until, "dms_disabled_until": serde_json::Value::Null }))
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            log::warn!("incident actions returned {}", response.status());
            false
        }
        Err(e) => {
            log::warn!("incident actions failed: {}", e);
            false
        }
    }
}

#[derive(serde::Serialize)]
pub struct LockdownReport {
    pub roles_changed: usize,
    pub invites_paused: bool,
}

pub async fn lockdown_start(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, by: UserId, source: &str) -> ServiceResult<LockdownReport> {
    if lockdown_status(pool, guild_id).await?.active {
        return Err(ServiceError::Invalid("This server is already in lockdown".into()));
    }

    let whitelisted: HashSet<String> = sqlx::query_as::<_, (String,)>("SELECT entity_id FROM guild_whitelist WHERE guild_id = $1 AND entity_type = 'role'")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(id,)| id)
        .collect();

    if let Err(e) = crate::recovery::take(bot, pool, guild_id, "pre_lockdown", Some(by)).await {
        log::warn!("pre-lockdown snapshot failed for {}: {}", guild_id, e);
    }

    let me = bot.me();
    let targets: Vec<(RoleId, Permissions)> = {
        let guild = bot.cache.guild(guild_id).ok_or(ServiceError::NotFound("Sentinel cannot see this server"))?;
        let my_roles: Vec<RoleId> = guild.members.get(&me).map(|m| m.roles.to_vec()).unwrap_or_default();
        let my_top = my_roles.iter().filter_map(|id| guild.roles.get(id)).map(|r| r.position).max().unwrap_or(0);
        guild
            .roles
            .iter()
            .filter(|r| r.position < my_top && !my_roles.contains(&r.id) && !whitelisted.contains(&r.id.to_string()))
            .filter(|r| !(r.permissions & lockdown_permissions()).is_empty())
            .map(|r| (r.id, r.permissions))
            .collect()
    };

    let mut removed: HashMap<String, u64> = HashMap::new();
    for (role_id, perms) in targets {
        let strip = perms & lockdown_permissions();
        match guild_id
            .edit_role(bot, role_id, EditRole::new().permissions(perms & !strip).audit_log_reason("Sentinel: lockdown"))
            .await
        {
            Ok(_) => {
                removed.insert(role_id.to_string(), strip.bits());
            }
            Err(e) => log::warn!("lockdown could not edit role {}: {}", role_id, e),
        }
    }

    let invites_paused = set_invites_paused(guild_id, true).await;

    sqlx::query("INSERT INTO lockdowns (guild_id, started_by, removed_permissions) VALUES ($1, $2, $3)")
        .bind(guild_id.to_string())
        .bind(by.to_string())
        .bind(serde_json::to_value(&removed).unwrap_or_default())
        .execute(pool)
        .await?;

    let detail = format!(
        "<@{}> started a lockdown: {} role{} restricted{}",
        by,
        removed.len(),
        if removed.len() == 1 { "" } else { "s" },
        if invites_paused { ", invites paused for 24 hours" } else { "" }
    );
    service::record_audit(pool, guild_id, by, source, "lockdown_started", &detail).await;
    if let Ok(settings) = service::settings(pool, guild_id).await {
        alert(bot, &settings, guild_id, "Lockdown started", &detail, "overview").await;
    }

    Ok(LockdownReport { roles_changed: removed.len(), invites_paused })
}

pub async fn lockdown_end(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, by: UserId, source: &str) -> ServiceResult<LockdownReport> {
    let row: Option<(serde_json::Value,)> = sqlx::query_as("SELECT removed_permissions FROM lockdowns WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .fetch_optional(pool)
        .await?;
    let (removed,) = row.ok_or(ServiceError::Invalid("This server is not in lockdown".into()))?;

    let entries: Vec<(RoleId, Permissions)> = removed
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(id, bits)| Some((id.parse::<RoleId>().ok()?, Permissions::from_bits_truncate(bits.as_u64()?))))
                .collect()
        })
        .unwrap_or_default();

    let mut restored = 0;
    for (role_id, bits) in entries {
        let current = bot.cache.guild(guild_id).and_then(|g| g.roles.get(&role_id).map(|r| r.permissions));
        let Some(current) = current else { continue };
        match guild_id
            .edit_role(bot, role_id, EditRole::new().permissions(current | bits).audit_log_reason("Sentinel: lockdown lifted"))
            .await
        {
            Ok(_) => restored += 1,
            Err(e) => log::warn!("could not restore role {}: {}", role_id, e),
        }
    }

    let invites_resumed = set_invites_paused(guild_id, false).await;

    sqlx::query("DELETE FROM lockdowns WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .execute(pool)
        .await?;

    let detail = format!("<@{}> lifted the lockdown: {} role{} restored", by, restored, if restored == 1 { "" } else { "s" });
    service::record_audit(pool, guild_id, by, source, "lockdown_ended", &detail).await;
    if let Ok(settings) = service::settings(pool, guild_id).await {
        alert(bot, &settings, guild_id, "Lockdown lifted", &detail, "overview").await;
    }

    Ok(LockdownReport { roles_changed: restored, invites_paused: !invites_resumed })
}

pub async fn guard_webhook(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId, webhook_id: u64) {
    let Ok(settings) = service::settings(pool, guild_id).await else { return };
    if !settings.guard_webhooks || is_exempt(bot, pool, guild_id, actor).await {
        return;
    }

    let outcome = match bot
        .http
        .delete_webhook(serenity::all::WebhookId::new(webhook_id), Some("Sentinel: webhook created by a non-whitelisted member"))
        .await
    {
        Ok(()) => "deleted".to_string(),
        Err(e) => format!("could not be deleted ({})", e),
    };

    let detail = format!("<@{}> created a webhook; it was {}", actor, outcome);
    service::record_audit(pool, guild_id, actor, "guard", "webhook_blocked", &detail).await;
    alert(bot, &settings, guild_id, "Webhook guard triggered", &detail, "audit").await;
    maybe_auto_lockdown(bot, pool, guild_id).await;
}

pub async fn guard_vanity(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId, actor: UserId, changes: &[Change]) -> bool {
    let changed = changes.iter().find_map(|change| match change {
        Change::VanityUrlCode { old, new } => Some((old.as_ref().map(|c| c.to_string()), new.as_ref().map(|c| c.to_string()))),
        _ => None,
    });
    let Some((old, new)) = changed else { return false };

    let Ok(settings) = service::settings(pool, guild_id).await else { return true };
    if !settings.guard_vanity || is_exempt(bot, pool, guild_id, actor).await {
        return true;
    }

    let outcome = match quarantine(bot, pool, guild_id, actor, None).await {
        Ok(n) => format!("quarantined them ({} role{} held)", n, if n == 1 { "" } else { "s" }),
        Err(e) => format!("could not quarantine them ({})", e),
    };

    let detail = format!(
        "<@{}> changed the vanity URL from `{}` to `{}`. Sentinel {}. Discord does not let bots change vanity URLs, so set it back in Server Settings.",
        actor,
        old.unwrap_or_else(|| "none".into()),
        new.unwrap_or_else(|| "none".into()),
        outcome
    );
    service::record_audit(pool, guild_id, actor, "guard", "vanity_changed", &detail).await;
    alert(bot, &settings, guild_id, "Vanity guard triggered", &detail, "audit").await;
    maybe_auto_lockdown(bot, pool, guild_id).await;
    true
}

pub async fn maybe_auto_lockdown(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId) {
    let Ok(settings) = service::settings(pool, guild_id).await else { return };
    if !settings.auto_lockdown {
        return;
    }
    if lockdown_status(pool, guild_id).await.map_or(true, |s| s.active) {
        return;
    }

    let counted: Result<(i64,), _> = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND NOT dry_run
                AND created_at > NOW() - make_interval(secs => $2::double precision))
          + (SELECT COUNT(*) FROM audit_trail WHERE guild_id = $1 AND source = 'guard'
                AND created_at > NOW() - make_interval(secs => $2::double precision))",
    )
    .bind(guild_id.to_string())
    .bind(settings.auto_lockdown_window_secs as f64)
    .fetch_one(pool)
    .await;

    let Ok((count,)) = counted else { return };
    if count < settings.auto_lockdown_threshold as i64 {
        return;
    }

    log::warn!("Auto-lockdown triggered in {} ({} incidents)", guild_id, count);
    if let Err(e) = lockdown_start(bot, pool, guild_id, bot.me(), "lockdown").await {
        log::error!("auto-lockdown failed in {}: {}", guild_id, e);
    }
}
