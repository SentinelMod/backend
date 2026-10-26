use std::collections::BTreeMap;

use poise::serenity_prelude::{ChannelId, CreateEmbed, CreateEmbedFooter, CreateMessage, Guild, GuildId, Permissions};
use serde::Serialize;
use sqlx::PgPool;

use crate::protect::{self, Bot};
use crate::service::{self, ServiceError, ServiceResult};

const BRAND_COLOR: u32 = 0x1F8FBF;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Error,
}

#[derive(Serialize, Debug)]
pub struct Check {
    pub level: Level,
    pub title: String,
    pub detail: String,
    pub tab: Option<&'static str>,
}

#[derive(Serialize, Debug)]
pub struct HealthReport {
    pub level: Level,
    pub checks: Vec<Check>,
}

struct Need {
    permission: Permissions,
    name: &'static str,
    reason: &'static str,
    level: Level,
}

fn need(permission: Permissions, name: &'static str, reason: &'static str, level: Level) -> Need {
    Need { permission, name, reason, level }
}

fn needs(settings: &service::GuildSettings, actions: &[String]) -> Vec<Need> {
    let mut list = vec![need(Permissions::VIEW_AUDIT_LOG, "View Audit Log", "detecting moderation events", Level::Error)];
    for action in actions {
        match action.as_str() {
            "timeout_user" => list.push(need(Permissions::MODERATE_MEMBERS, "Moderate Members", "Timeout responses", Level::Error)),
            "remove_all_roles" => list.push(need(Permissions::MANAGE_ROLES, "Manage Roles", "Quarantine responses", Level::Error)),
            "kick_user" => list.push(need(Permissions::KICK_MEMBERS, "Kick Members", "Kick responses", Level::Error)),
            "ban_user" => list.push(need(Permissions::BAN_MEMBERS, "Ban Members", "Ban responses", Level::Error)),
            _ => {}
        }
    }
    if settings.guard_bot_add {
        list.push(need(Permissions::KICK_MEMBERS, "Kick Members", "the bot-add guard", Level::Error));
    }
    if settings.guard_dangerous_perms {
        list.push(need(Permissions::MANAGE_ROLES, "Manage Roles", "the permission guard", Level::Error));
    }
    if settings.guard_webhooks {
        list.push(need(Permissions::MANAGE_WEBHOOKS, "Manage Webhooks", "the webhook guard", Level::Error));
    }
    if settings.guard_vanity {
        list.push(need(Permissions::MANAGE_ROLES, "Manage Roles", "the vanity guard", Level::Error));
    }
    if settings.auto_lockdown {
        list.push(need(Permissions::MANAGE_ROLES, "Manage Roles", "auto-lockdown", Level::Error));
        list.push(need(Permissions::MANAGE_GUILD, "Manage Server", "pausing invites during a lockdown", Level::Warn));
    }
    if settings.snapshots_enabled {
        list.push(need(Permissions::MANAGE_ROLES, "Manage Roles", "restoring roles from a snapshot", Level::Warn));
        list.push(need(Permissions::MANAGE_CHANNELS, "Manage Channels", "restoring channels from a snapshot", Level::Warn));
    }
    if settings.antiscam_links || settings.antiscam_mentions || settings.antiscam_everyone || settings.antiscam_invites {
        list.push(need(Permissions::MANAGE_GUILD, "Manage Server", "the anti-scam AutoMod rules", Level::Error));
    }
    if settings.antiscam_links && settings.antiscam_timeout_secs > 0 {
        list.push(need(Permissions::MODERATE_MEMBERS, "Moderate Members", "the anti-scam timeout", Level::Error));
    }
    list
}

fn missing_permissions(granted: Permissions, needs: Vec<Need>) -> Vec<Check> {
    let mut grouped: BTreeMap<&'static str, (Level, Vec<&'static str>)> = BTreeMap::new();
    for need in needs.into_iter().filter(|n| !granted.contains(n.permission)) {
        let entry = grouped.entry(need.name).or_insert((need.level, vec![]));
        entry.0 = entry.0.max(need.level);
        if !entry.1.contains(&need.reason) {
            entry.1.push(need.reason);
        }
    }
    grouped
        .into_iter()
        .map(|(name, (level, reasons))| Check {
            level,
            title: format!("Missing {}", name),
            detail: format!("Needed for {}. Grant it to Sentinel's role in Server Settings, Roles.", join_list(&reasons)),
            tab: None,
        })
        .collect()
}

fn join_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {}", rest.join(", "), last),
    }
}

struct GuildView {
    granted: Permissions,
    roles_above: Vec<String>,
    log_channel: Option<Option<Permissions>>,
}

fn view(guild: &Guild, me: poise::serenity_prelude::UserId, log_channel: Option<ChannelId>, whitelisted: &[String]) -> Option<GuildView> {
    let member = guild.members.get(&me)?;
    let my_top = member.roles.iter().filter_map(|id| guild.roles.get(id)).map(|r| r.position).max().unwrap_or(0);
    let mut above: Vec<(i16, String)> = guild
        .roles
        .iter()
        .filter(|r| {
            r.id != guild.id.everyone_role()
                && !r.managed()
                && r.position >= my_top
                && !member.roles.contains(&r.id)
                && !(r.permissions & protect::guarded_permissions()).is_empty()
                && !whitelisted.contains(&r.id.to_string())
        })
        .map(|r| (r.position, r.name.to_string()))
        .collect();
    above.sort_by(|a, b| b.0.cmp(&a.0));
    Some(GuildView {
        granted: guild.member_permissions(member),
        roles_above: above.into_iter().map(|(_, name)| name).collect(),
        log_channel: log_channel.map(|id| guild.channels.get(&id).map(|channel| guild.user_permissions_in(channel, member))),
    })
}

pub async fn check(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId) -> ServiceResult<HealthReport> {
    let setup = service::is_setup(pool, guild_id).await?;
    let settings = service::settings(pool, guild_id).await?;
    let actions: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT limit_action FROM limits WHERE guild_id = $1")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?;
    let actions: Vec<String> = actions.into_iter().map(|(a,)| a).collect();
    let (limits,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM limits WHERE guild_id = $1").bind(guild_id.to_string()).fetch_one(pool).await?;
    let whitelisted: Vec<(String,)> = sqlx::query_as("SELECT entity_id FROM guild_whitelist WHERE guild_id = $1 AND entity_type = 'role'")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?;
    let whitelisted: Vec<String> = whitelisted.into_iter().map(|(id,)| id).collect();
    let antiscam = crate::antiscam::status(pool, guild_id).await?;
    let log_channel = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<ChannelId>().ok());

    let me = bot.me();
    let view = {
        let guild = bot.cache.guild(guild_id).ok_or(ServiceError::NotFound("Sentinel is not in this server"))?;
        view(&guild, me, log_channel, &whitelisted)
    }
    .ok_or(ServiceError::NotFound("Sentinel's member data is not cached yet, try again in a minute"))?;

    let mut checks = vec![];

    if !setup {
        checks.push(Check {
            level: Level::Error,
            title: "Sentinel is not set up".into(),
            detail: "Nothing is being tracked yet. Run /setup or set it up from the dashboard.".into(),
            tab: Some("overview"),
        });
    }

    checks.extend(missing_permissions(view.granted, needs(&settings, &actions)));

    if !view.roles_above.is_empty() {
        let shown: Vec<&str> = view.roles_above.iter().take(5).map(String::as_str).collect();
        let more = view.roles_above.len().saturating_sub(shown.len());
        checks.push(Check {
            level: Level::Warn,
            title: format!("Sentinel's role is below {} staff role{}", view.roles_above.len(), if view.roles_above.len() == 1 { "" } else { "s" }),
            detail: format!(
                "Sentinel cannot quarantine, kick, ban or time out members with {}{}. Drag Sentinel's role above them in Server Settings, Roles, or whitelist them if they are trusted.",
                shown.join(", "),
                if more > 0 { format!(" and {} more", more) } else { String::new() }
            ),
            tab: Some("access"),
        });
    }

    match view.log_channel {
        None => checks.push(Check {
            level: Level::Warn,
            title: "No log channel".into(),
            detail: "Alerts only reach the server owner by DM. Pick a log channel so your team sees them too.".into(),
            tab: Some("settings"),
        }),
        Some(None) => checks.push(Check {
            level: Level::Error,
            title: "The log channel no longer exists".into(),
            detail: "Alerts have nowhere to go. Pick a new log channel.".into(),
            tab: Some("settings"),
        }),
        Some(Some(perms)) => {
            let required = Permissions::VIEW_CHANNEL | Permissions::SEND_MESSAGES | Permissions::EMBED_LINKS;
            if !perms.contains(required) {
                checks.push(Check {
                    level: Level::Error,
                    title: "Sentinel cannot post in the log channel".into(),
                    detail: "Allow View Channel, Send Messages and Embed Links for Sentinel in the log channel's permissions.".into(),
                    tab: Some("settings"),
                });
            }
        }
    }

    if setup && limits == 0 {
        checks.push(Check {
            level: Level::Warn,
            title: "No limits configured".into(),
            detail: "Sentinel records activity but will not step in. Apply a preset or add a limit.".into(),
            tab: Some("limits"),
        });
    }

    if let Some(error) = antiscam.error {
        checks.push(Check { level: Level::Error, title: "Anti-scam rules are out of sync".into(), detail: error, tab: Some("settings") });
    }

    checks.sort_by(|a, b| b.level.cmp(&a.level));
    let level = checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
    if checks.is_empty() {
        checks.push(Check { level: Level::Ok, title: "Everything looks good".into(), detail: "Sentinel has what it needs for every feature you have turned on.".into(), tab: None });
    }
    Ok(HealthReport { level, checks })
}

pub fn summary(report: &HealthReport, limit: usize) -> String {
    let issues: Vec<&Check> = report.checks.iter().filter(|c| c.level != Level::Ok).collect();
    if issues.is_empty() {
        return "Everything looks good. Sentinel has what it needs for every feature you have turned on.".into();
    }
    let mut lines: Vec<String> = issues
        .iter()
        .take(limit)
        .map(|c| format!("{} **{}**\n{}", if c.level == Level::Error { "🔴" } else { "🟠" }, c.title, c.detail))
        .collect();
    if issues.len() > limit {
        lines.push(format!("…and {} more on the dashboard.", issues.len() - limit));
    }
    lines.join("\n\n")
}

pub async fn welcome(bot: Bot<'_>, guild_id: GuildId) {
    let me = bot.me();
    let (target, owner) = {
        let Some(guild) = bot.cache.guild(guild_id) else { return };
        let Some(member) = guild.members.get(&me) else { return };
        let can_post = |id: ChannelId| {
            guild.channels.get(&id).map_or(false, |c| {
                guild.user_permissions_in(c, member).contains(Permissions::VIEW_CHANNEL | Permissions::SEND_MESSAGES | Permissions::EMBED_LINKS)
            })
        };
        let target = guild.system_channel_id.filter(|id| can_post(*id)).or_else(|| guild.default_channel(me).map(|c| c.id).filter(|id| can_post(*id)));
        (target, guild.owner_id)
    };

    let embed = CreateEmbed::new()
        .title("Thanks for adding Sentinel")
        .description(format!(
            "Sentinel watches your audit log and steps in when someone with power starts doing damage.\n\n\
             **1.** Run `/setup` to start tracking.\n\
             **2.** Run `/limits preset` for a tuned starting point, or `/limits add` for your own.\n\
             **3.** Run `/settings` and pick a log channel for alerts.\n\
             **4.** Whitelist trusted bots and staff with `/whitelist add`.\n\
             **5.** Run `/health` to check Sentinel has the permissions and role position it needs.\n\n\
             Everything is also on the [dashboard]({}).",
            protect::dashboard_link(guild_id, "overview")
        ))
        .color(BRAND_COLOR)
        .footer(CreateEmbedFooter::new("Only server admins can run Sentinel's commands"));

    let message = CreateMessage::new().embed(embed);
    let sent = match target {
        Some(channel) => channel.send_message(bot.http, message.clone()).await.is_ok(),
        None => false,
    };
    if !sent {
        if let Err(e) = owner.direct_message(bot.http, message).await {
            log::warn!("could not send welcome message for {}: {}", guild_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_reasons() {
        assert_eq!(join_list(&["a"]), "a");
        assert_eq!(join_list(&["a", "b"]), "a and b");
        assert_eq!(join_list(&["a", "b", "c"]), "a, b and c");
    }

    #[test]
    fn groups_missing_permissions() {
        let settings = service::GuildSettings { guard_bot_add: true, guard_dangerous_perms: true, snapshots_enabled: true, ..Default::default() };
        let checks = missing_permissions(Permissions::VIEW_AUDIT_LOG, needs(&settings, &["kick_user".into()]));
        let kick = checks.iter().find(|c| c.title == "Missing Kick Members").unwrap();
        assert_eq!(kick.level, Level::Error);
        assert!(kick.detail.contains("Kick responses and the bot-add guard"));
        let channels = checks.iter().find(|c| c.title == "Missing Manage Channels").unwrap();
        assert_eq!(channels.level, Level::Warn);
        assert!(!checks.iter().any(|c| c.title == "Missing View Audit Log"));
    }

    #[test]
    fn administrator_covers_everything() {
        let settings = service::GuildSettings { guard_webhooks: true, antiscam_links: true, antiscam_timeout_secs: 60, ..Default::default() };
        assert!(missing_permissions(Permissions::all(), needs(&settings, &["ban_user".into()])).is_empty());
    }
}
