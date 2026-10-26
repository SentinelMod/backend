use poise::{
    serenity_prelude::{CreateEmbed, Member, Role, User},
    CreateReply,
};
use serenity::{all::{ChannelId, UserId}, builder::CreateAttachment, prelude::Mentionable};

use crate::protect::{self, Bot};
use crate::{service, Context, Error};

#[poise::command(prefix_command, slash_command)]
pub async fn ping(ctx: Context<'_>) -> Result<(), Error> {
    ctx.say("Pong!").await?;
    Ok(())
}

/// Permission management
#[poise::command(
    prefix_command,
    slash_command,
    subcommands("add_admin", "remove_admin")
)]
pub async fn perms(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Add admin to the server
#[poise::command(prefix_command, slash_command, guild_only)]
pub async fn add_admin(ctx: Context<'_>, user: Member) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    if ctx.author().id != ctx.guild().ok_or("Could not get guild id")?.owner_id {
        return Err("In order to protect against nukes, bypassing the bot and other secuity concerns, only guild owners can add new admins at this time.".into());
    }

    service::admin_add(&ctx.data().pool, guild_id, user.user.id).await?;
    service::ensure_guild(&ctx.data().pool, guild_id).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "admin_added", &format!("Added <@{}> as a Sentinel admin", user.user.id)).await;

    ctx.say("Added admin successfully").await?;
    Ok(())
}

/// Configure log channel, alerts and guards
#[poise::command(slash_command, guild_only)]
#[allow(clippy::too_many_arguments)]
pub async fn settings(
    ctx: Context<'_>,
    #[description = "Channel for audit notifications and alerts"]
    logs_channel: Option<ChannelId>,
    #[description = "Whether routine audit notifications are posted"]
    logs_enabled: Option<bool>,
    #[description = "Embed color as hexadecimal (0xRRGGBB) or decimal"]
    logs_color: Option<String>,
    #[description = "Role to ping when a limit or guard fires"]
    alert_role: Option<Role>,
    #[description = "Stop pinging the alert role"]
    clear_alert_role: Option<bool>,
    #[description = "Direct message the server owner when a limit or guard fires"]
    dm_owner: Option<bool>,
    #[description = "Remove bots added by members who are not whitelisted"]
    guard_bot_add: Option<bool>,
    #[description = "Revert dangerous permissions granted by members who are not whitelisted"]
    guard_dangerous_perms: Option<bool>,
    #[description = "Delete webhooks created by members who are not whitelisted"]
    guard_webhooks: Option<bool>,
    #[description = "Quarantine members who are not whitelisted when they change the vanity URL"]
    guard_vanity: Option<bool>,
    #[description = "Start a lockdown automatically when incidents pile up"]
    auto_lockdown: Option<bool>,
    #[description = "Incidents within 5 minutes that trigger an automatic lockdown (1-20)"]
    auto_lockdown_threshold: Option<i32>,
    #[description = "Take a snapshot of roles and channels every 6 hours"]
    snapshots: Option<bool>,
    #[description = "Post a weekly summary to the log channel"]
    weekly_digest: Option<bool>,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let color = logs_color
        .map(|value| {
            i64::from_str_radix(value.trim_start_matches('#').trim_start_matches("0x"), 16)
                .or_else(|_| value.parse::<i64>())
                .map_err(|_| "logs_color must be hexadecimal (0xRRGGBB) or decimal")
        })
        .transpose()?;

    let alert_role_id = match (alert_role, clear_alert_role) {
        (_, Some(true)) => Some(None),
        (Some(role), _) => Some(Some(role.id.to_string())),
        _ => None,
    };

    service::update_settings(
        &ctx.data().pool,
        guild_id,
        service::SettingsPatch {
            logs_channel_id: logs_channel.map(|c| Some(c.to_string())),
            logs_enabled,
            logs_color: color,
            alert_role_id,
            alert_dm_owner: dm_owner,
            guard_bot_add,
            guard_dangerous_perms,
            guard_webhooks,
            guard_vanity,
            auto_lockdown,
            auto_lockdown_threshold,
            auto_lockdown_window_secs: None,
            snapshots_enabled: snapshots,
            digest_enabled: weekly_digest,
            ..Default::default()
        },
    )
    .await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "settings_updated", "Updated settings with /settings").await;

    ctx.say("Settings updated.").await?;
    Ok(())
}

/// Remove admin from the server
#[poise::command(prefix_command, slash_command, guild_only)]
pub async fn remove_admin(ctx: Context<'_>, user: Member) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    if ctx.author().id != ctx.guild().ok_or("Could not get guild id")?.owner_id {
        return Err("Only guild owners can remove admins".into());
    }

    service::admin_remove(&ctx.data().pool, guild_id, user.user.id).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "admin_removed", &format!("Removed <@{}> as a Sentinel admin", user.user.id)).await;

    ctx.say("Removed admin successfully").await?;
    Ok(())
}

/// Limits base command
#[poise::command(
    prefix_command,
    slash_command,
    guild_only,
    subcommands(
        "limits_add",
        "limits_edit",
        "limits_view",
        "limits_remove",
        "limits_guide",
        "hit_limits",
        "limits_preset"
    )
)]
pub async fn limits(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Explain how moderation limits work
#[poise::command(prefix_command, slash_command, guild_only, rename = "guide")]
pub async fn limits_guide(ctx: Context<'_>) -> Result<(), Error> {
    let embed = CreateEmbed::default()
        .title("How Sentinel limits work")
        .description(
            "Limits watch moderation events and apply a response when a moderator reaches a threshold."
        )
        .field(
            "Add a limit",
            "Use `/limits add` and choose a name, event type, number of infractions, time window, and response.",
            false,
        )
        .field(
            "Event types",
            "Roles, channels, webhooks and emoji (create, update, remove), kicks, bans, unbans, bots added, member prunes, server settings changes, invite and integration deletes, bulk message deletes, and dangerous permission grants.",
            false,
        )
        .field(
            "Threshold example",
            "`3` bans in `10` minutes means the response runs when the same moderator reaches three bans during that window.",
            false,
        )
        .field(
            "Responses",
            "Alert Only, Timeout User, Quarantine (removes roles, restorable with `/quarantine restore`), Kick User, or Ban User. Add several limits for the same event at different thresholds to build an escalation ladder; the most severe response that applies runs.",
            false,
        )
        .field(
            "Manage limits",
            "`/limits view` lists configured limits. `/limits edit` updates one in place. Use `/limits remove` and select a limit from the suggestions.",
            false,
        )
        .field(
            "Whitelist",
            "`/whitelist add` exempts a trusted user or role from limit tracking entirely; `/whitelist view` and `/whitelist remove` manage it.",
            false,
        )
        .field(
            "History",
            "`/limits hit` shows triggered limits, while `/actions view` shows recorded moderation actions.",
            false,
        )
        .color(0x00ff00);

    ctx.send(CreateReply::default().embed(embed)).await?;
    Ok(())
}

/// Add a limit to the server
#[poise::command(slash_command, guild_only, rename = "add")]
pub async fn limits_add(
    ctx: Context<'_>,
    #[description = "The name of the limit"]
    limit_name: String,
    #[description = "The type of limit to impose on moderators"]
    limit_type: crate::core::UserLimitTypesChoices,
    #[description = "How many actions trigger the limit"]
    limit_per: i32,
    #[description = "The time interval infractions are counted in"]
    limit_time: i64,
    #[description = "The time unit for the time interval [seconds/minutes/hours/days]"]
    limit_time_unit: crate::utils::Unit,
    #[description = "The action to take when the limit is hit"]
    limit_action: crate::core::UserLimitActionsChoices,
    #[description = "Timeout duration, only used when action is Timeout User (default 1 hour)"]
    timeout_duration: Option<i64>,
    #[description = "The time unit for the timeout duration [seconds/minutes/hours/days]"]
    timeout_duration_unit: Option<crate::utils::Unit>,
    #[description = "Count each moderator separately (default) or all moderators together"]
    scope: Option<ScopeChoice>,
    #[description = "Log what would happen without acting"]
    dry_run: Option<bool>,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let input = service::LimitInput {
        scope: scope.map(ScopeChoice::resolve).unwrap_or(service::LimitScope::Moderator),
        dry_run: dry_run.unwrap_or(false),
        name: limit_name,
        event: limit_type.resolve(),
        action: limit_action.resolve(),
        per: limit_per,
        window_secs: limit_time.saturating_mul(limit_time_unit.to_seconds()),
        timeout_secs: timeout_duration
            .map(|value| value.saturating_mul(timeout_duration_unit.unwrap_or(crate::utils::Unit::Seconds).to_seconds())),
    };
    let name = input.name.trim().to_string();

    service::create_limit(&ctx.data().pool, guild_id, input).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "limit_created", &format!("Created limit {}", name)).await;

    ctx.say("Added limit successfully").await?;
    Ok(())
}

/// Edit an existing limit
#[poise::command(slash_command, guild_only, rename = "edit")]
pub async fn limits_edit(
    ctx: Context<'_>,
    #[description = "The limit id to edit"]
    #[autocomplete = "crate::autocompletes::limits_autocomplete"]
    limit_id: String,
    #[description = "The new name of the limit"]
    limit_name: Option<String>,
    #[description = "The new type of limit to impose on moderators"]
    limit_type: Option<crate::core::UserLimitTypesChoices>,
    #[description = "How many actions trigger the limit"]
    limit_per: Option<i32>,
    #[description = "The new time interval infractions are counted in"]
    limit_time: Option<i64>,
    #[description = "The time unit for the time interval [seconds/minutes/hours/days]"]
    limit_time_unit: Option<crate::utils::Unit>,
    #[description = "The new action to take when the limit is hit"]
    limit_action: Option<crate::core::UserLimitActionsChoices>,
    #[description = "New timeout duration, only used when action is Timeout User"]
    timeout_duration: Option<i64>,
    #[description = "The time unit for the timeout duration [seconds/minutes/hours/days]"]
    timeout_duration_unit: Option<crate::utils::Unit>,
    #[description = "Count each moderator separately or all moderators together"]
    scope: Option<ScopeChoice>,
    #[description = "Log what would happen without acting"]
    dry_run: Option<bool>,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let patch = service::LimitPatch {
        scope: scope.map(ScopeChoice::resolve),
        dry_run,
        name: limit_name,
        event: limit_type.map(|t| t.resolve()),
        action: limit_action.map(|a| a.resolve()),
        per: limit_per,
        window_secs: limit_time
            .map(|value| value.saturating_mul(limit_time_unit.unwrap_or(crate::utils::Unit::Seconds).to_seconds())),
        timeout_secs: timeout_duration
            .map(|value| value.saturating_mul(timeout_duration_unit.unwrap_or(crate::utils::Unit::Seconds).to_seconds())),
    };

    let updated = service::update_limit(&ctx.data().pool, guild_id, &limit_id, patch).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "limit_updated", &format!("Edited limit {}", updated.name)).await;

    ctx.say("Updated limit successfully").await?;
    Ok(())
}

/// View the limits setup for this server
#[poise::command(prefix_command, slash_command, guild_only, rename = "view")]
pub async fn limits_view(ctx: Context<'_>) -> Result<(), Error> {
    let limits = crate::core::Limit::from_guild(
        &ctx.data().pool,
        ctx.guild_id().ok_or("Could not get guild id")?,
    )
    .await?;

    if limits.is_empty() {
        ctx.say("No limits setup for this server, use ``/limits add`` to add one!")
            .await?;
        return Ok(());
    }

    let mut cr: CreateReply<'_> = CreateReply::default();

    let mut added: i32 = 0;
    let mut i = 0;
    let mut embeds = vec![];

    for limit in limits {
        added += 1;

        if added >= 15 {
            added = 0;
            i += 1;
        }

        if embeds.len() <= i {
            embeds.push(CreateEmbed::default().title("Limits").color(0x00ff00));
        }

        embeds[i] = embeds[i].clone().field(
            limit.limit_name,
            format!(
                "If over {amount} ``{cond}`` triggered between {time} interval: ``{then}`` [{id}]",
                amount = limit.limit_per,
                cond = limit.limit_type.to_cond(),
                time = crate::utils::parse_pg_interval(limit.limit_time),
                then = limit.limit_action.to_cond(),
                id = limit.limit_id
            ),
            false,
        );
    }

    for embed in embeds {
        cr = cr.embed(embed);
    }

    ctx.send(cr).await?;

    Ok(())
}

/// Remove a limit from the server
#[poise::command(prefix_command, slash_command, guild_only, rename = "remove")]
pub async fn limits_remove(
    ctx: Context<'_>,
    #[description = "The limit id to remove"]
    #[autocomplete = "crate::autocompletes::limits_autocomplete"]
    limit_id: String,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let name = service::delete_limit(&ctx.data().pool, guild_id, &limit_id).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "limit_deleted", &format!("Deleted limit {}", name)).await;

    ctx.say("Removed limit successfully").await?;
    Ok(())
}

/// Setup the bot if it is not already setup
#[poise::command(prefix_command, slash_command, guild_only)]
pub async fn setup(ctx: Context<'_>) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    if service::is_setup(&ctx.data().pool, guild_id).await? {
        return Err("Guild is already setup".into());
    }

    service::ensure_guild(&ctx.data().pool, guild_id).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "setup", "Set up Sentinel").await;

    let report = crate::health::check(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id).await?;
    ctx.say(format!(
        "Sentinel is set up. Next, run `/limits preset` or `/limits add`, and pick a log channel with `/settings`.\n\n{}",
        crate::health::summary(&report, 4)
    ))
    .await?;
    Ok(())
}

/// Check that Sentinel has the permissions and role position it needs
#[poise::command(slash_command, guild_only)]
pub async fn health(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer().await?;
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let report = crate::health::check(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id).await?;
    ctx.say(format!("{}\n\n{}", crate::health::summary(&report, 8), protect::dashboard_link(guild_id, "overview"))).await?;
    Ok(())
}

/// Action management
#[poise::command(prefix_command, slash_command, guild_only, subcommands("actions_view"))]
pub async fn actions(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// View actions taken by users that have been recorded by Sentinel
#[poise::command(prefix_command, slash_command, guild_only, rename = "view")]
pub async fn actions_view(
    ctx: Context<'_>,
    #[description = "User ID (optional)"] user_id: Option<UserId>,
) -> Result<(), Error> {
    let actions = {
        if let Some(user_id) = user_id {
            crate::core::Action::user(
                &ctx.data().pool,
                ctx.guild_id().ok_or("Could not get guild id")?,
                user_id,
            )
            .await?
        } else {
            crate::core::Action::guild(
                &ctx.data().pool,
                ctx.guild_id().ok_or("Could not get guild id")?,
            )
            .await?
        }
    };

    if actions.is_empty() {
        ctx.say("No actions recorded").await?;
        return Ok(());
    }

    if actions.len() > 30 {
        let actions = serde_json::to_string(&actions).map_err(|_| "Could not serialize actions")?;

        // Create a attachment
        let attachment = CreateAttachment::bytes(actions.into_bytes(), "actions.json");

        ctx.send(CreateReply::default().attachment(attachment)).await?;

        return Ok(());
    }

    let mut cr = CreateReply::default();
    let mut embeds = vec![];
    let mut added: i32 = 0;
    let mut i = 0;

    for action in actions {
        added += 1;

        if added >= 8 {
            added = 0;
            i += 1;
        }

        if embeds.len() <= i {
            embeds.push(CreateEmbed::default().title("Actions").color(0x00ff00));
        }

        embeds[i] = embeds[i].clone().field(
            action.action_id.clone(),
            format!(
                "``{limit_type}`` on ``{action_target}`` by {user_id} at <t:{timestamp}:R> [{id}]\n**Hit Limits:** {limits_hit:#?}",
                limit_type = action.limit_type,
                action_target = action.action_target,
                user_id = action.user_id.mention().to_string() + " (" + &action.user_id.to_string() + ")",
                timestamp = action.created_at.timestamp(),
                id = action.action_id,
                limits_hit = action.limits_hit
            ),
            false,
        );
    }

    for embed in embeds {
        cr = cr.embed(embed);
    }

    ctx.send(cr).await?;

    Ok(())
}

/// View hit limits
#[poise::command(prefix_command, slash_command, guild_only, rename = "hit")]
pub async fn hit_limits(
    ctx: Context<'_>,
) -> Result<(), Error> {
    let hit_limits = crate::core::PastHitLimits::guild(
        &ctx.data().pool,
        ctx.guild_id().ok_or("Could not get guild id")?,
    ).await?;        

    if hit_limits.is_empty() {
        ctx.say("No hit limits recorded").await?;
        return Ok(());
    }

    if hit_limits.len() > 30 {
        let hit_limits = serde_json::to_string(&hit_limits).map_err(|_| "Could not serialize hit_limits")?;

        // Create a attachment
        let attachment = CreateAttachment::bytes(hit_limits.into_bytes(), "hit_limits.json");

        ctx.send(CreateReply::default().attachment(attachment)).await?;

        return Ok(());
    }

    let mut cr = CreateReply::default();
    let mut embeds = vec![];
    let mut added: i32 = 0;
    let mut i = 0;

    for hit_limit in hit_limits {
        added += 1;

        if added >= 8 {
            added = 0;
            i += 1;
        }

        if embeds.len() <= i {
            embeds.push(CreateEmbed::default().title("Past Limits History").color(0x00ff00));
        }

        let mut notes = String::new();

        for note in hit_limit.notes {
            notes.push_str(&format!("- ``{}`` ", note));
        }

        let mut causes = String::new();

        for cause in hit_limit.cause {
            causes.push_str(
                &format!(
                    "``{limit_type}`` on ``{action_target}`` by {user_id} at <t:{timestamp}:R> [{id}]\n**Hit Limits:** {limits_hit:#?}",
                    limit_type = cause.limit_type,
                    action_target = cause.action_target,
                    user_id = cause.user_id.mention().to_string() + " (" + &cause.user_id.to_string() + ")",
                    timestamp = cause.created_at.timestamp(),
                    id = cause.action_id,
                    limits_hit = cause.limits_hit
                ),
            );
        }

        embeds[i] = embeds[i].clone().field(
            hit_limit.id.clone(),
            format!(
                "Limit ``{limit_id}`` reached by ``{user_id}`` at <t:{timestamp}:R> [{id}]\n**Notes:** {notes}\n**Causes:** {causes}",
                limit_id = hit_limit.limit_id,
                user_id = hit_limit.user_id.mention().to_string() + " (" + &hit_limit.user_id.to_string() + ")",
                timestamp = hit_limit.created_at.timestamp(),
                id = hit_limit.id,
                notes = notes,
                causes = causes
            ),
            false,
        );
    }

    for embed in embeds {
        cr = cr.embed(embed);
    }

    ctx.send(cr).await?;

    Ok(())
}
/// Whitelist management: exempt trusted users or roles from limit tracking
#[poise::command(
    prefix_command,
    slash_command,
    guild_only,
    subcommands("whitelist_add", "whitelist_remove", "whitelist_view")
)]
pub async fn whitelist(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Add a user or role to the whitelist
#[poise::command(prefix_command, slash_command, guild_only, rename = "add")]
pub async fn whitelist_add(
    ctx: Context<'_>,
    #[description = "The user to exempt from limit tracking"] user: Option<User>,
    #[description = "The role to exempt from limit tracking"] role: Option<Role>,
) -> Result<(), Error> {
    let (entity_id, entity_type) = match (user, role) {
        (Some(user), None) => (user.id.to_string(), "user"),
        (None, Some(role)) => (role.id.to_string(), "role"),
        _ => return Err("Provide exactly one of `user` or `role`".into()),
    };

    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    service::whitelist_add(&ctx.data().pool, guild_id, &entity_id, entity_type).await?;
    let mention = if entity_type == "role" { format!("<@&{}>", entity_id) } else { format!("<@{}>", entity_id) };
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "whitelist_added", &format!("Whitelisted {}", mention)).await;

    ctx.say("Added to whitelist successfully").await?;
    Ok(())
}

/// Remove a user or role from the whitelist
#[poise::command(prefix_command, slash_command, guild_only, rename = "remove")]
pub async fn whitelist_remove(
    ctx: Context<'_>,
    #[description = "The user to remove from the whitelist"] user: Option<User>,
    #[description = "The role to remove from the whitelist"] role: Option<Role>,
) -> Result<(), Error> {
    let (entity_id, mention) = match (user, role) {
        (Some(user), None) => (user.id.to_string(), format!("<@{}>", user.id)),
        (None, Some(role)) => (role.id.to_string(), format!("<@&{}>", role.id)),
        _ => return Err("Provide exactly one of `user` or `role`".into()),
    };

    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    service::whitelist_remove(&ctx.data().pool, guild_id, &entity_id).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "whitelist_removed", &format!("Removed {} from the whitelist", mention)).await;

    ctx.say("Removed from whitelist successfully").await?;
    Ok(())
}

/// View the whitelist for this server
#[poise::command(prefix_command, slash_command, guild_only, rename = "view")]
pub async fn whitelist_view(ctx: Context<'_>) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?.to_string();

    let rec = sqlx::query!(
        "SELECT entity_id, entity_type FROM guild_whitelist WHERE guild_id = $1",
        guild_id
    )
    .fetch_all(&ctx.data().pool)
    .await?;

    if rec.is_empty() {
        ctx.say("No users or roles are whitelisted for this server").await?;
        return Ok(());
    }

    let mut description = String::new();

    for entry in rec {
        let mention = if entry.entity_type == "role" {
            format!("<@&{}>", entry.entity_id)
        } else {
            format!("<@{}>", entry.entity_id)
        };

        description.push_str(&format!("- {} (``{}``)\n", mention, entry.entity_type));
    }

    let embed = CreateEmbed::default()
        .title("Whitelisted users & roles")
        .description(description)
        .color(0x00ff00);

    ctx.send(CreateReply::default().embed(embed)).await?;

    Ok(())
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Lock the server down during an incident
#[poise::command(prefix_command, slash_command, guild_only, subcommands("lockdown_start", "lockdown_end", "lockdown_status"))]
pub async fn lockdown(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Strip dangerous permissions from roles that are not whitelisted and pause invites
#[poise::command(prefix_command, slash_command, guild_only, rename = "start")]
pub async fn lockdown_start(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer().await?;
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let report = protect::lockdown_start(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id, ctx.author().id, "command").await?;
    ctx.say(format!(
        "Lockdown started. {} role{} restricted{}. Run `/lockdown end` to restore them.",
        report.roles_changed,
        plural(report.roles_changed),
        if report.invites_paused { " and invites paused for 24 hours" } else { "" }
    ))
    .await?;
    Ok(())
}

/// Restore permissions removed by the lockdown and resume invites
#[poise::command(prefix_command, slash_command, guild_only, rename = "end")]
pub async fn lockdown_end(ctx: Context<'_>) -> Result<(), Error> {
    ctx.defer().await?;
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let report = protect::lockdown_end(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id, ctx.author().id, "command").await?;
    ctx.say(format!("Lockdown lifted. {} role{} restored.", report.roles_changed, plural(report.roles_changed))).await?;
    Ok(())
}

/// Show whether the server is in lockdown
#[poise::command(prefix_command, slash_command, guild_only, rename = "status")]
pub async fn lockdown_status(ctx: Context<'_>) -> Result<(), Error> {
    let status = protect::lockdown_status(&ctx.data().pool, ctx.guild_id().ok_or("Could not get guild id")?).await?;
    if status.active {
        ctx.say(format!(
            "Lockdown is active: {} role{} restricted, started by <@{}>.",
            status.roles_locked,
            plural(status.roles_locked),
            status.started_by.unwrap_or_default()
        ))
        .await?;
    } else {
        ctx.say("This server is not in lockdown.").await?;
    }
    Ok(())
}

/// Block scam links, malware adverts and mass mentions with Discord AutoMod
#[poise::command(slash_command, guild_only, subcommands("antiscam_setup", "antiscam_status"))]
pub async fn antiscam(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Turn the anti-scam AutoMod rules on or off and tune them
#[poise::command(slash_command, guild_only, rename = "setup")]
pub async fn antiscam_setup(
    ctx: Context<'_>,
    #[description = "Block scam links, fake Nitro and stealer adverts"]
    links: Option<bool>,
    #[description = "Block messages that mention too many users or roles"]
    mentions: Option<bool>,
    #[description = "Mentions allowed in one message before it is blocked (3-50)"]
    mention_limit: Option<i32>,
    #[description = "Seconds to time out someone who posts a scam link (0 to disable)"]
    timeout: Option<i32>,
    #[description = "Block @everyone and @here from members who are not whitelisted"]
    everyone: Option<bool>,
    #[description = "Block invite links to other servers"]
    invites: Option<bool>,
) -> Result<(), Error> {
    ctx.defer().await?;
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let pool = &ctx.data().pool;
    service::update_settings(
        pool,
        guild_id,
        service::SettingsPatch {
            antiscam_links: links,
            antiscam_mentions: mentions,
            antiscam_mention_limit: mention_limit,
            antiscam_timeout_secs: timeout,
            antiscam_everyone: everyone,
            antiscam_invites: invites,
            ..Default::default()
        },
    )
    .await?;
    let status = crate::antiscam::sync(Bot::from_ctx(ctx.serenity_context()), pool, guild_id).await?;
    service::record_audit(pool, guild_id, ctx.author().id, "command", "antiscam_updated", "Updated anti-scam with /antiscam setup").await;
    ctx.say(antiscam_summary(&status)).await?;
    Ok(())
}

/// Check the anti-scam AutoMod rules
#[poise::command(slash_command, guild_only, rename = "status")]
pub async fn antiscam_status(ctx: Context<'_>) -> Result<(), Error> {
    let status = crate::antiscam::status(&ctx.data().pool, ctx.guild_id().ok_or("Could not get guild id")?).await?;
    ctx.say(antiscam_summary(&status)).await?;
    Ok(())
}

fn antiscam_summary(status: &crate::antiscam::AntiscamStatus) -> String {
    let state = |on: bool| if on { "active" } else { "off" };
    let mentions = match &status.mentions_external {
        Some(name) => format!("handled by your existing AutoMod rule \"{}\"", name),
        None => state(status.mentions_rule).to_string(),
    };
    let mut text = format!(
        "**Scam links:** {}\n**Mass mentions:** {}\n**@everyone and invites:** {}",
        state(status.links_rule),
        mentions,
        state(status.pings_rule)
    );
    if status.domains > 0 {
        text.push_str(&format!("\n**Known scam domains:** {}", status.domains));
    }
    if let Some(error) = &status.error {
        text.push_str(&format!(
            "\n\nDiscord rejected part of the setup: {}.",
            error
        ));
    }
    text
}

/// Review and restore members Sentinel quarantined
#[poise::command(prefix_command, slash_command, guild_only, subcommands("quarantine_view", "quarantine_restore"))]
pub async fn quarantine(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// List members currently in quarantine
#[poise::command(prefix_command, slash_command, guild_only, rename = "view")]
pub async fn quarantine_view(ctx: Context<'_>) -> Result<(), Error> {
    let rows: Vec<(String, String, Vec<String>, sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>)> = sqlx::query_as(
        "SELECT id, user_id, roles, created_at FROM quarantines WHERE guild_id = $1 AND restored_at IS NULL ORDER BY created_at DESC LIMIT 20",
    )
    .bind(ctx.guild_id().ok_or("Could not get guild id")?.to_string())
    .fetch_all(&ctx.data().pool)
    .await?;

    if rows.is_empty() {
        ctx.say("Nobody is in quarantine.").await?;
        return Ok(());
    }

    let description = rows
        .iter()
        .map(|(id, user, roles, at)| format!("- <@{}>: {} role{} held, <t:{}:R> `{}`", user, roles.len(), plural(roles.len()), at.timestamp(), id))
        .collect::<Vec<_>>()
        .join("\n");

    ctx.send(CreateReply::default().embed(CreateEmbed::default().title("Quarantined members").description(description).color(0xf0ae5b)))
        .await?;
    Ok(())
}

/// Give a quarantined member their roles back
#[poise::command(prefix_command, slash_command, guild_only, rename = "restore")]
pub async fn quarantine_restore(
    ctx: Context<'_>,
    #[description = "The quarantine to restore"]
    #[autocomplete = "crate::autocompletes::quarantine_autocomplete"]
    quarantine_id: String,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let restored = protect::restore_quarantine(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id, &quarantine_id, ctx.author().id).await?;
    service::record_audit(
        &ctx.data().pool,
        guild_id,
        ctx.author().id,
        "command",
        "quarantine_restored",
        &format!("Restored {} role{} from quarantine {}", restored, plural(restored), quarantine_id),
    )
    .await;
    ctx.say(format!("Restored {} role{}.", restored, plural(restored))).await?;
    Ok(())
}

#[derive(poise::ChoiceParameter)]
pub enum ScopeChoice {
    #[name = "Per moderator"]
    Moderator,
    #[name = "All moderators combined"]
    Server,
}

impl ScopeChoice {
    fn resolve(self) -> service::LimitScope {
        match self {
            Self::Moderator => service::LimitScope::Moderator,
            Self::Server => service::LimitScope::Server,
        }
    }
}

#[derive(poise::ChoiceParameter)]
pub enum PresetChoice {
    #[name = "Small community"]
    Small,
    #[name = "Large server"]
    Large,
    #[name = "Strict"]
    Strict,
}

/// Add a recommended set of limits
#[poise::command(prefix_command, slash_command, guild_only, rename = "preset")]
pub async fn limits_preset(
    ctx: Context<'_>,
    #[description = "Which baseline to add; limits with the same name are skipped"] preset: PresetChoice,
) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let key = match preset {
        PresetChoice::Small => "small",
        PresetChoice::Large => "large",
        PresetChoice::Strict => "strict",
    };
    let (created, skipped) = crate::presets::apply(&ctx.data().pool, guild_id, key).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "preset_applied", &format!("Applied the {} preset: {} limits added", key, created)).await;
    ctx.say(format!(
        "Added {} limit{}{}. Review them with `/limits view`.",
        created,
        plural(created),
        if skipped > 0 { format!(", skipped {} that already existed", skipped) } else { String::new() }
    ))
    .await?;
    Ok(())
}

/// Back up and restore roles and channels
#[poise::command(prefix_command, slash_command, guild_only, subcommands("snapshot_take", "snapshot_list", "snapshot_restore"))]
pub async fn snapshot(_ctx: Context<'_>) -> Result<(), Error> {
    Ok(())
}

/// Take a snapshot of roles, permissions and channels now
#[poise::command(prefix_command, slash_command, guild_only, rename = "take")]
pub async fn snapshot_take(ctx: Context<'_>) -> Result<(), Error> {
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    crate::recovery::take(Bot::from_ctx(ctx.serenity_context()), &ctx.data().pool, guild_id, "manual", Some(ctx.author().id)).await?;
    service::record_audit(&ctx.data().pool, guild_id, ctx.author().id, "command", "snapshot_taken", "Took a snapshot").await;
    ctx.say("Snapshot saved. Sentinel keeps the last 10.").await?;
    Ok(())
}

/// List saved snapshots
#[poise::command(prefix_command, slash_command, guild_only, rename = "list")]
pub async fn snapshot_list(ctx: Context<'_>) -> Result<(), Error> {
    let snapshots = crate::recovery::list(&ctx.data().pool, ctx.guild_id().ok_or("Could not get guild id")?).await?;
    if snapshots.is_empty() {
        ctx.say("No snapshots yet. Run `/snapshot take` to save one.").await?;
        return Ok(());
    }
    let description = snapshots
        .iter()
        .map(|s| {
            let at = sqlx::types::chrono::DateTime::parse_from_rfc3339(&s.created_at).map(|t| t.timestamp()).unwrap_or_default();
            format!("- <t:{}:R> {}: {} roles, {} channels `{}`", at, s.trigger.replace('_', " "), s.role_count, s.channel_count, s.id)
        })
        .collect::<Vec<_>>()
        .join("\n");
    ctx.send(CreateReply::default().embed(CreateEmbed::default().title("Snapshots").description(description).color(0x42c6ef))).await?;
    Ok(())
}

/// Recreate roles and channels deleted since a snapshot
#[poise::command(prefix_command, slash_command, guild_only, rename = "restore")]
pub async fn snapshot_restore(
    ctx: Context<'_>,
    #[description = "The snapshot to restore from"]
    #[autocomplete = "crate::autocompletes::snapshot_autocomplete"]
    snapshot_id: String,
    #[description = "Also reset role permissions to the snapshot (default no)"] reset_permissions: Option<bool>,
) -> Result<(), Error> {
    ctx.defer().await?;
    let guild_id = ctx.guild_id().ok_or("Could not get guild id")?;
    let report = crate::recovery::restore(
        Bot::from_ctx(ctx.serenity_context()),
        &ctx.data().pool,
        guild_id,
        &snapshot_id,
        ctx.author().id,
        "recovery",
        crate::recovery::RestoreOptions { roles: true, channels: true, permissions: reset_permissions.unwrap_or(false) },
    )
    .await?;
    ctx.say(format!(
        "Restore finished: {} role{} and {} channel{} recreated, {} permission reset{}.{}",
        report.roles_created,
        plural(report.roles_created),
        report.channels_created,
        plural(report.channels_created),
        report.roles_reset,
        plural(report.roles_reset),
        if report.failures.is_empty() { String::new() } else { format!(" {} item{} failed; see the dashboard audit log.", report.failures.len(), plural(report.failures.len())) }
    ))
    .await?;
    Ok(())
}
