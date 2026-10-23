use log::{info, warn};
use poise::serenity_prelude::{CreateEmbed, CreateMessage, GuildId, UserId};
use sqlx::PgPool;

use crate::core::{self, UserLimitActions};
use crate::protect::{self, Bot};
use crate::{service, Error};

struct Hit {
    id: String,
    limit_id: String,
    name: String,
    action: UserLimitActions,
    per: i32,
    window_secs: i64,
    timeout_secs: Option<i64>,
    server_wide: bool,
    dry_run: bool,
    causes: Vec<String>,
}

type HitRow = (String, String, String, i32, i64, Option<i64>, String, bool, Vec<String>);

async fn limits_hit(pool: &PgPool, guild_id: GuildId, user_id: UserId, action: &core::UserLimitTypes) -> Result<Vec<Hit>, Error> {
    let rows: Vec<HitRow> = sqlx::query_as(
        "SELECT l.limit_id, l.limit_name, l.limit_action, l.limit_per,
                EXTRACT(EPOCH FROM l.limit_time)::BIGINT,
                EXTRACT(EPOCH FROM l.limit_timeout_duration)::BIGINT,
                l.limit_scope, l.dry_run,
                ARRAY(
                    SELECT a.action_id FROM user_actions a
                    WHERE a.guild_id = l.guild_id
                      AND (l.limit_scope = 'server' OR a.user_id = $2)
                      AND a.limit_type = l.limit_type
                      AND NOW() - a.created_at < l.limit_time
                      AND NOT (l.limit_id = ANY(a.limits_hit))
                )
         FROM limits l
         WHERE l.guild_id = $1 AND l.limit_type = $3",
    )
    .bind(guild_id.to_string())
    .bind(user_id.to_string())
    .bind(action.to_string())
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter(|row| row.8.len() >= row.3.max(1) as usize)
        .filter_map(|(limit_id, name, action, per, window_secs, timeout_secs, scope, dry_run, causes)| {
            Some(Hit {
                id: botox::crypto::gen_random(16),
                action: action.parse().ok()?,
                server_wide: scope == "server",
                limit_id,
                name,
                per,
                window_secs,
                timeout_secs,
                dry_run,
                causes,
            })
        })
        .collect())
}

fn can_moderate(ctx: &serenity::all::Context, guild_id: GuildId, user_id: UserId) -> bool {
    let me = ctx.cache.current_user().id;
    ctx.cache
        .guild(guild_id)
        .and_then(|guild| guild.greater_member_hierarchy(me, user_id))
        .map_or(false, |winner| winner == me)
}

async fn record_hits(pool: &PgPool, guild_id: GuildId, user_id: UserId, hits: &[&Hit], taken: impl Fn(&Hit) -> Option<String>, notes: &[String]) -> Result<(), Error> {
    let mut tx = pool.begin().await?;
    for hit in hits {
        sqlx::query("UPDATE user_actions SET limits_hit = array_append(limits_hit, $1) WHERE action_id = ANY($2)")
            .bind(&hit.limit_id)
            .bind(&hit.causes)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT INTO past_hit_limits (id, guild_id, user_id, limit_id, cause, notes, action_taken, dry_run)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&hit.id)
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .bind(&hit.limit_id)
        .bind(&hit.causes)
        .bind(notes)
        .bind(taken(hit))
        .bind(hit.dry_run)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

fn describe(hit: &Hit, action: &core::UserLimitTypes) -> String {
    format!(
        "{} {} within {}{}",
        hit.per,
        action.to_cond().to_lowercase(),
        crate::utils::format_duration(hit.window_secs),
        if hit.server_wide { " across all moderators" } else { "" }
    )
}

pub async fn handle_mod_action(
    guild_id: GuildId,
    user_id: UserId,
    pool: &PgPool,
    ctx: &serenity::all::Context,
    action: core::UserLimitTypes,
    action_target: String,
) -> Result<(), Error> {
    let member_roles = guild_id
        .member(&ctx, user_id)
        .await
        .map(|member| member.roles.to_vec())
        .unwrap_or_default();

    if core::is_whitelisted(pool, guild_id, user_id, &member_roles).await? {
        return Ok(());
    }

    if !service::is_setup(pool, guild_id).await? {
        return Ok(());
    }

    sqlx::query("INSERT INTO user_actions (action_id, guild_id, user_id, limit_type, action_target) VALUES ($1, $2, $3, $4, $5)")
        .bind(botox::crypto::gen_random(48))
        .bind(guild_id.to_string())
        .bind(user_id.to_string())
        .bind(action.to_string())
        .bind(&action_target)
        .execute(pool)
        .await?;

    let settings = service::settings(pool, guild_id).await.unwrap_or_default();
    let bot = Bot::from_ctx(ctx);
    let hits = limits_hit(pool, guild_id, user_id, &action).await?;

    let dry: Vec<&Hit> = hits.iter().filter(|h| h.dry_run).collect();
    if !dry.is_empty() {
        record_hits(pool, guild_id, user_id, &dry, |h| Some(format!("Dry run: would have used {}", h.action.to_cond())), &[]).await?;
        for hit in &dry {
            let body = format!(
                "<@{}> reached **{}**: {}.\n**Would have used:** {}. Nothing was done because this limit is in dry-run mode.",
                user_id,
                hit.name,
                describe(hit, &action),
                hit.action.to_cond()
            );
            protect::notice(bot, &settings, guild_id, &format!("Dry run: {}", hit.name), &body, "hits").await;
        }
    }

    let live: Vec<&Hit> = hits.iter().filter(|h| !h.dry_run).collect();
    if let Some(top) = live.iter().copied().max_by_key(|hit| hit.action.severity()) {
        info!("Limit {} reached by {} in {}", top.name, user_id, guild_id);

        let permitted = top.action == UserLimitActions::NotifyOnly || can_moderate(ctx, guild_id, user_id);
        let notes: Vec<String> = if permitted { vec![] } else { vec!["Sentinel's role is not above this member".to_string()] };
        let top_id = top.id.clone();
        let top_name = top.name.clone();
        record_hits(pool, guild_id, user_id, &live, |h| (h.id != top_id).then(|| format!("Covered by {}", top_name)), &notes).await?;

        let outcome = if permitted {
            protect::respond(bot, pool, guild_id, user_id, &top.action, top.timeout_secs, &top.id).await
        } else {
            warn!("Cannot moderate {} in {}: role hierarchy", user_id, guild_id);
            "Skipped: Sentinel's role is not above this member".to_string()
        };

        sqlx::query("UPDATE past_hit_limits SET action_taken = $2 WHERE id = $1")
            .bind(&top.id)
            .bind(&outcome)
            .execute(pool)
            .await?;

        let body = format!("<@{}> reached **{}**: {}.\n**Response:** {}", user_id, top.name, describe(top, &action), outcome);
        protect::alert(bot, &settings, guild_id, &format!("Limit reached: {}", top.name), &body, "hits").await;
        protect::maybe_auto_lockdown(bot, pool, guild_id).await;
    }

    if settings.logs_enabled {
        if let Some(channel_id) = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<serenity::all::ChannelId>().ok()) {
            let embed = CreateEmbed::default()
                .title("Moderation audit event")
                .description(format!("**{}** by <@{}> on `{}`", action.to_cond(), user_id, action_target))
                .color(settings.logs_color.clamp(0, 0xFFFFFF) as u32);

            if let Err(error) = channel_id.send_message(ctx, CreateMessage::new().embed(embed)).await {
                warn!("Could not send audit log message: {}", error);
            }
        }
    }

    Ok(())
}
