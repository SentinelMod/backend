use poise::serenity_prelude::{ChannelId, CreateEmbed, CreateEmbedFooter, CreateMessage, GuildId};
use serenity::all::Context;

use crate::protect::Bot;
use crate::Data;

fn retention_days() -> i64 {
    std::env::var("ACTION_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|days| *days >= 7)
        .unwrap_or(90)
}

pub async fn snapshots(ctx: &Context) -> Result<(), crate::Error> {
    let data = ctx.data::<Data>();
    crate::recovery::take_scheduled(Bot::from_ctx(ctx), &data.pool).await;
    Ok(())
}

pub async fn antiscam(ctx: &Context) -> Result<(), crate::Error> {
    let data = ctx.data::<Data>();
    crate::antiscam::resync_all(Bot::from_ctx(ctx), &data.pool).await;
    Ok(())
}

pub async fn omniplex_stats(ctx: &Context) -> Result<(), crate::Error> {
    crate::omniplex::post_stats(&ctx.cache).await;
    Ok(())
}

pub async fn retention(ctx: &Context) -> Result<(), crate::Error> {
    let data = ctx.data::<Data>();
    let result = sqlx::query(
        "DELETE FROM user_actions a
         WHERE a.created_at < NOW() - make_interval(days => $1::int)
           AND NOT EXISTS (SELECT 1 FROM past_hit_limits p WHERE p.guild_id = a.guild_id AND a.action_id = ANY(p.cause))",
    )
    .bind(retention_days() as i32)
    .execute(&data.pool)
    .await?;

    if result.rows_affected() > 0 {
        log::info!("Pruned {} action(s) older than {} days", result.rows_affected(), retention_days());
    }
    Ok(())
}

type DigestRow = (String, Option<String>, i32);
type DigestTotals = (i64, i64, i64, i64, i64);

pub async fn digest(ctx: &Context) -> Result<(), crate::Error> {
    let data = ctx.data::<Data>();
    let pool = &data.pool;

    let due: Vec<DigestRow> = sqlx::query_as(
        "SELECT guild_id, logs_channel_id, logs_color FROM guild_settings
         WHERE digest_enabled AND logs_channel_id IS NOT NULL
           AND (digest_last_sent IS NULL OR digest_last_sent < NOW() - INTERVAL '7 days')",
    )
    .fetch_all(pool)
    .await?;

    for (guild_id, channel_id, color) in due {
        let (Ok(gid), Some(Ok(channel))) = (guild_id.parse::<GuildId>(), channel_id.map(|c| c.parse::<ChannelId>())) else { continue };
        let Some(guild_name) = ctx.cache.guild(gid).map(|g| g.name.to_string()) else { continue };

        let totals: DigestTotals = sqlx::query_as(
            "SELECT
                (SELECT COUNT(*) FROM user_actions WHERE guild_id = $1 AND created_at > NOW() - INTERVAL '7 days'),
                (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND NOT dry_run AND created_at > NOW() - INTERVAL '7 days'),
                (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND dry_run AND created_at > NOW() - INTERVAL '7 days'),
                (SELECT COUNT(*) FROM audit_trail WHERE guild_id = $1 AND source = 'guard' AND created_at > NOW() - INTERVAL '7 days'),
                (SELECT COUNT(*) FROM quarantines WHERE guild_id = $1 AND restored_at IS NULL)",
        )
        .bind(&guild_id)
        .fetch_one(pool)
        .await?;

        let top: Vec<(String, i64)> = sqlx::query_as(
            "SELECT user_id, COUNT(*) FROM user_actions WHERE guild_id = $1 AND created_at > NOW() - INTERVAL '7 days'
             GROUP BY user_id ORDER BY COUNT(*) DESC LIMIT 3",
        )
        .bind(&guild_id)
        .fetch_all(pool)
        .await?;

        let (actions, hits, dry, guards, quarantined) = totals;
        let top_text = if top.is_empty() {
            "No moderation activity".to_string()
        } else {
            top.iter().map(|(u, n)| format!("<@{}> · {}", u, n)).collect::<Vec<_>>().join("\n")
        };

        let mut embed = CreateEmbed::new()
            .title("Weekly Sentinel digest")
            .description(format!("[Open the dashboard]({})", crate::protect::dashboard_link(gid, "overview")))
            .field("Actions recorded", actions.to_string(), true)
            .field("Limits hit", hits.to_string(), true)
            .field("Guard interventions", guards.to_string(), true)
            .field("Most active moderators", top_text, false)
            .color(color.clamp(0, 0xFFFFFF) as u32)
            .footer(CreateEmbedFooter::new(guild_name));
        if dry > 0 {
            embed = embed.field("Dry-run hits", format!("{} would have triggered a response", dry), true);
        }
        if quarantined > 0 {
            embed = embed.field("Waiting in quarantine", quarantined.to_string(), true);
        }

        if let Err(e) = channel.send_message(&ctx.http, CreateMessage::new().embed(embed)).await {
            log::warn!("could not send digest to {}: {}", gid, e);
        }

        sqlx::query("UPDATE guild_settings SET digest_last_sent = NOW() WHERE guild_id = $1")
            .bind(&guild_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}
