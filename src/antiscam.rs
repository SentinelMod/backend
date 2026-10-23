use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use poise::serenity_prelude::{ChannelId, GuildId, RoleId};
use serenity::all::RuleId;
use serenity::builder::EditAutoModRule;
use serenity::model::guild::automod::{Action, ActionExecution, EventType, Trigger, TriggerType};
use serenity::small_fixed_array::FixedString;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::protect::Bot;
use crate::service::{self, ServiceResult};

pub const LINK_RULE_NAME: &str = "Sentinel · Scam links";
pub const MENTION_RULE_NAME: &str = "Sentinel · Mass mentions";
const BLOCK_MESSAGE: &str = "Blocked by Sentinel: this looks like a scam, phishing or malware link.";
const MENTION_MESSAGE: &str = "Blocked by Sentinel: too many mentions in one message.";
const DEFAULT_FEED: &str = "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/domain-list.json";
const FEED_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_KEYWORDS: usize = 1000;
const MAX_KEYWORD_LEN: usize = 60;

const PHRASES: &[&str] = &[
    "free nitro",
    "free discord nitro",
    "nitro giveaway",
    "claim your nitro",
    "steam gift 50$",
    "free steam gift",
    "best stealer",
    "best grabber",
    "private stealer",
    "fud stealer",
    "fud crypter",
];

const REGEX_PATTERNS: &[&str] = &[
    r"(?i)\b(?:info)?(?:stealer|grabber|token\s?logger|crypter)s?\b.{0,80}\b(?:passwords?|cookies?|crypto|wallets?|tokens?|discord)\b",
    r"(?i)\b(?:passwords?|cookies?|wallets?|crypto)\b.{0,80}\b(?:info)?(?:stealer|grabber|logger)s?\b",
    r"(?i)\b(?:d[il1!|]sc[o0]r[dcl]|dis[cс]ord|dlscord|discrod|disocrd|dicsord|discorcl)[a-z0-9-]*\.(?:gift|gifts|com|net|org|app|ru|xyz|site|online|shop|pw|link|info|cc|me|store|club|top|live|fun|click)\b",
    r"(?i)\b(?:st[e3]{1,2}a?m|stearn|steaim)c[o0]m{1,2}[uv]n[il1]t[yi][a-z0-9-]*\.(?:com|net|ru|org|xyz|site|online|pw|link|cc|me|top)\b",
    r"(?i)\b(?:free\s+(?:discord\s+)?nitro|nitro\s+for\s+free|claim\s+(?:your\s+)?(?:free\s+)?nitro)\b",
    r"(?i)\b(?:mr\.?\s?beast|elon\s?musk)\b.{0,60}\b(?:giveaway|airdrop|usdt|btc|eth|crypto)\b",
];

const ALLOW_LIST: &[&str] = &[
    "discord.com",
    "discord.gg",
    "discord.gift",
    "discord.media",
    "discord.dev",
    "discord.new",
    "discord.co",
    "discordapp.com",
    "discordapp.net",
    "discordstatus.com",
    "discordcdn.com",
    "discordmerch.com",
    "steamcommunity.com",
    "steampowered.com",
];

static FEED: Lazy<RwLock<Option<(Instant, Vec<String>)>>> = Lazy::new(|| RwLock::new(None));

fn feed_url() -> String {
    std::env::var("ANTISCAM_FEED_URL").ok().filter(|u| !u.trim().is_empty()).unwrap_or_else(|| DEFAULT_FEED.to_string())
}

fn parse_feed(body: &str) -> Vec<String> {
    let from_json = serde_json::from_str::<serde_json::Value>(body).ok().and_then(|value| {
        let list = value.get("domains").cloned().unwrap_or(value);
        list.as_array().map(|items| items.iter().filter_map(|d| d.as_str().map(str::to_string)).collect::<Vec<_>>())
    });
    from_json
        .unwrap_or_else(|| body.lines().map(str::to_string).collect())
        .into_iter()
        .map(|d| d.trim().trim_start_matches("*.").to_lowercase())
        .filter(|d| !d.is_empty() && !d.starts_with('#') && d.contains('.'))
        .collect()
}

pub async fn scam_domains() -> Vec<String> {
    if let Some((at, domains)) = FEED.read().await.as_ref() {
        if at.elapsed() < FEED_TTL {
            return domains.clone();
        }
    }

    let fetched = async {
        let response = reqwest::Client::new().get(feed_url()).timeout(Duration::from_secs(15)).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        Some(parse_feed(&response.text().await.ok()?))
    }
    .await;

    let mut cache = FEED.write().await;
    match fetched {
        Some(domains) if !domains.is_empty() => {
            *cache = Some((Instant::now(), domains.clone()));
            domains
        }
        _ => {
            log::warn!("anti-scam domain feed unavailable; keeping previous list");
            cache.as_ref().map(|(_, d)| d.clone()).unwrap_or_default()
        }
    }
}

fn keywords(domains: &[String]) -> Vec<String> {
    let mut words: Vec<String> = PHRASES.iter().map(|p| p.to_string()).collect();
    for domain in domains {
        if words.len() >= MAX_KEYWORDS {
            break;
        }
        let word = format!("*{}*", domain);
        if word.len() <= MAX_KEYWORD_LEN && !ALLOW_LIST.iter().any(|a| domain == a || domain.ends_with(&format!(".{}", a))) {
            words.push(word);
        }
    }
    words
}

#[derive(serde::Serialize)]
pub struct AntiscamStatus {
    pub links_rule: bool,
    pub mentions_rule: bool,
    pub synced_at: Option<String>,
    pub error: Option<String>,
    pub domains: usize,
}

type StatusRow = (Option<String>, Option<String>, Option<sqlx::types::chrono::DateTime<sqlx::types::chrono::Utc>>, Option<String>);

pub async fn status(pool: &PgPool, guild_id: GuildId) -> ServiceResult<AntiscamStatus> {
    let row: Option<StatusRow> = sqlx::query_as(
        "SELECT antiscam_link_rule_id, antiscam_mention_rule_id, antiscam_synced_at, antiscam_error FROM guild_settings WHERE guild_id = $1",
    )
    .bind(guild_id.to_string())
    .fetch_optional(pool)
    .await?;
    let (link, mention, synced_at, error) = row.unwrap_or((None, None, None, None));
    let domains = FEED.read().await.as_ref().map_or(0, |(_, d)| d.len());
    Ok(AntiscamStatus {
        links_rule: link.is_some(),
        mentions_rule: mention.is_some(),
        synced_at: synced_at.map(|t| t.to_rfc3339()),
        error,
        domains,
    })
}

async fn whitelisted_roles(pool: &PgPool, guild_id: GuildId) -> ServiceResult<Vec<RoleId>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT entity_id FROM guild_whitelist WHERE guild_id = $1 AND entity_type = 'role' LIMIT 20")
        .bind(guild_id.to_string())
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().filter_map(|(id,)| id.parse().ok()).collect())
}

async fn upsert(bot: Bot<'_>, guild_id: GuildId, existing: Option<RuleId>, builder: EditAutoModRule<'_>) -> Result<RuleId, String> {
    if let Some(rule_id) = existing {
        match guild_id.edit_automod_rule(bot.http, rule_id, builder.clone()).await {
            Ok(rule) => return Ok(rule.id),
            Err(e) if !e.to_string().contains("Unknown") => return Err(e.to_string()),
            Err(_) => {}
        }
    }
    guild_id.create_automod_rule(bot.http, builder).await.map(|rule| rule.id).map_err(|e| e.to_string())
}

async fn remove(bot: Bot<'_>, guild_id: GuildId, existing: Option<RuleId>) {
    if let Some(rule_id) = existing {
        if let Err(e) = guild_id.delete_automod_rule(bot.http, rule_id, Some("Sentinel: anti-scam rule turned off")).await {
            log::warn!("could not delete anti-scam rule in {}: {}", guild_id, e);
        }
    }
}

fn parse_rule(id: Option<String>) -> Option<RuleId> {
    id.and_then(|id| id.parse().ok())
}

pub async fn sync(bot: Bot<'_>, pool: &PgPool, guild_id: GuildId) -> ServiceResult<AntiscamStatus> {
    let settings = service::settings(pool, guild_id).await?;
    let (link_id, mention_id): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT antiscam_link_rule_id, antiscam_mention_rule_id FROM guild_settings WHERE guild_id = $1")
            .bind(guild_id.to_string())
            .fetch_optional(pool)
            .await?
            .unwrap_or((None, None));

    let exempt = whitelisted_roles(pool, guild_id).await?;
    let alert = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<ChannelId>().ok());
    let mut errors: Vec<String> = vec![];

    let link_rule = if settings.antiscam_links {
        let domains = scam_domains().await;
        let mut actions = vec![Action::BlockMessage { custom_message: Some(FixedString::from_static_trunc(BLOCK_MESSAGE)) }];
        if let Some(channel) = alert {
            actions.push(Action::Alert(channel));
        }
        if settings.antiscam_timeout_secs > 0 {
            actions.push(Action::Timeout(Duration::from_secs(settings.antiscam_timeout_secs as u64)));
        }
        let builder = EditAutoModRule::new()
            .name(LINK_RULE_NAME)
            .event_type(EventType::MessageSend)
            .trigger(Trigger::Keyword {
                strings: keywords(&domains),
                regex_patterns: REGEX_PATTERNS.iter().map(|p| p.to_string()).collect(),
                allow_list: ALLOW_LIST.iter().map(|a| a.to_string()).collect(),
            })
            .actions(actions)
            .exempt_roles(exempt.clone())
            .enabled(true)
            .audit_log_reason("Sentinel: anti-scam link rule");
        match upsert(bot, guild_id, parse_rule(link_id.clone()), builder).await {
            Ok(id) => Some(id.to_string()),
            Err(e) => {
                errors.push(format!("Scam links: {}", e));
                link_id
            }
        }
    } else {
        remove(bot, guild_id, parse_rule(link_id)).await;
        None
    };

    let mention_rule = if settings.antiscam_mentions {
        let mut actions = vec![Action::BlockMessage { custom_message: Some(FixedString::from_static_trunc(MENTION_MESSAGE)) }];
        if let Some(channel) = alert {
            actions.push(Action::Alert(channel));
        }
        let builder = EditAutoModRule::new()
            .name(MENTION_RULE_NAME)
            .event_type(EventType::MessageSend)
            .trigger(Trigger::MentionSpam { mention_total_limit: settings.antiscam_mention_limit.clamp(1, 50) as u8 })
            .actions(actions)
            .exempt_roles(exempt)
            .enabled(true)
            .audit_log_reason("Sentinel: anti-scam mention rule");
        match upsert(bot, guild_id, parse_rule(mention_id.clone()), builder).await {
            Ok(id) => Some(id.to_string()),
            Err(e) => {
                errors.push(format!("Mass mentions: {}", e));
                mention_id
            }
        }
    } else {
        remove(bot, guild_id, parse_rule(mention_id)).await;
        None
    };

    let error = (!errors.is_empty()).then(|| errors.join(" · "));
    sqlx::query(
        "UPDATE guild_settings SET antiscam_link_rule_id = $2, antiscam_mention_rule_id = $3, antiscam_synced_at = NOW(), antiscam_error = $4
         WHERE guild_id = $1",
    )
    .bind(guild_id.to_string())
    .bind(&link_rule)
    .bind(&mention_rule)
    .bind(&error)
    .execute(pool)
    .await?;

    if let Some(e) = &error {
        log::warn!("anti-scam sync for {} had errors: {}", guild_id, e);
    }
    status(pool, guild_id).await
}

pub async fn is_sentinel_rule(pool: &PgPool, guild_id: GuildId, rule_id: RuleId) -> bool {
    let id = rule_id.to_string();
    sqlx::query_as::<_, (bool,)>(
        "SELECT EXISTS (SELECT 1 FROM guild_settings WHERE guild_id = $1 AND (antiscam_link_rule_id = $2 OR antiscam_mention_rule_id = $2))",
    )
    .bind(guild_id.to_string())
    .bind(id)
    .fetch_one(pool)
    .await
    .map(|(found,)| found)
    .unwrap_or(false)
}

pub async fn record_execution(pool: &PgPool, execution: &ActionExecution) {
    if !matches!(execution.action, Action::BlockMessage { .. }) || !is_sentinel_rule(pool, execution.guild_id, execution.rule_id).await {
        return;
    }
    let rule = if execution.trigger_type == TriggerType::MentionSpam { "mass mention" } else { "scam link" };
    let channel = execution.channel_id.map(|c| format!(" in <#{}>", c)).unwrap_or_default();
    let matched = execution.matched_keyword.as_deref().map(|k| format!(" (matched `{}`)", k.replace('`', "'"))).unwrap_or_default();
    let detail = format!("Blocked a {} message from <@{}>{}{}", rule, execution.user_id, channel, matched);
    service::record_audit(pool, execution.guild_id, execution.user_id, "antiscam", "message_blocked", &detail).await;
}

pub async fn resync_all(bot: Bot<'_>, pool: &PgPool) {
    let rows: Vec<(String,)> = match sqlx::query_as("SELECT guild_id FROM guild_settings WHERE antiscam_links OR antiscam_mentions").fetch_all(pool).await {
        Ok(rows) => rows,
        Err(e) => {
            log::error!("could not list anti-scam guilds: {}", e);
            return;
        }
    };
    for (guild_id,) in rows {
        let Ok(guild_id) = guild_id.parse::<GuildId>() else { continue };
        if bot.cache.guild(guild_id).is_none() {
            continue;
        }
        if let Err(e) = sync(bot, pool, guild_id).await {
            log::warn!("anti-scam resync failed for {}: {}", guild_id, e);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_and_text_feeds() {
        assert_eq!(parse_feed(r#"{"domains":["Bad.com","*.evil.ru",""]}"#), vec!["bad.com", "evil.ru"]);
        assert_eq!(parse_feed("# comment\nscam.gift\n\nnotadomain"), vec!["scam.gift"]);
    }

    #[test]
    fn keywords_respect_limits_and_allow_list() {
        let mut domains: Vec<String> = (0..2000).map(|i| format!("scam{}.gift", i)).collect();
        domains.push("discord.com".into());
        domains.push("a".repeat(70) + ".com");
        let words = keywords(&domains);
        assert!(words.len() <= MAX_KEYWORDS);
        assert!(words.iter().all(|w| w.len() <= MAX_KEYWORD_LEN));
        assert!(!words.iter().any(|w| w.contains("discord.com")));
    }

    #[test]
    fn rule_limits_hold() {
        assert!(REGEX_PATTERNS.len() <= 10);
        assert!(REGEX_PATTERNS.iter().all(|p| p.len() <= 260));
        assert!(ALLOW_LIST.len() <= 100);
        assert!(BLOCK_MESSAGE.len() <= 150 && MENTION_MESSAGE.len() <= 150);
    }
}
