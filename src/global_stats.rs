use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::core::UserLimitTypes;
use crate::server::AppState;

const TTL: Duration = Duration::from_secs(60);

static CACHE: Lazy<Mutex<Option<(Instant, Arc<GlobalStats>)>>> = Lazy::new(|| Mutex::new(None));

#[derive(Serialize)]
struct Totals {
    servers: usize,
    servers_protected: i64,
    members_covered: u64,
    limits: i64,
    actions: i64,
    actions_24h: i64,
    actions_7d: i64,
    hits: i64,
    hits_7d: i64,
    quarantines: i64,
    guard_blocks: i64,
    lockdowns_active: i64,
    scams_blocked: i64,
    scams_blocked_7d: i64,
    antiscam_servers: i64,
}

#[derive(Serialize)]
struct Breakdown {
    event: String,
    label: String,
    count: i64,
}

#[derive(Serialize)]
struct Day {
    date: String,
    actions: i64,
    hits: i64,
}

#[derive(Serialize)]
pub struct GlobalStats {
    generated_at: String,
    totals: Totals,
    events_30d: Vec<Breakdown>,
    responses_30d: Vec<Breakdown>,
    activity_30d: Vec<Day>,
}

async fn compute(app: &AppState) -> Result<GlobalStats, sqlx::Error> {
    let pool = &app.pool;
    let cache = &app.cache_http.cache;

    let guild_ids = cache.guilds();
    let members_covered: u64 = guild_ids.iter().filter_map(|id| cache.guild(*id).map(|g| g.member_count)).sum();

    let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM guilds),
            (SELECT COUNT(*) FROM limits),
            (SELECT COUNT(*) FROM user_actions),
            (SELECT COUNT(*) FROM user_actions WHERE created_at > NOW() - INTERVAL '1 day'),
            (SELECT COUNT(*) FROM user_actions WHERE created_at > NOW() - INTERVAL '7 days'),
            (SELECT COUNT(*) FROM past_hit_limits),
            (SELECT COUNT(*) FROM past_hit_limits WHERE created_at > NOW() - INTERVAL '7 days'),
            (SELECT COUNT(*) FROM quarantines),
            (SELECT COUNT(*) FROM audit_trail WHERE source = 'guard'),
            (SELECT COUNT(*) FROM lockdowns)",
    )
    .fetch_one(pool)
    .await?;

    let scams: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM audit_trail WHERE source = 'antiscam'),
            (SELECT COUNT(*) FROM audit_trail WHERE source = 'antiscam' AND created_at > NOW() - INTERVAL '7 days'),
            (SELECT COUNT(*) FROM guild_settings WHERE antiscam_links OR antiscam_mentions)",
    )
    .fetch_one(pool)
    .await?;

    let events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT limit_type, COUNT(*) FROM user_actions WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY limit_type ORDER BY COUNT(*) DESC",
    )
    .fetch_all(pool)
    .await?;

    let responses: Vec<(String, i64)> = sqlx::query_as(
        "SELECT l.limit_action, COUNT(*) FROM past_hit_limits p JOIN limits l ON l.limit_id = p.limit_id
         WHERE p.created_at > NOW() - INTERVAL '30 days' AND (p.action_taken IS NULL OR p.action_taken NOT LIKE 'Covered by%')
         GROUP BY l.limit_action ORDER BY COUNT(*) DESC",
    )
    .fetch_all(pool)
    .await?;

    let activity: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT to_char(day, 'YYYY-MM-DD'),
            (SELECT COUNT(*) FROM user_actions WHERE created_at >= day AND created_at < day + INTERVAL '1 day'),
            (SELECT COUNT(*) FROM past_hit_limits WHERE created_at >= day AND created_at < day + INTERVAL '1 day')
         FROM generate_series(date_trunc('day', NOW()) - INTERVAL '29 days', date_trunc('day', NOW()), INTERVAL '1 day') AS day",
    )
    .fetch_all(pool)
    .await?;

    let event_label = |raw: &str| raw.parse::<UserLimitTypes>().map(|t| t.to_cond()).unwrap_or_else(|_| raw.to_string());
    let action_label =
        |raw: &str| raw.parse::<crate::core::UserLimitActions>().map(|a| a.to_cond()).unwrap_or_else(|_| raw.to_string());

    Ok(GlobalStats {
        generated_at: sqlx::types::chrono::Utc::now().to_rfc3339(),
        totals: Totals {
            servers: guild_ids.len(),
            servers_protected: counts.0,
            members_covered,
            limits: counts.1,
            actions: counts.2,
            actions_24h: counts.3,
            actions_7d: counts.4,
            hits: counts.5,
            hits_7d: counts.6,
            quarantines: counts.7,
            guard_blocks: counts.8,
            lockdowns_active: counts.9,
            scams_blocked: scams.0,
            scams_blocked_7d: scams.1,
            antiscam_servers: scams.2,
        },
        events_30d: events.into_iter().map(|(event, count)| Breakdown { label: event_label(&event), event, count }).collect(),
        responses_30d: responses.into_iter().map(|(event, count)| Breakdown { label: action_label(&event), event, count }).collect(),
        activity_30d: activity.into_iter().map(|(date, actions, hits)| Day { date, actions, hits }).collect(),
    })
}

pub async fn global(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let mut cached = CACHE.lock().await;
    if let Some((at, stats)) = cached.as_ref() {
        if at.elapsed() < TTL {
            return Ok(Json(stats.clone()));
        }
    }

    match compute(&app).await {
        Ok(stats) => {
            let stats = Arc::new(stats);
            *cached = Some((Instant::now(), stats.clone()));
            Ok(Json(stats))
        }
        Err(e) => {
            log::error!("global stats failed: {}", e);
            match cached.as_ref() {
                Some((_, stale)) => Ok(Json(stale.clone())),
                None => Err((StatusCode::SERVICE_UNAVAILABLE, "Stats are unavailable right now")),
            }
        }
    }
}
