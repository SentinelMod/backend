use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use once_cell::sync::Lazy;
use poise::serenity_prelude::{ChannelId, GuildId, RoleId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::types::chrono::{DateTime, Utc};

use crate::core::{UserLimitActions, UserLimitTypes};
use crate::protect::{self, Bot};
use crate::server::AppState;
use crate::service::{self, GuildSettings, ServiceError};

static SECRET: Lazy<Option<String>> = Lazy::new(|| {
    std::env::var("DASHBOARD_API_SECRET")
        .ok()
        .filter(|secret| !secret.trim().is_empty())
});

const MAX_PAGE: i64 = 100;

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn db_error(e: sqlx::Error) -> ApiError {
    log::error!("dashboard query failed: {}", e);
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorize(headers: &HeaderMap) -> Result<UserId, ApiError> {
    let Some(secret) = SECRET.as_deref() else {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "Dashboard API is not configured".into()));
    };

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    if !constant_time_eq(provided.as_bytes(), secret.as_bytes()) {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Invalid dashboard credentials".into()));
    }

    headers
        .get("x-sentinel-user")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<UserId>().ok())
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "Missing user".into()))
}

async fn authorize_guild(app: &AppState, headers: &HeaderMap, gid: GuildId) -> Result<UserId, ApiError> {
    let user_id = authorize(headers)?;

    if app.cache_http.cache.guild(gid).is_none() {
        return Err(ApiError(StatusCode::NOT_FOUND, "Sentinel is not in this server".into()));
    }

    crate::utils::is_guild_admin(&app.cache_http, &app.pool, gid, user_id.to_string())
        .await
        .map_err(|_| ApiError(StatusCode::FORBIDDEN, "You are not a Sentinel admin in this server".into()))?;

    Ok(user_id)
}

fn is_owner(app: &AppState, gid: GuildId, user_id: UserId) -> bool {
    app.cache_http.cache.guild(gid).map_or(false, |g| g.owner_id == user_id)
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        let status = match e {
            ServiceError::Invalid(_) => StatusCode::BAD_REQUEST,
            ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
            ServiceError::Db => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(status, e.to_string())
    }
}

fn limit_type_label(raw: &str) -> String {
    raw.parse::<UserLimitTypes>().map(|t| t.to_cond()).unwrap_or_else(|_| raw.to_string())
}

fn limit_action_label(raw: &str) -> String {
    raw.parse::<UserLimitActions>().map(|a| a.to_cond()).unwrap_or_else(|_| raw.to_string())
}

struct Names<'a>(Option<poise::serenity_prelude::GuildRef<'a>>);

impl Names<'_> {
    fn user(&self, id: &str) -> Option<String> {
        let id = id.parse::<UserId>().ok()?;
        self.0.as_ref()?.members.get(&id).map(|m| m.display_name().to_string())
    }

    fn role(&self, id: &str) -> Option<String> {
        let id = id.parse::<RoleId>().ok()?;
        self.0.as_ref()?.roles.get(&id).map(|r| r.name.to_string())
    }

    fn channel(&self, id: &str) -> Option<String> {
        let id = id.parse::<ChannelId>().ok()?;
        self.0.as_ref()?.channels.get(&id).map(|c| c.name.to_string())
    }

    fn target(&self, limit_type: &str, id: &str) -> Option<String> {
        if limit_type.starts_with("role_") {
            self.role(id).map(|n| format!("@{}", n))
        } else if limit_type.starts_with("channel_") {
            self.channel(id).map(|n| format!("#{}", n))
        } else if matches!(limit_type, "kick" | "ban" | "unban") {
            self.user(id)
        } else {
            None
        }
    }
}

#[derive(Serialize)]
pub struct ManagedGuild {
    id: String,
    name: String,
    icon_url: Option<String>,
    member_count: u64,
    role: &'static str,
}

pub async fn guilds(State(app): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Vec<ManagedGuild>> {
    let user_id = authorize(&headers)?;

    let admin_rows: Vec<(String,)> = sqlx::query_as("SELECT guild_id FROM guild_admins WHERE user_id = $1")
        .bind(user_id.to_string())
        .fetch_all(&app.pool)
        .await
        .map_err(db_error)?;
    let admin_of: HashSet<String> = admin_rows.into_iter().map(|(id,)| id).collect();

    let cache = &app.cache_http.cache;
    let mut result: Vec<ManagedGuild> = cache
        .guilds()
        .into_iter()
        .filter_map(|gid| {
            let guild = cache.guild(gid)?;
            let role = if guild.owner_id == user_id {
                "owner"
            } else if admin_of.contains(&gid.to_string()) {
                "admin"
            } else {
                return None;
            };
            Some(ManagedGuild {
                id: gid.to_string(),
                name: guild.name.to_string(),
                icon_url: guild.icon_url(),
                member_count: guild.member_count,
                role,
            })
        })
        .collect();

    result.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(Json(result))
}

#[derive(Serialize)]
struct GuildInfo {
    id: String,
    name: String,
    icon_url: Option<String>,
    member_count: u64,
    owner_id: String,
}

#[derive(Serialize)]
struct Settings {
    #[serde(flatten)]
    stored: GuildSettings,
    logs_channel_name: Option<String>,
    alert_role_name: Option<String>,
}

#[derive(Serialize)]
struct Viewer {
    id: String,
    is_owner: bool,
}

#[derive(Serialize)]
struct LimitView {
    id: String,
    name: String,
    event: String,
    event_label: String,
    action: String,
    action_label: String,
    per: i32,
    window_seconds: i64,
    timeout_seconds: Option<i64>,
    scope: String,
    dry_run: bool,
    times_hit: i64,
}

#[derive(Serialize)]
struct Entity {
    id: String,
    kind: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct Totals {
    actions: i64,
    actions_7d: i64,
    hits: i64,
    hits_7d: i64,
}

#[derive(Serialize)]
struct Day {
    date: String,
    actions: i64,
    hits: i64,
}

#[derive(Serialize)]
pub struct Overview {
    setup: bool,
    viewer: Viewer,
    lockdown: protect::LockdownStatus,
    quarantined: i64,
    guild: GuildInfo,
    settings: Settings,
    limits: Vec<LimitView>,
    whitelist: Vec<Entity>,
    admins: Vec<Entity>,
    totals: Totals,
    activity: Vec<Day>,
}

type LimitRow = (String, String, String, String, i32, i64, Option<i64>, String, bool, i64);

pub async fn overview(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
) -> ApiResult<Overview> {
    let viewer_id = authorize_guild(&app, &headers, gid).await?;
    let pool = &app.pool;
    let g = gid.to_string();

    let setup = service::is_setup(pool, gid).await?;
    let stored = service::settings(pool, gid).await?;
    let lockdown = protect::lockdown_status(pool, gid).await?;
    let (quarantined,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM quarantines WHERE guild_id = $1 AND restored_at IS NULL")
        .bind(&g)
        .fetch_one(pool)
        .await
        .map_err(db_error)?;

    let limits: Vec<LimitRow> = sqlx::query_as(
        "SELECT l.limit_id, l.limit_name, l.limit_type, l.limit_action, l.limit_per,
                EXTRACT(EPOCH FROM l.limit_time)::BIGINT,
                EXTRACT(EPOCH FROM l.limit_timeout_duration)::BIGINT,
                l.limit_scope, l.dry_run,
                (SELECT COUNT(*) FROM past_hit_limits p WHERE p.limit_id = l.limit_id)
         FROM limits l WHERE l.guild_id = $1 ORDER BY l.limit_name",
    )
    .bind(&g)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let whitelist: Vec<(String, String)> =
        sqlx::query_as("SELECT entity_id, entity_type FROM guild_whitelist WHERE guild_id = $1")
            .bind(&g)
            .fetch_all(pool)
            .await
            .map_err(db_error)?;

    let admins: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT user_id FROM guild_admins WHERE guild_id = $1")
        .bind(&g)
        .fetch_all(pool)
        .await
        .map_err(db_error)?;

    let totals: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM user_actions WHERE guild_id = $1),
            (SELECT COUNT(*) FROM user_actions WHERE guild_id = $1 AND created_at > NOW() - INTERVAL '7 days'),
            (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND NOT dry_run),
            (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND NOT dry_run AND created_at > NOW() - INTERVAL '7 days')",
    )
    .bind(&g)
    .fetch_one(pool)
    .await
    .map_err(db_error)?;

    let activity: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT to_char(day, 'YYYY-MM-DD'),
            (SELECT COUNT(*) FROM user_actions
              WHERE guild_id = $1 AND created_at >= day AND created_at < day + INTERVAL '1 day'),
            (SELECT COUNT(*) FROM past_hit_limits
              WHERE guild_id = $1 AND NOT dry_run AND created_at >= day AND created_at < day + INTERVAL '1 day')
         FROM generate_series(date_trunc('day', NOW()) - INTERVAL '13 days', date_trunc('day', NOW()), INTERVAL '1 day') AS day",
    )
    .bind(&g)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    let guild = names.0.as_ref().ok_or(ApiError(StatusCode::NOT_FOUND, "Sentinel is not in this server".into()))?;

    let info = GuildInfo {
        id: g.clone(),
        name: guild.name.to_string(),
        icon_url: guild.icon_url(),
        member_count: guild.member_count,
        owner_id: guild.owner_id.to_string(),
    };

    let settings = Settings {
        logs_channel_name: stored.logs_channel_id.as_deref().and_then(|id| names.channel(id)),
        alert_role_name: stored.alert_role_id.as_deref().and_then(|id| names.role(id)),
        stored,
    };
    let viewer = Viewer { id: viewer_id.to_string(), is_owner: guild.owner_id == viewer_id };

    let limits = limits
        .into_iter()
        .map(|(id, name, event, action, per, window_seconds, timeout_seconds, scope, dry_run, times_hit)| LimitView {
            event_label: limit_type_label(&event),
            action_label: limit_action_label(&action),
            id,
            name,
            event,
            action,
            per,
            window_seconds,
            timeout_seconds,
            scope,
            dry_run,
            times_hit,
        })
        .collect();

    let whitelist = whitelist
        .into_iter()
        .map(|(id, kind)| Entity {
            name: if kind == "role" { names.role(&id) } else { names.user(&id) },
            id,
            kind,
        })
        .collect();

    let admins = admins
        .into_iter()
        .map(|(id,)| Entity { name: names.user(&id), id, kind: "user".into() })
        .collect();

    Ok(Json(Overview {
        setup,
        viewer,
        lockdown,
        quarantined,
        guild: info,
        settings,
        limits,
        whitelist,
        admins,
        totals: Totals { actions: totals.0, actions_7d: totals.1, hits: totals.2, hits_7d: totals.3 },
        activity: activity.into_iter().map(|(date, actions, hits)| Day { date, actions, hits }).collect(),
    }))
}

#[derive(Deserialize)]
pub struct ActionQuery {
    limit: Option<i64>,
    before: Option<String>,
    event: Option<String>,
}

#[derive(Serialize)]
struct ActionView {
    id: String,
    event: String,
    event_label: String,
    created_at: String,
    user_id: String,
    user_name: Option<String>,
    target_id: String,
    target_name: Option<String>,
    limits_hit: Vec<String>,
}

#[derive(Serialize)]
pub struct ActionPage {
    actions: Vec<ActionView>,
    next_before: Option<String>,
}

pub async fn actions(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    Query(query): Query<ActionQuery>,
    headers: HeaderMap,
) -> ApiResult<ActionPage> {
    authorize_guild(&app, &headers, gid).await?;
    let page = query.limit.unwrap_or(50).clamp(1, MAX_PAGE);

    let rows: Vec<(String, String, DateTime<Utc>, String, String, Vec<String>)> = sqlx::query_as(
        "SELECT action_id, limit_type, created_at, user_id, action_target, limits_hit
         FROM user_actions
         WHERE guild_id = $1
           AND ($2::text IS NULL OR created_at < $2::text::timestamptz)
           AND ($3::text IS NULL OR limit_type = $3)
         ORDER BY created_at DESC
         LIMIT $4",
    )
    .bind(gid.to_string())
    .bind(query.before.filter(|b| !b.is_empty()))
    .bind(query.event.filter(|e| !e.is_empty()))
    .bind(page)
    .fetch_all(&app.pool)
    .await
    .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "Invalid query".into()))?;

    let limit_names: HashMap<String, String> = sqlx::query_as::<_, (String, String)>(
        "SELECT limit_id, limit_name FROM limits WHERE guild_id = $1",
    )
    .bind(gid.to_string())
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?
    .into_iter()
    .collect();

    let next_before = if rows.len() as i64 == page {
        rows.last().map(|r| r.2.to_rfc3339())
    } else {
        None
    };

    let names = Names(app.cache_http.cache.guild(gid));
    let actions = rows
        .into_iter()
        .map(|(id, event, created_at, user_id, target_id, limits_hit)| ActionView {
            event_label: limit_type_label(&event),
            user_name: names.user(&user_id),
            target_name: names.target(&event, &target_id),
            limits_hit: limits_hit
                .iter()
                .map(|l| limit_names.get(l).cloned().unwrap_or_else(|| "Deleted limit".into()))
                .collect(),
            created_at: created_at.to_rfc3339(),
            id,
            event,
            user_id,
            target_id,
        })
        .collect();

    Ok(Json(ActionPage { actions, next_before }))
}

#[derive(Deserialize)]
pub struct HitQuery {
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct HitView {
    id: String,
    user_id: String,
    user_name: Option<String>,
    limit_id: String,
    limit_name: String,
    action_label: Option<String>,
    action_taken: Option<String>,
    dry_run: bool,
    cause_count: i32,
    notes: Vec<String>,
    created_at: String,
}

pub async fn hits(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    Query(query): Query<HitQuery>,
    headers: HeaderMap,
) -> ApiResult<Vec<HitView>> {
    authorize_guild(&app, &headers, gid).await?;

    let rows: Vec<(String, String, String, String, Option<String>, Option<String>, bool, i32, Vec<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT p.id, p.user_id, p.limit_id, COALESCE(l.limit_name, 'Deleted limit'), l.limit_action, p.action_taken, p.dry_run,
                COALESCE(cardinality(p.cause), 0), p.notes, p.created_at
         FROM past_hit_limits p
         LEFT JOIN limits l ON l.limit_id = p.limit_id
         WHERE p.guild_id = $1
         ORDER BY p.created_at DESC
         LIMIT $2",
    )
    .bind(gid.to_string())
    .bind(query.limit.unwrap_or(50).clamp(1, MAX_PAGE))
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    Ok(Json(
        rows.into_iter()
            .map(|(id, user_id, limit_id, limit_name, action, action_taken, dry_run, cause_count, notes, created_at)| HitView {
                user_name: names.user(&user_id),
                action_label: action.as_deref().map(limit_action_label),
                action_taken,
                dry_run,
                created_at: created_at.to_rfc3339(),
                id,
                user_id,
                limit_id,
                limit_name,
                cause_count,
                notes,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct PresenceBody {
    guild_ids: Vec<String>,
}

pub async fn presence(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PresenceBody>,
) -> ApiResult<Vec<String>> {
    authorize(&headers)?;
    let cache = &app.cache_http.cache;
    Ok(Json(
        body.guild_ids
            .into_iter()
            .take(500)
            .filter(|id| id.parse::<GuildId>().map_or(false, |gid| cache.guild(gid).is_some()))
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct Choice {
    value: String,
    label: String,
}

#[derive(Serialize)]
pub struct Meta {
    events: Vec<Choice>,
    actions: Vec<Choice>,
    limits: serde_json::Value,
}

pub async fn meta(headers: HeaderMap) -> ApiResult<Meta> {
    authorize(&headers)?;
    Ok(Json(Meta {
        events: UserLimitTypes::ALL.iter().map(|t| Choice { value: t.to_string(), label: t.to_cond() }).collect(),
        actions: UserLimitActions::ALL.iter().map(|a| Choice { value: a.to_string(), label: a.to_cond() }).collect(),
        limits: json!({
            "name": service::MAX_LIMIT_NAME,
            "threshold": service::MAX_THRESHOLD,
            "window_seconds": service::MAX_WINDOW_SECS,
            "timeout_min_seconds": service::MIN_TIMEOUT_SECS,
            "timeout_max_seconds": service::MAX_TIMEOUT_SECS,
        }),
    }))
}

#[derive(Serialize)]
pub struct RoleView {
    id: String,
    name: String,
    color: u32,
    position: i16,
    managed: bool,
    dangerous: bool,
}

#[derive(Serialize)]
pub struct ChannelView {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub struct Resources {
    roles: Vec<RoleView>,
    channels: Vec<ChannelView>,
}

pub async fn resources(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Resources> {
    authorize_guild(&app, &headers, gid).await?;
    let guild = app.cache_http.cache.guild(gid).ok_or(ApiError(StatusCode::NOT_FOUND, "Sentinel is not in this server".into()))?;

    let mut roles: Vec<RoleView> = guild
        .roles
        .iter()
        .filter(|r| r.id.get() != gid.get())
        .map(|r| RoleView {
            id: r.id.to_string(),
            name: r.name.to_string(),
            color: r.colour.0,
            position: r.position,
            managed: r.managed(),
            dangerous: !(r.permissions & protect::guarded_permissions()).is_empty(),
        })
        .collect();
    roles.sort_by(|a, b| b.position.cmp(&a.position));

    let mut channels: Vec<(u16, ChannelView)> = guild
        .channels
        .iter()
        .filter(|c| matches!(c.kind, serenity::all::ChannelType::Text | serenity::all::ChannelType::News))
        .map(|c| (c.position, ChannelView { id: c.id.to_string(), name: c.name.to_string() }))
        .collect();
    channels.sort_by_key(|(position, _)| *position);

    Ok(Json(Resources { roles, channels: channels.into_iter().map(|(_, c)| c).collect() }))
}

#[derive(Deserialize)]
pub struct MemberQuery {
    q: String,
}

#[derive(Serialize)]
pub struct MemberView {
    id: String,
    name: String,
    username: String,
    avatar_url: String,
    bot: bool,
}

pub async fn members(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    Query(query): Query<MemberQuery>,
    headers: HeaderMap,
) -> ApiResult<Vec<MemberView>> {
    authorize_guild(&app, &headers, gid).await?;
    let q = query.q.trim();
    if q.is_empty() {
        return Ok(Json(vec![]));
    }

    if let Ok(id) = q.parse::<UserId>() {
        if let Ok(member) = gid.member(&app.cache_http, id).await {
            return Ok(Json(vec![MemberView {
                id: member.user.id.to_string(),
                name: member.display_name().to_string(),
                username: member.user.name.to_string(),
                avatar_url: member.face(),
                bot: member.user.bot(),
            }]));
        }
        return Ok(Json(vec![]));
    }

    let found = gid
        .search_members(&app.cache_http.http, q, nonmax::NonMaxU16::new(10))
        .await
        .map_err(|_| ApiError(StatusCode::BAD_GATEWAY, "Discord member search failed".into()))?;

    Ok(Json(
        found
            .into_iter()
            .map(|m| MemberView {
                id: m.user.id.to_string(),
                name: m.display_name().to_string(),
                username: m.user.name.to_string(),
                avatar_url: m.face(),
                bot: m.user.bot(),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct QuarantineView {
    id: String,
    user_id: String,
    user_name: Option<String>,
    roles: Vec<Entity>,
    created_at: String,
    restored_at: Option<String>,
    restored_by: Option<String>,
}

type QuarantineRow = (String, String, Vec<String>, DateTime<Utc>, Option<DateTime<Utc>>, Option<String>);

pub async fn quarantines(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Vec<QuarantineView>> {
    authorize_guild(&app, &headers, gid).await?;
    let rows: Vec<QuarantineRow> = sqlx::query_as(
        "SELECT id, user_id, roles, created_at, restored_at, restored_by FROM quarantines WHERE guild_id = $1 ORDER BY restored_at IS NOT NULL, created_at DESC LIMIT 100",
    )
    .bind(gid.to_string())
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    Ok(Json(
        rows.into_iter()
            .map(|(id, user_id, roles, created_at, restored_at, restored_by)| QuarantineView {
                user_name: names.user(&user_id),
                roles: roles.into_iter().map(|r| Entity { name: names.role(&r), id: r, kind: "role".into() }).collect(),
                created_at: created_at.to_rfc3339(),
                restored_at: restored_at.map(|t| t.to_rfc3339()),
                restored_by,
                id,
                user_id,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct AuditView {
    id: String,
    user_id: String,
    user_name: Option<String>,
    source: String,
    action: String,
    detail: String,
    created_at: String,
}

pub async fn audit(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    Query(query): Query<HitQuery>,
    headers: HeaderMap,
) -> ApiResult<Vec<AuditView>> {
    authorize_guild(&app, &headers, gid).await?;
    let rows: Vec<(String, String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, user_id, source, action, detail, created_at FROM audit_trail WHERE guild_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(gid.to_string())
    .bind(query.limit.unwrap_or(50).clamp(1, MAX_PAGE))
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    Ok(Json(
        rows.into_iter()
            .map(|(id, user_id, source, action, detail, created_at)| AuditView {
                user_name: names.user(&user_id),
                created_at: created_at.to_rfc3339(),
                id,
                user_id,
                source,
                action,
                detail,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct Done {
    ok: bool,
    message: String,
}

fn done(message: impl Into<String>) -> ApiResult<Done> {
    Ok(Json(Done { ok: true, message: message.into() }))
}

async fn log_change(app: &AppState, gid: GuildId, actor: UserId, action: &str, detail: String) {
    service::record_audit(&app.pool, gid, actor, "dashboard", action, &detail).await;

    let Ok(settings) = service::settings(&app.pool, gid).await else { return };
    let Some(channel_id) = settings.logs_channel_id.as_deref().and_then(|id| id.parse::<ChannelId>().ok()) else { return };
    let embed = serenity::all::CreateEmbed::new()
        .title("Changed from the dashboard")
        .description(format!("{}\nby <@{}>", detail, actor))
        .color(settings.logs_color.clamp(0, 0xFFFFFF) as u32)
        .timestamp(serenity::all::Timestamp::now());
    if let Err(e) = channel_id.send_message(&app.cache_http.http, serenity::all::CreateMessage::new().embed(embed)).await {
        log::warn!("could not post dashboard change: {}", e);
    }
}

fn parse_event(raw: &str) -> Result<UserLimitTypes, ApiError> {
    raw.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "Unknown event type".into()))
}

fn parse_action(raw: &str) -> Result<UserLimitActions, ApiError> {
    raw.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "Unknown response".into()))
}

async fn require_setup(app: &AppState, gid: GuildId) -> Result<(), ApiError> {
    if service::is_setup(&app.pool, gid).await? {
        Ok(())
    } else {
        Err(ApiError(StatusCode::CONFLICT, "Set up Sentinel for this server first".into()))
    }
}

pub async fn setup(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    service::ensure_guild(&app.pool, gid).await?;
    log_change(&app, gid, actor, "setup", "Set up Sentinel".into()).await;
    done("Sentinel is set up for this server")
}

#[derive(Deserialize)]
pub struct LimitBody {
    name: String,
    event: String,
    action: String,
    per: i32,
    window_seconds: i64,
    timeout_seconds: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

pub async fn create_limit(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<LimitBody>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    require_setup(&app, gid).await?;
    let input = service::LimitInput {
        name: body.name,
        event: parse_event(&body.event)?,
        action: parse_action(&body.action)?,
        per: body.per,
        window_secs: body.window_seconds,
        timeout_secs: body.timeout_seconds,
        scope: body.scope.as_deref().map(service::LimitScope::parse).transpose()?.unwrap_or(service::LimitScope::Moderator),
        dry_run: body.dry_run,
    };
    let summary = format!("{} {} in {}", input.per, input.event.to_cond().to_lowercase(), crate::utils::format_duration(input.window_secs));
    let name = input.name.trim().to_string();
    service::create_limit(&app.pool, gid, input).await?;
    log_change(&app, gid, actor, "limit_created", format!("Created limit **{}** ({})", name, summary)).await;
    done("Limit created")
}

#[derive(Deserialize)]
pub struct LimitPatchBody {
    name: Option<String>,
    event: Option<String>,
    action: Option<String>,
    per: Option<i32>,
    window_seconds: Option<i64>,
    timeout_seconds: Option<i64>,
    scope: Option<String>,
    dry_run: Option<bool>,
}

pub async fn update_limit(
    State(app): State<Arc<AppState>>,
    Path((gid, limit_id)): Path<(GuildId, String)>,
    headers: HeaderMap,
    Json(body): Json<LimitPatchBody>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let patch = service::LimitPatch {
        name: body.name,
        event: body.event.as_deref().map(parse_event).transpose()?,
        action: body.action.as_deref().map(parse_action).transpose()?,
        per: body.per,
        window_secs: body.window_seconds,
        timeout_secs: body.timeout_seconds,
        scope: body.scope.as_deref().map(service::LimitScope::parse).transpose()?,
        dry_run: body.dry_run,
    };
    let updated = service::update_limit(&app.pool, gid, &limit_id, patch).await?;
    log_change(&app, gid, actor, "limit_updated", format!("Edited limit **{}**", updated.name)).await;
    done("Limit updated")
}

pub async fn delete_limit(State(app): State<Arc<AppState>>, Path((gid, limit_id)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let name = service::delete_limit(&app.pool, gid, &limit_id).await?;
    log_change(&app, gid, actor, "limit_deleted", format!("Deleted limit **{}**", name)).await;
    done("Limit deleted")
}

#[derive(Deserialize)]
pub struct EntityBody {
    id: String,
    kind: String,
}

fn mention(kind: &str, id: &str) -> String {
    if kind == "role" { format!("<@&{}>", id) } else { format!("<@{}>", id) }
}

pub async fn add_whitelist(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<EntityBody>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    require_setup(&app, gid).await?;
    service::whitelist_add(&app.pool, gid, &body.id, &body.kind).await?;
    log_change(&app, gid, actor, "whitelist_added", format!("Whitelisted {}", mention(&body.kind, &body.id))).await;
    done("Added to the whitelist")
}

pub async fn remove_whitelist(State(app): State<Arc<AppState>>, Path((gid, entity_id)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    service::whitelist_remove(&app.pool, gid, &entity_id).await?;
    log_change(&app, gid, actor, "whitelist_removed", format!("Removed `{}` from the whitelist", entity_id)).await;
    done("Removed from the whitelist")
}

#[derive(Deserialize)]
pub struct UserBody {
    user_id: String,
}

pub async fn add_admin(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<UserBody>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    if !is_owner(&app, gid, actor) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Only the server owner can manage Sentinel admins".into()));
    }
    require_setup(&app, gid).await?;
    let user_id: UserId = body.user_id.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "That is not a valid user id".into()))?;
    service::admin_add(&app.pool, gid, user_id).await?;
    log_change(&app, gid, actor, "admin_added", format!("Added <@{}> as a Sentinel admin", user_id)).await;
    done("Admin added")
}

pub async fn remove_admin(State(app): State<Arc<AppState>>, Path((gid, user_id)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    if !is_owner(&app, gid, actor) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Only the server owner can manage Sentinel admins".into()));
    }
    let user_id: UserId = user_id.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "That is not a valid user id".into()))?;
    service::admin_remove(&app.pool, gid, user_id).await?;
    log_change(&app, gid, actor, "admin_removed", format!("Removed <@{}> as a Sentinel admin", user_id)).await;
    done("Admin removed")
}

pub async fn update_settings(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<service::SettingsPatch>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let changed = body.changed().join(", ");
    let resync = body.touches_antiscam();
    service::update_settings(&app.pool, gid, body).await?;
    log_change(&app, gid, actor, "settings_updated", format!("Updated settings: {}", changed)).await;
    if resync {
        let status = crate::antiscam::sync(Bot::from_cache_http(&app.cache_http), &app.pool, gid).await?;
        if let Some(error) = status.error {
            return done(format!("Settings saved, but Discord rejected the anti-scam rules: {}", error));
        }
    }
    done("Settings saved")
}

pub async fn health(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<crate::health::HealthReport> {
    authorize_guild(&app, &headers, gid).await?;
    Ok(Json(crate::health::check(Bot::from_cache_http(&app.cache_http), &app.pool, gid).await?))
}

pub async fn antiscam_status(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<crate::antiscam::AntiscamStatus> {
    authorize_guild(&app, &headers, gid).await?;
    Ok(Json(crate::antiscam::status(&app.pool, gid).await?))
}

pub async fn antiscam_sync(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<crate::antiscam::AntiscamStatus> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let status = crate::antiscam::sync(Bot::from_cache_http(&app.cache_http), &app.pool, gid).await?;
    log_change(&app, gid, actor, "antiscam_synced", "Re-synced the anti-scam AutoMod rules".to_string()).await;
    Ok(Json(status))
}

#[derive(Deserialize)]
pub struct LockdownBody {
    active: bool,
}

pub async fn set_lockdown(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<LockdownBody>,
) -> ApiResult<protect::LockdownReport> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    require_setup(&app, gid).await?;
    let bot = Bot::from_cache_http(&app.cache_http);
    let report = if body.active {
        protect::lockdown_start(bot, &app.pool, gid, actor, "dashboard").await?
    } else {
        protect::lockdown_end(bot, &app.pool, gid, actor, "dashboard").await?
    };
    Ok(Json(report))
}

pub async fn restore_quarantine(State(app): State<Arc<AppState>>, Path((gid, qid)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let restored = protect::restore_quarantine(Bot::from_cache_http(&app.cache_http), &app.pool, gid, &qid, actor).await?;
    log_change(&app, gid, actor, "quarantine_restored", format!("Restored {} role{} from a quarantine", restored, if restored == 1 { "" } else { "s" })).await;
    done(format!("Restored {} role{}", restored, if restored == 1 { "" } else { "s" }))
}

#[derive(Deserialize)]
pub struct NoteBody {
    note: String,
}

pub async fn add_hit_note(
    State(app): State<Arc<AppState>>,
    Path((gid, hit_id)): Path<(GuildId, String)>,
    headers: HeaderMap,
    Json(body): Json<NoteBody>,
) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let note = body.note.trim();
    if note.is_empty() || note.chars().count() > 500 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "Notes must be between 1 and 500 characters".into()));
    }
    let result = sqlx::query("UPDATE past_hit_limits SET notes = array_append(notes, $3) WHERE guild_id = $1 AND id = $2")
        .bind(gid.to_string())
        .bind(&hit_id)
        .bind(format!("{} (by {})", note, actor))
        .execute(&app.pool)
        .await
        .map_err(db_error)?;
    if result.rows_affected() == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "That hit was not found".into()));
    }
    service::record_audit(&app.pool, gid, actor, "dashboard", "hit_note_added", &format!("Added a note to hit {}", hit_id)).await;
    done("Note added")
}

pub async fn preset_catalog(headers: HeaderMap) -> ApiResult<Vec<crate::presets::PresetView>> {
    authorize(&headers)?;
    Ok(Json(crate::presets::catalog()))
}

pub async fn apply_preset(State(app): State<Arc<AppState>>, Path((gid, key)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    require_setup(&app, gid).await?;
    let preset = crate::presets::find(&key)?;
    let (created, skipped) = crate::presets::apply(&app.pool, gid, &key).await?;
    log_change(&app, gid, actor, "preset_applied", format!("Applied the **{}** preset: {} limits added", preset.name, created)).await;
    done(format!(
        "Added {} limit{}{}",
        created,
        if created == 1 { "" } else { "s" },
        if skipped > 0 { format!(", skipped {} that already existed", skipped) } else { String::new() }
    ))
}

pub async fn export_config(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<crate::presets::ExportedConfig> {
    authorize_guild(&app, &headers, gid).await?;
    Ok(Json(crate::presets::export(&app.pool, gid).await?))
}

#[derive(Deserialize)]
pub struct ImportBody {
    config: crate::presets::ExportedConfig,
    #[serde(default)]
    replace_limits: bool,
}

pub async fn import_config(
    State(app): State<Arc<AppState>>,
    Path(gid): Path<GuildId>,
    headers: HeaderMap,
    Json(body): Json<ImportBody>,
) -> ApiResult<crate::presets::ImportReport> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let (roles, channels): (HashSet<String>, HashSet<String>) = {
        let guild = app.cache_http.cache.guild(gid).ok_or(ApiError(StatusCode::NOT_FOUND, "Sentinel is not in this server".into()))?;
        (
            guild.roles.iter().map(|r| r.id.to_string()).collect(),
            guild.channels.iter().map(|c| c.id.to_string()).collect(),
        )
    };
    let report = crate::presets::import(&app.pool, gid, body.config, body.replace_limits, &roles, &channels).await?;
    if let Err(e) = crate::antiscam::sync(Bot::from_cache_http(&app.cache_http), &app.pool, gid).await {
        log::warn!("anti-scam sync after import failed for {}: {}", gid, e);
    }
    log_change(
        &app,
        gid,
        actor,
        "config_imported",
        format!(
            "Imported a config: {} limits added{}, {} whitelist entries",
            report.limits_created,
            if body.replace_limits { format!(" ({} replaced)", report.limits_replaced) } else { String::new() },
            report.whitelist_added
        ),
    )
    .await;
    Ok(Json(report))
}

pub async fn list_snapshots(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Vec<crate::recovery::SnapshotMeta>> {
    authorize_guild(&app, &headers, gid).await?;
    Ok(Json(crate::recovery::list(&app.pool, gid).await?))
}

pub async fn take_snapshot(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Done> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    require_setup(&app, gid).await?;
    crate::recovery::take(Bot::from_cache_http(&app.cache_http), &app.pool, gid, "manual", Some(actor)).await?;
    service::record_audit(&app.pool, gid, actor, "dashboard", "snapshot_taken", "Took a snapshot from the dashboard").await;
    done("Snapshot saved")
}

pub async fn snapshot_plan(State(app): State<Arc<AppState>>, Path((gid, sid)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<crate::recovery::RestorePlan> {
    authorize_guild(&app, &headers, gid).await?;
    Ok(Json(crate::recovery::plan(Bot::from_cache_http(&app.cache_http), &app.pool, gid, &sid).await?))
}

pub async fn restore_snapshot(
    State(app): State<Arc<AppState>>,
    Path((gid, sid)): Path<(GuildId, String)>,
    headers: HeaderMap,
    Json(options): Json<crate::recovery::RestoreOptions>,
) -> ApiResult<crate::recovery::RestoreReport> {
    let actor = authorize_guild(&app, &headers, gid).await?;
    let report = crate::recovery::restore(Bot::from_cache_http(&app.cache_http), &app.pool, gid, &sid, actor, "recovery", options).await?;
    Ok(Json(report))
}

#[derive(Serialize)]
pub struct HitDetail {
    hit: HitView,
    causes: Vec<ActionView>,
    quarantine: Option<QuarantineView>,
}

pub async fn hit_detail(State(app): State<Arc<AppState>>, Path((gid, hid)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<HitDetail> {
    authorize_guild(&app, &headers, gid).await?;

    let row: Option<(String, String, String, Option<String>, Option<String>, bool, Vec<String>, Vec<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT p.user_id, p.limit_id, COALESCE(l.limit_name, 'Deleted limit'), l.limit_action, p.action_taken, p.dry_run, p.cause, p.notes, p.created_at
         FROM past_hit_limits p LEFT JOIN limits l ON l.limit_id = p.limit_id
         WHERE p.guild_id = $1 AND p.id = $2",
    )
    .bind(gid.to_string())
    .bind(&hid)
    .fetch_optional(&app.pool)
    .await
    .map_err(db_error)?;
    let (user_id, limit_id, limit_name, action, action_taken, dry_run, cause, notes, created_at) =
        row.ok_or(ApiError(StatusCode::NOT_FOUND, "That hit was not found".into()))?;

    let causes: Vec<(String, String, DateTime<Utc>, String, String, Vec<String>)> = sqlx::query_as(
        "SELECT action_id, limit_type, created_at, user_id, action_target, limits_hit FROM user_actions
         WHERE guild_id = $1 AND action_id = ANY($2) ORDER BY created_at",
    )
    .bind(gid.to_string())
    .bind(&cause)
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?;

    let quarantine: Option<QuarantineRow> = sqlx::query_as(
        "SELECT id, user_id, roles, created_at, restored_at, restored_by FROM quarantines WHERE guild_id = $1 AND hit_id = $2",
    )
    .bind(gid.to_string())
    .bind(&hid)
    .fetch_optional(&app.pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    Ok(Json(HitDetail {
        hit: HitView {
            user_name: names.user(&user_id),
            action_label: action.as_deref().map(limit_action_label),
            action_taken,
            dry_run,
            cause_count: cause.len() as i32,
            notes,
            created_at: created_at.to_rfc3339(),
            id: hid,
            user_id,
            limit_id,
            limit_name,
        },
        causes: causes
            .into_iter()
            .map(|(id, event, created_at, user_id, target_id, limits_hit)| ActionView {
                event_label: limit_type_label(&event),
                user_name: names.user(&user_id),
                target_name: names.target(&event, &target_id),
                limits_hit,
                created_at: created_at.to_rfc3339(),
                id,
                event,
                user_id,
                target_id,
            })
            .collect(),
        quarantine: quarantine.map(|(id, user_id, roles, created_at, restored_at, restored_by)| QuarantineView {
            user_name: names.user(&user_id),
            roles: roles.into_iter().map(|r| Entity { name: names.role(&r), id: r, kind: "role".into() }).collect(),
            created_at: created_at.to_rfc3339(),
            restored_at: restored_at.map(|t| t.to_rfc3339()),
            restored_by,
            id,
            user_id,
        }),
    }))
}

#[derive(Serialize)]
pub struct ModeratorSummary {
    user_id: String,
    user_name: Option<String>,
    actions_30d: i64,
    hits_30d: i64,
    last_action: String,
    whitelisted: bool,
}

pub async fn moderators(State(app): State<Arc<AppState>>, Path(gid): Path<GuildId>, headers: HeaderMap) -> ApiResult<Vec<ModeratorSummary>> {
    authorize_guild(&app, &headers, gid).await?;
    let rows: Vec<(String, i64, i64, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT a.user_id, COUNT(*),
                (SELECT COUNT(*) FROM past_hit_limits p WHERE p.guild_id = $1 AND p.user_id = a.user_id AND NOT p.dry_run
                    AND p.created_at > NOW() - INTERVAL '30 days'),
                MAX(a.created_at),
                EXISTS (SELECT 1 FROM guild_whitelist w WHERE w.guild_id = $1 AND w.entity_id = a.user_id)
         FROM user_actions a
         WHERE a.guild_id = $1 AND a.created_at > NOW() - INTERVAL '30 days'
         GROUP BY a.user_id
         ORDER BY COUNT(*) DESC
         LIMIT 100",
    )
    .bind(gid.to_string())
    .fetch_all(&app.pool)
    .await
    .map_err(db_error)?;

    let names = Names(app.cache_http.cache.guild(gid));
    Ok(Json(
        rows.into_iter()
            .map(|(user_id, actions_30d, hits_30d, last_action, whitelisted)| ModeratorSummary {
                user_name: names.user(&user_id),
                last_action: last_action.to_rfc3339(),
                user_id,
                actions_30d,
                hits_30d,
                whitelisted,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct EventCount {
    event: String,
    label: String,
    count: i64,
}

#[derive(Serialize)]
pub struct ModeratorProfile {
    user_id: String,
    user_name: Option<String>,
    avatar_url: Option<String>,
    whitelisted: bool,
    events_30d: Vec<EventCount>,
    activity: Vec<Day>,
    recent_actions: Vec<ActionView>,
    hits: Vec<HitView>,
}

pub async fn moderator_profile(State(app): State<Arc<AppState>>, Path((gid, uid)): Path<(GuildId, String)>, headers: HeaderMap) -> ApiResult<ModeratorProfile> {
    authorize_guild(&app, &headers, gid).await?;
    let user_id: UserId = uid.parse().map_err(|_| ApiError(StatusCode::BAD_REQUEST, "That is not a valid user id".into()))?;
    let pool = &app.pool;
    let g = gid.to_string();
    let u = user_id.to_string();

    let events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT limit_type, COUNT(*) FROM user_actions WHERE guild_id = $1 AND user_id = $2 AND created_at > NOW() - INTERVAL '30 days'
         GROUP BY limit_type ORDER BY COUNT(*) DESC",
    )
    .bind(&g)
    .bind(&u)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let activity: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT to_char(day, 'YYYY-MM-DD'),
            (SELECT COUNT(*) FROM user_actions WHERE guild_id = $1 AND user_id = $2 AND created_at >= day AND created_at < day + INTERVAL '1 day'),
            (SELECT COUNT(*) FROM past_hit_limits WHERE guild_id = $1 AND user_id = $2 AND NOT dry_run AND created_at >= day AND created_at < day + INTERVAL '1 day')
         FROM generate_series(date_trunc('day', NOW()) - INTERVAL '29 days', date_trunc('day', NOW()), INTERVAL '1 day') AS day",
    )
    .bind(&g)
    .bind(&u)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let actions: Vec<(String, String, DateTime<Utc>, String, String, Vec<String>)> = sqlx::query_as(
        "SELECT action_id, limit_type, created_at, user_id, action_target, limits_hit FROM user_actions
         WHERE guild_id = $1 AND user_id = $2 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&g)
    .bind(&u)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let hits: Vec<(String, String, String, Option<String>, Option<String>, bool, i32, Vec<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT p.id, p.limit_id, COALESCE(l.limit_name, 'Deleted limit'), l.limit_action, p.action_taken, p.dry_run,
                COALESCE(cardinality(p.cause), 0), p.notes, p.created_at
         FROM past_hit_limits p LEFT JOIN limits l ON l.limit_id = p.limit_id
         WHERE p.guild_id = $1 AND p.user_id = $2 ORDER BY p.created_at DESC LIMIT 25",
    )
    .bind(&g)
    .bind(&u)
    .fetch_all(pool)
    .await
    .map_err(db_error)?;

    let (whitelisted,): (bool,) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM guild_whitelist WHERE guild_id = $1 AND entity_id = $2)")
        .bind(&g)
        .bind(&u)
        .fetch_one(pool)
        .await
        .map_err(db_error)?;

    let avatar_url = gid.member(&app.cache_http, user_id).await.ok().map(|m| m.face());
    let names = Names(app.cache_http.cache.guild(gid));
    let user_name = names.user(&u);

    Ok(Json(ModeratorProfile {
        events_30d: events.into_iter().map(|(event, count)| EventCount { label: limit_type_label(&event), event, count }).collect(),
        activity: activity.into_iter().map(|(date, actions, hits)| Day { date, actions, hits }).collect(),
        recent_actions: actions
            .into_iter()
            .map(|(id, event, created_at, user_id, target_id, limits_hit)| ActionView {
                event_label: limit_type_label(&event),
                user_name: names.user(&user_id),
                target_name: names.target(&event, &target_id),
                limits_hit,
                created_at: created_at.to_rfc3339(),
                id,
                event,
                user_id,
                target_id,
            })
            .collect(),
        hits: hits
            .into_iter()
            .map(|(id, limit_id, limit_name, action, action_taken, dry_run, cause_count, notes, created_at)| HitView {
                user_name: user_name.clone(),
                action_label: action.as_deref().map(limit_action_label),
                action_taken,
                dry_run,
                cause_count,
                notes,
                created_at: created_at.to_rfc3339(),
                id,
                user_id: u.clone(),
                limit_id,
                limit_name,
            })
            .collect(),
        user_name,
        avatar_url,
        whitelisted,
        user_id: u,
    }))
}
