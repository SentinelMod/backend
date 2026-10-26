use std::sync::Arc;

use axum::http::header;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderName, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Json,
    Router,
};
use log::info;
use poise::serenity_prelude::{GuildId, UserId};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tower_http::cors::{Any, CorsLayer};

use botox::cache::CacheHttpImpl;

pub struct AppState {
    pub cache_http: CacheHttpImpl,
    pub pool: PgPool,
}

pub async fn setup_server(pool: PgPool, cache_http: CacheHttpImpl) {
    let shared_state = Arc::new(AppState { pool, cache_http });

    let app = Router::new()
        .route("/api/stats", get(stats))
        .route("/api/stats/global", get(crate::global_stats::global))
        .route("/api/health", get(health))
        .route("/api/shards", get(shards))
        .route("/api/commands", get(commands))
        .route("/api/changelog", get(crate::changelog::changelog))
        .route("/api/dashboard/guilds", get(crate::dashboard::guilds))
        .route("/api/dashboard/presence", post(crate::dashboard::presence))
        .route("/api/dashboard/meta", get(crate::dashboard::meta))
        .route("/api/dashboard/guilds/:gid/resources", get(crate::dashboard::resources))
        .route("/api/dashboard/guilds/:gid/members", get(crate::dashboard::members))
        .route("/api/dashboard/guilds/:gid/quarantines", get(crate::dashboard::quarantines))
        .route("/api/dashboard/guilds/:gid/quarantines/:qid/restore", post(crate::dashboard::restore_quarantine))
        .route("/api/dashboard/guilds/:gid/audit", get(crate::dashboard::audit))
        .route("/api/dashboard/guilds/:gid/setup", post(crate::dashboard::setup))
        .route("/api/dashboard/guilds/:gid/limits", post(crate::dashboard::create_limit))
        .route("/api/dashboard/guilds/:gid/limits/:lid", patch(crate::dashboard::update_limit).delete(crate::dashboard::delete_limit))
        .route("/api/dashboard/guilds/:gid/whitelist", post(crate::dashboard::add_whitelist))
        .route("/api/dashboard/guilds/:gid/whitelist/:eid", delete(crate::dashboard::remove_whitelist))
        .route("/api/dashboard/guilds/:gid/admins", post(crate::dashboard::add_admin))
        .route("/api/dashboard/guilds/:gid/admins/:uid", delete(crate::dashboard::remove_admin))
        .route("/api/dashboard/guilds/:gid/settings", patch(crate::dashboard::update_settings))
        .route("/api/dashboard/guilds/:gid/lockdown", post(crate::dashboard::set_lockdown))
        .route("/api/dashboard/guilds/:gid/health", get(crate::dashboard::health))
        .route("/api/dashboard/guilds/:gid/antiscam", get(crate::dashboard::antiscam_status).post(crate::dashboard::antiscam_sync))
        .route("/api/dashboard/guilds/:gid/hits/:hid/notes", post(crate::dashboard::add_hit_note))
        .route("/api/dashboard/presets", get(crate::dashboard::preset_catalog))
        .route("/api/dashboard/guilds/:gid/presets/:key", post(crate::dashboard::apply_preset))
        .route("/api/dashboard/guilds/:gid/config", get(crate::dashboard::export_config).post(crate::dashboard::import_config))
        .route("/api/dashboard/guilds/:gid/snapshots", get(crate::dashboard::list_snapshots).post(crate::dashboard::take_snapshot))
        .route("/api/dashboard/guilds/:gid/snapshots/:sid/plan", get(crate::dashboard::snapshot_plan))
        .route("/api/dashboard/guilds/:gid/snapshots/:sid/restore", post(crate::dashboard::restore_snapshot))
        .route("/api/dashboard/guilds/:gid/hits/:hid", get(crate::dashboard::hit_detail))
        .route("/api/dashboard/guilds/:gid/moderators", get(crate::dashboard::moderators))
        .route("/api/dashboard/guilds/:gid/moderators/:uid", get(crate::dashboard::moderator_profile))
        .route("/api/dashboard/guilds/:gid", get(crate::dashboard::overview))
        .route("/api/dashboard/guilds/:gid/actions", get(crate::dashboard::actions))
        .route("/api/dashboard/guilds/:gid/hits", get(crate::dashboard::hits))
        .route("/:gid", get(create_login))
        .route("/confirm-login", get(confirm_login))
        .with_state(shared_state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let bind_addr = std::env::var("API_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:4950".to_string());
    let addr = bind_addr.parse().expect("Invalid API_BIND_ADDR");

    info!("Starting server on {}", addr);

    if let Err(e) = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
    {
        panic!("server error: {}", e);
    }
}

async fn stats(State(app_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let shard_count = match crate::SHARD_MANAGER.get() {
        Some(manager) => manager.runners.lock().await.len(),
        None => 0,
    };

    Json(json!({
        "status": "online",
        "name": "Sentinel",
        "service": "discord-moderation-safety",
        "version": crate::stats::VERSION,
        "commit": crate::stats::GIT_SHA,
        "semver": crate::stats::GIT_SEMVER,
        "capabilities": ["audit monitoring", "thresholds", "automatic response", "owner alerts"],
        "guild_count": app_state.cache_http.cache.guild_count(),
        "shard_count": shard_count,
        "uptime_seconds": crate::stats::START_TIME.elapsed().as_secs(),
    }))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn shards(State(app_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let Some(shard_manager) = crate::SHARD_MANAGER.get() else {
        return Json(json!({ "shard_count": 0, "shards": [] }));
    };

    let runners = shard_manager.runners.lock().await;
    let total_shards = std::num::NonZeroU16::new(runners.len() as u16)
        .unwrap_or(std::num::NonZeroU16::new(1).expect("1 is non-zero"));

    let mut guild_counts = std::collections::HashMap::new();
    for guild_id in app_state.cache_http.cache.guilds() {
        *guild_counts.entry(guild_id.shard_id(total_shards)).or_insert(0u32) += 1;
    }

    let mut shards: Vec<serde_json::Value> = runners
        .iter()
        .map(|(shard_id, info)| {
            json!({
                "id": shard_id.0,
                "status": format!("{:?}", info.stage),
                "latency_ms": info.latency.map(|d| d.as_millis()),
                "guild_count": guild_counts.get(&shard_id.0).copied().unwrap_or(0),
            })
        })
        .collect();

    shards.sort_by_key(|shard| shard["id"].as_u64().unwrap_or(0));

    Json(json!({
        "shard_count": runners.len(),
        "shards": shards,
    }))
}

pub const CATALOG: &[(&str, &str, &str)] = &[
    ("help", "Essentials", "Browse Sentinel commands and usage."),
    ("simplehelp", "Essentials", "Get a compact command reference."),
    ("ping", "Essentials", "Check whether Sentinel is responding."),
    ("stats", "Essentials", "View Sentinel build and runtime details."),
    ("setup", "Server", "Initialize Sentinel protection for a server."),
    ("settings", "Server", "Configure the log channel, alerts and protection guards."),
    ("health", "Server", "Check Sentinel's permissions, role position and log channel."),
    ("limits guide", "Protection", "Understand thresholds, windows, and responses."),
    ("limits add", "Protection", "Create a threshold for a moderation event."),
    ("limits edit", "Protection", "Update an existing protection threshold."),
    ("limits view", "Protection", "Review active protection thresholds."),
    ("limits hit", "Protection", "Review triggered thresholds."),
    ("limits remove", "Protection", "Remove a configured threshold."),
    ("limits preset", "Protection", "Apply a ready-made set of limits for your server size."),
    ("actions view", "Audit", "Review recorded moderation actions."),
    ("perms", "Administration", "Manage Sentinel administrators."),
    ("whitelist add", "Administration", "Exempt a trusted user or role from limit tracking."),
    ("whitelist remove", "Administration", "Remove a user or role from the whitelist."),
    ("whitelist view", "Administration", "Review whitelisted users and roles."),
    ("lockdown start", "Incident", "Strip dangerous permissions from roles and pause invites."),
    ("lockdown end", "Incident", "Restore permissions removed by a lockdown."),
    ("lockdown status", "Incident", "Check whether the server is in lockdown."),
    ("quarantine view", "Incident", "List members Sentinel has quarantined."),
    ("quarantine restore", "Incident", "Give a quarantined member their roles back."),
    ("antiscam setup", "Protection", "Block scam links, mass mentions, @everyone and invites with AutoMod."),
    ("antiscam status", "Protection", "Check the anti-scam AutoMod rules and when they last synced."),
    ("snapshot take", "Recovery", "Save roles, permissions and channels right now."),
    ("snapshot list", "Recovery", "List saved snapshots."),
    ("snapshot restore", "Recovery", "Recreate roles and channels deleted since a snapshot."),
];

async fn commands() -> Json<serde_json::Value> {
    let commands: Vec<serde_json::Value> = CATALOG
        .iter()
        .map(|(name, group, description)| json!({ "name": name, "group": group, "description": description }))
        .collect();
    Json(json!({ "name": "Sentinel", "commands": commands }))
}

enum ServerError {
    Error(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::Error(e) => (StatusCode::BAD_REQUEST, e).into_response(),
        }
    }
}

async fn create_login(Path(gid): Path<UserId>) -> Redirect {
    let url = format!("https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}/confirm-login&scope={}&state={}&response_type=code", crate::config::CONFIG.client_id, crate::config::CONFIG.frontend_url, "identify", gid);

    Redirect::temporary(&url)
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
}

#[derive(Deserialize)]
struct ConfirmLogin {
    code: String,
    state: GuildId,
}

async fn confirm_login(
    State(app_state): State<Arc<AppState>>,
    data: Query<ConfirmLogin>,
) -> Result<([(HeaderName, &'static str); 2], String), ServerError> {
    let client = reqwest::Client::new();

    let access_token = client
        .post("https://discord.com/api/v10/oauth2/token")
        .form(&json!({
            "client_id": crate::config::CONFIG.client_id,
            "client_secret": crate::config::CONFIG.client_secret,
            "grant_type": "authorization_code",
            "code": data.code,
            "redirect_uri": format!("{}/confirm-login", crate::config::CONFIG.frontend_url),
        }))
        .send()
        .await
        .map_err(|_| ServerError::Error("Could not send request to get access token".to_string()))?
        .error_for_status()
        .map_err(|e| ServerError::Error(format!("Could not get access token: {}", e)))?;

    let access_token = access_token
        .json::<AccessToken>()
        .await
        .map_err(|_| ServerError::Error("Could not deserialize response".to_string()))?;

    let user = client
        .get("https://discord.com/api/v10/users/@me")
        .header(
            "Authorization",
            format!("Bearer {}", access_token.access_token),
        )
        .send()
        .await
        .map_err(|_| ServerError::Error("Could not send request to get user".to_string()))?
        .error_for_status()
        .map_err(|_| ServerError::Error("Get User failed!".to_string()))?;

    let user = user
        .json::<serenity::model::user::User>()
        .await
        .map_err(|_| ServerError::Error("Could not deserialize response".to_string()))?;

    crate::utils::is_guild_admin(
        &app_state.cache_http,
        &app_state.pool,
        data.state,
        user.id.to_string(),
    )
    .await
    .map_err(|e| ServerError::Error(e.to_string()))?;

    let actions = crate::core::Action::guild(&app_state.pool, data.state)
        .await
        .map_err(|e| ServerError::Error(e.to_string()))?;

    let actions = serde_json::to_string(&actions)
        .map_err(|_| ServerError::Error("Could not serialize actions".to_string()))?;

    let headers = [
        (
            header::CONTENT_TYPE,
            "application/octet-stream; charset=utf-8",
        ),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"data.json\"",
        ),
    ];

    Ok((headers, actions))
}
