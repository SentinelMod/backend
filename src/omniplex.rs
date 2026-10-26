use std::collections::HashMap;
use std::time::Duration;

use poise::serenity_prelude::UserId;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::changelog::{self, Release};
use crate::server::CATALOG;

const DEFAULT_API: &str = "https://spider.omniplex.gg";

#[derive(Serialize)]
struct CommandEntry {
    category: String,
    description: String,
    name: String,
    usage: String,
}

#[derive(Serialize)]
struct ChangelogEntry<'a> {
    title: String,
    version: &'a str,
    content: String,
}

#[derive(Serialize, Debug, PartialEq)]
struct Stats {
    servers: usize,
    shards: u16,
    users: u64,
    shard_list: Vec<u16>,
    status: &'static str,
}

fn stats(servers: usize, shards: u16, users: u64) -> Stats {
    Stats { servers, shards, users, shard_list: (0..shards).collect(), status: "online" }
}

#[derive(Deserialize)]
struct Created {
    id: String,
}

fn api() -> String {
    std::env::var("OMNIPLEX_API_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_API.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn token() -> Option<String> {
    std::env::var("OMNIPLEX_TOKEN").ok().filter(|t| !t.trim().is_empty())
}

pub fn usages<U, E>(commands: &[poise::Command<U, E>]) -> HashMap<String, String> {
    fn walk<U, E>(commands: &[poise::Command<U, E>], prefix: &str, out: &mut HashMap<String, String>) {
        for command in commands {
            let name = if prefix.is_empty() { command.name.clone() } else { format!("{} {}", prefix, command.name) };
            if command.subcommands.is_empty() {
                let params: Vec<String> = command
                    .parameters
                    .iter()
                    .map(|p| if p.required { format!("<{}>", p.name) } else { format!("[{}]", p.name) })
                    .collect();
                let usage = std::iter::once(format!("/{}", name)).chain(params).collect::<Vec<_>>().join(" ");
                out.insert(name, usage);
            } else {
                walk(&command.subcommands, &name, out);
            }
        }
    }
    let mut out = HashMap::new();
    walk(commands, "", &mut out);
    out
}

fn command_entries(usages: &HashMap<String, String>) -> Vec<CommandEntry> {
    CATALOG
        .iter()
        .map(|(name, group, description)| CommandEntry {
            category: group.to_string(),
            description: description.to_string(),
            name: format!("/{}", name),
            usage: usages.get(*name).cloned().unwrap_or_else(|| format!("/{}", name)),
        })
        .collect()
}

fn changelog_content(release: &Release) -> String {
    let mut sections: Vec<String> = vec![];
    if !release.summary.is_empty() {
        sections.push(release.summary.clone());
    }
    for group in release.groups.iter().filter(|g| !g.items.is_empty()) {
        let mut heading = group.kind.clone();
        if let Some(first) = heading.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        let items: Vec<String> = group.items.iter().map(|i| format!("- {}", i)).collect();
        sections.push(format!("### {}\n\n{}", heading, items.join("\n")));
    }
    sections.join("\n\n")
}

async fn push_commands(client: &reqwest::Client, bot_id: UserId, token: &str, usages: &HashMap<String, String>) {
    let commands = command_entries(usages);
    let count = commands.len();
    let result = client
        .put(format!("{}/bots/{}/commands", api(), bot_id))
        .header("Authorization", format!("Bot {}", token))
        .json(&serde_json::json!({ "commands": commands }))
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => log::info!("Synced {} commands to Omniplex", count),
        Ok(response) => log::warn!("Omniplex rejected the command list ({}): {}", response.status(), response.text().await.unwrap_or_default()),
        Err(e) => log::warn!("Could not reach Omniplex to sync commands: {}", e),
    }
}

async fn push_changelogs(client: &reqwest::Client, pool: &PgPool, bot_id: UserId, token: &str) {
    let posted: Vec<(String,)> = match sqlx::query_as("SELECT version FROM omniplex_changelogs").fetch_all(pool).await {
        Ok(rows) => rows,
        Err(e) => {
            log::warn!("Could not read posted Omniplex changelogs: {}", e);
            return;
        }
    };
    let posted: Vec<String> = posted.into_iter().map(|(v,)| v).collect();

    for release in changelog::releases().iter().rev().filter(|r| !posted.contains(&r.version)) {
        let entry = ChangelogEntry { title: format!("Sentinel {}", release.version), version: &release.version, content: changelog_content(release) };
        let response = match client
            .post(format!("{}/bots/{}/changelogs", api(), bot_id))
            .header("Authorization", format!("Bot {}", token))
            .json(&entry)
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                log::warn!("Could not reach Omniplex to post changelog {}: {}", release.version, e);
                return;
            }
        };
        if !response.status().is_success() {
            log::warn!("Omniplex rejected changelog {} ({}): {}", release.version, response.status(), response.text().await.unwrap_or_default());
            return;
        }
        let id = response.json::<Created>().await.map(|c| c.id).ok();
        if let Err(e) = sqlx::query("INSERT INTO omniplex_changelogs (version, entry_id) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING")
            .bind(&release.version)
            .bind(&id)
            .execute(pool)
            .await
        {
            log::warn!("Posted changelog {} to Omniplex but could not record it: {}", release.version, e);
            return;
        }
        log::info!("Posted changelog {} to Omniplex", release.version);
    }
}

pub async fn post_stats(cache: &serenity::all::Cache) {
    let Some(token) = token() else { return };
    let guilds = cache.guilds();
    let users: u64 = guilds.iter().filter_map(|id| cache.guild(*id).map(|g| g.member_count)).sum();
    let body = stats(guilds.len(), cache.shard_count().get(), users);
    let result = reqwest::Client::new()
        .post(format!("{}/bots/stats", api()))
        .header("Authorization", format!("Bot {}", token))
        .timeout(Duration::from_secs(15))
        .json(&body)
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => log::info!("Posted stats to Omniplex: {} servers, {} users", body.servers, body.users),
        Ok(response) => log::warn!("Omniplex rejected stats ({}): {}", response.status(), response.text().await.unwrap_or_default()),
        Err(e) => log::warn!("Could not reach Omniplex to post stats: {}", e),
    }
}

pub async fn sync(pool: PgPool, bot_id: UserId, usages: HashMap<String, String>) {
    let Some(token) = token() else { return };
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(15)).build() {
        Ok(client) => client,
        Err(e) => {
            log::warn!("Could not build the Omniplex client: {}", e);
            return;
        }
    };
    push_commands(&client, bot_id, &token, &usages).await;
    push_changelogs(&client, &pool, bot_id, &token).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changelog::Group;

    #[test]
    fn every_catalog_entry_becomes_a_command() {
        let mut usages = HashMap::new();
        usages.insert("limits add".to_string(), "/limits add <name> <event> [scope]".to_string());
        let entries = command_entries(&usages);
        assert_eq!(entries.len(), CATALOG.len());
        let add = entries.iter().find(|e| e.name == "/limits add").unwrap();
        assert_eq!(add.usage, "/limits add <name> <event> [scope]");
        assert_eq!(add.category, "Protection");
        assert!(entries.iter().find(|e| e.name == "/ping").unwrap().usage == "/ping");
    }

    #[test]
    fn builds_stats_body() {
        let body = serde_json::to_value(stats(12, 2, 3400)).unwrap();
        assert_eq!(body, serde_json::json!({ "servers": 12, "shards": 2, "users": 3400, "shard_list": [0, 1], "status": "online" }));
    }

    #[test]
    fn renders_changelog_markdown() {
        let release = Release {
            version: "1.0.0".into(),
            date: Some("2026-10-26".into()),
            summary: "First.".into(),
            groups: vec![Group { kind: "added".into(), items: vec!["One".into(), "Two".into()] }, Group { kind: "fixed".into(), items: vec![] }],
        };
        assert_eq!(changelog_content(&release), "First.\n\n### Added\n\n- One\n- Two");
    }
}
