pub mod maintenance;
pub mod update_status;

use botox::taskman::Task;
use futures_util::FutureExt;

pub fn tasks() -> Vec<Task> {
    vec![
        Task {
            name: "Update Status",
            description: "Update the status of the bot",
            enabled: true,
            duration: std::time::Duration::from_secs(600),
            run: Box::new(move |ctx| {
                update_status::update_status(ctx).boxed()
            })
        },
        Task {
            name: "Snapshots",
            description: "Snapshot roles and channels for servers that are due",
            enabled: true,
            duration: std::time::Duration::from_secs(1800),
            run: Box::new(move |ctx| maintenance::snapshots(ctx).boxed()),
        },
        Task {
            name: "Weekly Digest",
            description: "Post the weekly summary to servers that are due",
            enabled: true,
            duration: std::time::Duration::from_secs(3600),
            run: Box::new(move |ctx| maintenance::digest(ctx).boxed()),
        },
        Task {
            name: "Retention",
            description: "Prune raw moderation actions past the retention window",
            enabled: true,
            duration: std::time::Duration::from_secs(86400),
            run: Box::new(move |ctx| maintenance::retention(ctx).boxed()),
        },
        Task {
            name: "Omniplex Stats",
            description: "Post server, shard and user counts to Omniplex",
            enabled: true,
            duration: std::time::Duration::from_secs(900),
            run: Box::new(move |ctx| maintenance::omniplex_stats(ctx).boxed()),
        },
        Task {
            name: "Anti-scam Sync",
            description: "Refresh the scam domain list and re-sync anti-scam AutoMod rules",
            enabled: true,
            duration: std::time::Duration::from_secs(43200),
            run: Box::new(move |ctx| maintenance::antiscam(ctx).boxed()),
        },
    ]
}
