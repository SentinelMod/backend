use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{error, info};
use once_cell::sync::OnceCell;
use poise::serenity_prelude::{FullEvent, GuildId, RoleAction, RoleId, UserId};
use serenity::model::guild::audit_log::{
    Action, ChannelAction, EmojiAction, IntegrationAction, InviteAction, MemberAction, MessageAction, WebhookAction,
};
use protect::Bot;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod antiscam;
mod autocompletes;
mod changelog;
mod cmds;
mod config;
mod handler;
mod health;
mod help;
mod core;
mod dashboard;
mod global_stats;
mod omniplex;
mod owner;
mod presets;
mod protect;
mod recovery;
mod service;
mod server;
mod stats;
mod utils;
mod tasks;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

pub struct Data {
    pool: sqlx::PgPool,
}

pub static SHARD_MANAGER: OnceCell<Arc<serenity::all::ShardManager>> = OnceCell::new();

static READY_INIT: AtomicBool = AtomicBool::new(false);

static CHECKED_GUILDS: once_cell::sync::Lazy<std::sync::Mutex<HashSet<GuildId>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(HashSet::new()));

async fn clear_guild_commands(http: Arc<serenity::all::Http>, guild_ids: Vec<GuildId>) {
    let mut cleared = 0;
    for guild_id in guild_ids {
        let fresh = CHECKED_GUILDS.lock().map(|mut checked| checked.insert(guild_id)).unwrap_or(false);
        if !fresh {
            continue;
        }

        match guild_id.get_commands(&http).await {
            Ok(commands) if !commands.is_empty() => match guild_id.set_commands(&http, &[]).await {
                Ok(_) => {
                    cleared += 1;
                    info!("Removed {} stale guild command(s) from {}", commands.len(), guild_id);
                }
                Err(e) => error!("Could not clear guild commands in {}: {}", guild_id, e),
            },
            Ok(_) => {}
            Err(e) => error!("Could not list guild commands in {}: {}", guild_id, e),
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    if cleared > 0 {
        info!("Cleared stale guild commands from {} server(s)", cleared);
    }
}

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    match error {
        poise::FrameworkError::Command { error, ctx, .. } => {
            error!("Error in command `{}`: {:?}", ctx.command().name, error,);
            let err = ctx
                .say(format!(
                    "There was an error running this command: {}",
                    error
                ))
                .await;

            if let Err(e) = err {
                error!("SQLX Error: {}", e);
            }
        }
        poise::FrameworkError::CommandCheckFailed { error, ctx, .. } => {
            error!(
                "[Possible] error in command `{}`: {:?}",
                ctx.command().name,
                error,
            );
            if let Some(error) = error {
                error!("Error in command `{}`: {:?}", ctx.command().name, error,);
                let err = ctx.say(format!("**{}**", error)).await;

                if let Err(e) = err {
                    error!("Error while sending error message: {}", e);
                }
            }
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                error!("Error while handling error: {}", e);
            }
        }
    }
}

async fn event_listener<'a>(
    ctx: poise::FrameworkContext<'a, Data, Error>,
    event: &FullEvent,
) -> Result<(), Error> {
    match event {
        FullEvent::InteractionCreate {
            interaction,
        } => {
            info!("Interaction received: {:?}", interaction.id());
        }
        FullEvent::Ready {
            data_about_bot,
        } => {
            info!("{} is ready! (shard {})", data_about_bot.user.name, ctx.serenity_context.shard_id);

            let _ = SHARD_MANAGER.set(ctx.shard_manager.clone());

            tokio::task::spawn(clear_guild_commands(
                ctx.serenity_context.http.clone(),
                data_about_bot.guilds.iter().map(|g| g.id).collect(),
            ));

            if READY_INIT.swap(true, Ordering::SeqCst) {
                return Ok(());
            }

            let user_data = ctx.serenity_context.data::<Data>();

            match poise::builtins::register_globally(&ctx.serenity_context.http, &ctx.options().commands).await {
                Ok(()) => info!("Synced {} global application commands", ctx.options().commands.len()),
                Err(error) => error!("Could not register global application commands: {error}"),
            }

            tokio::task::spawn(omniplex::sync(
                user_data.pool.clone(),
                data_about_bot.user.id,
                omniplex::usages(&ctx.options().commands),
            ));

            let stats_cache = ctx.serenity_context.cache.clone();
            tokio::task::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                omniplex::post_stats(&stats_cache).await;
            });

            let cache_http_server = botox::cache::CacheHttpImpl::from_ctx(ctx.serenity_context);

            tokio::task::spawn(server::setup_server(
                user_data.pool.clone(),
                cache_http_server,
            ));

            tokio::task::spawn(botox::taskman::start_all_tasks(
                crate::tasks::tasks(),
                ctx.serenity_context.clone(),
            ));
        }
        FullEvent::GuildAuditLogEntryCreate {
            entry,
            guild_id,
        } => {
            let user_data = ctx.serenity_context.data::<Data>();

            info!("Audit log created: {:?}. Guild: {}", entry, guild_id);

            let res = match entry.action {
                Action::Channel(ch) => {
                    let ch_id = entry.target_id.ok_or("No channel ID found")?;

                    match ch {
                        ChannelAction::Create => {
                            info!("Channel created: {}", ch_id);

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::ChannelAdd,
                                ch_id.to_string(),
                            )
                            .await
                        }
                        ChannelAction::Delete => {
                            info!("Channel deleted: {}", ch_id);

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::ChannelRemove,
                                ch_id.to_string(),
                            )
                            .await
                        }
                        ChannelAction::Update => {
                            info!("Channel updated: {}", ch_id);

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::ChannelUpdate,
                                ch_id.to_string(),
                            )
                            .await
                        }
                        _ => Ok(()),
                    }
                }
                Action::Role(ra) => {
                    let r_id = entry.target_id.ok_or("No role ID found")?;

                    match ra {
                        RoleAction::Create => {
                            info!("Role created: {}", r_id);

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::RoleAdd,
                                r_id.to_string(),
                            )
                            .await
                        }
                        RoleAction::Update => {
                            info!("Role updated: {}", r_id);

                            let changes = entry.changes.as_deref().unwrap_or_default();
                            let bot = Bot::from_ctx(ctx.serenity_context);
                            if protect::guard_role_permissions(bot, &user_data.pool, *guild_id, entry.user_id, RoleId::new(r_id.get()), changes).await {
                                record(ctx.serenity_context, &user_data.pool, *guild_id, entry.user_id, core::UserLimitTypes::DangerousPermission, r_id.to_string()).await?;
                            }

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::RoleUpdate,
                                r_id.to_string(),
                            )
                            .await
                        }
                        RoleAction::Delete => {
                            info!("Role deleted: {}", r_id);

                            handler::handle_mod_action(
                                *guild_id,
                                entry.user_id,
                                &user_data.pool,
                                ctx.serenity_context,
                                core::UserLimitTypes::RoleRemove,
                                r_id.to_string(),
                            )
                            .await
                        }
                        _ => Ok(()),
                    }
                }
                Action::Webhook(wa) => {
                    let w_id = entry.target_id.ok_or("No webhook ID found")?;

                    let limit_type = match wa {
                        WebhookAction::Create => core::UserLimitTypes::WebhookAdd,
                        WebhookAction::Delete => core::UserLimitTypes::WebhookRemove,
                        _ => return Ok(()),
                    };

                    info!("Webhook {:?}: {}", wa, w_id);
                    if matches!(wa, WebhookAction::Create) {
                        protect::guard_webhook(Bot::from_ctx(ctx.serenity_context), &user_data.pool, *guild_id, entry.user_id, w_id.get()).await;
                    }
                    handler::handle_mod_action(
                        *guild_id,
                        entry.user_id,
                        &user_data.pool,
                        ctx.serenity_context,
                        limit_type,
                        w_id.to_string(),
                    )
                    .await
                }
                Action::Emoji(ea) => {
                    let e_id = entry.target_id.ok_or("No emoji ID found")?;

                    let limit_type = match ea {
                        EmojiAction::Create => core::UserLimitTypes::EmojiAdd,
                        EmojiAction::Delete => core::UserLimitTypes::EmojiRemove,
                        _ => return Ok(()),
                    };

                    info!("Emoji {:?}: {}", ea, e_id);
                    handler::handle_mod_action(
                        *guild_id,
                        entry.user_id,
                        &user_data.pool,
                        ctx.serenity_context,
                        limit_type,
                        e_id.to_string(),
                    )
                    .await
                }
                Action::Member(member_action) => {
                    let pool = &user_data.pool;
                    let bot = Bot::from_ctx(ctx.serenity_context);
                    let target = entry.target_id.map(|id| id.get());

                    match member_action {
                        MemberAction::BotAdd => {
                            let bot_id = UserId::new(target.ok_or("No bot ID found")?);
                            info!("Bot added: {}", bot_id);
                            protect::guard_bot_add(bot, pool, *guild_id, entry.user_id, bot_id).await;
                            record(ctx.serenity_context, pool, *guild_id, entry.user_id, core::UserLimitTypes::BotAdd, bot_id.to_string()).await
                        }
                        MemberAction::Prune => {
                            info!("Members pruned in {}", guild_id);
                            record(ctx.serenity_context, pool, *guild_id, entry.user_id, core::UserLimitTypes::MemberPrune, "prune".to_string()).await
                        }
                        MemberAction::RoleUpdate => {
                            let member_id = UserId::new(target.ok_or("No member ID found")?);
                            let changes = entry.changes.as_deref().unwrap_or_default();
                            if protect::guard_member_roles(bot, pool, *guild_id, entry.user_id, member_id, changes).await {
                                record(ctx.serenity_context, pool, *guild_id, entry.user_id, core::UserLimitTypes::DangerousPermission, member_id.to_string()).await
                            } else {
                                Ok(())
                            }
                        }
                        MemberAction::Kick | MemberAction::BanAdd | MemberAction::BanRemove => {
                            let target_id = target.ok_or("No member ID found")?;
                            let limit_type = match member_action {
                                MemberAction::Kick => core::UserLimitTypes::Kick,
                                MemberAction::BanAdd => core::UserLimitTypes::Ban,
                                _ => core::UserLimitTypes::Unban,
                            };
                            info!("{:?}: {}", member_action, target_id);
                            record(ctx.serenity_context, pool, *guild_id, entry.user_id, limit_type, target_id.to_string()).await
                        }
                        _ => Ok(()),
                    }
                }
                Action::GuildUpdate => {
                    info!("Server settings updated in {}", guild_id);
                    let changes = entry.changes.as_deref().unwrap_or_default();
                    protect::guard_vanity(Bot::from_ctx(ctx.serenity_context), &user_data.pool, *guild_id, entry.user_id, changes).await;
                    record(ctx.serenity_context, &user_data.pool, *guild_id, entry.user_id, core::UserLimitTypes::GuildUpdate, guild_id.to_string()).await
                }
                Action::Invite(InviteAction::Delete) => {
                    let target = entry.target_id.map(|id| id.to_string()).unwrap_or_else(|| "invite".to_string());
                    record(ctx.serenity_context, &user_data.pool, *guild_id, entry.user_id, core::UserLimitTypes::InviteDelete, target).await
                }
                Action::Integration(IntegrationAction::Delete) => {
                    let target = entry.target_id.map(|id| id.to_string()).unwrap_or_else(|| "integration".to_string());
                    record(ctx.serenity_context, &user_data.pool, *guild_id, entry.user_id, core::UserLimitTypes::IntegrationDelete, target).await
                }
                Action::Message(MessageAction::BulkDelete) => {
                    let target = entry.target_id.map(|id| id.to_string()).unwrap_or_else(|| "channel".to_string());
                    record(ctx.serenity_context, &user_data.pool, *guild_id, entry.user_id, core::UserLimitTypes::MessageBulkDelete, target).await
                }
                _ => Ok(()),
            };

            if let Err(res) = res {
                error!("Error while handling audit log: {}", res);
                return Err(res);
            }
        }
        FullEvent::GuildCreate { guild, is_new: Some(true) } => {
            info!("Joined guild {} ({})", guild.name, guild.id);
            health::welcome(Bot::from_ctx(ctx.serenity_context), guild.id).await;
        }
        FullEvent::AutoModActionExecution { execution } => {
            let user_data = ctx.serenity_context.data::<Data>();
            antiscam::record_execution(&user_data.pool, execution).await;
        }
        _ => {}
    }

    Ok(())
}

async fn record(
    ctx: &serenity::all::Context,
    pool: &sqlx::PgPool,
    guild_id: GuildId,
    user_id: UserId,
    kind: core::UserLimitTypes,
    target: String,
) -> Result<(), Error> {
    handler::handle_mod_action(guild_id, user_id, pool, ctx, kind, target).await
}

#[tokio::main]
async fn main() {
    const MAX_CONNECTIONS: u32 = 3;

    once_cell::sync::Lazy::force(&stats::START_TIME);

    std::env::set_var("RUST_LOG", "skynet=info");

    env_logger::init();

    if !config::CONFIG.proxy_url.trim().is_empty() {
        info!("Proxy URL: {}", config::CONFIG.proxy_url);
    }

    let mut http = serenity::all::HttpBuilder::new(&config::CONFIG.token)
        .ratelimiter_disabled(true);

    if !config::CONFIG.proxy_url.trim().is_empty() {
        http = http.proxy(config::CONFIG.proxy_url.clone());
    }

    let http = http.build();

    let client_builder = serenity::all::ClientBuilder::new_with_http(
        Arc::new(http),
        serenity::all::GatewayIntents::non_privileged(),
    );

    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect(&config::CONFIG.database_url)
        .await
        .expect("Could not initialize connection");

    info!("Applying database migrations");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Could not apply database migrations");

    let data = Data { pool };

    let owners = config::CONFIG
        .owners
        .iter()
        .cloned()
        .collect::<HashSet<UserId>>();

    let framework = poise::Framework::new(
        poise::FrameworkOptions {
            owners,
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("sky.".into()),
                ..poise::PrefixFrameworkOptions::default()
            },
            event_handler: |ctx, event| Box::pin(event_listener(ctx, event)),
            commands: vec![
                help::help(),
                help::simplehelp(),
                stats::stats(),
                cmds::ping(),
                cmds::perms(),
                cmds::setup(),
                cmds::settings(),
                cmds::limits(),
                cmds::actions(),
                cmds::whitelist(),
                cmds::lockdown(),
                cmds::antiscam(),
                cmds::health(),
                cmds::quarantine(),
                cmds::snapshot(),
                owner::guild(),
            ],
            command_check: Some(|ctx| {
                Box::pin(async move {
                    if ["help", "simplehelp", "ping"].contains(&ctx.command().name.as_str()) {
                        return Ok(true);
                    }

                    crate::utils::is_guild_admin(
                        &ctx,
                        &ctx.data().pool,
                        ctx.guild_id().ok_or("Could not get guild id")?,
                        ctx.author().id.to_string(),
                    )
                    .await?;

                    if let Some(guild_id) = ctx.guild_id() {
                        if ctx.command().name == "setup" {
                            return Ok(true);
                        }

                        let data = ctx.data();

                        let guild = sqlx::query!(
                            "
                            SELECT COUNT(*)
                            FROM guilds
                            WHERE guild_id = $1
                        ",
                            guild_id.to_string()
                        )
                        .fetch_one(&data.pool)
                        .await?;

                        if guild.count.unwrap_or_default() == 0 {
                            return Err("Please run ``/setup`` to get started!".into());
                        }

                        Ok(true)
                    } else {
                        Err("This command can only be run from servers".into())
                    }
                })
            }),
            pre_command: |ctx| {
                Box::pin(async move {
                    info!(
                        "Executing command {} for user {} ({})...",
                        ctx.command().qualified_name,
                        ctx.author().name,
                        ctx.author().id
                    );
                })
            },
            post_command: |ctx| {
                Box::pin(async move {
                    info!(
                        "Done executing command {} for user {} ({})...",
                        ctx.command().qualified_name,
                        ctx.author().name,
                        ctx.author().id
                    );
                })
            },
            on_error: |error| Box::pin(on_error(error)),
            ..Default::default()
        },
    );

    let mut client = client_builder
        .framework(framework)
        .data(Arc::new(data))
        .await
        .expect("Error creating client");

    if let Err(why) = client.start_autosharded().await {
        error!("Client error: {:?}", why);
    }
}
