use poise::serenity_prelude::{GuildId, UserId};
use serde::Serialize;
use sqlx::{
    postgres::types::PgInterval,
    types::chrono::{DateTime, Utc},
    PgPool,
};
use strum_macros::{Display, EnumString, EnumVariantNames};

use crate::Error;

#[derive(poise::ChoiceParameter)]
pub enum UserLimitTypesChoices {
    #[name = "Role Create"]
    RoleAdd,
    #[name = "Role Update"]
    RoleUpdate,
    #[name = "Role Remove"]
    RoleRemove,
    #[name = "Channel Create"]
    ChannelAdd,
    #[name = "Channel Update"]
    ChannelUpdate,
    #[name = "Channel Remove"]
    ChannelRemove,
    #[name = "Kick"]
    Kick,
    #[name = "Ban"]
    Ban,
    #[name = "Unban"]
    Unban,
    #[name = "Webhook Create"]
    WebhookAdd,
    #[name = "Webhook Remove"]
    WebhookRemove,
    #[name = "Emoji Create"]
    EmojiAdd,
    #[name = "Emoji Remove"]
    EmojiRemove,
    #[name = "Bot Added"]
    BotAdd,
    #[name = "Member Prune"]
    MemberPrune,
    #[name = "Server Settings Update"]
    GuildUpdate,
    #[name = "Invite Delete"]
    InviteDelete,
    #[name = "Integration Delete"]
    IntegrationDelete,
    #[name = "Bulk Message Delete"]
    MessageBulkDelete,
    #[name = "Dangerous Permission Granted"]
    DangerousPermission,
}

impl UserLimitTypesChoices {
    pub fn resolve(self) -> UserLimitTypes {
        match self {
            Self::RoleAdd => UserLimitTypes::RoleAdd,
            Self::RoleUpdate => UserLimitTypes::RoleUpdate,
            Self::RoleRemove => UserLimitTypes::RoleRemove,
            Self::ChannelAdd => UserLimitTypes::ChannelAdd,
            Self::ChannelUpdate => UserLimitTypes::ChannelUpdate,
            Self::ChannelRemove => UserLimitTypes::ChannelRemove,
            Self::Kick => UserLimitTypes::Kick,
            Self::Ban => UserLimitTypes::Ban,
            Self::Unban => UserLimitTypes::Unban,
            Self::WebhookAdd => UserLimitTypes::WebhookAdd,
            Self::WebhookRemove => UserLimitTypes::WebhookRemove,
            Self::EmojiAdd => UserLimitTypes::EmojiAdd,
            Self::EmojiRemove => UserLimitTypes::EmojiRemove,
            Self::BotAdd => UserLimitTypes::BotAdd,
            Self::MemberPrune => UserLimitTypes::MemberPrune,
            Self::GuildUpdate => UserLimitTypes::GuildUpdate,
            Self::InviteDelete => UserLimitTypes::InviteDelete,
            Self::IntegrationDelete => UserLimitTypes::IntegrationDelete,
            Self::MessageBulkDelete => UserLimitTypes::MessageBulkDelete,
            Self::DangerousPermission => UserLimitTypes::DangerousPermission,
        }
    }
}

#[derive(EnumString, Display, PartialEq, EnumVariantNames, Clone, Debug, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum UserLimitTypes {
    RoleAdd,
    RoleUpdate,
    RoleRemove,
    ChannelAdd,
    ChannelUpdate,
    ChannelRemove,
    Kick,
    Ban,
    Unban,
    WebhookAdd,
    WebhookRemove,
    EmojiAdd,
    EmojiRemove,
    BotAdd,
    MemberPrune,
    GuildUpdate,
    InviteDelete,
    IntegrationDelete,
    MessageBulkDelete,
    DangerousPermission,
}

impl UserLimitTypes {
    pub const ALL: [UserLimitTypes; 20] = [
        Self::RoleAdd,
        Self::RoleUpdate,
        Self::RoleRemove,
        Self::ChannelAdd,
        Self::ChannelUpdate,
        Self::ChannelRemove,
        Self::Kick,
        Self::Ban,
        Self::Unban,
        Self::WebhookAdd,
        Self::WebhookRemove,
        Self::EmojiAdd,
        Self::EmojiRemove,
        Self::BotAdd,
        Self::MemberPrune,
        Self::GuildUpdate,
        Self::InviteDelete,
        Self::IntegrationDelete,
        Self::MessageBulkDelete,
        Self::DangerousPermission,
    ];

    pub fn to_cond(&self) -> String {
        match &self {
            Self::RoleAdd => "Roles Created",
            Self::RoleUpdate => "Roles Updated",
            Self::RoleRemove => "Roles Removed",
            Self::ChannelAdd => "Channels Created",
            Self::ChannelUpdate => "Channels Updated",
            Self::ChannelRemove => "Channels Removed",
            Self::Kick => "Kicks",
            Self::Ban => "Bans",
            Self::Unban => "Unbans",
            Self::WebhookAdd => "Webhooks Created",
            Self::WebhookRemove => "Webhooks Removed",
            Self::EmojiAdd => "Emoji Created",
            Self::EmojiRemove => "Emoji Removed",
            Self::BotAdd => "Bots Added",
            Self::MemberPrune => "Member Prunes",
            Self::GuildUpdate => "Server Settings Changes",
            Self::InviteDelete => "Invites Deleted",
            Self::IntegrationDelete => "Integrations Deleted",
            Self::MessageBulkDelete => "Bulk Message Deletes",
            Self::DangerousPermission => "Dangerous Permissions Granted",
        }
        .to_string()
    }
}

#[derive(poise::ChoiceParameter)]
pub enum UserLimitActionsChoices {
    #[name = "Alert Only"]
    NotifyOnly,
    #[name = "Timeout User"]
    TimeoutUser,
    #[name = "Quarantine (Remove All Roles)"]
    RemoveAllRoles,
    #[name = "Kick User"]
    KickUser,
    #[name = "Ban User"]
    BanUser,
}

impl UserLimitActionsChoices {
    pub fn resolve(self) -> UserLimitActions {
        match self {
            Self::NotifyOnly => UserLimitActions::NotifyOnly,
            Self::RemoveAllRoles => UserLimitActions::RemoveAllRoles,
            Self::KickUser => UserLimitActions::KickUser,
            Self::BanUser => UserLimitActions::BanUser,
            Self::TimeoutUser => UserLimitActions::TimeoutUser,
        }
    }
}

#[derive(EnumString, Display, PartialEq, EnumVariantNames, Clone, Debug, Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum UserLimitActions {
    NotifyOnly,
    TimeoutUser,
    RemoveAllRoles,
    KickUser,
    BanUser,
}

impl UserLimitActions {
    pub const ALL: [UserLimitActions; 5] = [
        Self::NotifyOnly,
        Self::TimeoutUser,
        Self::RemoveAllRoles,
        Self::KickUser,
        Self::BanUser,
    ];

    pub fn to_cond(&self) -> String {
        match &self {
            Self::NotifyOnly => "Alert Only",
            Self::RemoveAllRoles => "Quarantine (Remove All Roles)",
            Self::KickUser => "Kick User",
            Self::BanUser => "Ban User",
            Self::TimeoutUser => "Timeout User",
        }
        .to_string()
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::NotifyOnly => 0,
            Self::TimeoutUser => 1,
            Self::RemoveAllRoles => 2,
            Self::KickUser => 3,
            Self::BanUser => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Action {
    pub action_id: String,
    pub limit_type: UserLimitTypes,
    pub created_at: DateTime<Utc>,
    pub user_id: UserId,
    pub guild_id: GuildId,
    pub action_target: String,
    pub limits_hit: Vec<String>,
}

impl Action {
    /// Fetch actions for a action id
    pub async fn by_id(
        pool: &PgPool,
        guild_id: GuildId,
        action_id: &str,
    ) -> Result<Self, Error> {
        let r = sqlx::query!(
            "
                SELECT user_id, limit_type, created_at, action_target, limits_hit
                FROM user_actions
                WHERE guild_id = $1
                AND action_id = $2
            ",
            guild_id.to_string(),
            action_id.to_string()
        )
        .fetch_one(pool)
        .await?;


    let actions = Self {
            guild_id,
            action_id: action_id.to_string(),
            user_id: r.user_id.parse()?,
            limit_type: r.limit_type.parse()?,
            created_at: r.created_at,
            action_target: r.action_target.parse()?,
            limits_hit: r.limits_hit,
        };

        Ok(actions)
    }

    /// Fetch actions for user
    pub async fn user(
        pool: &PgPool,
        guild_id: GuildId,
        user_id: UserId,
    ) -> Result<Vec<Self>, Error> {
        let rec = sqlx::query!(
            "
                SELECT action_id, limit_type, created_at, action_target, limits_hit
                FROM user_actions
                WHERE guild_id = $1
                AND user_id = $2
            ",
            guild_id.to_string(),
            user_id.to_string()
        )
        .fetch_all(pool)
        .await?;

        let mut actions = Vec::new();

        for r in rec {
            actions.push(Self {
                guild_id,
                user_id,
                action_id: r.action_id,
                limit_type: r.limit_type.parse()?,
                created_at: r.created_at,
                action_target: r.action_target.parse()?,
                limits_hit: r.limits_hit,
            });
        }

        Ok(actions)
    }

    /// Fetch actions for guild
    pub async fn guild(pool: &PgPool, guild_id: GuildId) -> Result<Vec<Self>, Error> {
        let rec = sqlx::query!(
            "
                SELECT action_id, limit_type, created_at, user_id, action_target, limits_hit
                FROM user_actions
                WHERE guild_id = $1
            ",
            guild_id.to_string()
        )
        .fetch_all(pool)
        .await?;

        let mut actions = Vec::new();

        for r in rec {
            actions.push(Self {
                guild_id,
                action_id: r.action_id,
                limit_type: r.limit_type.parse()?,
                created_at: r.created_at,
                user_id: r.user_id.parse()?,
                action_target: r.action_target.parse()?,
                limits_hit: r.limits_hit,
            });
        }

        Ok(actions)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Limit {
    pub guild_id: GuildId,
    pub limit_id: String,
    pub limit_name: String,
    pub limit_type: UserLimitTypes,
    pub limit_action: UserLimitActions,
    pub limit_per: i32,
    pub limit_time: PgInterval,
    pub limit_timeout_duration: Option<PgInterval>,
}

impl Limit {
    pub async fn from_guild(pool: &PgPool, guild_id: GuildId) -> Result<Vec<Self>, Error> {
        let rec = sqlx::query!(
            "
                SELECT limit_id, limit_name, limit_type, limit_action, limit_per, limit_time, limit_timeout_duration
                FROM limits
                WHERE guild_id = $1
            ",
            guild_id.to_string()
        )
        .fetch_all(pool)
        .await?;

        let mut limits = Vec::new();

        for r in rec {
            limits.push(Self {
                guild_id,
                limit_id: r.limit_id,
                limit_name: r.limit_name,
                limit_type: r.limit_type.parse()?,
                limit_action: r.limit_action.parse()?,
                limit_per: r.limit_per,
                limit_time: r.limit_time,
                limit_timeout_duration: r.limit_timeout_duration,
            });
        }

        Ok(limits)
    }
}

/// Returns whether a user (directly, or via one of their roles) is whitelisted
/// from limit tracking in a guild.
pub async fn is_whitelisted(
    pool: &PgPool,
    guild_id: GuildId,
    user_id: UserId,
    role_ids: &[poise::serenity_prelude::RoleId],
) -> Result<bool, Error> {
    let mut entity_ids: Vec<String> = vec![user_id.to_string()];
    entity_ids.extend(role_ids.iter().map(|r| r.to_string()));

    let count = sqlx::query!(
        "
            SELECT COUNT(*) FROM guild_whitelist
            WHERE guild_id = $1
            AND entity_id = ANY($2)
        ",
        guild_id.to_string(),
        &entity_ids
    )
    .fetch_one(pool)
    .await?;

    Ok(count.count.unwrap_or_default() > 0)
}

#[derive(Debug, Serialize)]
pub struct PastHitLimits {
    pub id: String,
    pub user_id: UserId,
    pub guild_id: GuildId,
    pub limit_id: String,
    pub cause: Vec<Action>,
    pub notes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl PastHitLimits {
    /// Fetch actions for guild
    pub async fn guild(pool: &PgPool, guild_id: GuildId) -> Result<Vec<Self>, Error> {
        let rec = sqlx::query!(
            "
                SELECT id, user_id, limit_id, cause, notes, created_at FROM past_hit_limits
                WHERE guild_id = $1
            ",
            guild_id.to_string()
        )
        .fetch_all(pool)
        .await?;

        let mut hits = Vec::new();

        for r in rec {
            let mut cause = vec![];

            for action in r.cause {
                cause.push(Action::by_id(pool, guild_id, &action).await?);
            }

            hits.push(Self {
                guild_id,
                id: r.id,
                limit_id: r.limit_id,
                created_at: r.created_at,
                user_id: r.user_id.parse()?,
                notes: r.notes,
                cause,
            });
        }

        Ok(hits)
    }    
}