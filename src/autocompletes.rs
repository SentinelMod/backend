use crate::Context;

pub async fn limits_autocomplete<'a>(
    ctx: Context<'_>,
    partial: &'a str,
) -> Vec<serenity::all::AutocompleteChoice<'a>> {
    let data = ctx.data();

    let guild_id = ctx.guild_id();

    if guild_id.is_none() {
        return Vec::new();
    }

    let guild_id = guild_id.unwrap();

    let limits = crate::core::Limit::from_guild(&data.pool, guild_id).await;

    if let Ok(limits) = limits {
        let mut choices = Vec::new();

        let partial = partial.to_ascii_lowercase();

        for limit in limits {
            if limit.limit_name.to_ascii_lowercase().contains(&partial) {
                choices.push(serenity::all::AutocompleteChoice::new(
                    limit.limit_name,
                    limit.limit_id,
                ));

                if choices.len() == 25 {
                    break;
                }
            }
        }

        return choices;
    }

    Vec::new()
}

pub async fn quarantine_autocomplete<'a>(
    ctx: Context<'_>,
    partial: &'a str,
) -> Vec<serenity::all::AutocompleteChoice<'a>> {
    let Some(guild_id) = ctx.guild_id() else { return Vec::new() };
    let rows: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT id, user_id, cardinality(roles) FROM quarantines WHERE guild_id = $1 AND restored_at IS NULL ORDER BY created_at DESC LIMIT 50",
    )
    .bind(guild_id.to_string())
    .fetch_all(&ctx.data().pool)
    .await
    .unwrap_or_default();

    let partial = partial.to_ascii_lowercase();
    rows.into_iter()
        .filter_map(|(id, user_id, count)| {
            let name = user_id
                .parse::<serenity::all::UserId>()
                .ok()
                .and_then(|uid| ctx.cache().guild(guild_id).and_then(|g| g.members.get(&uid).map(|m| m.display_name().to_string())))
                .unwrap_or(user_id);
            let label = format!("{} ({} roles)", name, count);
            label.to_ascii_lowercase().contains(&partial).then(|| serenity::all::AutocompleteChoice::new(label, id))
        })
        .take(25)
        .collect()
}

pub async fn snapshot_autocomplete<'a>(
    ctx: Context<'_>,
    partial: &'a str,
) -> Vec<serenity::all::AutocompleteChoice<'a>> {
    let Some(guild_id) = ctx.guild_id() else { return Vec::new() };
    let Ok(snapshots) = crate::recovery::list(&ctx.data().pool, guild_id).await else { return Vec::new() };
    let partial = partial.to_ascii_lowercase();
    snapshots
        .into_iter()
        .filter_map(|s| {
            let label = format!("{} {} ({} roles, {} channels)", &s.created_at[..16].replace('T', " "), s.trigger.replace('_', " "), s.role_count, s.channel_count);
            label.to_ascii_lowercase().contains(&partial).then(|| serenity::all::AutocompleteChoice::new(label, s.id))
        })
        .take(25)
        .collect()
}
