# Sentinel

Sentinel is a Discord moderation safety bot that helps server administrators detect destructive moderation activity and respond before a mistake or raid becomes a disaster.

It tracks moderation events per moderator, lets administrators define thresholds, and responds automatically when a configured limit is reached. Sentinel is designed to be focused and understandable rather than a replacement for a large, all-in-one moderation suite.

## Features

- Monitor role, channel, webhook and emoji changes, kicks, bans, unbans, bots added, member prunes, server settings changes, invite and integration deletes, bulk message deletes, and dangerous permission grants.
- Count each moderator separately against per-server thresholds and time windows.
- Respond with Alert Only, Timeout, Quarantine (roles are stored and can be restored), Kick, or Ban. Several limits on the same event form an escalation ladder; the most severe applicable response runs.
- Bot-add guard and dangerous permission guard that revert changes made by members who are not the owner or whitelisted.
- `/lockdown` strips dangerous permissions from roles and pauses invites, then restores exactly what it removed.
- Optional anti-scam filters built on Discord AutoMod: block phishing domains, fake Nitro and Steam links, stealer and grabber adverts, mass mentions, @everyone and @here, and invites to other servers. Off until enabled with `/antiscam setup` or the dashboard.
- Alerts in the log channel with an optional role ping, plus a DM to the server owner.
- Whitelist trusted users and roles.
- An audit trail of configuration changes, guard interventions and lockdowns.
- A web dashboard for reviewing and editing everything above, and a public aggregate stats endpoint.

## Commands

The main workflow is:

1. Run `/setup` once in the server.
2. Run `/limits guide` for an explanation of the limit system.
3. Run `/limits add` and choose the event, threshold, time window, and response.
4. Use `/limits view` to review limits.
5. Use `/limits hit` to review triggered limits.
6. Use `/limits edit` and `/limits remove` to change limits from the autocomplete list.
7. Use `/settings` to configure the log channel, alerts and guards.
8. Use `/whitelist add` to exempt trusted bots and staff.
9. Run `/health` to check Sentinel has the permissions and role position it needs.
10. Use `/antiscam setup` to turn on the scam link, mass mention, @everyone and invite filters.

During an incident, `/lockdown start` and `/lockdown end` contain and restore the server, and `/quarantine view` and `/quarantine restore` review members Sentinel quarantined.

Other useful commands include `/actions view`, `/help`, `/simplehelp`, and `/stats`.

`/settings` accepts optional values so you can change one setting at a time:

- `logs_channel`: the channel where Sentinel posts audit event embeds.
- `logs_enabled`: whether Sentinel posts notifications. Limits and action history continue to work when this is disabled.
- `logs_color`: an embed color such as `0x3498DB` or its decimal value.
- `alert_role` / `clear_alert_role`: a role to ping when a limit or guard fires.
- `dm_owner`: whether the server owner is sent a DM when a limit or guard fires.
- `guard_bot_add`: remove bots added by members who are not the owner or whitelisted. Off by default.
- `guard_dangerous_perms`: revert dangerous permissions granted by members who are not the owner or whitelisted. Off by default.

The settings command does not clear an existing channel when `logs_channel` is omitted. Run it with the channel you want to replace. Only guild owners and Sentinel guild admins can use it.

## Required Discord permissions

Invite Sentinel with the permissions required by the responses you configure:

- View Audit Log
- View Channels
- Send Messages
- Embed Links
- Read Message History
- Manage Roles, if using Quarantine, the dangerous permission guard, or lockdown
- Moderate Members, if using Timeout User or the anti-scam timeout
- Kick Members, if using Kick User or the bot-add guard
- Ban Members, if using Ban User
- Manage Webhooks, if using the webhook guard
- Manage Channels, if restoring deleted channels from a snapshot
- Manage Server, if lockdown should pause invites or anti-scam is enabled

The configured logs channel must also allow Sentinel to view the channel, send messages, and embed links.

Sentinel cannot manage roles above its highest role. Move the bot role above the roles it needs to remove, and enable the required privileged intents if the Discord application configuration asks for them.

## Configuration

Sentinel supports either `config.yaml` or environment variables. Environment variables are convenient for Docker and Dokploy deployments. A `.env` file is also accepted for local development and should not be committed.

Required environment variables:

```text
DATABASE_URL=postgres://user:password@host:5432/sentinel
DISCORD_TOKEN=your-bot-token
DISCORD_CLIENT_ID=your-application-client-id
DISCORD_CLIENT_SECRET=your-oauth-client-secret
```

Optional variables:

```text
FRONTEND_URL=https://sentinelbot.space
PROXY_URL=https://your-proxy.example
API_BIND_ADDR=127.0.0.1:4950
DASHBOARD_API_SECRET=a-long-random-string
ANTISCAM_FEED_URL=https://example.com/domains.json
OMNIPLEX_TOKEN=your-omniplex-bot-token
```

`DASHBOARD_API_SECRET` enables the dashboard API and must match the website's value. `FRONTEND_URL` is used for dashboard links in alerts. `ANTISCAM_FEED_URL` overrides the scam domain list (JSON with a `domains` array, or one domain per line). `OMNIPLEX_TOKEN` is the bot token from Omniplex; when set, Sentinel replaces its Omniplex command list on startup, posts any `CHANGELOG.md` version it has not posted yet, and posts server, shard and user counts every 15 minutes. `OMNIPLEX_API_URL` overrides the API base.

The website (`frontend/.env.local`) uses:

```text
BOT_API_URL=http://127.0.0.1:4950
DASHBOARD_API_SECRET=the-same-random-string
DISCORD_CLIENT_SECRET=your-oauth-client-secret
SITE_URL=https://sentinelbot.space
```

Add `<SITE_URL>/api/auth/callback` as an OAuth2 redirect in the Discord developer portal.

`TOKEN`, `CLIENT_ID`, and `CLIENT_SECRET` are also accepted as compatibility aliases. `PROXY_URL` can be omitted.

## Run locally

Install Rust and PostgreSQL, create an empty database, point `DATABASE_URL` at it, then run:

```powershell
cargo run
```

### Database migrations

Sentinel applies the SQL files in [migrations](backend/migrations) automatically on startup, in order, and records each one in the `_sqlx_migrations` table so it only runs once. A fresh database gets the full schema; an existing database is brought up to date. Every migration is idempotent, so databases created before automatic migrations existed are upgraded safely.

To change the schema, add a new numbered file such as `005_description.sql`. Never edit a migration that has already been deployed: Sentinel verifies checksums and refuses to start if an applied migration has changed.

The database user needs permission to create tables, and on first run to create the `uuid-ossp` extension.

For a release build:

```powershell
cargo build --release
```

## Docker

The included [Dockerfile](Dockerfile) installs the native build dependencies required by the Rust dependencies and includes Git metadata during the build so the bot can display its commit information.

```powershell
docker build -t sentinel-bot .
docker run --rm --env-file .env sentinel-bot
```

Do not copy `.env` into the image or commit it to the repository.

## Dokploy and Railpack

Create a service from this repository and provide the required environment variables in the service settings. Dokploy can build the included Dockerfile. Railpack can use [railpack.json](railpack.json), but the Dockerfile is the preferred path when you need the repository metadata and native build packages to be explicit.

The application listens for the OAuth web server when the bot becomes ready. Make sure the configured `FRONTEND_URL` and any reverse-proxy or public routing settings match the deployment.

The same server exposes public read-only endpoints for the website:

- `GET /api/stats` returns availability, release, and capability metadata.
- `GET /api/commands` returns the public command catalog used by the website.

Set `API_BIND_ADDR` to the address required by your deployment. The web frontend can proxy these endpoints by setting `BOT_API_URL` to the bot's base URL.

## Project identity

The user-facing bot name is **Sentinel**. The Rust package and executable are still named `skynet` for deployment compatibility with existing services, Docker commands, and databases. Renaming those internal identifiers requires a coordinated deployment migration.