# Changelog

All notable changes to the Sentinel bot. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/). This file is also served at `/api/changelog` and shown on https://sentinelbot.space/changelog.

## [Unreleased]

## [1.0.0] - 2026-10-26

The first full release: protection that adapts to your server, recovery when something gets through, and a dashboard for all of it.

### Added

- Web dashboard with Discord sign-in for limits, guards, the whitelist, admins, activity, hits, moderators, recovery, settings and the audit trail.
- Escalation ladders, server-wide limits, dry-run mode and presets for small, large and strict servers.
- Quarantine response that stores roles so they can be restored in one click.
- Bot-add, dangerous permission, webhook and vanity URL guards.
- Manual and automatic lockdown that restores exactly what it removed.
- Scheduled and pre-lockdown snapshots, with restore for deleted roles, channels and permissions.
- Anti-scam AutoMod filters for scam links, mass mentions, @everyone and @here, and invites to other servers.
- `/health` and a dashboard health panel for missing permissions, role position and log channel problems.
- Welcome message with setup steps when Sentinel joins a server.
- Weekly digest, alert role pings and owner DMs.
- Config export and import between servers.
- Public aggregate stats and changelog endpoints.

### Changed

- Commands are slash-only.
- `/setup` finishes with a health check.

### Fixed

- Stale and duplicate slash commands are cleared and resynced on startup.
- Database migrations run automatically on startup.

[Unreleased]: https://github.com/SentinelMod/backend/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SentinelMod/backend/releases/tag/v1.0.0
