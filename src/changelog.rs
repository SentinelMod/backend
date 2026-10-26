use axum::Json;
use once_cell::sync::Lazy;
use serde::Serialize;

const SOURCE: &str = include_str!("../CHANGELOG.md");

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Group {
    pub kind: String,
    pub items: Vec<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Release {
    pub version: String,
    pub date: Option<String>,
    pub summary: String,
    pub groups: Vec<Group>,
}

static RELEASES: Lazy<Vec<Release>> = Lazy::new(|| parse(SOURCE));

pub fn parse(source: &str) -> Vec<Release> {
    let mut releases: Vec<Release> = vec![];
    for line in source.lines() {
        let trimmed = line.trim_end();
        if let Some(heading) = trimmed.strip_prefix("## ") {
            let (version, date) = match heading.split_once(" - ") {
                Some((v, d)) => (v, Some(d.trim().to_string())),
                None => (heading, None),
            };
            releases.push(Release {
                version: version.trim().trim_start_matches('[').trim_end_matches(']').to_string(),
                date,
                summary: String::new(),
                groups: vec![],
            });
            continue;
        }
        let Some(release) = releases.last_mut() else { continue };
        if let Some(kind) = trimmed.strip_prefix("### ") {
            release.groups.push(Group { kind: kind.trim().to_lowercase(), items: vec![] });
        } else if let Some(item) = trimmed.trim_start().strip_prefix("- ") {
            if let Some(group) = release.groups.last_mut() {
                group.items.push(item.trim().to_string());
            }
        } else if !trimmed.trim().is_empty() {
            if release.groups.is_empty() {
                if !release.summary.is_empty() {
                    release.summary.push(' ');
                }
                release.summary.push_str(trimmed.trim());
            } else if line.starts_with(' ') {
                if let Some(item) = release.groups.last_mut().and_then(|g| g.items.last_mut()) {
                    item.push(' ');
                    item.push_str(trimmed.trim());
                }
            }
        }
    }
    releases.retain(|r| !r.version.eq_ignore_ascii_case("unreleased") && r.groups.iter().any(|g| !g.items.is_empty()));
    releases
}

pub fn releases() -> &'static [Release] {
    RELEASES.as_slice()
}

pub async fn changelog() -> Json<&'static [Release]> {
    Json(RELEASES.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_releases() {
        let source = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n## [1.1.0] - 2026-11-01\n\nA summary\nover two lines.\n\n### Added\n\n- One\n- Two that\n  wraps\n\n### Fixed\n\n- Three\n\n## [1.0.0] - 2026-10-26\n\n### Added\n\n- First\n";
        let releases = parse(source);
        assert_eq!(releases.len(), 2);
        assert_eq!(releases[0].version, "1.1.0");
        assert_eq!(releases[0].date.as_deref(), Some("2026-11-01"));
        assert_eq!(releases[0].summary, "A summary over two lines.");
        assert_eq!(releases[0].groups[0], Group { kind: "added".into(), items: vec!["One".into(), "Two that wraps".into()] });
        assert_eq!(releases[0].groups[1].kind, "fixed");
        assert_eq!(releases[1].summary, "");
    }

    #[test]
    fn bundled_changelog_has_current_version() {
        assert!(RELEASES.iter().any(|r| r.version == env!("CARGO_PKG_VERSION")));
    }
}
