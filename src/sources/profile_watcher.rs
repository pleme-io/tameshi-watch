use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::config::ProfileRepo;
use crate::error::WatchError;
use crate::event::ComplianceEvent;
use crate::sources::SourcePoller;

/// Watches git repos for new commits via `git ls-remote`.
pub struct ProfileWatcher {
    #[allow(dead_code)]
    repos: Vec<ProfileRepo>,
    poll_interval: Duration,
}

impl ProfileWatcher {
    /// Create a new profile watcher.
    #[must_use]
    pub fn new(repos: Vec<ProfileRepo>, poll_interval: Duration) -> Self {
        Self {
            repos,
            poll_interval,
        }
    }
}

impl SourcePoller for ProfileWatcher {
    fn name(&self) -> &str {
        "profile_watcher"
    }

    fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn poll(
        &self,
        _since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ComplianceEvent>, WatchError>> + Send + '_>> {
        // In production, this would run git ls-remote. For now, return empty.
        Box::pin(async { Ok(vec![]) })
    }
}

/// Parse the output of `git ls-remote` to extract the HEAD commit hash.
///
/// Format: `<hash>\tHEAD` or `<hash>\trefs/heads/<branch>`
#[must_use]
pub fn parse_ls_remote(output: &str, branch: &str) -> Option<String> {
    let ref_suffix = format!("refs/heads/{branch}");

    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            let hash = parts[0].trim();
            let refname = parts[1].trim();

            if refname == ref_suffix || (branch == "HEAD" && refname == "HEAD") {
                if hash.len() >= 7 {
                    return Some(hash.to_string());
                }
            }
        }
    }
    None
}

/// Build a `ProfileUpdated` event from a repo config and detected commit.
#[must_use]
pub fn build_profile_event(repo: &ProfileRepo, commit: &str) -> ComplianceEvent {
    ComplianceEvent::ProfileUpdated {
        profile_id: repo.id.clone(),
        source: repo.source.clone(),
        repo_url: repo.url.clone(),
        new_commit: commit.to_string(),
        timestamp: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ProfileSource;

    #[test]
    fn parse_ls_remote_head() {
        let output = "abc123def456\tHEAD\n";
        let result = parse_ls_remote(output, "HEAD");
        assert_eq!(result, Some("abc123def456".to_string()));
    }

    #[test]
    fn parse_ls_remote_branch() {
        let output = "abc123def456\trefs/heads/main\nxyz789\trefs/heads/develop\n";
        let result = parse_ls_remote(output, "main");
        assert_eq!(result, Some("abc123def456".to_string()));
    }

    #[test]
    fn parse_ls_remote_develop_branch() {
        let output = "abc123def456\trefs/heads/main\nxyz789012345\trefs/heads/develop\n";
        let result = parse_ls_remote(output, "develop");
        assert_eq!(result, Some("xyz789012345".to_string()));
    }

    #[test]
    fn parse_ls_remote_no_match() {
        let output = "abc123def456\trefs/heads/main\n";
        let result = parse_ls_remote(output, "feature-branch");
        assert!(result.is_none());
    }

    #[test]
    fn parse_ls_remote_empty() {
        let result = parse_ls_remote("", "main");
        assert!(result.is_none());
    }

    #[test]
    fn parse_ls_remote_full_hash() {
        let output = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\trefs/heads/main\n";
        let result = parse_ls_remote(output, "main");
        assert_eq!(
            result,
            Some("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string())
        );
    }

    #[test]
    fn parse_ls_remote_short_hash_rejected() {
        let output = "abc\trefs/heads/main\n";
        let result = parse_ls_remote(output, "main");
        assert!(result.is_none());
    }

    #[test]
    fn build_profile_event_mitre() {
        let repo = ProfileRepo {
            id: "mitre-attack".to_string(),
            url: "https://github.com/mitre/cti".to_string(),
            branch: "master".to_string(),
            source: ProfileSource::Mitre,
        };
        let event = build_profile_event(&repo, "abc123");
        if let ComplianceEvent::ProfileUpdated {
            profile_id,
            new_commit,
            source,
            ..
        } = &event
        {
            assert_eq!(profile_id, "mitre-attack");
            assert_eq!(new_commit, "abc123");
            assert_eq!(*source, ProfileSource::Mitre);
        } else {
            panic!("expected ProfileUpdated");
        }
    }

    #[test]
    fn build_profile_event_devsec() {
        let repo = ProfileRepo {
            id: "devsec-linux".to_string(),
            url: "https://github.com/dev-sec/linux-baseline".to_string(),
            branch: "master".to_string(),
            source: ProfileSource::DevSec,
        };
        let event = build_profile_event(&repo, "def456");
        if let ComplianceEvent::ProfileUpdated {
            profile_id, source, ..
        } = &event
        {
            assert_eq!(profile_id, "devsec-linux");
            assert_eq!(*source, ProfileSource::DevSec);
        } else {
            panic!("expected ProfileUpdated");
        }
    }

    #[test]
    fn profile_watcher_name() {
        let watcher = ProfileWatcher::new(vec![], Duration::from_secs(3600));
        assert_eq!(watcher.name(), "profile_watcher");
    }

    #[test]
    fn profile_watcher_interval() {
        let watcher = ProfileWatcher::new(vec![], Duration::from_secs(1800));
        assert_eq!(watcher.poll_interval(), Duration::from_secs(1800));
    }

    #[tokio::test]
    async fn profile_watcher_returns_empty_without_git() {
        let watcher = ProfileWatcher::new(vec![], Duration::from_secs(60));
        let result = watcher.poll(None).await.unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_ls_remote_multiple_refs() {
        let output = "\
a1b2c3d4e5f6\tHEAD\n\
a1b2c3d4e5f6\trefs/heads/main\n\
f6e5d4c3b2a1\trefs/heads/develop\n\
1234567890ab\trefs/tags/v1.0.0\n";
        assert_eq!(
            parse_ls_remote(output, "main"),
            Some("a1b2c3d4e5f6".to_string())
        );
        assert_eq!(
            parse_ls_remote(output, "HEAD"),
            Some("a1b2c3d4e5f6".to_string())
        );
    }
}
