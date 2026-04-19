use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::event::CveSeverity;

/// Configuration for tameshi-watch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Health server bind address.
    pub listen_addr: String,
    /// Health server port.
    pub port: u16,
    /// Minimum severity threshold for events.
    pub severity_threshold: CveSeverity,
    /// Directory for poll state persistence.
    pub state_dir: PathBuf,
    /// NVD source configuration.
    pub nvd: NvdConfig,
    /// OSV source configuration.
    pub osv: OsvConfig,
    /// Profile watcher configuration.
    pub profiles: ProfilesConfig,
    /// Log format: "json" or "pretty".
    pub log_format: String,
}

/// NVD API configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NvdConfig {
    /// Enable NVD polling.
    pub enabled: bool,
    /// NVD API base URL.
    pub base_url: String,
    /// Optional NVD API key.
    pub api_key: Option<String>,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
}

/// OSV.dev configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsvConfig {
    /// Enable OSV polling.
    pub enabled: bool,
    /// OSV API base URL.
    pub base_url: String,
    /// Ecosystems to query.
    pub ecosystems: Vec<String>,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
}

/// Profile watcher configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfilesConfig {
    /// Enable profile watching.
    pub enabled: bool,
    /// Git repos to watch for new commits.
    pub repos: Vec<ProfileRepo>,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
}

/// A git repo to watch for compliance profile updates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileRepo {
    /// Profile identifier.
    pub id: String,
    /// Git remote URL.
    pub url: String,
    /// Branch to watch.
    pub branch: String,
    /// Profile source type.
    pub source: crate::event::ProfileSource,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            port: 9090,
            severity_threshold: CveSeverity::Low,
            state_dir: PathBuf::from("/tmp/tameshi-watch/state"),
            nvd: NvdConfig {
                enabled: true,
                base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
                api_key: None,
                poll_interval_secs: 300,
            },
            osv: OsvConfig {
                enabled: true,
                base_url: "https://api.osv.dev/v1".to_string(),
                ecosystems: vec!["npm".to_string(), "crates.io".to_string()],
                poll_interval_secs: 600,
            },
            profiles: ProfilesConfig {
                enabled: false,
                repos: vec![],
                poll_interval_secs: 3600,
            },
            log_format: "pretty".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from defaults, optional YAML file, and env vars.
    ///
    /// Priority: defaults < YAML < `TAMESHI_WATCH_` env vars.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be extracted.
    pub fn load(config_path: Option<&str>) -> Result<Self, shikumi::ShikumiError> {
        let mut chain = shikumi::ProviderChain::new().with_defaults(&Self::default());

        if let Some(path) = config_path {
            chain = chain.with_file(std::path::Path::new(path));
        }

        chain.with_env("TAMESHI_WATCH_").extract()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = Config::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1");
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.severity_threshold, CveSeverity::Low);
        assert!(cfg.nvd.enabled);
        assert!(cfg.osv.enabled);
        assert!(!cfg.profiles.enabled);
    }

    #[test]
    fn default_nvd_config() {
        let cfg = Config::default();
        assert!(cfg.nvd.base_url.contains("nvd.nist.gov"));
        assert!(cfg.nvd.api_key.is_none());
        assert_eq!(cfg.nvd.poll_interval_secs, 300);
    }

    #[test]
    fn default_osv_config() {
        let cfg = Config::default();
        assert!(cfg.osv.base_url.contains("osv.dev"));
        assert_eq!(cfg.osv.ecosystems.len(), 2);
        assert!(cfg.osv.ecosystems.contains(&"npm".to_string()));
        assert!(cfg.osv.ecosystems.contains(&"crates.io".to_string()));
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = Config::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.port, cfg.port);
        assert_eq!(back.listen_addr, cfg.listen_addr);
    }

    #[test]
    fn load_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            r#"
listen_addr: "0.0.0.0"
port: 8080
severity_threshold: critical
state_dir: /var/lib/tameshi-watch
nvd:
  enabled: false
  base_url: "https://example.com/nvd"
  api_key: "test-key"
  poll_interval_secs: 60
osv:
  enabled: true
  base_url: "https://api.osv.dev/v1"
  ecosystems:
    - npm
  poll_interval_secs: 120
profiles:
  enabled: true
  repos: []
  poll_interval_secs: 1800
log_format: json
"#,
        )
        .unwrap();

        let cfg = Config::load(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(cfg.listen_addr, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.severity_threshold, CveSeverity::Critical);
        assert!(!cfg.nvd.enabled);
        assert_eq!(cfg.nvd.api_key, Some("test-key".to_string()));
        assert!(cfg.profiles.enabled);
        assert_eq!(cfg.log_format, "json");
    }

    #[test]
    fn load_no_file_uses_defaults() {
        let cfg = Config::load(None).unwrap();
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn load_missing_file_uses_defaults() {
        let cfg = Config::load(Some("/nonexistent/path.yaml")).unwrap();
        assert_eq!(cfg.port, 9090);
    }

    #[test]
    fn profile_repo_serde() {
        let repo = ProfileRepo {
            id: "mitre-attack".to_string(),
            url: "https://github.com/mitre/cti".to_string(),
            branch: "master".to_string(),
            source: crate::event::ProfileSource::Mitre,
        };
        let json = serde_json::to_string(&repo).unwrap();
        let back: ProfileRepo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "mitre-attack");
    }

    #[test]
    fn nvd_config_with_api_key() {
        let cfg = NvdConfig {
            enabled: true,
            base_url: "https://example.com".to_string(),
            api_key: Some("my-key".to_string()),
            poll_interval_secs: 120,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("my-key"));
    }

    #[test]
    fn osv_config_custom_ecosystems() {
        let cfg = OsvConfig {
            enabled: true,
            base_url: "https://api.osv.dev/v1".to_string(),
            ecosystems: vec!["Go".to_string(), "PyPI".to_string(), "Maven".to_string()],
            poll_interval_secs: 300,
        };
        assert_eq!(cfg.ecosystems.len(), 3);
    }
}
