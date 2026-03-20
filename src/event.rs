use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A compliance event ingested from an external source.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ComplianceEvent {
    /// A new CVE was published.
    NewCve {
        cve_id: String,
        severity: CveSeverity,
        affected_packages: Vec<AffectedPackage>,
        description: String,
        source: EventSource,
        timestamp: DateTime<Utc>,
    },
    /// A compliance profile was updated (new commit).
    ProfileUpdated {
        profile_id: String,
        source: ProfileSource,
        repo_url: String,
        new_commit: String,
        timestamp: DateTime<Utc>,
    },
    /// A specific package version was found vulnerable.
    PackageVulnerable {
        package: String,
        ecosystem: String,
        version: String,
        vulnerability_id: String,
        severity: CveSeverity,
        fix_version: Option<String>,
        source: EventSource,
        timestamp: DateTime<Utc>,
    },
}

impl ComplianceEvent {
    /// Returns a unique identifier for deduplication.
    #[must_use]
    pub fn dedup_id(&self) -> String {
        match self {
            Self::NewCve { cve_id, source, .. } => {
                format!("cve:{cve_id}:{source:?}")
            }
            Self::ProfileUpdated {
                profile_id,
                new_commit,
                ..
            } => {
                format!("profile:{profile_id}:{new_commit}")
            }
            Self::PackageVulnerable {
                package,
                vulnerability_id,
                version,
                ..
            } => {
                format!("pkg:{package}:{version}:{vulnerability_id}")
            }
        }
    }

    /// Returns the severity of this event, if applicable.
    #[must_use]
    pub fn severity(&self) -> Option<&CveSeverity> {
        match self {
            Self::NewCve { severity, .. } | Self::PackageVulnerable { severity, .. } => {
                Some(severity)
            }
            Self::ProfileUpdated { .. } => None,
        }
    }

    /// Returns the timestamp of this event.
    #[must_use]
    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            Self::NewCve { timestamp, .. }
            | Self::ProfileUpdated { timestamp, .. }
            | Self::PackageVulnerable { timestamp, .. } => timestamp,
        }
    }

    /// Returns a BLAKE3 hash of the event's dedup ID.
    #[must_use]
    pub fn content_hash(&self) -> String {
        let hash = blake3::hash(self.dedup_id().as_bytes());
        hash.to_hex().to_string()
    }
}

/// CVE severity level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl CveSeverity {
    /// Numeric rank for ordering (higher = more severe).
    #[must_use]
    pub fn rank(&self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Unknown => 0,
        }
    }

    /// Returns true if this severity meets or exceeds the threshold.
    #[must_use]
    pub fn meets_threshold(&self, threshold: &Self) -> bool {
        self.rank() >= threshold.rank()
    }
}

impl PartialOrd for CveSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CveSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

/// A package affected by a CVE.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AffectedPackage {
    pub name: String,
    pub ecosystem: Option<String>,
    pub version_range: Option<String>,
    pub fixed_version: Option<String>,
}

/// Source of a compliance event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Nvd,
    Osv,
    GitHubAdvisory,
    RustAdvisory,
    NixVuln,
}

/// Source of a compliance profile update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSource {
    Mitre,
    DevSec,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_timestamp() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn new_cve_serde_roundtrip() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-1234".to_string(),
            severity: CveSeverity::Critical,
            affected_packages: vec![AffectedPackage {
                name: "openssl".to_string(),
                ecosystem: Some("npm".to_string()),
                version_range: Some("< 3.0.12".to_string()),
                fixed_version: Some("3.0.12".to_string()),
            }],
            description: "A critical vulnerability".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ComplianceEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ComplianceEvent::NewCve { .. }));
    }

    #[test]
    fn profile_updated_serde_roundtrip() {
        let event = ComplianceEvent::ProfileUpdated {
            profile_id: "nist-800-53".to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://github.com/mitre/nist-800-53".to_string(),
            new_commit: "abc123".to_string(),
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ComplianceEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ComplianceEvent::ProfileUpdated { .. }));
    }

    #[test]
    fn package_vulnerable_serde_roundtrip() {
        let event = ComplianceEvent::PackageVulnerable {
            package: "lodash".to_string(),
            ecosystem: "npm".to_string(),
            version: "4.17.20".to_string(),
            vulnerability_id: "GHSA-xxxx".to_string(),
            severity: CveSeverity::High,
            fix_version: Some("4.17.21".to_string()),
            source: EventSource::GitHubAdvisory,
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ComplianceEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ComplianceEvent::PackageVulnerable { .. }));
    }

    #[test]
    fn package_vulnerable_no_fix_version() {
        let event = ComplianceEvent::PackageVulnerable {
            package: "foo".to_string(),
            ecosystem: "crates.io".to_string(),
            version: "0.1.0".to_string(),
            vulnerability_id: "RUSTSEC-2024-0001".to_string(),
            severity: CveSeverity::Medium,
            fix_version: None,
            source: EventSource::RustAdvisory,
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"fix_version\":null"));
        let back: ComplianceEvent = serde_json::from_str(&json).unwrap();
        if let ComplianceEvent::PackageVulnerable { fix_version, .. } = back {
            assert!(fix_version.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn severity_ordering_critical_highest() {
        assert!(CveSeverity::Critical > CveSeverity::High);
        assert!(CveSeverity::High > CveSeverity::Medium);
        assert!(CveSeverity::Medium > CveSeverity::Low);
        assert!(CveSeverity::Low > CveSeverity::Unknown);
    }

    #[test]
    fn severity_ordering_equal() {
        assert_eq!(CveSeverity::Critical, CveSeverity::Critical);
        assert_eq!(CveSeverity::Unknown, CveSeverity::Unknown);
    }

    #[test]
    fn severity_rank_values() {
        assert_eq!(CveSeverity::Critical.rank(), 4);
        assert_eq!(CveSeverity::High.rank(), 3);
        assert_eq!(CveSeverity::Medium.rank(), 2);
        assert_eq!(CveSeverity::Low.rank(), 1);
        assert_eq!(CveSeverity::Unknown.rank(), 0);
    }

    #[test]
    fn severity_meets_threshold() {
        assert!(CveSeverity::Critical.meets_threshold(&CveSeverity::High));
        assert!(CveSeverity::High.meets_threshold(&CveSeverity::High));
        assert!(!CveSeverity::Medium.meets_threshold(&CveSeverity::High));
        assert!(CveSeverity::Low.meets_threshold(&CveSeverity::Unknown));
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in &[
            CveSeverity::Critical,
            CveSeverity::High,
            CveSeverity::Medium,
            CveSeverity::Low,
            CveSeverity::Unknown,
        ] {
            let json = serde_json::to_string(sev).unwrap();
            let back: CveSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, sev);
        }
    }

    #[test]
    fn severity_serde_snake_case() {
        let json = serde_json::to_string(&CveSeverity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let json = serde_json::to_string(&CveSeverity::Unknown).unwrap();
        assert_eq!(json, "\"unknown\"");
    }

    #[test]
    fn affected_package_with_all_fields() {
        let pkg = AffectedPackage {
            name: "openssl".to_string(),
            ecosystem: Some("debian".to_string()),
            version_range: Some("< 1.1.1w".to_string()),
            fixed_version: Some("1.1.1w".to_string()),
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let back: AffectedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pkg);
    }

    #[test]
    fn affected_package_minimal() {
        let pkg = AffectedPackage {
            name: "curl".to_string(),
            ecosystem: None,
            version_range: None,
            fixed_version: None,
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let back: AffectedPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pkg);
    }

    #[test]
    fn event_source_all_variants() {
        let sources = vec![
            EventSource::Nvd,
            EventSource::Osv,
            EventSource::GitHubAdvisory,
            EventSource::RustAdvisory,
            EventSource::NixVuln,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: EventSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, src);
        }
    }

    #[test]
    fn event_source_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&EventSource::GitHubAdvisory).unwrap(),
            "\"git_hub_advisory\""
        );
        assert_eq!(
            serde_json::to_string(&EventSource::NixVuln).unwrap(),
            "\"nix_vuln\""
        );
    }

    #[test]
    fn profile_source_all_variants() {
        let sources = vec![ProfileSource::Mitre, ProfileSource::DevSec];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: ProfileSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, src);
        }
    }

    #[test]
    fn dedup_id_cve() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        assert!(event.dedup_id().starts_with("cve:CVE-2024-0001:"));
    }

    #[test]
    fn dedup_id_profile() {
        let event = ComplianceEvent::ProfileUpdated {
            profile_id: "nist".to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://example.com".to_string(),
            new_commit: "abc123".to_string(),
            timestamp: sample_timestamp(),
        };
        assert_eq!(event.dedup_id(), "profile:nist:abc123");
    }

    #[test]
    fn dedup_id_package() {
        let event = ComplianceEvent::PackageVulnerable {
            package: "foo".to_string(),
            ecosystem: "npm".to_string(),
            version: "1.0.0".to_string(),
            vulnerability_id: "GHSA-1234".to_string(),
            severity: CveSeverity::Low,
            fix_version: None,
            source: EventSource::Osv,
            timestamp: sample_timestamp(),
        };
        assert_eq!(event.dedup_id(), "pkg:foo:1.0.0:GHSA-1234");
    }

    #[test]
    fn content_hash_deterministic() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-9999".to_string(),
            severity: CveSeverity::Critical,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        let h1 = event.content_hash();
        let h2 = event.content_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // BLAKE3 hex length
    }

    #[test]
    fn severity_method_returns_some_for_cve() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        assert_eq!(event.severity(), Some(&CveSeverity::High));
    }

    #[test]
    fn severity_method_returns_none_for_profile() {
        let event = ComplianceEvent::ProfileUpdated {
            profile_id: "nist".to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://example.com".to_string(),
            new_commit: "abc".to_string(),
            timestamp: sample_timestamp(),
        };
        assert!(event.severity().is_none());
    }

    #[test]
    fn new_cve_tagged_json() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"new_cve\""));
    }

    #[test]
    fn multiple_affected_packages() {
        let event = ComplianceEvent::NewCve {
            cve_id: "CVE-2024-MULTI".to_string(),
            severity: CveSeverity::Critical,
            affected_packages: vec![
                AffectedPackage {
                    name: "pkg-a".to_string(),
                    ecosystem: Some("npm".to_string()),
                    version_range: None,
                    fixed_version: None,
                },
                AffectedPackage {
                    name: "pkg-b".to_string(),
                    ecosystem: Some("crates.io".to_string()),
                    version_range: Some(">= 1.0, < 2.0".to_string()),
                    fixed_version: Some("2.0.0".to_string()),
                },
            ],
            description: "Multi-package vuln".to_string(),
            source: EventSource::Nvd,
            timestamp: sample_timestamp(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ComplianceEvent = serde_json::from_str(&json).unwrap();
        if let ComplianceEvent::NewCve {
            affected_packages, ..
        } = back
        {
            assert_eq!(affected_packages.len(), 2);
        } else {
            panic!("wrong variant");
        }
    }
}
