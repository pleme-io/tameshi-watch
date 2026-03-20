use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::WatchError;
use crate::event::{ComplianceEvent, CveSeverity, EventSource};
use crate::sources::SourcePoller;

/// OSV.dev source poller.
pub struct OsvPoller {
    /// OSV API base URL.
    #[allow(dead_code)]
    base_url: String,
    /// Ecosystems to query.
    #[allow(dead_code)]
    ecosystems: Vec<String>,
    /// Poll interval.
    poll_interval: Duration,
}

impl OsvPoller {
    /// Create a new OSV poller.
    #[must_use]
    pub fn new(base_url: String, ecosystems: Vec<String>, poll_interval: Duration) -> Self {
        Self {
            base_url,
            ecosystems,
            poll_interval,
        }
    }
}

impl SourcePoller for OsvPoller {
    fn name(&self) -> &str {
        "osv"
    }

    fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn poll(
        &self,
        _since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ComplianceEvent>, WatchError>> + Send + '_>> {
        // In production, this would query OSV API. For now, return empty.
        Box::pin(async { Ok(vec![]) })
    }
}

/// Map OSV severity to our severity enum.
#[must_use]
pub fn parse_osv_severity(score: f64) -> CveSeverity {
    if score >= 9.0 {
        CveSeverity::Critical
    } else if score >= 7.0 {
        CveSeverity::High
    } else if score >= 4.0 {
        CveSeverity::Medium
    } else if score > 0.0 {
        CveSeverity::Low
    } else {
        CveSeverity::Unknown
    }
}

/// Parse an OSV.dev query response into compliance events.
///
/// OSV response format: `{"vulns": [...]}`
#[must_use]
pub fn parse_osv_response(json: &serde_json::Value) -> Vec<ComplianceEvent> {
    let Some(vulns) = json.get("vulns").and_then(|v| v.as_array()) else {
        return vec![];
    };

    let mut events = Vec::new();

    for vuln in vulns {
        let vuln_id = vuln
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        if vuln_id.is_empty() {
            continue;
        }

        let severity = extract_osv_severity(vuln);

        let timestamp = vuln
            .get("modified")
            .or_else(|| vuln.get("published"))
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        // Extract affected packages
        let affected = vuln.get("affected").and_then(|a| a.as_array());

        if let Some(affected_list) = affected {
            for affected_entry in affected_list {
                let package_name = affected_entry
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or_default()
                    .to_string();

                let ecosystem = affected_entry
                    .get("package")
                    .and_then(|p| p.get("ecosystem"))
                    .and_then(|e| e.as_str())
                    .unwrap_or_default()
                    .to_string();

                if package_name.is_empty() {
                    continue;
                }

                // Extract affected versions
                let versions = affected_entry
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(String::from)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                // Find fix version from ranges
                let fix_version = extract_fix_version(affected_entry);

                let version = versions.first().cloned().unwrap_or_default();

                events.push(ComplianceEvent::PackageVulnerable {
                    package: package_name,
                    ecosystem,
                    version,
                    vulnerability_id: vuln_id.clone(),
                    severity: severity.clone(),
                    fix_version,
                    source: EventSource::Osv,
                    timestamp,
                });
            }
        } else {
            // No affected packages — emit as a generic CVE-like event
            let description = vuln
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            events.push(ComplianceEvent::NewCve {
                cve_id: vuln_id,
                severity,
                affected_packages: vec![],
                description,
                source: EventSource::Osv,
                timestamp,
            });
        }
    }

    events
}

fn extract_osv_severity(vuln: &serde_json::Value) -> CveSeverity {
    // Try database_specific.severity first
    if let Some(sev) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        return match sev.to_uppercase().as_str() {
            "CRITICAL" => CveSeverity::Critical,
            "HIGH" => CveSeverity::High,
            "MODERATE" | "MEDIUM" => CveSeverity::Medium,
            "LOW" => CveSeverity::Low,
            _ => CveSeverity::Unknown,
        };
    }

    // Try severity array with CVSS score
    if let Some(severities) = vuln.get("severity").and_then(|s| s.as_array()) {
        for sev in severities {
            if let Some(score) = sev.get("score").and_then(|s| s.as_str()) {
                // CVSS vector string: try to extract base score
                if let Some(base) = extract_cvss_base_score(score) {
                    return parse_osv_severity(base);
                }
            }
        }
    }

    CveSeverity::Unknown
}

fn extract_cvss_base_score(vector: &str) -> Option<f64> {
    // CVSS v3 vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // We just look for the score pattern — in real code, use a CVSS library.
    // For simplicity, we don't parse the vector; OSV usually provides numeric scores elsewhere.
    let _ = vector;
    None
}

fn extract_fix_version(affected: &serde_json::Value) -> Option<String> {
    let ranges = affected.get("ranges").and_then(|r| r.as_array())?;
    for range in ranges {
        let events = range.get("events").and_then(|e| e.as_array())?;
        for event in events {
            if let Some(fixed) = event.get("fixed").and_then(|f| f.as_str()) {
                return Some(fixed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_osv_response() -> serde_json::Value {
        serde_json::json!({
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Prototype pollution in lodash",
                    "modified": "2024-06-01T00:00:00Z",
                    "database_specific": {
                        "severity": "HIGH"
                    },
                    "affected": [
                        {
                            "package": {
                                "name": "lodash",
                                "ecosystem": "npm"
                            },
                            "versions": ["4.17.20", "4.17.19"],
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "4.17.21"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        })
    }

    #[test]
    fn parse_single_osv_vuln() {
        let events = parse_osv_response(&sample_osv_response());
        assert_eq!(events.len(), 1);
        if let ComplianceEvent::PackageVulnerable {
            package,
            vulnerability_id,
            ..
        } = &events[0]
        {
            assert_eq!(package, "lodash");
            assert_eq!(vulnerability_id, "GHSA-xxxx-yyyy-zzzz");
        } else {
            panic!("expected PackageVulnerable");
        }
    }

    #[test]
    fn parse_osv_severity_value() {
        let events = parse_osv_response(&sample_osv_response());
        if let ComplianceEvent::PackageVulnerable { severity, .. } = &events[0] {
            assert_eq!(*severity, CveSeverity::High);
        }
    }

    #[test]
    fn parse_osv_fix_version() {
        let events = parse_osv_response(&sample_osv_response());
        if let ComplianceEvent::PackageVulnerable { fix_version, .. } = &events[0] {
            assert_eq!(fix_version.as_deref(), Some("4.17.21"));
        }
    }

    #[test]
    fn parse_osv_ecosystem() {
        let events = parse_osv_response(&sample_osv_response());
        if let ComplianceEvent::PackageVulnerable { ecosystem, .. } = &events[0] {
            assert_eq!(ecosystem, "npm");
        }
    }

    #[test]
    fn parse_osv_empty_response() {
        let json = serde_json::json!({"vulns": []});
        let events = parse_osv_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_osv_no_vulns_key() {
        let json = serde_json::json!({"results": []});
        let events = parse_osv_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_osv_vuln_without_affected() {
        let json = serde_json::json!({
            "vulns": [{
                "id": "GHSA-1234",
                "summary": "A vulnerability"
            }]
        });
        let events = parse_osv_response(&json);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], ComplianceEvent::NewCve { .. }));
    }

    #[test]
    fn parse_osv_multiple_affected() {
        let json = serde_json::json!({
            "vulns": [{
                "id": "GHSA-MULTI",
                "modified": "2024-01-01T00:00:00Z",
                "affected": [
                    {"package": {"name": "pkg-a", "ecosystem": "npm"}, "versions": ["1.0"]},
                    {"package": {"name": "pkg-b", "ecosystem": "PyPI"}, "versions": ["2.0"]}
                ]
            }]
        });
        let events = parse_osv_response(&json);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn parse_osv_severity_from_score() {
        assert_eq!(parse_osv_severity(9.5), CveSeverity::Critical);
        assert_eq!(parse_osv_severity(7.0), CveSeverity::High);
        assert_eq!(parse_osv_severity(4.0), CveSeverity::Medium);
        assert_eq!(parse_osv_severity(2.0), CveSeverity::Low);
        assert_eq!(parse_osv_severity(0.0), CveSeverity::Unknown);
    }

    #[test]
    fn parse_osv_severity_moderate_maps_to_medium() {
        let json = serde_json::json!({
            "vulns": [{
                "id": "MOD-1",
                "database_specific": {"severity": "MODERATE"},
                "affected": [
                    {"package": {"name": "foo", "ecosystem": "npm"}, "versions": ["1.0"]}
                ]
            }]
        });
        let events = parse_osv_response(&json);
        if let ComplianceEvent::PackageVulnerable { severity, .. } = &events[0] {
            assert_eq!(*severity, CveSeverity::Medium);
        }
    }

    #[test]
    fn osv_poller_name() {
        let poller = OsvPoller::new(
            "https://api.osv.dev/v1".to_string(),
            vec!["npm".to_string()],
            Duration::from_secs(600),
        );
        assert_eq!(poller.name(), "osv");
    }

    #[test]
    fn osv_poller_interval() {
        let poller = OsvPoller::new(
            "https://api.osv.dev/v1".to_string(),
            vec![],
            Duration::from_secs(300),
        );
        assert_eq!(poller.poll_interval(), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn osv_poller_returns_empty_without_http() {
        let poller = OsvPoller::new(
            "https://api.osv.dev/v1".to_string(),
            vec![],
            Duration::from_secs(60),
        );
        let result = poller.poll(None).await.unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_osv_vuln_without_id_skipped() {
        let json = serde_json::json!({
            "vulns": [{"summary": "No ID"}]
        });
        let events = parse_osv_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_osv_affected_without_package_name_skipped() {
        let json = serde_json::json!({
            "vulns": [{
                "id": "GHSA-NONAME",
                "affected": [{"package": {"ecosystem": "npm"}}]
            }]
        });
        let events = parse_osv_response(&json);
        // Skips the affected entry but since there are no valid affected entries,
        // falls through — this particular structure yields no events from affected
        assert!(events.is_empty());
    }
}
