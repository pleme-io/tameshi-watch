use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::WatchError;
use crate::event::{AffectedPackage, ComplianceEvent, CveSeverity, EventSource};
use crate::sources::SourcePoller;

/// NVD API v2.0 source poller.
pub struct NvdPoller {
    /// Optional NVD API key.
    #[allow(dead_code)]
    api_key: Option<String>,
    /// NVD API base URL.
    #[allow(dead_code)]
    base_url: String,
    /// Poll interval.
    poll_interval: Duration,
}

impl NvdPoller {
    /// Create a new NVD poller.
    #[must_use]
    pub fn new(base_url: String, api_key: Option<String>, poll_interval: Duration) -> Self {
        Self {
            api_key,
            base_url,
            poll_interval,
        }
    }
}

impl SourcePoller for NvdPoller {
    fn name(&self) -> &str {
        "nvd"
    }

    fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn poll(
        &self,
        _since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ComplianceEvent>, WatchError>> + Send + '_>> {
        // In production, this would make an HTTP request. For now, return empty.
        Box::pin(async { Ok(vec![]) })
    }
}

/// Map NVD CVSS v3 base severity string to our severity enum.
#[must_use]
pub fn parse_nvd_severity(severity_str: &str) -> CveSeverity {
    match severity_str.to_uppercase().as_str() {
        "CRITICAL" => CveSeverity::Critical,
        "HIGH" => CveSeverity::High,
        "MEDIUM" => CveSeverity::Medium,
        "LOW" => CveSeverity::Low,
        _ => CveSeverity::Unknown,
    }
}

/// Parse NVD API v2.0 JSON response into compliance events.
///
/// Expected format follows the NVD API 2.0 CVE response schema.
#[must_use]
pub fn parse_nvd_response(json: &serde_json::Value) -> Vec<ComplianceEvent> {
    let Some(vulnerabilities) = json.get("vulnerabilities").and_then(|v| v.as_array()) else {
        return vec![];
    };

    let mut events = Vec::new();

    for vuln_wrapper in vulnerabilities {
        let Some(cve) = vuln_wrapper.get("cve") else {
            continue;
        };

        let cve_id = cve
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        if cve_id.is_empty() {
            continue;
        }

        let description = cve
            .get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| {
                arr.iter().find(|d| {
                    d.get("lang")
                        .and_then(|l| l.as_str())
                        .is_some_and(|l| l == "en")
                })
            })
            .and_then(|d| d.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let severity = extract_severity(cve);

        let affected_packages = extract_affected_packages(cve);

        let timestamp = cve
            .get("published")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        events.push(ComplianceEvent::NewCve {
            cve_id,
            severity,
            affected_packages,
            description,
            source: EventSource::Nvd,
            timestamp,
        });
    }

    events
}

fn extract_severity(cve: &serde_json::Value) -> CveSeverity {
    // Try CVSS v3.1 first, then v3.0, then v2.0
    if let Some(metrics) = cve.get("metrics") {
        for key in &["cvssMetricV31", "cvssMetricV30"] {
            if let Some(arr) = metrics.get(*key).and_then(|v| v.as_array()) {
                if let Some(first) = arr.first() {
                    if let Some(severity) = first
                        .get("cvssData")
                        .and_then(|d| d.get("baseSeverity"))
                        .and_then(|s| s.as_str())
                    {
                        return parse_nvd_severity(severity);
                    }
                }
            }
        }
    }
    CveSeverity::Unknown
}

fn extract_affected_packages(cve: &serde_json::Value) -> Vec<AffectedPackage> {
    let Some(configurations) = cve.get("configurations").and_then(|c| c.as_array()) else {
        return vec![];
    };

    let mut packages = Vec::new();

    for config in configurations {
        let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) else {
            continue;
        };
        for node in nodes {
            let Some(cpe_match) = node.get("cpeMatch").and_then(|c| c.as_array()) else {
                continue;
            };
            for cpe in cpe_match {
                let vulnerable = cpe
                    .get("vulnerable")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !vulnerable {
                    continue;
                }

                let criteria = cpe
                    .get("criteria")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                // CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                let parts: Vec<&str> = criteria.split(':').collect();
                if parts.len() >= 5 {
                    let name = format!("{}:{}", parts[3], parts[4]);

                    let version_end = cpe
                        .get("versionEndExcluding")
                        .or_else(|| cpe.get("versionEndIncluding"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let version_start = cpe
                        .get("versionStartIncluding")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    let version_range = match (&version_start, &version_end) {
                        (Some(start), Some(end)) => Some(format!(">= {start}, < {end}")),
                        (None, Some(end)) => Some(format!("< {end}")),
                        (Some(start), None) => Some(format!(">= {start}")),
                        (None, None) => None,
                    };

                    packages.push(AffectedPackage {
                        name,
                        ecosystem: None,
                        version_range,
                        fixed_version: version_end,
                    });
                }
            }
        }
    }

    packages
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    fn sample_nvd_response() -> serde_json::Value {
        serde_json::json!({
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "published": "2024-01-15T12:00:00.000+00:00",
                        "descriptions": [
                            {"lang": "en", "value": "A critical buffer overflow in openssl."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseSeverity": "CRITICAL",
                                        "baseScore": 9.8
                                    }
                                }
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "operator": "OR",
                                        "cpeMatch": [
                                            {
                                                "vulnerable": true,
                                                "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "1.0.0",
                                                "versionEndExcluding": "3.0.12"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        })
    }

    #[test]
    fn parse_single_cve() {
        let events = parse_nvd_response(&sample_nvd_response());
        assert_eq!(events.len(), 1);
        if let ComplianceEvent::NewCve {
            cve_id, severity, ..
        } = &events[0]
        {
            assert_eq!(cve_id, "CVE-2024-12345");
            assert_eq!(*severity, CveSeverity::Critical);
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_description() {
        let events = parse_nvd_response(&sample_nvd_response());
        if let ComplianceEvent::NewCve { description, .. } = &events[0] {
            assert!(description.contains("buffer overflow"));
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_affected_packages() {
        let events = parse_nvd_response(&sample_nvd_response());
        if let ComplianceEvent::NewCve {
            affected_packages, ..
        } = &events[0]
        {
            assert_eq!(affected_packages.len(), 1);
            assert!(affected_packages[0].name.contains("openssl"));
            assert_eq!(
                affected_packages[0].fixed_version,
                Some("3.0.12".to_string())
            );
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_version_range() {
        let events = parse_nvd_response(&sample_nvd_response());
        if let ComplianceEvent::NewCve {
            affected_packages, ..
        } = &events[0]
        {
            let range = affected_packages[0].version_range.as_ref().unwrap();
            assert!(range.contains("1.0.0"));
            assert!(range.contains("3.0.12"));
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_empty_response() {
        let json = serde_json::json!({"vulnerabilities": []});
        let events = parse_nvd_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_no_vulnerabilities_key() {
        let json = serde_json::json!({"foo": "bar"});
        let events = parse_nvd_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_cve_without_metrics() {
        let json = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-0000",
                    "descriptions": [{"lang": "en", "value": "Unknown severity"}]
                }
            }]
        });
        let events = parse_nvd_response(&json);
        assert_eq!(events.len(), 1);
        if let ComplianceEvent::NewCve { severity, .. } = &events[0] {
            assert_eq!(*severity, CveSeverity::Unknown);
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_multiple_cves() {
        let json = serde_json::json!({
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "First"}]}},
                {"cve": {"id": "CVE-2024-0002", "descriptions": [{"lang": "en", "value": "Second"}]}}
            ]
        });
        let events = parse_nvd_response(&json);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn parse_nvd_severity_values() {
        assert_eq!(parse_nvd_severity("CRITICAL"), CveSeverity::Critical);
        assert_eq!(parse_nvd_severity("HIGH"), CveSeverity::High);
        assert_eq!(parse_nvd_severity("MEDIUM"), CveSeverity::Medium);
        assert_eq!(parse_nvd_severity("LOW"), CveSeverity::Low);
        assert_eq!(parse_nvd_severity("UNKNOWN"), CveSeverity::Unknown);
        assert_eq!(parse_nvd_severity("invalid"), CveSeverity::Unknown);
    }

    #[test]
    fn parse_nvd_severity_case_insensitive() {
        assert_eq!(parse_nvd_severity("critical"), CveSeverity::Critical);
        assert_eq!(parse_nvd_severity("High"), CveSeverity::High);
        assert_eq!(parse_nvd_severity("medium"), CveSeverity::Medium);
    }

    #[test]
    fn parse_cve_without_id_skipped() {
        let json = serde_json::json!({
            "vulnerabilities": [
                {"cve": {"descriptions": [{"lang": "en", "value": "No ID"}]}}
            ]
        });
        let events = parse_nvd_response(&json);
        assert!(events.is_empty());
    }

    #[test]
    fn parse_cve_with_cvss_v30() {
        let json = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-V30",
                    "descriptions": [{"lang": "en", "value": "v3.0 test"}],
                    "metrics": {
                        "cvssMetricV30": [{
                            "cvssData": {"baseSeverity": "HIGH"}
                        }]
                    }
                }
            }]
        });
        let events = parse_nvd_response(&json);
        if let ComplianceEvent::NewCve { severity, .. } = &events[0] {
            assert_eq!(*severity, CveSeverity::High);
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_non_vulnerable_cpe_skipped() {
        let json = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-SKIP",
                    "descriptions": [{"lang": "en", "value": "test"}],
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": false,
                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
                            }]
                        }]
                    }]
                }
            }]
        });
        let events = parse_nvd_response(&json);
        if let ComplianceEvent::NewCve {
            affected_packages, ..
        } = &events[0]
        {
            assert!(affected_packages.is_empty());
        }
    }

    #[test]
    fn nvd_poller_name() {
        let poller = NvdPoller::new("https://example.com".to_string(), None, Duration::from_secs(300));
        assert_eq!(poller.name(), "nvd");
    }

    #[test]
    fn nvd_poller_interval() {
        let poller = NvdPoller::new("https://example.com".to_string(), None, Duration::from_secs(120));
        assert_eq!(poller.poll_interval(), Duration::from_secs(120));
    }

    #[tokio::test]
    async fn nvd_poller_returns_empty_without_http() {
        let poller = NvdPoller::new("https://example.com".to_string(), None, Duration::from_secs(60));
        let result = poller.poll(None).await.unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_timestamp_from_response() {
        let events = parse_nvd_response(&sample_nvd_response());
        if let ComplianceEvent::NewCve { timestamp, .. } = &events[0] {
            assert_eq!(timestamp.year(), 2024);
        } else {
            panic!("expected NewCve");
        }
    }

    #[test]
    fn parse_end_version_only_range() {
        let json = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-ENDONLY",
                    "descriptions": [{"lang": "en", "value": "test"}],
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.0.0"
                            }]
                        }]
                    }]
                }
            }]
        });
        let events = parse_nvd_response(&json);
        if let ComplianceEvent::NewCve {
            affected_packages, ..
        } = &events[0]
        {
            let range = affected_packages[0].version_range.as_ref().unwrap();
            assert_eq!(range, "< 2.0.0");
        }
    }
}
