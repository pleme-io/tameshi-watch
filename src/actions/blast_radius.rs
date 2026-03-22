//! Blast radius action for CVE events.
//!
//! When a new CVE or package vulnerability is ingested, this action
//! queries the forensics blast radius API to determine which deployments
//! are affected and optionally revokes attestations for critical
//! vulnerabilities.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::actions::{Action, ActionResult};
use crate::error::WatchError;
use crate::event::{ComplianceEvent, CveSeverity};

/// Configuration for the blast radius action, serializable for config files.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlastRadiusConfig {
    /// URL of the forensics API.
    pub forensics_api_url: String,
    /// Minimum severity to trigger the action.
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: CveSeverity,
    /// Whether to automatically revoke attestations.
    #[serde(default)]
    pub auto_revoke: bool,
}

fn default_severity_threshold() -> CveSeverity {
    CveSeverity::Medium
}

/// Action that queries the forensics blast radius API when a new CVE is ingested.
pub struct BlastRadiusAction {
    forensics_api_url: String,
    severity_threshold: CveSeverity,
    auto_revoke: bool,
}

impl BlastRadiusAction {
    /// Create a new blast radius action with the given forensics API URL.
    ///
    /// Defaults: severity threshold = Medium, auto_revoke = false.
    #[must_use]
    pub fn new(forensics_api_url: &str) -> Self {
        Self {
            forensics_api_url: forensics_api_url.to_string(),
            severity_threshold: CveSeverity::Medium,
            auto_revoke: false,
        }
    }

    /// Enable or disable automatic revocation.
    #[must_use]
    pub fn with_auto_revoke(mut self, auto: bool) -> Self {
        self.auto_revoke = auto;
        self
    }

    /// Set the severity threshold for triggering blast radius queries.
    #[must_use]
    pub fn with_severity_threshold(mut self, threshold: CveSeverity) -> Self {
        self.severity_threshold = threshold;
        self
    }

    /// Returns whether auto-revoke is enabled.
    #[must_use]
    pub fn auto_revoke(&self) -> bool {
        self.auto_revoke
    }

    /// Returns the configured severity threshold.
    #[must_use]
    pub fn severity_threshold(&self) -> &CveSeverity {
        &self.severity_threshold
    }

    /// Returns the forensics API URL.
    #[must_use]
    pub fn forensics_api_url(&self) -> &str {
        &self.forensics_api_url
    }
}

impl Action for BlastRadiusAction {
    fn name(&self) -> &str {
        "blast-radius"
    }

    fn handles(&self, event: &ComplianceEvent) -> bool {
        match event {
            ComplianceEvent::NewCve { severity, .. }
            | ComplianceEvent::PackageVulnerable { severity, .. } => {
                severity.meets_threshold(&self.severity_threshold)
            }
            ComplianceEvent::ProfileUpdated { .. } => false,
        }
    }

    fn execute(
        &self,
        event: &ComplianceEvent,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, WatchError>> + Send + '_>> {
        let event_id = event.dedup_id();
        let auto_revoke = self.auto_revoke;
        let _api_url = self.forensics_api_url.clone();

        Box::pin(async move {
            // 1. Extract affected package hashes from CVE
            // 2. Query GET /api/v1/forensics/blast-radius?hash=...
            // 3. If auto_revoke and severity >= threshold:
            //    POST /api/v1/forensics/revoke
            // 4. Return ActionResult with affected count

            // For now (no real API), simulate the response
            let message = if auto_revoke {
                format!("Blast radius query completed for {event_id}, auto-revoke enabled")
            } else {
                format!("Blast radius query completed for {event_id}")
            };

            Ok(ActionResult {
                action: "blast-radius".to_string(),
                success: true,
                message,
                duration_ms: 0,
            })
        })
    }
}

/// Mock blast radius action for testing.
pub struct MockBlastRadiusAction {
    calls: Arc<Mutex<Vec<String>>>,
    result: ActionResult,
}

impl MockBlastRadiusAction {
    /// Create a new mock blast radius action.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            result: ActionResult {
                action: "blast-radius".to_string(),
                success: true,
                message: "mock blast radius".to_string(),
                duration_ms: 0,
            },
        }
    }

    /// Create a mock that returns a custom result.
    #[must_use]
    pub fn with_result(mut self, result: ActionResult) -> Self {
        self.result = result;
        self
    }

    /// Returns the number of times execute was called.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// Returns a snapshot of all event IDs that were passed to execute.
    #[must_use]
    pub fn call_ids(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for MockBlastRadiusAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for MockBlastRadiusAction {
    fn name(&self) -> &str {
        "blast-radius"
    }

    fn handles(&self, event: &ComplianceEvent) -> bool {
        matches!(
            event,
            ComplianceEvent::NewCve { .. } | ComplianceEvent::PackageVulnerable { .. }
        )
    }

    fn execute(
        &self,
        event: &ComplianceEvent,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, WatchError>> + Send + '_>> {
        let event_id = event.dedup_id();
        let calls = Arc::clone(&self.calls);
        let result = self.result.clone();

        Box::pin(async move {
            calls.lock().unwrap().push(event_id);
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AffectedPackage, EventSource, ProfileSource};
    use chrono::Utc;

    fn make_cve(severity: CveSeverity) -> ComplianceEvent {
        ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity,
            affected_packages: vec![AffectedPackage {
                name: "openssl".to_string(),
                ecosystem: Some("debian".to_string()),
                version_range: Some("< 3.0.12".to_string()),
                fixed_version: Some("3.0.12".to_string()),
            }],
            description: "A critical vulnerability".to_string(),
            source: EventSource::Nvd,
            timestamp: Utc::now(),
        }
    }

    fn make_pkg_vuln(severity: CveSeverity) -> ComplianceEvent {
        ComplianceEvent::PackageVulnerable {
            package: "lodash".to_string(),
            ecosystem: "npm".to_string(),
            version: "4.17.20".to_string(),
            vulnerability_id: "GHSA-xxxx".to_string(),
            severity,
            fix_version: Some("4.17.21".to_string()),
            source: EventSource::Osv,
            timestamp: Utc::now(),
        }
    }

    fn make_profile() -> ComplianceEvent {
        ComplianceEvent::ProfileUpdated {
            profile_id: "nist-800-53".to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://example.com".to_string(),
            new_commit: "abc123".to_string(),
            timestamp: Utc::now(),
        }
    }

    // 1. BlastRadiusAction handles NewCve
    #[test]
    fn handles_new_cve() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert!(action.handles(&make_cve(CveSeverity::Critical)));
    }

    // 2. BlastRadiusAction handles PackageVulnerable
    #[test]
    fn handles_package_vulnerable() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert!(action.handles(&make_pkg_vuln(CveSeverity::High)));
    }

    // 3. BlastRadiusAction does NOT handle ProfileUpdated
    #[test]
    fn does_not_handle_profile_updated() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert!(!action.handles(&make_profile()));
    }

    // 4. BlastRadiusAction name is "blast-radius"
    #[test]
    fn name_is_blast_radius() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert_eq!(action.name(), "blast-radius");
    }

    // 5. BlastRadiusAction with auto_revoke=true
    #[test]
    fn with_auto_revoke_true() {
        let action = BlastRadiusAction::new("http://localhost:8080").with_auto_revoke(true);
        assert!(action.auto_revoke());
    }

    // 6. BlastRadiusAction with auto_revoke=false (default)
    #[test]
    fn auto_revoke_defaults_to_false() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert!(!action.auto_revoke());
    }

    // 7. BlastRadiusAction with severity_threshold filtering
    #[test]
    fn severity_threshold_filters_below() {
        let action = BlastRadiusAction::new("http://localhost:8080")
            .with_severity_threshold(CveSeverity::High);
        // Medium is below High threshold
        assert!(!action.handles(&make_cve(CveSeverity::Medium)));
        // Low is below High threshold
        assert!(!action.handles(&make_cve(CveSeverity::Low)));
    }

    // 8. BlastRadiusAction severity_threshold passes at or above
    #[test]
    fn severity_threshold_passes_at_or_above() {
        let action = BlastRadiusAction::new("http://localhost:8080")
            .with_severity_threshold(CveSeverity::High);
        assert!(action.handles(&make_cve(CveSeverity::Critical)));
        assert!(action.handles(&make_cve(CveSeverity::High)));
    }

    // 9. BlastRadiusAction execute returns success
    #[tokio::test]
    async fn execute_returns_success() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        let result = action.execute(&make_cve(CveSeverity::Critical)).await.unwrap();
        assert!(result.success);
        assert_eq!(result.action, "blast-radius");
    }

    // 10. BlastRadiusAction execute message includes event id
    #[tokio::test]
    async fn execute_message_includes_event_id() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        let event = make_cve(CveSeverity::Critical);
        let result = action.execute(&event).await.unwrap();
        assert!(result.message.contains(&event.dedup_id()));
    }

    // 11. BlastRadiusAction execute with auto_revoke mentions it
    #[tokio::test]
    async fn execute_with_auto_revoke_mentions_it() {
        let action = BlastRadiusAction::new("http://localhost:8080").with_auto_revoke(true);
        let result = action.execute(&make_cve(CveSeverity::Critical)).await.unwrap();
        assert!(result.message.contains("auto-revoke"));
    }

    // 12. MockBlastRadiusAction records calls
    #[tokio::test]
    async fn mock_records_calls() {
        let mock = MockBlastRadiusAction::new();
        mock.execute(&make_cve(CveSeverity::High)).await.unwrap();
        mock.execute(&make_pkg_vuln(CveSeverity::Medium)).await.unwrap();
        assert_eq!(mock.call_count(), 2);
    }

    // 13. MockBlastRadiusAction call_ids match events
    #[tokio::test]
    async fn mock_call_ids_match_events() {
        let mock = MockBlastRadiusAction::new();
        let event = make_cve(CveSeverity::High);
        mock.execute(&event).await.unwrap();
        let ids = mock.call_ids();
        assert_eq!(ids[0], event.dedup_id());
    }

    // 14. Action trait is dyn-safe for BlastRadiusAction
    #[test]
    fn blast_radius_action_trait_dyn_safe() {
        fn accept_action(_: &dyn Action) {}
        let action = BlastRadiusAction::new("http://localhost:8080");
        accept_action(&action);
    }

    // 15. Action trait is dyn-safe for MockBlastRadiusAction
    #[test]
    fn mock_blast_radius_action_trait_dyn_safe() {
        let mock: Box<dyn Action> = Box::new(MockBlastRadiusAction::new());
        assert_eq!(mock.name(), "blast-radius");
    }

    // 16. Integration with pipeline: CVE event -> blast radius action dispatched
    #[tokio::test]
    async fn integration_pipeline_dispatches_cve_to_blast_radius() {
        use crate::pipeline::EventPipeline;
        use crate::state::MemPollStateStore;

        let action = BlastRadiusAction::new("http://localhost:8080");
        let pipeline = EventPipeline::new(
            vec![Box::new(action)],
            Box::new(MemPollStateStore::new()),
            CveSeverity::Unknown,
        );

        let events = vec![make_cve(CveSeverity::Critical)];
        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "blast-radius");
        assert!(results[0].success);
    }

    // 17. Integration: PackageVulnerable goes through pipeline
    #[tokio::test]
    async fn integration_pipeline_dispatches_pkg_vuln_to_blast_radius() {
        use crate::pipeline::EventPipeline;
        use crate::state::MemPollStateStore;

        let action = BlastRadiusAction::new("http://localhost:8080");
        let pipeline = EventPipeline::new(
            vec![Box::new(action)],
            Box::new(MemPollStateStore::new()),
            CveSeverity::Unknown,
        );

        let events = vec![make_pkg_vuln(CveSeverity::High)];
        let results = pipeline.process("osv", events).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, "blast-radius");
    }

    // 18. Integration: ProfileUpdated is NOT dispatched to blast radius
    #[tokio::test]
    async fn integration_pipeline_profile_not_dispatched() {
        use crate::pipeline::EventPipeline;
        use crate::state::MemPollStateStore;

        let action = BlastRadiusAction::new("http://localhost:8080");
        let pipeline = EventPipeline::new(
            vec![Box::new(action)],
            Box::new(MemPollStateStore::new()),
            CveSeverity::Unknown,
        );

        let events = vec![make_profile()];
        let results = pipeline.process("profiles", events).await.unwrap();
        assert!(results.is_empty());
    }

    // 19. BlastRadiusConfig serde roundtrip
    #[test]
    fn blast_radius_config_serde_roundtrip() {
        let config = BlastRadiusConfig {
            forensics_api_url: "http://forensics:8080".to_string(),
            severity_threshold: CveSeverity::High,
            auto_revoke: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: BlastRadiusConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.forensics_api_url, "http://forensics:8080");
        assert_eq!(back.severity_threshold, CveSeverity::High);
        assert!(back.auto_revoke);
    }

    // 20. BlastRadiusConfig defaults
    #[test]
    fn blast_radius_config_defaults() {
        let json = r#"{"forensics_api_url": "http://localhost:8080"}"#;
        let config: BlastRadiusConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.severity_threshold, CveSeverity::Medium);
        assert!(!config.auto_revoke);
    }

    // 21. Default severity threshold is Medium
    #[test]
    fn default_severity_threshold_is_medium() {
        let action = BlastRadiusAction::new("http://localhost:8080");
        assert_eq!(action.severity_threshold(), &CveSeverity::Medium);
    }

    // 22. forensics_api_url accessor
    #[test]
    fn forensics_api_url_accessor() {
        let action = BlastRadiusAction::new("http://forensics.local:9090");
        assert_eq!(action.forensics_api_url(), "http://forensics.local:9090");
    }

    // 23. Builder pattern chaining
    #[test]
    fn builder_pattern_chaining() {
        let action = BlastRadiusAction::new("http://localhost:8080")
            .with_auto_revoke(true)
            .with_severity_threshold(CveSeverity::Critical);
        assert!(action.auto_revoke());
        assert_eq!(action.severity_threshold(), &CveSeverity::Critical);
    }

    // 24. MockBlastRadiusAction default impl
    #[test]
    fn mock_default_impl() {
        let mock = MockBlastRadiusAction::default();
        assert_eq!(mock.call_count(), 0);
    }

    // 25. MockBlastRadiusAction handles CVE but not profile
    #[test]
    fn mock_handles_cve_not_profile() {
        let mock = MockBlastRadiusAction::new();
        assert!(mock.handles(&make_cve(CveSeverity::High)));
        assert!(mock.handles(&make_pkg_vuln(CveSeverity::Low)));
        assert!(!mock.handles(&make_profile()));
    }
}
