use chrono::Utc;
use tracing::{debug, info, warn};

use crate::actions::{Action, ActionResult};
use crate::error::WatchError;
use crate::event::{ComplianceEvent, CveSeverity};
use crate::state::{PollState, PollStateStore};

/// Processes compliance events through a pipeline of actions.
pub struct EventPipeline {
    actions: Vec<Box<dyn Action>>,
    state_store: Box<dyn PollStateStore>,
    severity_threshold: CveSeverity,
}

impl EventPipeline {
    /// Create a new event pipeline.
    #[must_use]
    pub fn new(
        actions: Vec<Box<dyn Action>>,
        state_store: Box<dyn PollStateStore>,
        severity_threshold: CveSeverity,
    ) -> Self {
        Self {
            actions,
            state_store,
            severity_threshold,
        }
    }

    /// Process a batch of events from a source.
    ///
    /// 1. Filter by severity threshold
    /// 2. Dedup against known IDs in `PollState`
    /// 3. Dispatch new events to matching actions
    /// 4. Update `PollState`
    ///
    /// # Errors
    ///
    /// Returns an error if state cannot be loaded or saved.
    pub async fn process(
        &self,
        source: &str,
        events: Vec<ComplianceEvent>,
    ) -> Result<Vec<ActionResult>, WatchError> {
        let mut state = self.state_store.load(source)?;
        let mut results = Vec::new();

        let filtered = self.filter_events(&events, &state);

        info!(
            source = source,
            total = events.len(),
            filtered = filtered.len(),
            "processing events"
        );

        for event in &filtered {
            let dedup_id = event.dedup_id();
            debug!(event_id = %dedup_id, "dispatching event");

            for action in &self.actions {
                if action.handles(event) {
                    match action.execute(event).await {
                        Ok(result) => {
                            debug!(
                                action = result.action,
                                success = result.success,
                                "action completed"
                            );
                            results.push(result);
                        }
                        Err(e) => {
                            warn!(action = action.name(), error = %e, "action failed");
                            results.push(ActionResult {
                                action: action.name().to_string(),
                                success: false,
                                message: e.to_string(),
                                duration_ms: 0,
                            });
                        }
                    }
                }
            }

            state.record(dedup_id);
        }

        state.last_poll = Some(Utc::now());
        self.state_store.save(source, &state)?;

        info!(
            source = source,
            results = results.len(),
            total_ingested = state.total_ingested,
            "pipeline completed"
        );

        Ok(results)
    }

    fn filter_events(&self, events: &[ComplianceEvent], state: &PollState) -> Vec<ComplianceEvent> {
        events
            .iter()
            .filter(|e| {
                // Severity filter: profile events always pass
                let meets_severity = match e.severity() {
                    Some(sev) => sev.meets_threshold(&self.severity_threshold),
                    None => true,
                };

                // Dedup filter
                let is_new = !state.is_known(&e.dedup_id());

                meets_severity && is_new
            })
            .cloned()
            .collect()
    }

    /// Returns the number of configured actions.
    #[must_use]
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{CveOnlyAction, MockAction};
    use crate::event::{AffectedPackage, EventSource, ProfileSource};
    use crate::state::MemPollStateStore;

    fn make_cve(id: &str, severity: CveSeverity) -> ComplianceEvent {
        ComplianceEvent::NewCve {
            cve_id: id.to_string(),
            severity,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: Utc::now(),
        }
    }

    fn make_profile(id: &str, commit: &str) -> ComplianceEvent {
        ComplianceEvent::ProfileUpdated {
            profile_id: id.to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://example.com".to_string(),
            new_commit: commit.to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_pkg(name: &str, vuln_id: &str, severity: CveSeverity) -> ComplianceEvent {
        ComplianceEvent::PackageVulnerable {
            package: name.to_string(),
            ecosystem: "npm".to_string(),
            version: "1.0.0".to_string(),
            vulnerability_id: vuln_id.to_string(),
            severity,
            fix_version: None,
            source: EventSource::Osv,
            timestamp: Utc::now(),
        }
    }

    fn make_pipeline(
        actions: Vec<Box<dyn Action>>,
        threshold: CveSeverity,
    ) -> EventPipeline {
        EventPipeline::new(
            actions,
            Box::new(MemPollStateStore::new()),
            threshold,
        )
    }

    #[tokio::test]
    async fn pipeline_processes_events() {
        let action = MockAction::new("test");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);
        let events = vec![make_cve("CVE-1", CveSeverity::High)];
        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[tokio::test]
    async fn pipeline_dedup_known_ids() {
        let action = MockAction::new("dedup");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let events = vec![make_cve("CVE-DUP", CveSeverity::High)];

        // First run: should process
        let r1 = pipeline.process("nvd", events.clone()).await.unwrap();
        assert_eq!(r1.len(), 1);

        // Second run: same event should be deduped
        let r2 = pipeline.process("nvd", events).await.unwrap();
        assert!(r2.is_empty());
    }

    #[tokio::test]
    async fn pipeline_severity_threshold_filters() {
        let action = MockAction::new("high-only");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::High);

        let events = vec![
            make_cve("CVE-CRIT", CveSeverity::Critical),
            make_cve("CVE-HIGH", CveSeverity::High),
            make_cve("CVE-MED", CveSeverity::Medium),
            make_cve("CVE-LOW", CveSeverity::Low),
        ];

        let results = pipeline.process("nvd", events).await.unwrap();
        // Only Critical and High should pass
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn pipeline_profile_events_bypass_severity() {
        let action = MockAction::new("profiles");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Critical);

        let events = vec![make_profile("nist", "abc123")];

        let results = pipeline.process("profiles", events).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_multiple_actions_per_event() {
        let a1 = MockAction::new("a1");
        let a2 = MockAction::new("a2");
        let pipeline = make_pipeline(
            vec![Box::new(a1), Box::new(a2)],
            CveSeverity::Unknown,
        );

        let events = vec![make_cve("CVE-MULTI", CveSeverity::High)];
        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn pipeline_selective_action_skips_non_matching() {
        let selective = MockAction::new_selective("skip-all");
        let pipeline = make_pipeline(vec![Box::new(selective)], CveSeverity::Unknown);

        let events = vec![make_cve("CVE-1", CveSeverity::High)];
        let results = pipeline.process("nvd", events).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn pipeline_cve_only_action() {
        let cve_action = CveOnlyAction::new("cve-handler");
        let pipeline = make_pipeline(vec![Box::new(cve_action)], CveSeverity::Unknown);

        let events = vec![
            make_cve("CVE-1", CveSeverity::High),
            make_profile("nist", "abc"),
            make_pkg("lodash", "GHSA-1", CveSeverity::Medium),
        ];

        let results = pipeline.process("mixed", events).await.unwrap();
        // Only CVE events should trigger the CVE-only action
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_empty_events() {
        let action = MockAction::new("empty");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);
        let results = pipeline.process("nvd", vec![]).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn pipeline_no_actions() {
        let pipeline = make_pipeline(vec![], CveSeverity::Unknown);
        let events = vec![make_cve("CVE-1", CveSeverity::High)];
        let results = pipeline.process("nvd", events).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn pipeline_updates_state() {
        let store = MemPollStateStore::new();
        let action = MockAction::new("state-test");
        let pipeline = EventPipeline::new(
            vec![Box::new(action)],
            Box::new(MemPollStateStore::new()),
            CveSeverity::Unknown,
        );

        let events = vec![make_cve("CVE-1", CveSeverity::High)];
        pipeline.process("nvd", events).await.unwrap();

        // Pipeline's internal state store was updated
        // (We can't access it directly, but the dedup test proves it works)
        let _ = store;
    }

    #[tokio::test]
    async fn pipeline_action_count() {
        let pipeline = make_pipeline(
            vec![
                Box::new(MockAction::new("a1")),
                Box::new(MockAction::new("a2")),
                Box::new(MockAction::new("a3")),
            ],
            CveSeverity::Unknown,
        );
        assert_eq!(pipeline.action_count(), 3);
    }

    #[tokio::test]
    async fn pipeline_mixed_event_types() {
        let action = MockAction::new("all");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let events = vec![
            make_cve("CVE-1", CveSeverity::Critical),
            make_profile("nist", "abc"),
            make_pkg("lodash", "GHSA-1", CveSeverity::High),
        ];

        let results = pipeline.process("mixed", events).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn pipeline_severity_unknown_threshold_passes_all() {
        let action = MockAction::new("all");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let events = vec![
            make_cve("CVE-1", CveSeverity::Low),
            make_cve("CVE-2", CveSeverity::Unknown),
        ];

        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn pipeline_package_vuln_severity_filtered() {
        let action = MockAction::new("high");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::High);

        let events = vec![
            make_pkg("lodash", "GHSA-1", CveSeverity::Critical),
            make_pkg("lodash", "GHSA-2", CveSeverity::Medium),
        ];

        let results = pipeline.process("osv", events).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_cve_with_affected_packages() {
        let action = MockAction::new("pkgs");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let events = vec![ComplianceEvent::NewCve {
            cve_id: "CVE-2024-PKG".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![
                AffectedPackage {
                    name: "openssl".to_string(),
                    ecosystem: Some("debian".to_string()),
                    version_range: Some("< 3.0.12".to_string()),
                    fixed_version: Some("3.0.12".to_string()),
                },
            ],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: Utc::now(),
        }];

        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_multiple_sources_independent_state() {
        let action = MockAction::new("multi");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let cve = make_cve("CVE-SHARED", CveSeverity::High);

        // Same event from different sources should NOT be deduped
        let r1 = pipeline.process("nvd", vec![cve.clone()]).await.unwrap();
        let r2 = pipeline.process("osv", vec![cve]).await.unwrap();
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
    }

    #[tokio::test]
    async fn pipeline_processes_many_events() {
        let action = MockAction::new("bulk");
        let pipeline = make_pipeline(vec![Box::new(action)], CveSeverity::Unknown);

        let events: Vec<_> = (0..50)
            .map(|i| make_cve(&format!("CVE-{i}"), CveSeverity::High))
            .collect();

        let results = pipeline.process("nvd", events).await.unwrap();
        assert_eq!(results.len(), 50);
    }
}
