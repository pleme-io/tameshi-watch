pub mod blast_radius;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::WatchError;
use crate::event::ComplianceEvent;

/// Result of executing an action.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionResult {
    /// Name of the action that produced this result.
    pub action: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
    /// How long the action took in milliseconds.
    pub duration_ms: u64,
}

/// An action that responds to compliance events.
pub trait Action: Send + Sync {
    /// Human-readable name for this action.
    fn name(&self) -> &str;

    /// Returns true if this action should handle the given event.
    fn handles(&self, event: &ComplianceEvent) -> bool;

    /// Execute this action for the given event.
    fn execute(
        &self,
        event: &ComplianceEvent,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, WatchError>> + Send + '_>>;
}

/// Record of a mock action call (for testing).
#[derive(Clone, Debug)]
pub struct MockCall {
    /// The dedup ID of the event that triggered this call.
    pub event_id: String,
}

/// A mock action that records all calls for verification.
pub struct MockAction {
    action_name: String,
    calls: Arc<Mutex<Vec<MockCall>>>,
    handles_all: bool,
}

impl MockAction {
    /// Create a mock action that handles all events.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            action_name: name.to_string(),
            calls: Arc::new(Mutex::new(Vec::new())),
            handles_all: true,
        }
    }

    /// Create a mock action that handles no events.
    #[must_use]
    pub fn new_selective(name: &str) -> Self {
        Self {
            action_name: name.to_string(),
            calls: Arc::new(Mutex::new(Vec::new())),
            handles_all: false,
        }
    }

    /// Get a snapshot of all recorded calls.
    #[must_use]
    pub fn calls(&self) -> Vec<MockCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Get the number of recorded calls.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Action for MockAction {
    fn name(&self) -> &str {
        &self.action_name
    }

    fn handles(&self, _event: &ComplianceEvent) -> bool {
        self.handles_all
    }

    fn execute(
        &self,
        event: &ComplianceEvent,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, WatchError>> + Send + '_>> {
        let name = self.action_name.clone();
        let event_id = event.dedup_id();
        let calls = Arc::clone(&self.calls);

        Box::pin(async move {
            calls.lock().unwrap().push(MockCall {
                event_id: event_id.clone(),
            });
            Ok(ActionResult {
                action: name,
                success: true,
                message: format!("processed {event_id}"),
                duration_ms: 0,
            })
        })
    }
}

/// An action that only handles CVE events.
pub struct CveOnlyAction {
    action_name: String,
    calls: Arc<Mutex<Vec<MockCall>>>,
}

impl CveOnlyAction {
    /// Create a new CVE-only action.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            action_name: name.to_string(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get the number of recorded calls.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Action for CveOnlyAction {
    fn name(&self) -> &str {
        &self.action_name
    }

    fn handles(&self, event: &ComplianceEvent) -> bool {
        matches!(event, ComplianceEvent::NewCve { .. })
    }

    fn execute(
        &self,
        event: &ComplianceEvent,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, WatchError>> + Send + '_>> {
        let name = self.action_name.clone();
        let event_id = event.dedup_id();
        let calls = Arc::clone(&self.calls);

        Box::pin(async move {
            calls.lock().unwrap().push(MockCall {
                event_id: event_id.clone(),
            });
            Ok(ActionResult {
                action: name,
                success: true,
                message: format!("cve: {event_id}"),
                duration_ms: 1,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CveSeverity, EventSource, ProfileSource};
    use chrono::Utc;

    fn make_cve_event() -> ComplianceEvent {
        ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: Utc::now(),
        }
    }

    fn make_profile_event() -> ComplianceEvent {
        ComplianceEvent::ProfileUpdated {
            profile_id: "nist".to_string(),
            source: ProfileSource::Mitre,
            repo_url: "https://example.com".to_string(),
            new_commit: "abc".to_string(),
            timestamp: Utc::now(),
        }
    }

    fn make_pkg_event() -> ComplianceEvent {
        ComplianceEvent::PackageVulnerable {
            package: "lodash".to_string(),
            ecosystem: "npm".to_string(),
            version: "4.17.20".to_string(),
            vulnerability_id: "GHSA-xxxx".to_string(),
            severity: CveSeverity::Medium,
            fix_version: Some("4.17.21".to_string()),
            source: EventSource::Osv,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn mock_action_name() {
        let action = MockAction::new("test-action");
        assert_eq!(action.name(), "test-action");
    }

    #[test]
    fn mock_action_handles_all() {
        let action = MockAction::new("all");
        assert!(action.handles(&make_cve_event()));
        assert!(action.handles(&make_profile_event()));
        assert!(action.handles(&make_pkg_event()));
    }

    #[test]
    fn mock_action_selective_handles_none() {
        let action = MockAction::new_selective("none");
        assert!(!action.handles(&make_cve_event()));
        assert!(!action.handles(&make_profile_event()));
    }

    #[tokio::test]
    async fn mock_action_records_calls() {
        let action = MockAction::new("recorder");
        action.execute(&make_cve_event()).await.unwrap();
        action.execute(&make_pkg_event()).await.unwrap();
        assert_eq!(action.call_count(), 2);
    }

    #[tokio::test]
    async fn mock_action_returns_success() {
        let action = MockAction::new("success");
        let result = action.execute(&make_cve_event()).await.unwrap();
        assert!(result.success);
        assert_eq!(result.action, "success");
    }

    #[tokio::test]
    async fn mock_action_call_event_ids() {
        let action = MockAction::new("ids");
        let cve = make_cve_event();
        action.execute(&cve).await.unwrap();
        let calls = action.calls();
        assert_eq!(calls[0].event_id, cve.dedup_id());
    }

    #[test]
    fn action_result_serde_roundtrip() {
        let result = ActionResult {
            action: "test".to_string(),
            success: true,
            message: "ok".to_string(),
            duration_ms: 42,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ActionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, "test");
        assert!(back.success);
        assert_eq!(back.duration_ms, 42);
    }

    #[test]
    fn action_result_failure() {
        let result = ActionResult {
            action: "fail".to_string(),
            success: false,
            message: "something went wrong".to_string(),
            duration_ms: 100,
        };
        assert!(!result.success);
    }

    #[test]
    fn cve_only_action_handles_cve() {
        let action = CveOnlyAction::new("cve-only");
        assert!(action.handles(&make_cve_event()));
    }

    #[test]
    fn cve_only_action_rejects_profile() {
        let action = CveOnlyAction::new("cve-only");
        assert!(!action.handles(&make_profile_event()));
    }

    #[test]
    fn cve_only_action_rejects_package() {
        let action = CveOnlyAction::new("cve-only");
        assert!(!action.handles(&make_pkg_event()));
    }

    #[tokio::test]
    async fn cve_only_action_records_calls() {
        let action = CveOnlyAction::new("cve-recorder");
        action.execute(&make_cve_event()).await.unwrap();
        assert_eq!(action.call_count(), 1);
    }

    #[test]
    fn action_trait_is_object_safe() {
        fn _accept(_: &dyn Action) {}
        let action = MockAction::new("safe");
        _accept(&action);
    }

    #[test]
    fn action_trait_dyn_box() {
        let action: Box<dyn Action> = Box::new(MockAction::new("boxed"));
        assert_eq!(action.name(), "boxed");
    }

    #[test]
    fn mock_action_zero_calls_initially() {
        let action = MockAction::new("empty");
        assert_eq!(action.call_count(), 0);
        assert!(action.calls().is_empty());
    }

    #[tokio::test]
    async fn action_result_message_contains_event_id() {
        let action = MockAction::new("msg");
        let event = make_cve_event();
        let result = action.execute(&event).await.unwrap();
        assert!(result.message.contains(&event.dedup_id()));
    }

    #[tokio::test]
    async fn multiple_actions_same_event() {
        let a1 = MockAction::new("a1");
        let a2 = MockAction::new("a2");
        let event = make_cve_event();
        a1.execute(&event).await.unwrap();
        a2.execute(&event).await.unwrap();
        assert_eq!(a1.call_count(), 1);
        assert_eq!(a2.call_count(), 1);
    }
}
