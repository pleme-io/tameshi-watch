pub mod nvd;
pub mod osv;
pub mod profile_watcher;

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::WatchError;
use crate::event::ComplianceEvent;

/// A source that can be polled for compliance events.
pub trait SourcePoller: Send + Sync {
    /// Human-readable name for this source.
    fn name(&self) -> &str;

    /// How often this source should be polled.
    fn poll_interval(&self) -> Duration;

    /// Poll for new events since the given timestamp.
    fn poll(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ComplianceEvent>, WatchError>> + Send + '_>>;
}

/// A mock source poller for testing.
pub struct MockSourcePoller {
    source_name: String,
    interval: Duration,
    events: Vec<ComplianceEvent>,
}

impl MockSourcePoller {
    /// Create a mock poller that returns the given events on each poll.
    #[must_use]
    pub fn new(name: &str, interval: Duration, events: Vec<ComplianceEvent>) -> Self {
        Self {
            source_name: name.to_string(),
            interval,
            events,
        }
    }
}

impl SourcePoller for MockSourcePoller {
    fn name(&self) -> &str {
        &self.source_name
    }

    fn poll_interval(&self) -> Duration {
        self.interval
    }

    fn poll(
        &self,
        _since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ComplianceEvent>, WatchError>> + Send + '_>> {
        let events = self.events.clone();
        Box::pin(async move { Ok(events) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CveSeverity, EventSource};

    fn make_test_event() -> ComplianceEvent {
        ComplianceEvent::NewCve {
            cve_id: "CVE-2024-0001".to_string(),
            severity: CveSeverity::High,
            affected_packages: vec![],
            description: "test".to_string(),
            source: EventSource::Nvd,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn mock_poller_name() {
        let poller = MockSourcePoller::new("test", Duration::from_secs(60), vec![]);
        assert_eq!(poller.name(), "test");
    }

    #[test]
    fn mock_poller_interval() {
        let poller = MockSourcePoller::new("test", Duration::from_secs(120), vec![]);
        assert_eq!(poller.poll_interval(), Duration::from_secs(120));
    }

    #[tokio::test]
    async fn mock_poller_returns_events() {
        let events = vec![make_test_event()];
        let poller = MockSourcePoller::new("test", Duration::from_secs(60), events);
        let result = poller.poll(None).await.unwrap();
        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn mock_poller_empty() {
        let poller = MockSourcePoller::new("test", Duration::from_secs(60), vec![]);
        let result = poller.poll(None).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn mock_poller_multiple_events() {
        let events = vec![make_test_event(), make_test_event(), make_test_event()];
        let poller = MockSourcePoller::new("multi", Duration::from_secs(30), events);
        let result = poller.poll(Some(Utc::now())).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn source_poller_is_object_safe() {
        // Verify the trait can be used as a trait object.
        fn _accept(_: &dyn SourcePoller) {}
        let poller = MockSourcePoller::new("test", Duration::from_secs(1), vec![]);
        _accept(&poller);
    }

    #[test]
    fn source_poller_dyn_box() {
        let poller: Box<dyn SourcePoller> =
            Box::new(MockSourcePoller::new("boxed", Duration::from_secs(10), vec![]));
        assert_eq!(poller.name(), "boxed");
    }
}
