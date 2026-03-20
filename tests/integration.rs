use std::time::Duration;

use chrono::Utc;
use tameshi_watch::actions::{CveOnlyAction, MockAction};
use tameshi_watch::config::Config;
use tameshi_watch::event::{
    AffectedPackage, ComplianceEvent, CveSeverity, EventSource, ProfileSource,
};
use tameshi_watch::pipeline::EventPipeline;
use tameshi_watch::sources::{MockSourcePoller, SourcePoller};
use tameshi_watch::state::MemPollStateStore;

fn make_cve(id: &str, severity: CveSeverity) -> ComplianceEvent {
    ComplianceEvent::NewCve {
        cve_id: id.to_string(),
        severity,
        affected_packages: vec![AffectedPackage {
            name: "test-pkg".to_string(),
            ecosystem: Some("npm".to_string()),
            version_range: Some("< 2.0".to_string()),
            fixed_version: Some("2.0.0".to_string()),
        }],
        description: format!("Description for {id}"),
        source: EventSource::Nvd,
        timestamp: Utc::now(),
    }
}

fn make_pkg(name: &str, vuln_id: &str, severity: CveSeverity) -> ComplianceEvent {
    ComplianceEvent::PackageVulnerable {
        package: name.to_string(),
        ecosystem: "crates.io".to_string(),
        version: "0.1.0".to_string(),
        vulnerability_id: vuln_id.to_string(),
        severity,
        fix_version: Some("0.2.0".to_string()),
        source: EventSource::RustAdvisory,
        timestamp: Utc::now(),
    }
}

fn make_profile(id: &str, commit: &str) -> ComplianceEvent {
    ComplianceEvent::ProfileUpdated {
        profile_id: id.to_string(),
        source: ProfileSource::DevSec,
        repo_url: "https://github.com/dev-sec/linux-baseline".to_string(),
        new_commit: commit.to_string(),
        timestamp: Utc::now(),
    }
}

#[tokio::test]
async fn full_pipeline_mock_source_to_actions() {
    // Build a mock source with events
    let events = vec![
        make_cve("CVE-2024-0001", CveSeverity::Critical),
        make_cve("CVE-2024-0002", CveSeverity::High),
        make_pkg("serde", "RUSTSEC-2024-0001", CveSeverity::Medium),
    ];

    let poller = MockSourcePoller::new("test-source", Duration::from_secs(60), events.clone());

    // Build pipeline with mock action
    let action = MockAction::new("alert");
    let pipeline = EventPipeline::new(
        vec![Box::new(action)],
        Box::new(MemPollStateStore::new()),
        CveSeverity::Unknown,
    );

    // Poll the source
    let polled = poller.poll(None).await.unwrap();
    assert_eq!(polled.len(), 3);

    // Process through pipeline
    let results = pipeline.process(poller.name(), polled).await.unwrap();
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|r| r.success));
}

#[tokio::test]
async fn full_pipeline_with_severity_filtering() {
    let events = vec![
        make_cve("CVE-CRIT", CveSeverity::Critical),
        make_cve("CVE-HIGH", CveSeverity::High),
        make_cve("CVE-MED", CveSeverity::Medium),
        make_cve("CVE-LOW", CveSeverity::Low),
        make_profile("nist", "abc123"),
    ];

    let poller = MockSourcePoller::new("filtered", Duration::from_secs(120), events);
    let action = MockAction::new("high-filter");
    let pipeline = EventPipeline::new(
        vec![Box::new(action)],
        Box::new(MemPollStateStore::new()),
        CveSeverity::High,
    );

    let polled = poller.poll(None).await.unwrap();
    let results = pipeline.process(poller.name(), polled).await.unwrap();

    // Critical + High + Profile (bypasses severity) = 3
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn full_pipeline_dedup_across_polls() {
    let events = vec![make_cve("CVE-DUP", CveSeverity::High)];

    let poller = MockSourcePoller::new("dedup-src", Duration::from_secs(60), events);
    let action = MockAction::new("dedup-action");
    let store = MemPollStateStore::new();
    let pipeline = EventPipeline::new(
        vec![Box::new(action)],
        Box::new(store),
        CveSeverity::Unknown,
    );

    // First poll
    let polled1 = poller.poll(None).await.unwrap();
    let r1 = pipeline.process(poller.name(), polled1).await.unwrap();
    assert_eq!(r1.len(), 1);

    // Second poll — same events should be deduped
    let polled2 = poller.poll(None).await.unwrap();
    let r2 = pipeline.process(poller.name(), polled2).await.unwrap();
    assert!(r2.is_empty());
}

#[tokio::test]
async fn multi_source_concurrent_simulation() {
    let nvd_events = vec![
        make_cve("CVE-NVD-1", CveSeverity::Critical),
        make_cve("CVE-NVD-2", CveSeverity::High),
    ];
    let osv_events = vec![
        make_pkg("tokio", "GHSA-OSV-1", CveSeverity::High),
        make_pkg("serde", "GHSA-OSV-2", CveSeverity::Medium),
    ];

    let nvd_poller = MockSourcePoller::new("nvd", Duration::from_secs(300), nvd_events);
    let osv_poller = MockSourcePoller::new("osv", Duration::from_secs(600), osv_events);

    let action = MockAction::new("unified");
    let pipeline = EventPipeline::new(
        vec![Box::new(action)],
        Box::new(MemPollStateStore::new()),
        CveSeverity::Unknown,
    );

    // Simulate concurrent polling
    let nvd_polled = nvd_poller.poll(None).await.unwrap();
    let osv_polled = osv_poller.poll(None).await.unwrap();

    let nvd_results = pipeline
        .process(nvd_poller.name(), nvd_polled)
        .await
        .unwrap();
    let osv_results = pipeline
        .process(osv_poller.name(), osv_polled)
        .await
        .unwrap();

    assert_eq!(nvd_results.len(), 2);
    assert_eq!(osv_results.len(), 2);
}

#[tokio::test]
async fn pipeline_with_cve_only_and_general_actions() {
    let events = vec![
        make_cve("CVE-1", CveSeverity::High),
        make_profile("devsec", "def456"),
        make_pkg("rand", "RUSTSEC-1", CveSeverity::Low),
    ];

    let general = MockAction::new("general");
    let cve_only = CveOnlyAction::new("cve-alert");

    let pipeline = EventPipeline::new(
        vec![Box::new(general), Box::new(cve_only)],
        Box::new(MemPollStateStore::new()),
        CveSeverity::Unknown,
    );

    let results = pipeline.process("multi", events).await.unwrap();

    // general handles all 3, cve_only handles 1 = 4 total
    assert_eq!(results.len(), 4);
}

#[tokio::test]
async fn config_defaults_are_valid() {
    let config = Config::default();
    assert_eq!(config.port, 9090);
    assert!(config.nvd.enabled);
    assert!(config.osv.enabled);
    assert!(!config.profiles.enabled);
    assert_eq!(config.severity_threshold, CveSeverity::Low);
}

#[tokio::test]
async fn event_content_hash_uniqueness() {
    let e1 = make_cve("CVE-1", CveSeverity::High);
    let e2 = make_cve("CVE-2", CveSeverity::High);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[tokio::test]
async fn event_dedup_id_stability() {
    let e = make_cve("CVE-STABLE", CveSeverity::Critical);
    let id1 = e.dedup_id();
    let id2 = e.dedup_id();
    assert_eq!(id1, id2);
}

#[tokio::test]
async fn large_batch_processing() {
    let events: Vec<_> = (0..200)
        .map(|i| make_cve(&format!("CVE-BATCH-{i}"), CveSeverity::High))
        .collect();

    let action = MockAction::new("bulk");
    let pipeline = EventPipeline::new(
        vec![Box::new(action)],
        Box::new(MemPollStateStore::new()),
        CveSeverity::Unknown,
    );

    let results = pipeline.process("bulk", events).await.unwrap();
    assert_eq!(results.len(), 200);
}

#[tokio::test]
async fn fs_state_store_integration() {
    use tameshi_watch::state::{FsPollStateStore, PollState, PollStateStore};

    let dir = tempfile::tempdir().unwrap();
    let store = FsPollStateStore::new(dir.path().to_path_buf()).unwrap();

    let mut state = PollState::default();
    state.record("evt-1".to_string());
    state.record("evt-2".to_string());
    state.last_poll = Some(Utc::now());

    store.save("test-src", &state).unwrap();

    let loaded = store.load("test-src").unwrap();
    assert!(loaded.is_known("evt-1"));
    assert!(loaded.is_known("evt-2"));
    assert_eq!(loaded.total_ingested, 2);
    assert!(loaded.last_poll.is_some());
}
