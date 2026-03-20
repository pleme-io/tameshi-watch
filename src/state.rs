use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::WatchError;

/// Tracks polling state for a single source.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PollState {
    /// When the source was last successfully polled.
    pub last_poll: Option<DateTime<Utc>>,
    /// Known event IDs (for dedup).
    pub known_ids: HashSet<String>,
    /// Total number of events ingested from this source.
    pub total_ingested: u64,
}

impl PollState {
    /// Returns true if the given ID is already known.
    #[must_use]
    pub fn is_known(&self, id: &str) -> bool {
        self.known_ids.contains(id)
    }

    /// Record a new event ID.
    pub fn record(&mut self, id: String) {
        self.known_ids.insert(id);
        self.total_ingested += 1;
    }
}

/// Trait for persisting poll state.
pub trait PollStateStore: Send + Sync {
    /// Load state for the named source.
    ///
    /// # Errors
    ///
    /// Returns an error if state cannot be loaded.
    fn load(&self, source: &str) -> Result<PollState, WatchError>;

    /// Save state for the named source.
    ///
    /// # Errors
    ///
    /// Returns an error if state cannot be saved.
    fn save(&self, source: &str, state: &PollState) -> Result<(), WatchError>;
}

/// Filesystem-backed poll state store.
pub struct FsPollStateStore {
    dir: PathBuf,
}

impl FsPollStateStore {
    /// Create a new filesystem poll state store.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn new(dir: PathBuf) -> Result<Self, WatchError> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path_for(&self, source: &str) -> PathBuf {
        self.dir.join(format!("{source}.json"))
    }
}

impl PollStateStore for FsPollStateStore {
    fn load(&self, source: &str) -> Result<PollState, WatchError> {
        let path = self.path_for(source);
        if !path.exists() {
            return Ok(PollState::default());
        }
        let data = std::fs::read_to_string(&path)?;
        serde_json::from_str(&data).map_err(WatchError::from)
    }

    fn save(&self, source: &str, state: &PollState) -> Result<(), WatchError> {
        let path = self.path_for(source);
        let data = serde_json::to_string_pretty(state)?;
        std::fs::write(&path, data).map_err(WatchError::from)
    }
}

/// In-memory poll state store (for testing).
pub struct MemPollStateStore {
    states: Mutex<HashMap<String, PollState>>,
}

impl MemPollStateStore {
    /// Create a new in-memory state store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemPollStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PollStateStore for MemPollStateStore {
    fn load(&self, source: &str) -> Result<PollState, WatchError> {
        let states = self
            .states
            .lock()
            .map_err(|e| WatchError::StateStore(e.to_string()))?;
        Ok(states.get(source).cloned().unwrap_or_default())
    }

    fn save(&self, source: &str, state: &PollState) -> Result<(), WatchError> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| WatchError::StateStore(e.to_string()))?;
        states.insert(source.to_string(), state.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_state_default() {
        let state = PollState::default();
        assert!(state.last_poll.is_none());
        assert!(state.known_ids.is_empty());
        assert_eq!(state.total_ingested, 0);
    }

    #[test]
    fn poll_state_record() {
        let mut state = PollState::default();
        state.record("id-1".to_string());
        assert!(state.is_known("id-1"));
        assert!(!state.is_known("id-2"));
        assert_eq!(state.total_ingested, 1);
    }

    #[test]
    fn poll_state_record_idempotent_set() {
        let mut state = PollState::default();
        state.record("id-1".to_string());
        state.record("id-1".to_string());
        assert_eq!(state.known_ids.len(), 1);
        // total_ingested increments regardless
        assert_eq!(state.total_ingested, 2);
    }

    #[test]
    fn poll_state_serde_roundtrip() {
        let mut state = PollState::default();
        state.last_poll = Some(Utc::now());
        state.record("abc".to_string());
        state.record("def".to_string());

        let json = serde_json::to_string(&state).unwrap();
        let back: PollState = serde_json::from_str(&json).unwrap();
        assert!(back.last_poll.is_some());
        assert_eq!(back.known_ids.len(), 2);
        assert_eq!(back.total_ingested, 2);
    }

    #[test]
    fn mem_store_load_empty() {
        let store = MemPollStateStore::new();
        let state = store.load("test").unwrap();
        assert!(state.known_ids.is_empty());
    }

    #[test]
    fn mem_store_save_and_load() {
        let store = MemPollStateStore::new();
        let mut state = PollState::default();
        state.record("event-1".to_string());
        state.last_poll = Some(Utc::now());

        store.save("nvd", &state).unwrap();
        let loaded = store.load("nvd").unwrap();
        assert!(loaded.is_known("event-1"));
        assert_eq!(loaded.total_ingested, 1);
    }

    #[test]
    fn mem_store_multiple_sources() {
        let store = MemPollStateStore::new();

        let mut s1 = PollState::default();
        s1.record("a".to_string());
        store.save("src1", &s1).unwrap();

        let mut s2 = PollState::default();
        s2.record("b".to_string());
        s2.record("c".to_string());
        store.save("src2", &s2).unwrap();

        let loaded1 = store.load("src1").unwrap();
        let loaded2 = store.load("src2").unwrap();
        assert_eq!(loaded1.known_ids.len(), 1);
        assert_eq!(loaded2.known_ids.len(), 2);
    }

    #[test]
    fn mem_store_overwrite() {
        let store = MemPollStateStore::new();
        let mut s1 = PollState::default();
        s1.record("a".to_string());
        store.save("src", &s1).unwrap();

        let mut s2 = PollState::default();
        s2.record("b".to_string());
        store.save("src", &s2).unwrap();

        let loaded = store.load("src").unwrap();
        assert!(!loaded.is_known("a"));
        assert!(loaded.is_known("b"));
    }

    #[test]
    fn fs_store_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsPollStateStore::new(dir.path().to_path_buf()).unwrap();

        let mut state = PollState::default();
        state.record("cve-1".to_string());
        state.last_poll = Some(Utc::now());

        store.save("nvd", &state).unwrap();
        let loaded = store.load("nvd").unwrap();
        assert!(loaded.is_known("cve-1"));
        assert_eq!(loaded.total_ingested, 1);
    }

    #[test]
    fn fs_store_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsPollStateStore::new(dir.path().to_path_buf()).unwrap();
        let state = store.load("nonexistent").unwrap();
        assert!(state.known_ids.is_empty());
    }

    #[test]
    fn fs_store_multiple_sources() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsPollStateStore::new(dir.path().to_path_buf()).unwrap();

        let mut s1 = PollState::default();
        s1.record("x".to_string());
        store.save("a", &s1).unwrap();

        let mut s2 = PollState::default();
        s2.record("y".to_string());
        store.save("b", &s2).unwrap();

        assert!(store.load("a").unwrap().is_known("x"));
        assert!(store.load("b").unwrap().is_known("y"));
        assert!(!store.load("a").unwrap().is_known("y"));
    }

    #[test]
    fn fs_store_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsPollStateStore::new(dir.path().to_path_buf()).unwrap();

        let mut s1 = PollState::default();
        s1.record("old".to_string());
        store.save("src", &s1).unwrap();

        let mut s2 = PollState::default();
        s2.record("new".to_string());
        store.save("src", &s2).unwrap();

        let loaded = store.load("src").unwrap();
        assert!(!loaded.is_known("old"));
        assert!(loaded.is_known("new"));
    }

    #[test]
    fn poll_state_with_many_ids() {
        let mut state = PollState::default();
        for i in 0..100 {
            state.record(format!("id-{i}"));
        }
        assert_eq!(state.known_ids.len(), 100);
        assert_eq!(state.total_ingested, 100);
        assert!(state.is_known("id-50"));
    }

    #[test]
    fn mem_store_default_impl() {
        let store = MemPollStateStore::default();
        let state = store.load("test").unwrap();
        assert!(state.known_ids.is_empty());
    }
}
