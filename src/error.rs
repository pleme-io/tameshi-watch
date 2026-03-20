use thiserror::Error;

/// Errors that can occur in tameshi-watch.
#[derive(Debug, Error)]
pub enum WatchError {
    /// An HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// File I/O failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Source polling failed.
    #[error("source '{source_name}' poll failed: {message}")]
    PollFailed {
        source_name: String,
        message: String,
    },

    /// Action execution failed.
    #[error("action '{action_name}' failed: {message}")]
    ActionFailed {
        action_name: String,
        message: String,
    },

    /// State store error.
    #[error("state store error: {0}")]
    StateStore(String),

    /// Git operation error.
    #[error("git error: {0}")]
    Git(String),

    /// Parse error.
    #[error("parse error: {0}")]
    Parse(String),
}
