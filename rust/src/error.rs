use std::array::TryFromSliceError;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;

#[derive(thiserror::Error, Debug)]
pub enum HeraclitusError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Byte parsing error (slice conversion): {0}")]
    TryFromSlice(#[from] TryFromSliceError),

    #[error("System time error: {0}")]
    SystemTime(#[from] SystemTimeError),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] FromUtf8Error),

    #[error("Artifact not found or invalid: {0}")]
    ArtifactError(String),

    #[error("Invalid FlatBuffer encoding/decoding: {0}")]
    FactEncodingError(String),

    #[error("Database corruption detected: {0}")]
    DatabaseCorruption(String),

    #[error("Schema Drift: {0}")]
    SchemaDrift(String),

    #[error("Runner Error: {0}")]
    RunnerError(String),

    #[error("Other Error: {0}")]
    Other(String),
}
