//! Verification results and error types

use thiserror::Error;

/// Main error type for verification operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("SMT solver error: {0}")]
    SmtSolver(String),
    #[error("Verification timeout after {seconds} seconds")]
    Timeout { seconds: u64 },
    #[error("Bytecode analysis failed: {0}")]
    BytecodeAnalysis(String),
    #[error("Property verification failed: {property}")]
    PropertyFailed { property: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for verification operations
pub type Result<T> = std::result::Result<T, Error>;
