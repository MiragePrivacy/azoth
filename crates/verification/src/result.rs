//! Verification results and error types

use thiserror::Error;

/// Main error type for verification operations
#[derive(Error, Debug)]
pub enum Error {
    /// The requested verification flow has no sound implementation yet.
    #[error("verification is unavailable: {reason}")]
    VerificationUnavailable { reason: String },
    /// A proof request contained no obligations or otherwise omitted required work.
    #[error("verification is incomplete: {reason}")]
    IncompleteProof { reason: String },
    /// The verifier cannot soundly interpret the requested formula or obligation.
    #[error("unsupported verification obligation: {0}")]
    Unsupported(String),
    /// The SMT solver could not determine satisfiability.
    #[error("SMT solver returned unknown: {0}")]
    SolverUnknown(String),
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
