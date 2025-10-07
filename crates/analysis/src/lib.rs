pub mod metrics;
pub use metrics::{Metrics, collect_metrics, compare};

use thiserror::Error;

/// Error type for metrics computation.
#[derive(Debug, Error)]
pub enum Error {
    /// CFG is empty or malformed.
    #[error("CFG is empty or malformed")]
    EmptyCfg,
    /// No body blocks found.
    #[error("no body blocks found")]
    NoBodyBlocks,
}

/// Analysis result type
pub type Result<T> = std::result::Result<T, Error>;
