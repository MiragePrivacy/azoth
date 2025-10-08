//! The analysis module implements a minimal set of metrics quantified by bytecode size, control flow complexity,
//! stack usage, and dominator overlap to assess transform potency (analyst effort) and gas
//! efficiency. The module provides functions to collect metrics from a `CfgIrBundle` and
//! `CleanReport`, compare pre- and post-obfuscation states, and compute
//! dominator/post-dominator pairs for control flow analysis.

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
