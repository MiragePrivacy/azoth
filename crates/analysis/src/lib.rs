//! Analytical utilities for Azoth. The crate exposes:
//! - Core metrics for bytecode size, control-flow structure, stack usage, and dominator overlap.
//! - Comparison helpers that derive before/after deltas directly from a `CfgIrBundle` and
//!   `CleanReport`.
//! - Dataset analysis helpers for comparing bytecode against deployed contract corpora.

pub mod decompile_diff;
pub mod metrics;
pub use metrics::{Metrics, collect_metrics, compare};

pub mod comparison;
pub mod dataset;

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
