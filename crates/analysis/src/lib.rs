//! Analytical utilities for assessing Azoth camouflage results. The crate exposes:
//! - Core metrics for bytecode size, control-flow structure, stack usage, and dominator overlap to
//!   estimate transform potency and gas impact.
//! - Comparison helpers that derive before/after deltas directly from a `CfgIrBundle` and
//!   `CleanReport`.
//! - An camouflage study that repeatedly camouflages bytecode with randomized seeds,
//!   aggregates longest preserved byte sequences, emits percentile summaries, tracks top repeated
//!   motifs, and measures n-gram diversity for multiple n values before producing a Markdown
//!   report.

pub mod decompile_diff;
pub mod metrics;
pub use metrics::{Metrics, collect_metrics, compare};

pub mod camouflage;

/// Compatibility imports for the original analysis module.
pub mod obfuscation {
    pub use crate::camouflage::analyze_camouflage as analyze_obfuscation;
    pub use crate::camouflage::*;
}

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
