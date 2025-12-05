//! Formatting modules for trace events, diffs, and bytecode.

pub mod bytecode;
mod cache;
pub mod diff;
pub mod operation;

pub use cache::build_detail_cache;
pub use operation::{format_diff_summary, format_operation_kind_full, format_operation_kind_short};
