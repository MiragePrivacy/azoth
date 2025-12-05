//! Data structures for the TUI application.

use serde::Deserialize;
use std::collections::HashMap;

use azoth_core::cfg_ir::TraceEvent;
use ratatui::text::Line;

/// Debug output format - subset of ObfuscationResult.
///
/// This is the main data structure loaded from the debug JSON file
/// produced by the obfuscator.
#[derive(Debug, Deserialize)]
pub struct DebugOutput {
    /// Metadata about the obfuscation run.
    #[allow(dead_code)]
    pub metadata: DebugMetadata,
    /// Trace events recording each operation performed.
    pub trace: Vec<TraceEvent>,
}

/// Metadata from obfuscation.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DebugMetadata {
    /// Names of transforms that were applied.
    pub transforms_applied: Vec<String>,
    /// Whether the size limit was exceeded during obfuscation.
    #[serde(default)]
    pub size_limit_exceeded: bool,
    /// Whether unknown opcodes were preserved.
    #[serde(default)]
    pub unknown_opcodes_preserved: bool,
}

/// A displayable item in the list (either a group header or an operation).
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ListEntry {
    /// Transform group header.
    GroupHeader {
        name: String,
        op_count: usize,
        expanded: bool,
        group_idx: usize,
    },
    /// Individual operation.
    Operation { trace_idx: usize, group_idx: usize },
    /// Grouped consecutive edge operations (collapsible).
    EdgeGroup {
        trace_indices: Vec<usize>,
        group_idx: usize,
        /// First trace index used as unique key for expansion state.
        key: usize,
        expanded: bool,
    },
    /// Individual edge operation within an expanded EdgeGroup.
    EdgeOperation { trace_idx: usize, group_idx: usize },
    /// Grouped consecutive symbolic immediate operations (collapsible).
    SymbolicGroup {
        trace_indices: Vec<usize>,
        group_idx: usize,
        /// First trace index used as unique key for expansion state.
        key: usize,
        expanded: bool,
    },
    /// Individual symbolic operation within an expanded SymbolicGroup.
    SymbolicOperation { trace_idx: usize, group_idx: usize },
}

/// A group of trace events belonging to a transform phase.
#[derive(Debug)]
#[allow(missing_docs)]
pub struct TraceGroup {
    pub name: String,
    pub event_indices: Vec<usize>,
    pub expanded: bool,
}

/// Pre-computed detail content for each entry type.
#[derive(Debug)]
pub struct DetailCache {
    /// Detail lines for each trace event (indexed by trace_idx).
    pub trace_details: Vec<Vec<Line<'static>>>,
    /// Detail lines for each group header (indexed by group_idx).
    pub group_details: Vec<Vec<Line<'static>>>,
    /// Detail lines for edge groups (keyed by first trace index).
    pub edge_group_details: HashMap<usize, Vec<Line<'static>>>,
    /// Detail lines for symbolic groups (keyed by first trace index).
    pub symbolic_group_details: HashMap<usize, Vec<Line<'static>>>,
}

impl DetailCache {
    /// Create a new detail cache.
    pub(crate) const fn new(
        trace_details: Vec<Vec<Line<'static>>>,
        group_details: Vec<Vec<Line<'static>>>,
        edge_group_details: HashMap<usize, Vec<Line<'static>>>,
        symbolic_group_details: HashMap<usize, Vec<Line<'static>>>,
    ) -> Self {
        Self {
            trace_details,
            group_details,
            edge_group_details,
            symbolic_group_details,
        }
    }
}
