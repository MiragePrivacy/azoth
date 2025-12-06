//! Detail cache building for pre-computed UI content.

use std::collections::HashMap;

use ratatui::text::Line;

use crate::data::{DebugOutput, DetailCache, TraceGroup};
use crate::format::operation::{
    format_edge_group_detail_lines, format_group_detail_lines, format_operation_detail_lines,
    format_symbolic_group_detail_lines,
};
use crate::trace::{collect_consecutive, is_edge_operation, is_symbolic_operation};

/// Build the detail cache for all entries at startup.
///
/// This pre-computes all detail content so that render_detail can simply
/// look up the cached lines rather than recomputing them on every frame.
pub fn build_detail_cache(debug: &DebugOutput, groups: &[TraceGroup]) -> DetailCache {
    // Pre-compute detail lines for each trace event
    let trace_details: Vec<Vec<Line<'static>>> = debug
        .trace
        .iter()
        .map(format_operation_detail_lines)
        .collect();

    // Pre-compute detail lines for each group header
    let group_details: Vec<Vec<Line<'static>>> = groups
        .iter()
        .map(|group| {
            format_group_detail_lines(&group.name, group.event_indices.len(), groups, &debug.trace)
        })
        .collect();

    // Pre-compute detail lines for edge groups and symbolic groups
    // We need to identify all possible edge groups and symbolic groups
    let mut edge_group_details = HashMap::new();
    let mut symbolic_group_details = HashMap::new();

    for group in groups {
        let mut i = 0;
        while i < group.event_indices.len() {
            let trace_idx = group.event_indices[i];
            let event = &debug.trace[trace_idx];

            if is_edge_operation(&event.kind) {
                let edge_indices = collect_consecutive(group, &debug.trace, i, is_edge_operation);
                if edge_indices.len() > 1 {
                    let key = edge_indices[0];
                    edge_group_details.entry(key).or_insert_with(|| {
                        format_edge_group_detail_lines(&edge_indices, &debug.trace)
                    });
                    i += edge_indices.len();
                } else {
                    i += 1;
                }
            } else if is_symbolic_operation(&event.kind) {
                let symbolic_indices =
                    collect_consecutive(group, &debug.trace, i, is_symbolic_operation);
                if symbolic_indices.len() > 1 {
                    let key = symbolic_indices[0];
                    symbolic_group_details.entry(key).or_insert_with(|| {
                        format_symbolic_group_detail_lines(&symbolic_indices, &debug.trace)
                    });
                    i += symbolic_indices.len();
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
    }

    DetailCache::new(
        trace_details,
        group_details,
        edge_group_details,
        symbolic_group_details,
    )
}
