//! Trace grouping and visible entry building logic.

use std::collections::HashSet;

use azoth_core::cfg_ir::{OperationKind, TraceEvent};

use crate::data::{ListEntry, TraceGroup};

/// Build trace groups from TransformStart/TransformEnd markers.
pub fn build_trace_groups(trace: &[TraceEvent]) -> Vec<TraceGroup> {
    let mut groups = Vec::new();
    let mut current_group: Option<TraceGroup> = None;
    let mut pending_events = Vec::new();
    let mut pending_name = "Setup".to_string();

    for (i, event) in trace.iter().enumerate() {
        match &event.kind {
            OperationKind::TransformStart { name } => {
                // Push any accumulated pending events as their own group
                if !pending_events.is_empty() {
                    groups.push(TraceGroup {
                        name: std::mem::take(&mut pending_name),
                        event_indices: std::mem::take(&mut pending_events),
                        expanded: false,
                    });
                }
                // Start new transform group
                current_group = Some(TraceGroup {
                    name: name.clone(),
                    event_indices: Vec::new(),
                    expanded: false,
                });
            }
            OperationKind::TransformEnd { .. } => {
                // Close current group
                if let Some(group) = current_group.take() {
                    groups.push(group);
                }
            }
            OperationKind::FinalizeStart => {
                // Push any accumulated pending events as their own group
                if !pending_events.is_empty() {
                    groups.push(TraceGroup {
                        name: std::mem::take(&mut pending_name),
                        event_indices: std::mem::take(&mut pending_events),
                        expanded: false,
                    });
                }
                // Start Finalize group
                current_group = Some(TraceGroup {
                    name: "Finalize".to_string(),
                    event_indices: Vec::new(),
                    expanded: false,
                });
            }
            OperationKind::Finalize => {
                // Add to current group (should be Finalize)
                if let Some(ref mut group) = current_group {
                    group.event_indices.push(i);
                } else {
                    pending_events.push(i);
                }
            }
            _ => {
                // Add to current transform group or pending
                if let Some(ref mut group) = current_group {
                    group.event_indices.push(i);
                } else {
                    pending_events.push(i);
                }
            }
        }
    }

    // Handle remaining pending events
    if !pending_events.is_empty() {
        if groups.is_empty() {
            groups.push(TraceGroup {
                name: "All Operations".to_string(),
                event_indices: pending_events,
                expanded: false,
            });
        } else {
            groups.push(TraceGroup {
                name: pending_name,
                event_indices: pending_events,
                expanded: false,
            });
        }
    }

    // Handle any unclosed transform group
    if let Some(group) = current_group {
        groups.push(group);
    }

    groups
}

/// Check if an operation kind is an edge-related operation.
pub const fn is_edge_operation(kind: &OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::SetUnconditionalJump { .. }
            | OperationKind::SetConditionalJump { .. }
            | OperationKind::RebuildEdges { .. }
    )
}

/// Check if an operation kind is a symbolic immediate operation.
pub const fn is_symbolic_operation(kind: &OperationKind) -> bool {
    matches!(kind, OperationKind::WriteSymbolicImmediates { .. })
}

/// Helper to collect consecutive operations matching a predicate.
pub fn collect_consecutive<F>(
    group: &TraceGroup,
    trace: &[TraceEvent],
    start: usize,
    predicate: F,
) -> Vec<usize>
where
    F: Fn(&OperationKind) -> bool,
{
    let mut indices = vec![group.event_indices[start]];
    let mut j = start + 1;
    while j < group.event_indices.len() {
        let next_idx = group.event_indices[j];
        let next_event = &trace[next_idx];
        if predicate(&next_event.kind) {
            indices.push(next_idx);
            j += 1;
        } else {
            break;
        }
    }
    indices
}

/// Build the flattened list of visible entries from groups and expansion state.
pub fn build_visible_entries(
    groups: &[TraceGroup],
    trace: &[TraceEvent],
    expanded_edge_groups: &HashSet<usize>,
    expanded_symbolic_groups: &HashSet<usize>,
) -> Vec<ListEntry> {
    let mut entries = Vec::new();
    for (gi, group) in groups.iter().enumerate() {
        entries.push(ListEntry::GroupHeader {
            name: group.name.clone(),
            op_count: group.event_indices.len(),
            expanded: group.expanded,
            group_idx: gi,
        });
        if group.expanded {
            let mut i = 0;
            while i < group.event_indices.len() {
                let trace_idx = group.event_indices[i];
                let event = &trace[trace_idx];

                // Check if this is an edge operation
                if is_edge_operation(&event.kind) {
                    let edge_indices = collect_consecutive(group, trace, i, is_edge_operation);
                    let count = edge_indices.len();

                    // Only group if there are multiple consecutive edge ops
                    if count > 1 {
                        let key = edge_indices[0];
                        let expanded = expanded_edge_groups.contains(&key);
                        entries.push(ListEntry::EdgeGroup {
                            trace_indices: edge_indices.clone(),
                            group_idx: gi,
                            key,
                            expanded,
                        });
                        if expanded {
                            for &idx in &edge_indices {
                                entries.push(ListEntry::EdgeOperation {
                                    trace_idx: idx,
                                    group_idx: gi,
                                });
                            }
                        }
                        i += count;
                    } else {
                        entries.push(ListEntry::Operation {
                            trace_idx,
                            group_idx: gi,
                        });
                        i += 1;
                    }
                // Check if this is a symbolic operation
                } else if is_symbolic_operation(&event.kind) {
                    let symbolic_indices =
                        collect_consecutive(group, trace, i, is_symbolic_operation);
                    let count = symbolic_indices.len();

                    // Only group if there are multiple consecutive symbolic ops
                    if count > 1 {
                        let key = symbolic_indices[0];
                        let expanded = expanded_symbolic_groups.contains(&key);
                        entries.push(ListEntry::SymbolicGroup {
                            trace_indices: symbolic_indices.clone(),
                            group_idx: gi,
                            key,
                            expanded,
                        });
                        if expanded {
                            for &idx in &symbolic_indices {
                                entries.push(ListEntry::SymbolicOperation {
                                    trace_idx: idx,
                                    group_idx: gi,
                                });
                            }
                        }
                        i += count;
                    } else {
                        entries.push(ListEntry::Operation {
                            trace_idx,
                            group_idx: gi,
                        });
                        i += 1;
                    }
                } else {
                    entries.push(ListEntry::Operation {
                        trace_idx,
                        group_idx: gi,
                    });
                    i += 1;
                }
            }
        }
    }
    entries
}
