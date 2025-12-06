//! Formatting functions for operations and groups.

use std::collections::{HashMap, HashSet};

use azoth_core::cfg_ir::{CfgIrDiff, OperationKind, TraceEvent};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::data::TraceGroup;
use crate::format::bytecode::format_annotated_bytecode;
use crate::format::diff::{format_control_flow, format_instruction_diff_colored};

/// Format an operation kind as a short string for the list view.
pub fn format_operation_kind_short(kind: &OperationKind) -> String {
    match kind {
        OperationKind::TransformStart { name } => format!("▶ {name}"),
        OperationKind::TransformEnd { name } => format!("◀ {name}"),
        OperationKind::Build { body_blocks, .. } => format!("Build({body_blocks})"),
        OperationKind::AddBlock { node, .. } => format!("AddBlock({node})"),
        OperationKind::OverwriteBlock { node } => format!("Overwrite({node})"),
        OperationKind::OverwriteBlocks { blocks_modified } => {
            format!("Overwrite({blocks_modified})")
        }
        OperationKind::SetUnconditionalJump { source, target } => {
            format!("Jump({source}->{target})")
        }
        OperationKind::SetConditionalJump { source, .. } => format!("Branch({source})"),
        OperationKind::RebuildEdges { node } => format!("Edges({node})"),
        OperationKind::WriteSymbolicImmediates { node } => format!("Symbolic({node})"),
        OperationKind::ReindexPcs => "ReindexPCs".to_string(),
        OperationKind::PatchJumpImmediates => "PatchJumps".to_string(),
        OperationKind::PatchDispatcher { blocks_modified } => {
            format!("PatchDispatcher({blocks_modified})")
        }
        OperationKind::ReplaceBody { instruction_count } => format!("Replace({instruction_count})"),
        OperationKind::FinalizeStart => "▶ Finalize".to_string(),
        OperationKind::Finalize => "Finalize".to_string(),
    }
}

/// Format an operation kind as a full descriptive string.
pub fn format_operation_kind_full(kind: &OperationKind) -> String {
    match kind {
        OperationKind::TransformStart { name } => format!("Transform Start: {name}"),
        OperationKind::TransformEnd { name } => format!("Transform End: {name}"),
        OperationKind::Build {
            body_blocks,
            sections,
        } => {
            format!("Build CFG ({body_blocks} blocks, {sections} sections)")
        }
        OperationKind::AddBlock {
            node,
            instruction_count,
        } => {
            format!("Add Block {node} ({instruction_count} instructions)")
        }
        OperationKind::OverwriteBlock { node } => format!("Overwrite Block {node}"),
        OperationKind::OverwriteBlocks { blocks_modified } => {
            format!("Overwrite Blocks ({blocks_modified} blocks)")
        }
        OperationKind::SetUnconditionalJump { source, target } => {
            format!("Set Jump: {source} → {target}")
        }
        OperationKind::SetConditionalJump {
            source,
            true_target,
            false_target,
        } => {
            format!("Set Branch: {source} → T:{true_target} / F:{false_target:?}")
        }
        OperationKind::RebuildEdges { node } => format!("Rebuild Edges for {node}"),
        OperationKind::WriteSymbolicImmediates { node } => {
            format!("Write Symbolic Immediates for {node}")
        }
        OperationKind::ReindexPcs => "Reindex PCs".to_string(),
        OperationKind::PatchJumpImmediates => "Patch Jump Immediates".to_string(),
        OperationKind::PatchDispatcher { blocks_modified } => {
            format!("Patch Dispatcher ({blocks_modified} blocks)")
        }
        OperationKind::ReplaceBody { instruction_count } => {
            format!("Replace Body ({instruction_count} instructions)")
        }
        OperationKind::FinalizeStart => "Finalize Start".to_string(),
        OperationKind::Finalize => "Finalize".to_string(),
    }
}

/// Format a diff summary as a short string for the list view.
pub fn format_diff_summary(diff: &CfgIrDiff) -> String {
    match diff {
        CfgIrDiff::None => String::new(),
        CfgIrDiff::BlockChanges(changes) => format!("[{}Δ]", changes.changes.len()),
        CfgIrDiff::EdgeChanges(changes) => {
            format!("[+{}-{}e]", changes.added.len(), changes.removed.len())
        }
        CfgIrDiff::PcsRemapped { blocks, .. } => format!("[{}remap]", blocks.len()),
        CfgIrDiff::FullSnapshot(snap) => format!("[{}blk]", snap.blocks.len()),
    }
}

/// Format detail lines for a group header.
pub fn format_group_detail_lines(
    name: &str,
    _op_count: usize,
    groups: &[TraceGroup],
    trace: &[TraceEvent],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Find this group and summarize its operations
    for group in groups {
        if group.name == name {
            // Count operation types
            let mut op_counts: HashMap<&str, usize> = HashMap::new();
            for &idx in &group.event_indices {
                if let Some(event) = trace.get(idx) {
                    let op_type = match &event.kind {
                        OperationKind::Build { .. } => "Build",
                        OperationKind::AddBlock { .. } => "AddBlock",
                        OperationKind::OverwriteBlock { .. } => "OverwriteBlock",
                        OperationKind::OverwriteBlocks { .. } => "OverwriteBlocks",
                        OperationKind::SetUnconditionalJump { .. } => "SetUnconditionalJump",
                        OperationKind::SetConditionalJump { .. } => "SetConditionalJump",
                        OperationKind::RebuildEdges { .. } => "RebuildEdges",
                        OperationKind::WriteSymbolicImmediates { .. } => "WriteSymbolicImmediates",
                        OperationKind::ReindexPcs => "ReindexPcs",
                        OperationKind::PatchJumpImmediates => "PatchJumpImmediates",
                        OperationKind::PatchDispatcher { .. } => "PatchDispatcher",
                        OperationKind::ReplaceBody { .. } => "ReplaceBody",
                        OperationKind::Finalize => "Finalize",
                        _ => "Other",
                    };
                    *op_counts.entry(op_type).or_insert(0) += 1;
                }
            }

            lines.push(Line::from(Span::styled(
                "Operation breakdown:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            let mut sorted: Vec<_> = op_counts.into_iter().collect();
            // Sort by count descending, then by name ascending for stable ordering
            sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            for (op_type, count) in sorted {
                lines.push(Line::from(format!("  {op_type}: {count}")));
            }

            // Summarize all diffs in this group
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "CFG changes summary:",
                Style::default().add_modifier(Modifier::BOLD),
            )));

            let mut total_blocks_added = 0usize;
            let mut total_blocks_modified = 0usize;
            let mut total_instructions_added = 0i32;
            let mut total_instructions_removed = 0i32;
            let mut total_edges_added = 0usize;
            let mut total_edges_removed = 0usize;
            let mut total_pcs_remapped = 0usize;
            let mut blocks_affected: HashSet<usize> = HashSet::new();

            for &idx in &group.event_indices {
                if let Some(event) = trace.get(idx) {
                    // Count blocks added from AddBlock operations
                    if let OperationKind::AddBlock {
                        instruction_count, ..
                    } = &event.kind
                    {
                        total_blocks_added += 1;
                        total_instructions_added += *instruction_count as i32;
                    }

                    match &event.diff {
                        CfgIrDiff::BlockChanges(changes) => {
                            for change in &changes.changes {
                                blocks_affected.insert(change.node);
                                total_blocks_modified += 1;
                                let before_count = change.before.instructions.len() as i32;
                                let after_count = change.after.instructions.len() as i32;
                                let delta = after_count - before_count;
                                if delta > 0 {
                                    total_instructions_added += delta;
                                } else {
                                    total_instructions_removed += -delta;
                                }
                            }
                        }
                        CfgIrDiff::EdgeChanges(changes) => {
                            total_edges_added += changes.added.len();
                            total_edges_removed += changes.removed.len();
                        }
                        CfgIrDiff::PcsRemapped { blocks, .. } => {
                            total_pcs_remapped += blocks.len();
                        }
                        CfgIrDiff::FullSnapshot(_) | CfgIrDiff::None => {}
                    }
                }
            }

            if total_blocks_added > 0 {
                lines.push(Line::from(format!("  Blocks added: {total_blocks_added}")));
            }
            if total_blocks_modified > 0 {
                lines.push(Line::from(format!(
                    "  Blocks modified: {} ({} unique)",
                    total_blocks_modified,
                    blocks_affected.len()
                )));
            }
            if total_instructions_added > 0 || total_instructions_removed > 0 {
                lines.push(Line::from(format!(
                    "  Instructions: +{total_instructions_added} / -{total_instructions_removed}"
                )));
            }
            if total_edges_added > 0 || total_edges_removed > 0 {
                lines.push(Line::from(format!(
                    "  Edges: +{total_edges_added} / -{total_edges_removed}"
                )));
            }
            if total_pcs_remapped > 0 {
                lines.push(Line::from(format!(
                    "  PCs remapped: {total_pcs_remapped} blocks"
                )));
            }
            if total_blocks_added == 0
                && total_blocks_modified == 0
                && total_edges_added == 0
                && total_edges_removed == 0
                && total_pcs_remapped == 0
            {
                lines.push(Line::from(Span::styled(
                    "  (no recorded changes)",
                    Style::default().fg(Color::DarkGray),
                )));
            }

            break;
        }
    }

    lines
}

/// Format detail lines for an edge group.
pub fn format_edge_group_detail_lines(
    trace_indices: &[usize],
    trace: &[TraceEvent],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Count edge types
    let mut jump_count = 0;
    let mut branch_count = 0;
    let mut rebuild_count = 0;

    for &idx in trace_indices {
        if let Some(event) = trace.get(idx) {
            match &event.kind {
                OperationKind::SetUnconditionalJump { .. } => jump_count += 1,
                OperationKind::SetConditionalJump { .. } => branch_count += 1,
                OperationKind::RebuildEdges { .. } => rebuild_count += 1,
                _ => {}
            }
        }
    }

    lines.push(Line::from(Span::styled(
        "Summary:",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    if jump_count > 0 {
        lines.push(Line::from(format!("  Unconditional jumps: {jump_count}")));
    }
    if branch_count > 0 {
        lines.push(Line::from(format!(
            "  Conditional branches: {branch_count}"
        )));
    }
    if rebuild_count > 0 {
        lines.push(Line::from(format!("  Edge rebuilds: {rebuild_count}")));
    }
    lines.push(Line::from(""));

    // List individual operations
    lines.push(Line::from(Span::styled(
        "Operations:",
        Style::default().add_modifier(Modifier::BOLD),
    )));

    for &idx in trace_indices {
        if let Some(event) = trace.get(idx) {
            let desc = match &event.kind {
                OperationKind::SetUnconditionalJump { source, target } => {
                    format!("  Jump: {source} → {target}")
                }
                OperationKind::SetConditionalJump {
                    source,
                    true_target,
                    false_target,
                } => {
                    format!("  Branch: {source} → T:{true_target} / F:{false_target:?}")
                }
                OperationKind::RebuildEdges { node } => {
                    format!("  Rebuild: {node}")
                }
                _ => format!("  {}", format_operation_kind_short(&event.kind)),
            };
            lines.push(Line::from(desc));
        }
    }

    lines
}

/// Format detail lines for a symbolic group.
pub fn format_symbolic_group_detail_lines(
    trace_indices: &[usize],
    trace: &[TraceEvent],
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Collect nodes
    let mut nodes: Vec<usize> = Vec::new();
    for &idx in trace_indices {
        if let Some(event) = trace.get(idx) {
            if let OperationKind::WriteSymbolicImmediates { node } = &event.kind {
                nodes.push(*node);
            }
        }
    }

    lines.push(Line::from(Span::styled(
        "Summary:",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(format!(
        "  Blocks with symbolic writes: {}",
        nodes.len()
    )));
    lines.push(Line::from(""));

    // List individual operations
    lines.push(Line::from(Span::styled(
        "Operations:",
        Style::default().add_modifier(Modifier::BOLD),
    )));

    for &idx in trace_indices {
        if let Some(event) = trace.get(idx) {
            if let OperationKind::WriteSymbolicImmediates { node } = &event.kind {
                lines.push(Line::from(format!("  Symbolic({node})")));
            }
        }
    }

    lines
}

/// Format detail lines for an individual operation.
pub fn format_operation_detail_lines(event: &TraceEvent) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Diff details
    match &event.diff {
        CfgIrDiff::None => {
            lines.push(Line::from(Span::styled(
                "No changes recorded",
                Style::default().fg(Color::DarkGray),
            )));
        }
        CfgIrDiff::BlockChanges(changes) => {
            lines.push(Line::from(format!(
                "Block Changes: {}",
                changes.changes.len()
            )));
            lines.push(Line::from(""));

            // Sort by node index for consistent display
            let mut sorted_changes: Vec<_> = changes.changes.iter().collect();
            sorted_changes.sort_by_key(|c| c.node);

            for change in sorted_changes {
                lines.push(Line::from(Span::styled(
                    format!("─── Block {} ───", change.node),
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(Line::from(format!(
                    "Instructions: {} → {}",
                    change.before.instructions.len(),
                    change.after.instructions.len()
                )));
                lines.push(Line::from(""));

                // Inline diff with colors
                let diff_lines = format_instruction_diff_colored(change);
                lines.extend(diff_lines);
                lines.push(Line::from(""));

                // Control flow change
                if change.before.control != change.after.control {
                    lines.push(Line::from(Span::styled(
                        "Control flow:",
                        Style::default().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("  - {}", format_control_flow(&change.before.control)),
                        Style::default().fg(Color::Red),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!("  + {}", format_control_flow(&change.after.control)),
                        Style::default().fg(Color::Green),
                    )));
                }
                lines.push(Line::from(""));
            }
        }
        CfgIrDiff::EdgeChanges(changes) => {
            lines.push(Line::from(format!(
                "Edge Changes for node {}",
                changes.node
            )));
            if !changes.removed.is_empty() {
                lines.push(Line::from(format!(
                    "Removed edges: {}",
                    changes.removed.len()
                )));
                for edge in &changes.removed {
                    lines.push(Line::from(Span::styled(
                        format!("  - {edge:?}"),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
            if !changes.added.is_empty() {
                lines.push(Line::from(format!("Added edges: {}", changes.added.len())));
                for edge in &changes.added {
                    lines.push(Line::from(Span::styled(
                        format!("  + {edge:?}"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
        }
        CfgIrDiff::PcsRemapped {
            blocks,
            instructions,
        } => {
            lines.push(Line::from(Span::styled(
                "PC Remapping:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Blocks remapped: {}", blocks.len())));
            lines.push(Line::from(format!(
                "  Instructions remapped: {}",
                instructions.len()
            )));

            if !blocks.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from("Block PC changes:"));
                for diff in blocks.iter().take(20) {
                    lines.push(Line::from(format!(
                        "  Block {}: {} → {}",
                        diff.node, diff.old_start_pc, diff.new_start_pc
                    )));
                }
                if blocks.len() > 20 {
                    lines.push(Line::from(Span::styled(
                        format!("  ... and {} more", blocks.len() - 20),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }
        CfgIrDiff::FullSnapshot(snap) => {
            // Summary header
            lines.push(Line::from(Span::styled(
                "Full Snapshot:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Blocks: {}", snap.blocks.len())));
            lines.push(Line::from(format!("  Edges: {}", snap.edges.len())));
            lines.push(Line::from(format!("  Sections: {}", snap.sections.len())));
            if !snap.protected_pcs.is_empty() {
                lines.push(Line::from(format!(
                    "  Protected PCs: {}",
                    snap.protected_pcs.len()
                )));
            }
            if let Some((start, end)) = snap.runtime_bounds {
                lines.push(Line::from(format!(
                    "  Runtime bounds: 0x{start:x} - 0x{end:x}"
                )));
            }
            lines.push(Line::from(""));
            lines.extend(format_annotated_bytecode(snap));
        }
    }

    lines
}
