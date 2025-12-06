//! Annotated bytecode view rendering.

use std::collections::{HashMap, HashSet};

use azoth_core::cfg_ir::{
    BlockControlSnapshot, BlockSnapshotKind, CfgIrSnapshot, TraceJumpTargetKind,
};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Metadata about a block for annotation purposes.
struct BlockInfo {
    node: usize,
    start_pc: usize,
    end_pc: usize,
    control: BlockControlSnapshot,
}

/// Build a list of BlockInfo from a snapshot, sorted by start_pc.
fn collect_block_info(snap: &CfgIrSnapshot) -> Vec<BlockInfo> {
    let mut blocks: Vec<BlockInfo> = snap
        .blocks
        .iter()
        .filter_map(|b| match &b.kind {
            BlockSnapshotKind::Body(body) => {
                let end_pc = if body.instructions.is_empty() {
                    body.start_pc
                } else {
                    let last = body.instructions.last().unwrap();
                    // End PC is start of last instruction + its size
                    last.pc + instruction_byte_size(last)
                };
                Some(BlockInfo {
                    node: b.node,
                    start_pc: body.start_pc,
                    end_pc,
                    control: body.control.clone(),
                })
            }
            _ => None,
        })
        .collect();
    blocks.sort_by_key(|b| b.start_pc);
    blocks
}

/// Calculate the byte size of an instruction.
const fn instruction_byte_size(instr: &azoth_core::decoder::Instruction) -> usize {
    match &instr.op {
        azoth_core::Opcode::PUSH(n) => 1 + *n as usize,
        _ => 1,
    }
}

/// Build jump target lookup: target PC -> list of source block nodes.
fn build_jump_target_lookup(blocks: &[BlockInfo]) -> HashMap<usize, Vec<usize>> {
    let mut lookup: HashMap<usize, Vec<usize>> = HashMap::new();
    for block in blocks {
        match &block.control {
            BlockControlSnapshot::Jump { target } => {
                if let TraceJumpTargetKind::Raw { value } = &target.kind {
                    lookup.entry(*value).or_default().push(block.node);
                }
            }
            BlockControlSnapshot::Branch {
                true_target,
                false_target,
            } => {
                if let TraceJumpTargetKind::Raw { value } = &true_target.kind {
                    lookup.entry(*value).or_default().push(block.node);
                }
                if let TraceJumpTargetKind::Raw { value } = &false_target.kind {
                    lookup.entry(*value).or_default().push(block.node);
                }
            }
            _ => {}
        }
    }
    lookup
}

/// Format a control flow annotation for a block.
fn format_control_annotation(
    control: &BlockControlSnapshot,
    next_block: Option<usize>,
) -> Option<String> {
    match control {
        BlockControlSnapshot::Jump { target } => {
            let dest = match &target.kind {
                TraceJumpTargetKind::Block { node } => format!("block {node}"),
                TraceJumpTargetKind::Raw { value } => format!("0x{value:x}"),
            };
            Some(format!("jump to {dest}"))
        }
        BlockControlSnapshot::Branch {
            true_target,
            false_target,
        } => {
            let t_dest = match &true_target.kind {
                TraceJumpTargetKind::Block { node } => format!("block {node}"),
                TraceJumpTargetKind::Raw { value } => format!("0x{value:x}"),
            };
            // Check if false target is the next sequential block (fallthrough)
            let is_fallthrough = match &false_target.kind {
                TraceJumpTargetKind::Block { node } => Some(*node) == next_block,
                _ => false,
            };
            if is_fallthrough {
                Some(format!("if true jump to {t_dest}, or fallthrough"))
            } else {
                let f_dest = match &false_target.kind {
                    TraceJumpTargetKind::Block { node } => format!("block {node}"),
                    TraceJumpTargetKind::Raw { value } => format!("0x{value:x}"),
                };
                Some(format!("if true jump to {t_dest}, else {f_dest}"))
            }
        }
        BlockControlSnapshot::Terminal => Some("END".to_string()),
        BlockControlSnapshot::Fallthrough => Some("fallthrough".to_string()),
        BlockControlSnapshot::Unknown => None,
    }
}

/// Render annotated bytecode lines from a snapshot.
///
/// Format per line:
/// ```text
/// LINE  │S│B│ PC     MNEMONIC   IMM        ; comments
/// ```
/// Where:
/// - LINE: sequential line number
/// - S: section indicator (colored vertical bar)
/// - B: block indicator (colored vertical bar, different colors for different blocks)
/// - PC: program counter in hex
/// - MNEMONIC: opcode mnemonic
/// - IMM: immediate value if present
/// - comments: jump targets, block boundaries, edge info
pub fn format_annotated_bytecode(snap: &CfgIrSnapshot) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // Collect all instructions from all blocks, sorted by PC
    let mut all_instructions: Vec<(usize, &azoth_core::decoder::Instruction, &BlockInfo)> =
        Vec::new();
    let blocks = collect_block_info(snap);

    for block in &blocks {
        if let Some(block_snap) = snap.blocks.iter().find(|b| b.node == block.node) {
            if let BlockSnapshotKind::Body(body) = &block_snap.kind {
                for instr in &body.instructions {
                    all_instructions.push((block.node, instr, block));
                }
            }
        }
    }
    all_instructions.sort_by_key(|(_, i, _)| i.pc);

    if all_instructions.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no instructions)",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }

    // Build lookups
    let jump_targets = build_jump_target_lookup(&blocks);

    // Build dispatcher instruction range (by instruction index, not PC) for original dispatcher
    let dispatcher_range: Option<(usize, usize)> = snap
        .dispatcher_info
        .as_ref()
        .map(|d| (d.start_offset, d.end_offset));

    // Build set of dispatcher block nodes (includes blocks added by transform)
    let dispatcher_block_set: HashSet<usize> = snap.dispatcher_blocks.iter().copied().collect();

    // Build set of protected PCs
    let protected_pcs: HashSet<usize> = snap.protected_pcs.iter().copied().collect();

    // Build selector lookups:
    // - original_selectors: set of original selector hex strings (from dispatcher_info)
    // - mapped_to_original: maps mapped token hex -> original selector value
    let mut original_selectors: HashSet<String> = HashSet::new();
    let mut mapped_to_original: HashMap<String, u32> = HashMap::new();

    if let Some(info) = &snap.dispatcher_info {
        for sel in &info.selectors {
            original_selectors.insert(format!("{:08x}", sel.selector));
        }
    }
    if let Some(mapping) = &snap.selector_mapping {
        for (original, mapped) in mapping {
            let mapped_hex: String = mapped.iter().map(|b| format!("{b:02x}")).collect();
            mapped_to_original.insert(mapped_hex, *original);
        }
    }

    // Build a map of block node -> is_preceded_by_fallthrough
    // A block is preceded by fallthrough if the previous block (by PC order) falls through to it.
    // This includes:
    // - Fallthrough control (unconditional fallthrough)
    // - Branch control where false_target is the next block (conditional fallthrough)
    let mut preceded_by_fallthrough: HashSet<usize> = HashSet::new();
    // Also build a map of block node -> next block node (by PC order)
    let mut next_block_map: HashMap<usize, usize> = HashMap::new();
    for i in 1..blocks.len() {
        let dominated = matches!(
            blocks[i - 1].control,
            BlockControlSnapshot::Fallthrough | BlockControlSnapshot::Branch { .. }
        );
        if dominated {
            preceded_by_fallthrough.insert(blocks[i].node);
        }
        next_block_map.insert(blocks[i - 1].node, blocks[i].node);
    }

    // Track active blocks for the gutter display
    // We'll use a simple approach: show pipes for blocks that span the current line
    let block_colors = [
        Color::Cyan,
        Color::Yellow,
        Color::Magenta,
        Color::Blue,
        Color::Red,
        Color::Green,
    ];

    // Header
    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("Sec  ", Style::default().fg(Color::LightRed)),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(" Block ", Style::default().fg(Color::Cyan)),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " PC       OPCODE      IMM",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        " ─────┼───────┼─────────────────────────────────────",
        Style::default().fg(Color::DarkGray),
    )));

    // Track position within dispatcher for vertical label
    let dispatcher_label = "DISPATCHER";
    let mut dispatcher_line_count: usize = 0;

    for (line_no, (block_node, instr, block_info)) in all_instructions.iter().enumerate() {
        let mut spans = Vec::new();

        // Leading space
        spans.push(Span::raw(" "));

        // Block start/end detection (needed for both section and block columns)
        let is_block_start = block_info.start_pc == instr.pc;
        let is_block_end = instr.pc + instruction_byte_size(instr) >= block_info.end_pc;

        // Section indicator (dispatcher takes precedence for coloring)
        // A block is in dispatcher if it's in dispatcher_blocks OR in the original dispatcher range
        let is_in_dispatcher_block = dispatcher_block_set.contains(block_node);
        let is_in_dispatcher_range = dispatcher_range
            .map(|(start, end)| line_no >= start && line_no < end)
            .unwrap_or(false);
        let is_in_dispatcher = is_in_dispatcher_block || is_in_dispatcher_range;

        // For dispatcher blocks, we track start/end based on block boundaries
        let is_dispatcher_block_start = is_in_dispatcher_block && is_block_start;
        let is_dispatcher_block_end = is_in_dispatcher_block && is_block_end;
        // For original dispatcher range, use instruction indices
        let is_dispatcher_range_start = !is_in_dispatcher_block
            && dispatcher_range
                .map(|(start, _)| line_no == start)
                .unwrap_or(false);
        let is_dispatcher_range_end = !is_in_dispatcher_block
            && dispatcher_range
                .map(|(_, end)| line_no + 1 == end)
                .unwrap_or(false);
        let is_dispatcher_start = is_dispatcher_block_start || is_dispatcher_range_start;
        let is_dispatcher_end = is_dispatcher_block_end || is_dispatcher_range_end;

        // Dispatcher column (shows pipe + vertical "DISPATCHER" label starting 2 lines after start)
        let dispatcher_str = if is_in_dispatcher {
            let color = Color::LightRed;
            let (pipe, label) = if is_dispatcher_start && is_dispatcher_end {
                ("─", "────")
            } else if is_dispatcher_start {
                ("┌", "────")
            } else if is_dispatcher_end {
                ("└", "────")
            } else {
                // Show letter from "DISPATCHER" starting at offset 2
                let label_idx = dispatcher_line_count.saturating_sub(2);
                let lbl = if dispatcher_line_count >= 2 && label_idx < dispatcher_label.len() {
                    &dispatcher_label[label_idx..label_idx + 1]
                } else {
                    " "
                };
                ("│", lbl)
            };
            dispatcher_line_count += 1;
            vec![
                Span::styled(pipe, Style::default().fg(color)),
                Span::styled(format!("{label:<4}"), Style::default().fg(color)),
            ]
        } else {
            dispatcher_line_count = 0; // Reset when not in dispatcher
            vec![Span::styled("     ", Style::default())]
        };
        spans.extend(dispatcher_str);

        // Block indicator with block number at start
        let block_color = block_colors[*block_node % block_colors.len()];
        // A block "falls through" if it continues to the next sequential block
        // This includes Fallthrough (unconditional) and Branch (conditional - false path)
        let is_fallthrough = matches!(
            block_info.control,
            BlockControlSnapshot::Fallthrough | BlockControlSnapshot::Branch { .. }
        );
        let is_after_fallthrough = preceded_by_fallthrough.contains(block_node);

        // Format: "─ N ────" where N is block number padded with dashes to fill 7 chars total
        let block_col_width: usize = 7;
        let (lead_pipe, block_num_str, trail_pipe) = if is_block_start && is_block_end {
            // Single-instruction block
            let lead = if is_fallthrough {
                if is_after_fallthrough {
                    "┼"
                } else {
                    "┬"
                }
            } else if is_after_fallthrough {
                "┴"
            } else {
                "─"
            };
            let num_str = format!(" {block_node} ");
            let trail_len = block_col_width.saturating_sub(1 + num_str.len());
            (lead, num_str, "─".repeat(trail_len))
        } else if is_block_start {
            let lead = if is_after_fallthrough { "├" } else { "┌" };
            let num_str = format!(" {block_node} ");
            let trail_len = block_col_width.saturating_sub(1 + num_str.len());
            (lead, num_str, "─".repeat(trail_len))
        } else if is_block_end {
            let lead = if is_fallthrough { "├" } else { "└" };
            let fill = "─".repeat(block_col_width - 1);
            (lead, fill, String::new())
        } else {
            let fill = " ".repeat(block_col_width - 1);
            ("│", fill, String::new())
        };

        spans.push(Span::styled("│", Style::default().fg(Color::DarkGray)));
        spans.push(Span::styled(lead_pipe, Style::default().fg(block_color)));
        spans.push(Span::styled(
            block_num_str,
            Style::default().fg(block_color),
        ));
        spans.push(Span::styled(trail_pipe, Style::default().fg(block_color)));
        spans.push(Span::styled("│", Style::default().fg(Color::DarkGray)));

        // PC (colored by block)
        spans.push(Span::styled(
            format!(" {:06x}   ", instr.pc),
            Style::default().fg(block_color),
        ));

        // Opcode mnemonic
        let op_str = format!("{:<10}", format!("{:?}", instr.op));
        let op_color = match &instr.op {
            azoth_core::Opcode::JUMP | azoth_core::Opcode::JUMPI => Color::Yellow,
            azoth_core::Opcode::JUMPDEST => Color::Green,
            azoth_core::Opcode::STOP
            | azoth_core::Opcode::RETURN
            | azoth_core::Opcode::REVERT
            | azoth_core::Opcode::INVALID
            | azoth_core::Opcode::SELFDESTRUCT => Color::Red,
            azoth_core::Opcode::PUSH(_) => Color::Cyan,
            _ => Color::White,
        };
        spans.push(Span::styled(op_str, Style::default().fg(op_color)));

        // Immediate value
        if let Some(imm) = &instr.imm {
            let imm_display = if imm.len() > 14 {
                format!("0x{}...", &imm[..14])
            } else {
                format!("0x{imm}")
            };
            spans.push(Span::styled(
                format!(" {imm_display:<18}"),
                Style::default().fg(Color::Gray),
            ));
        } else {
            spans.push(Span::raw(format!("{:19}", "")));
        }

        // Comments
        let mut comments = Vec::new();

        // Jump target annotation (something jumps here)
        if let Some(sources) = jump_targets.get(&instr.pc) {
            let src_str = sources
                .iter()
                .map(|n| format!("block {n}"))
                .collect::<Vec<_>>()
                .join(", ");
            comments.push(format!("from: {src_str}"));
        }

        // Protected PC annotation
        if protected_pcs.contains(&instr.pc) {
            comments.push("protected".to_string());
        }

        // Selector annotation for PUSH4 instructions
        if matches!(instr.op, azoth_core::Opcode::PUSH(4)) {
            if let Some(imm) = &instr.imm {
                let imm_lower = imm.to_lowercase();
                if let Some(&original) = mapped_to_original.get(&imm_lower) {
                    // This is a mapped selector - show original
                    comments.push(format!("mapped selector (was 0x{original:08x})"));
                } else if original_selectors.contains(&imm_lower) {
                    // This is an original selector
                    comments.push("selector".to_string());
                }
            }
        }

        // Control flow annotation at block end
        if is_block_end {
            let next_block = next_block_map.get(block_node).copied();
            if let Some(ctrl_anno) = format_control_annotation(&block_info.control, next_block) {
                comments.push(ctrl_anno);
            }
        }

        if !comments.is_empty() {
            spans.push(Span::styled(
                format!(" ; {}", comments.join(" ")),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            ));
        }

        lines.push(Line::from(spans));
    }

    lines
}
