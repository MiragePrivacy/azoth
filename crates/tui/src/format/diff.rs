//! Diff formatting for instruction and control flow changes.

use azoth_core::cfg_ir::{
    BlockControlSnapshot, BlockModification, JumpEncoding, JumpTargetSnapshot, TraceJumpTargetKind,
};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Format instruction diff with colored additions and deletions.
pub fn format_instruction_diff_colored(change: &BlockModification) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let before: Vec<_> = change
        .before
        .instructions
        .iter()
        .map(|i| {
            let imm = i.imm.as_deref().unwrap_or("");
            format!("{:?} {}", i.op, imm)
        })
        .collect();

    let after: Vec<_> = change
        .after
        .instructions
        .iter()
        .map(|i| {
            let imm = i.imm.as_deref().unwrap_or("");
            format!("{:?} {}", i.op, imm)
        })
        .collect();

    // Simple diff algorithm
    let mut bi = 0;
    let mut ai = 0;

    while bi < before.len() || ai < after.len() {
        if bi < before.len() && ai < after.len() && before[bi] == after[ai] {
            lines.push(Line::from(Span::styled(
                format!("   {}", before[bi]),
                Style::default().fg(Color::DarkGray),
            )));
            bi += 1;
            ai += 1;
        } else if bi < before.len() && ai < after.len() {
            // Look ahead for matches
            let after_match = after[ai..].iter().position(|x| x == &before[bi]);
            let before_match = before[bi..].iter().position(|x| x == &after[ai]);

            match (after_match, before_match) {
                (Some(am), None) if am > 0 => {
                    for j in 0..am {
                        lines.push(Line::from(Span::styled(
                            format!(" + {}", after[ai + j]),
                            Style::default().fg(Color::Green),
                        )));
                    }
                    ai += am;
                }
                (None, Some(bm)) if bm > 0 => {
                    for j in 0..bm {
                        lines.push(Line::from(Span::styled(
                            format!(" - {}", before[bi + j]),
                            Style::default().fg(Color::Red),
                        )));
                    }
                    bi += bm;
                }
                (Some(am), Some(bm)) if am > 0 || bm > 0 => {
                    if am <= bm {
                        for j in 0..am {
                            lines.push(Line::from(Span::styled(
                                format!(" + {}", after[ai + j]),
                                Style::default().fg(Color::Green),
                            )));
                        }
                        ai += am;
                    } else {
                        for j in 0..bm {
                            lines.push(Line::from(Span::styled(
                                format!(" - {}", before[bi + j]),
                                Style::default().fg(Color::Red),
                            )));
                        }
                        bi += bm;
                    }
                }
                _ => {
                    lines.push(Line::from(Span::styled(
                        format!(" - {}", before[bi]),
                        Style::default().fg(Color::Red),
                    )));
                    lines.push(Line::from(Span::styled(
                        format!(" + {}", after[ai]),
                        Style::default().fg(Color::Green),
                    )));
                    bi += 1;
                    ai += 1;
                }
            }
        } else if bi < before.len() {
            lines.push(Line::from(Span::styled(
                format!(" - {}", before[bi]),
                Style::default().fg(Color::Red),
            )));
            bi += 1;
        } else {
            lines.push(Line::from(Span::styled(
                format!(" + {}", after[ai]),
                Style::default().fg(Color::Green),
            )));
            ai += 1;
        }
    }

    lines
}

/// Format a control flow snapshot in a human-readable way.
pub fn format_control_flow(control: &BlockControlSnapshot) -> String {
    match control {
        BlockControlSnapshot::Unknown => "Unknown".to_string(),
        BlockControlSnapshot::Fallthrough => "Fallthrough (continue to next block)".to_string(),
        BlockControlSnapshot::Terminal => "Terminal (STOP/REVERT/RETURN/etc)".to_string(),
        BlockControlSnapshot::Jump { target } => {
            format!("Jump to {}", format_jump_target(target))
        }
        BlockControlSnapshot::Branch {
            true_target,
            false_target,
        } => {
            format!(
                "Branch (true: {}, false: {})",
                format_jump_target(true_target),
                format_jump_target(false_target)
            )
        }
    }
}

/// Format a jump target snapshot.
pub fn format_jump_target(target: &JumpTargetSnapshot) -> String {
    let dest = match &target.kind {
        TraceJumpTargetKind::Block { node } => format!("block {node}"),
        TraceJumpTargetKind::Raw { value } => format!("pc {value:#x}"),
    };
    let enc = match target.encoding {
        JumpEncoding::Absolute => "absolute",
        JumpEncoding::RuntimeRelative => "runtime-relative",
        JumpEncoding::PcRelative => "pc-relative",
    };
    format!("{dest} ({enc})")
}
