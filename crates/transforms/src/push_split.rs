//! Push splitting for medium-width literals.
//!
//! This transform replaces direct PUSH4–PUSH16 literals with multiple pushes
//! and a combine operation so the final constant is assembled on stack.
//!
//! For example:
//! ```assembly
//! // Original
//! PUSH8 0x1122334455667788
//! SSTORE
//!
//! // Transformed (randomized variant)
//! PUSH4 0x11223344
//! PUSH4 0x55667788
//! SUB                // variant op; chain length and ops vary per split
//! SSTORE
//! ```
//!
//! Safety: blocks that contain `JUMP`/`JUMPI` are skipped to avoid mutating
//! raw jump-table immediates that are not symbolically remapped.

use crate::{collect_protected_nodes, collect_protected_pcs, Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockControl, CfgIrBundle, JumpTarget};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::Rng;
use std::fmt::Write;
use tracing::debug;

/// Split medium-width PUSH immediates into multi-step arithmetic chains.
#[derive(Default)]
pub struct PushSplit;

impl PushSplit {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for PushSplit {
    fn name(&self) -> &'static str {
        "PushSplit"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("PushSplit: scanning for eligible PUSH4–PUSH16 literals");

        let protected_pcs = collect_protected_pcs(ir);
        let protected_nodes = collect_protected_nodes(ir);
        let mut changed = false;

        let runtime_bounds = ir.runtime_bounds;

        let _ = runtime_bounds;
        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        for node in nodes {
            if protected_nodes.contains(&node) {
                continue;
            }
            if ir.dispatcher_blocks.contains(&node.index()) {
                continue;
            }
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };

            // Skip init-code blocks; only mutate runtime for now to avoid constructor jumps.
            if let Some((start, end)) = runtime_bounds {
                if body.start_pc < start || body.start_pc >= end {
                    continue;
                }
            }

            if block_has_jump(body) {
                debug!(
                    "PushSplit: skipping block with jump opcode at PC 0x{:x}",
                    body.start_pc
                );
                continue;
            }

            if has_raw_jump_target(body) {
                debug!(
                    "PushSplit: skipping block with raw jump target at PC 0x{:x}",
                    body.start_pc
                );
                continue;
            }

            let original = body.instructions.clone();
            let original_max_stack = body.max_stack;
            let mut rewritten: Vec<Instruction> = Vec::with_capacity(original.len());
            let mut new_max_stack = original_max_stack;

            for (idx, instr) in original.iter().enumerate() {
                if let Some(width) = matches_push_range(&instr.op) {
                    if protected_pcs.contains(&instr.pc) {
                        rewritten.push(instr.clone());
                        continue;
                    }

                    // Skip immediate jump targets so we don't break branch metadata.
                    if original
                        .get(idx + 1)
                        .is_some_and(|next| matches!(next.op, Opcode::JUMP | Opcode::JUMPI))
                    {
                        rewritten.push(instr.clone());
                        continue;
                    }

                    // Skip if this is the second PUSH in a SplitAdd pattern: PUSH; PUSH; ADD; JUMP
                    if idx >= 1
                        && original
                            .get(idx + 2)
                            .is_some_and(|jump| matches!(jump.op, Opcode::JUMP | Opcode::JUMPI))
                        && original
                            .get(idx + 1)
                            .is_some_and(|add| matches!(add.op, Opcode::ADD))
                        && original
                            .get(idx - 1)
                            .is_some_and(|prev| matches!(prev.op, Opcode::PUSH(_)))
                    {
                        debug!("Skipping second PUSH in SplitAdd at PC 0x{:x}", instr.pc);
                        rewritten.push(instr.clone());
                        continue;
                    }

                    // Skip SplitAdd jump patterns: PUSH <lhs>; PUSH <rhs>; ADD; JUMP/JUMPI
                    if original
                        .get(idx + 3)
                        .is_some_and(|jump| matches!(jump.op, Opcode::JUMP | Opcode::JUMPI))
                    {
                        if let (Some(push_b), Some(add_instr)) =
                            (original.get(idx + 1), original.get(idx + 2))
                        {
                            // Check for PUSH; PUSH; ADD; JUMP pattern
                            if matches!(push_b.op, Opcode::PUSH(_))
                                && matches!(add_instr.op, Opcode::ADD)
                            {
                                debug!("Skipping first PUSH in SplitAdd at PC 0x{:x}", instr.pc);
                                rewritten.push(instr.clone());
                                continue;
                            }
                            // Also check for PC-relative: PUSH <delta>; PC; ADD; JUMP
                            if matches!(push_b.op, Opcode::PC)
                                && matches!(add_instr.op, Opcode::ADD)
                            {
                                debug!("Skipping PUSH in PcRelative at PC 0x{:x}", instr.pc);
                                rewritten.push(instr.clone());
                                continue;
                            }
                        }
                    }

                    if let Some(imm_hex) = &instr.imm {
                        if let Ok(value) = u128::from_str_radix(imm_hex, 16) {
                            let before_window = format_window(&original, idx, 2);
                            let chain = generate_chain(value, width, rng);
                            let base_pc = instr.pc;
                            let mut pc = base_pc;

                            debug!(
                                "PushSplit: split at pc=0x{:x} width={} value=0x{} into parts={}",
                                base_pc,
                                width,
                                imm_hex,
                                format_chain(&chain, width)
                            );

                            let chain_len = chain.len() * 2;
                            let rewritten_start = rewritten.len();
                            for (part, op) in chain {
                                pc = emit_part(part, op, pc, &mut rewritten);
                            }
                            let after_window =
                                format_window(&rewritten, rewritten_start, chain_len.min(6));
                            if !before_window.is_empty() || !after_window.is_empty() {
                                debug!(
                                    "PushSplit: context before=[{}] after=[{}]",
                                    before_window, after_window
                                );
                            }

                            new_max_stack = new_max_stack.max(2);
                            changed = true;
                            continue;
                        }
                    }
                }

                rewritten.push(instr.clone());
            }

            if rewritten != original || new_max_stack != original_max_stack {
                let mut new_body = body.clone();
                new_body.instructions = rewritten;
                new_body.max_stack = new_max_stack;
                ir.overwrite_block(node, new_body)
                    .map_err(|e| Error::CoreError(e.to_string()))?;
            }
        }

        if changed {
            debug!("PushSplit: applied splits");
        } else {
            debug!("PushSplit: no eligible PUSH instructions found");
        }

        Ok(changed)
    }
}

fn has_raw_jump_target(body: &azoth_core::cfg_ir::BlockBody) -> bool {
    fn target_is_raw(target: &JumpTarget) -> bool {
        matches!(target, JumpTarget::Raw { .. })
    }

    match &body.control {
        BlockControl::Jump { target } => target_is_raw(target),
        BlockControl::Branch {
            true_target,
            false_target,
        } => target_is_raw(true_target) || target_is_raw(false_target),
        _ => false,
    }
}

fn block_has_jump(body: &azoth_core::cfg_ir::BlockBody) -> bool {
    body.instructions
        .iter()
        .any(|instr| matches!(instr.op, Opcode::JUMP | Opcode::JUMPI))
}

fn matches_push_range(op: &Opcode) -> Option<u8> {
    match op {
        Opcode::PUSH(width) if (4..=16).contains(width) => Some(*width),
        _ => None,
    }
}

fn format_hex(value: u128, width_bytes: u8) -> String {
    format!("{:0width$x}", value, width = (width_bytes as usize) * 2)
}

fn minimal_push_width(value: u128) -> u8 {
    if value == 0 {
        1
    } else {
        let bits = 128 - value.leading_zeros();
        bits.div_ceil(8) as u8
    }
}

#[derive(Clone, Copy)]
enum CombineOp {
    Add,
    Sub,
    Xor,
}

/// Generate a randomized chain of (push, combine-op) pairs whose reduction yields `value`.
fn generate_chain(value: u128, width_bytes: u8, rng: &mut StdRng) -> Vec<(u128, CombineOp)> {
    let bits = (width_bytes as u32) * 8;
    let full_width = bits == 128;
    let modulus = (!full_width).then(|| 1u128 << bits);
    let mask = modulus.map(|m| m - 1).unwrap_or(u128::MAX);
    let sample = |rng: &mut StdRng| -> u128 {
        if let Some(m) = modulus {
            rng.random_range(0..m)
        } else {
            rng.random::<u128>()
        }
    };

    let add_mod = |acc: u128, part: u128| -> u128 {
        if let Some(m) = modulus {
            (acc + part) % m
        } else {
            acc.wrapping_add(part)
        }
    };

    let sub_mod = |acc: u128, part: u128| -> u128 {
        if let Some(m) = modulus {
            (acc + m - part) % m
        } else {
            acc.wrapping_sub(part)
        }
    };
    let parts = rng.random_range(2..=4);

    let prefer_xor = rng.random_bool(0.4);
    if prefer_xor {
        let mut pushes = Vec::with_capacity(parts);
        let mut acc = 0u128;
        for i in 0..parts {
            if i + 1 == parts {
                pushes.push(((acc ^ value) & mask, CombineOp::Xor));
            } else {
                let part = sample(rng);
                acc ^= part;
                pushes.push((part & mask, CombineOp::Xor));
            }
        }
        return pushes;
    }

    // Mixed add/sub chain: (((p1 (+|-) p2) (+|-) p3) ... ) == value mod modulus
    let mut pushes = Vec::with_capacity(parts);
    let mut acc = 0u128;
    let mut ops: Vec<CombineOp> = Vec::with_capacity(parts.saturating_sub(1));

    for _ in 0..parts.saturating_sub(2) {
        ops.push(if rng.random_bool(0.7) {
            CombineOp::Add
        } else {
            CombineOp::Sub
        });
    }
    ops.push(if rng.random_bool(0.5) {
        CombineOp::Add
    } else {
        CombineOp::Sub
    });

    for (i, op) in ops.iter().enumerate() {
        let part = sample(rng) & mask;
        pushes.push((part, *op));
        acc = match op {
            CombineOp::Add => add_mod(acc, part),
            CombineOp::Sub => sub_mod(acc, part),
            CombineOp::Xor => unreachable!(),
        };

        if i + 1 == ops.len() {
            let final_op = *op;
            let final_part = match final_op {
                CombineOp::Add => {
                    if let Some(m) = modulus {
                        (value + m - acc) % m
                    } else {
                        value.wrapping_sub(acc)
                    }
                }
                CombineOp::Sub => {
                    if let Some(m) = modulus {
                        (acc + m - value) % m
                    } else {
                        acc.wrapping_sub(value)
                    }
                }
                CombineOp::Xor => unreachable!(),
            };
            pushes.push((final_part & mask, final_op));
        }
    }

    pushes
}

fn format_chain(chain: &[(u128, CombineOp)], width_bytes: u8) -> String {
    let mut parts = Vec::with_capacity(chain.len());
    for (val, op) in chain {
        let op_str = match op {
            CombineOp::Add => "+",
            CombineOp::Sub => "-",
            CombineOp::Xor => "^",
        };
        parts.push(format!("{op_str}0x{}", format_hex(*val, width_bytes)));
    }
    parts.join(" ")
}

fn format_window(instructions: &[Instruction], center_idx: usize, count: usize) -> String {
    if instructions.is_empty() || count == 0 {
        return String::new();
    }
    let start = center_idx.saturating_sub(count / 2);
    let end = (start + count).min(instructions.len());
    let mut out = String::new();
    for instr in &instructions[start..end] {
        let op = match instr.op {
            Opcode::PUSH(w) => format!("PUSH{}", w),
            other => format!("{:?}", other),
        };
        let _ = write!(
            &mut out,
            "pc=0x{:x}: {} {} | ",
            instr.pc,
            op,
            instr.imm.as_deref().unwrap_or("")
        );
    }
    if out.ends_with(" | ") {
        out.truncate(out.len().saturating_sub(3));
    }
    out
}

fn emit_part(part: u128, op: CombineOp, pc: usize, out: &mut Vec<Instruction>) -> usize {
    let width = minimal_push_width(part);
    out.push(Instruction {
        pc,
        op: Opcode::PUSH(width),
        imm: Some(format_hex(part, width)),
    });
    let pc_after_push = pc + 1 + width as usize;
    let opcode = match op {
        CombineOp::Add => Opcode::ADD,
        CombineOp::Sub => Opcode::SUB,
        CombineOp::Xor => Opcode::XOR,
    };
    out.push(Instruction {
        pc: pc_after_push,
        op: opcode,
        imm: None,
    });
    pc_after_push + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;

    const STORAGE_BYTECODE: &str = include_str!("../../../tests/bytecode/storage.hex");
    const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn runs_on_storage_fixture() {
        let bytecode = STORAGE_BYTECODE;
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();
        let transform = PushSplit::new();
        let _ = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    }

    #[tokio::test]
    async fn splits_push_and_produces_chain() {
        // PUSH8 0x1122334455667788 ; STOP
        let bytecode = "0x67112233445566778800";
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();
        let transform = PushSplit::new();
        let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "push should be split");

        let mut instructions: Vec<azoth_core::decoder::Instruction> = Vec::new();
        for node in cfg_ir.cfg.node_indices() {
            if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[node] {
                instructions.extend(body.instructions.clone());
            }
        }

        // Original single PUSH8 literal should be gone.
        let has_original = instructions.iter().any(|i| {
            matches!(i.op, Opcode::PUSH(8))
                && i.imm
                    .as_deref()
                    .is_some_and(|imm| imm.eq_ignore_ascii_case("1122334455667788"))
        });
        assert!(!has_original, "original PUSH8 should be replaced");

        let combine_count = instructions
            .iter()
            .filter(|i| matches!(i.op, Opcode::ADD | Opcode::SUB | Opcode::XOR))
            .count();
        let push_count = instructions
            .iter()
            .filter(|i| matches!(i.op, Opcode::PUSH(_)))
            .count();
        assert!(combine_count >= 1, "expected at least one combine op");
        assert!(push_count >= 2, "expected multiple pushes in split chain");
    }
}
