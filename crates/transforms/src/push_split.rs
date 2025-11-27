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

use crate::{collect_protected_nodes, collect_protected_pcs, Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::Rng;
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

        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        for node in nodes {
            if protected_nodes.contains(&node) {
                continue;
            }
            let Some(block) = ir.cfg.node_weight_mut(node) else {
                continue;
            };
            let body = match block {
                Block::Body(body) => body,
                _ => continue,
            };

            let original = body.instructions.clone();
            let mut rewritten: Vec<Instruction> = Vec::with_capacity(original.len());

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

                    if let Some(imm_hex) = &instr.imm {
                        if let Ok(value) = u128::from_str_radix(imm_hex, 16) {
                            let chain = generate_chain(value, width, rng);
                            let base_pc = instr.pc;
                            let mut pc = base_pc;

                            for (part, op) in chain {
                                pc = emit_part(part, op, pc, &mut rewritten);
                            }

                            body.max_stack = body.max_stack.max(2);
                            changed = true;
                            continue;
                        }
                    }
                }

                rewritten.push(instr.clone());
            }

            body.instructions = rewritten;
        }

        if changed {
            debug!("PushSplit: applied splits, reindexing PCs");
            ir.reindex_pcs()
                .map_err(|e| Error::CoreError(e.to_string()))?;
        } else {
            debug!("PushSplit: no eligible PUSH instructions found");
        }

        Ok(changed)
    }
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
    let modulus: u128 = 1u128 << (width_bytes as u32 * 8);
    let parts = rng.random_range(2..=4);

    let prefer_xor = rng.random_bool(0.4);
    if prefer_xor {
        let mut pushes = Vec::with_capacity(parts);
        let mut acc = 0u128;
        for i in 0..parts {
            if i + 1 == parts {
                pushes.push((acc ^ value, CombineOp::Xor));
            } else {
                let part = rng.random_range(0..modulus);
                acc ^= part;
                pushes.push((part, CombineOp::Xor));
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
        let part = rng.random_range(0..modulus);
        pushes.push((part, *op));
        acc = match op {
            CombineOp::Add => (acc + part) % modulus,
            CombineOp::Sub => (acc + modulus - part) % modulus,
            CombineOp::Xor => unreachable!(),
        };

        if i + 1 == ops.len() {
            let final_op = *op;
            let final_part = match final_op {
                CombineOp::Add => (value + modulus - acc) % modulus,
                CombineOp::Sub => (acc + modulus - value) % modulus,
                CombineOp::Xor => unreachable!(),
            };
            pushes.push((final_part, final_op));
        }
    }

    pushes
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
