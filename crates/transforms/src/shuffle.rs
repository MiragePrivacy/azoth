use crate::Transform;
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use azoth_utils::errors::TransformError;
use rand::{rngs::StdRng, seq::SliceRandom};
use std::collections::HashMap;
use tracing::debug;

pub struct Shuffle;

impl Transform for Shuffle {
    fn name(&self) -> &'static str {
        "Shuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool, TransformError> {
        let mut blocks: Vec<(usize, &Block)> = ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body { start_pc, .. } = &ir.cfg[n] {
                    Some((*start_pc, &ir.cfg[n]))
                } else {
                    None
                }
            })
            .collect();

        if blocks.len() <= 1 {
            debug!("Not enough blocks to shuffle");
            return Ok(false);
        }

        let original_order: Vec<usize> = blocks.iter().map(|(pc, _)| *pc).collect();
        blocks.shuffle(rng);
        let new_order: Vec<usize> = blocks.iter().map(|(pc, _)| *pc).collect();
        if original_order == new_order {
            debug!("Shuffle produced no change");
            return Ok(false);
        }

        let mut new_instrs = Vec::new();
        let mut pc_map = HashMap::new();
        let mut current_pc = 0;

        for (_, block) in blocks {
            if let Block::Body { instructions, .. } = block {
                for instr in instructions {
                    pc_map.insert(instr.pc, current_pc);
                    let mut new_instr = instr.clone();
                    new_instr.pc = current_pc;
                    new_instrs.push(new_instr);
                    current_pc += self.instruction_size(instr);
                }
            }
        }

        for instr in &mut new_instrs {
            if matches!(instr.op, Opcode::JUMP | Opcode::JUMPI) {
                if let Some(imm) = &instr.imm {
                    if let Ok(old_target) = usize::from_str_radix(imm, 16) {
                        if let Some(new_target) = pc_map.get(&old_target) {
                            instr.imm = Some(format!("{new_target:x}"));
                        } else {
                            return Err(TransformError::InvalidJumpTarget(old_target));
                        }
                    }
                }
            }
        }

        ir.replace_body(new_instrs, &[])?;
        Ok(true)
    }
}

impl Shuffle {
    fn instruction_size(&self, instr: &Instruction) -> usize {
        match instr.op {
            Opcode::PUSH(n) => 1 + n as usize,
            Opcode::PUSH0 => 1,
            _ => 1,
        }
    }
}
