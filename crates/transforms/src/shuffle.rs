use crate::Transform;
use crate::{Error, Result};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::{rngs::StdRng, seq::SliceRandom};
use std::collections::HashMap;
use tracing::debug;

pub struct Shuffle;

impl Transform for Shuffle {
    fn name(&self) -> &'static str {
        "Shuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        let mut blocks: Vec<(usize, &Block)> = ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &ir.cfg[n] {
                    Some((body.start_pc, &ir.cfg[n]))
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
        let mut original_pcs = Vec::new();
        let mut program_counter_mapping = HashMap::new();
        let mut current_pc = 0;

        for (_, block) in blocks {
            if let Block::Body(body) = block {
                let instructions = &body.instructions;
                for instruction in instructions {
                    program_counter_mapping.insert(instruction.pc, current_pc);
                    let mut new_instruction = instruction.clone();
                    original_pcs.push(instruction.pc);
                    new_instruction.pc = current_pc;
                    new_instrs.push(new_instruction);
                    current_pc += self.instruction_size(instruction);
                }
            }
        }

        self.rewrite_jump_immediates(&mut new_instrs, &original_pcs, &program_counter_mapping)?;

        ir.replace_body(new_instrs, &[])
            .map_err(|e| Error::CoreError(e.to_string()))?;
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

    fn rewrite_jump_immediates(
        &self,
        instructions: &mut [Instruction],
        original_pcs: &[usize],
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<()> {
        for idx in 0..instructions.len() {
            let op = instructions[idx].op;
            if !matches!(op, Opcode::JUMP | Opcode::JUMPI) {
                continue;
            }

            // Handle direct PUSH <target>; JUMP/JUMPI patterns.
            if idx > 0 {
                if let Opcode::PUSH(push_bytes) = instructions[idx - 1].op {
                    if let Some(ref immediate) = instructions[idx - 1].imm {
                        if let Ok(old_target) = usize::from_str_radix(immediate, 16) {
                            let new_target = pc_mapping
                                .get(&old_target)
                                .copied()
                                .ok_or(Error::InvalidJumpTarget(old_target))?;
                            let formatted = Self::format_immediate(new_target, push_bytes)?;
                            instructions[idx - 1].imm = Some(formatted);
                        }
                    }
                }
            }

            // Handle PC-relative dispatcher pattern: PUSH <delta>; PC; ADD; JUMPI
            if matches!(op, Opcode::JUMPI) && idx >= 3 {
                if let Opcode::PUSH(push_bytes) = instructions[idx - 3].op {
                    if matches!(instructions[idx - 2].op, Opcode::PC)
                        && matches!(instructions[idx - 1].op, Opcode::ADD)
                    {
                        if let Some(ref immediate) = instructions[idx - 3].imm {
                            if let Ok(old_delta) = usize::from_str_radix(immediate, 16) {
                                let pc_original = original_pcs
                                    .get(idx - 2)
                                    .copied()
                                    .ok_or(Error::Generic("missing original PC".into()))?;
                                let old_target = pc_original
                                    .checked_add(old_delta)
                                    .ok_or_else(|| Error::Generic("jump delta overflow".into()))?;

                                let new_target = pc_mapping
                                    .get(&old_target)
                                    .copied()
                                    .ok_or(Error::InvalidJumpTarget(old_target))?;
                                let new_pc_value = instructions[idx - 2].pc;
                                let new_delta = new_target
                                    .checked_sub(new_pc_value)
                                    .ok_or_else(|| Error::Generic("negative jump delta".into()))?;

                                let formatted = Self::format_immediate(new_delta, push_bytes)?;
                                instructions[idx - 3].imm = Some(formatted);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn format_immediate(value: usize, push_bytes: u8) -> Result<String> {
        if push_bytes == 0 {
            return Ok(String::new());
        }

        let width = push_bytes as usize * 2;
        let raw = format!("{value:x}");
        if raw.len() > width {
            return Err(Error::Generic(format!(
                "jump target 0x{value:x} does not fit in PUSH{}",
                push_bytes
            )));
        }

        Ok(format!("{:0width$x}", value, width = width))
    }
}
