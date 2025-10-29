use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::{rngs::StdRng, Rng};
use tracing::debug;

/// Jump Address Transformer obfuscates direct jump patterns by splitting the
/// destination immediate into an `ADD` across two `PUSH` instructions.
#[derive(Default)]
pub struct JumpAddressTransformer;

impl JumpAddressTransformer {
    pub fn new() -> Self {
        Self
    }

    fn capacity_for_width(width: usize) -> usize {
        match width {
            0 => 0,
            w if w >= 8 => usize::MAX,
            w => (1usize << (w * 8)) - 1,
        }
    }

    fn format_immediate(value: usize, width: usize) -> Result<String> {
        if width == 0 {
            if value != 0 {
                return Err(Error::InvalidImmediate(format!(
                    "value 0x{value:x} does not fit PUSH0"
                )));
            }
            return Ok("00".into());
        }

        let cap = Self::capacity_for_width(width);
        if value > cap {
            return Err(Error::InvalidImmediate(format!(
                "value 0x{value:x} exceeds PUSH{width} capacity"
            )));
        }

        Ok(format!("{value:0width$x}", width = width * 2))
    }

    fn assign_block_pcs(start_pc: usize, instructions: &mut [Instruction]) {
        let mut pc = start_pc;
        for instr in instructions {
            instr.pc = pc;
            pc += instr.byte_size();
        }
    }

    fn choose_widths(&self, original_width: usize, rng: &mut StdRng) -> (usize, usize) {
        let base_width = original_width.max(1);
        let lhs_max = base_width.min(4);
        let lhs_width = if lhs_max == 1 {
            1
        } else {
            rng.random_range(1..=lhs_max)
        };

        let rhs_width = if original_width == 0 {
            1
        } else if base_width >= 4 {
            8
        } else {
            (base_width + 4).min(8)
        };

        (lhs_width, rhs_width.max(lhs_width))
    }

    fn transform_block(
        &self,
        ir: &mut CfgIrBundle,
        node_idx: NodeIndex,
        rng: &mut StdRng,
    ) -> Result<bool> {
        let original_body = match ir.cfg.node_weight(node_idx) {
            Some(Block::Body(body)) => body.clone(),
            _ => return Ok(false),
        };

        let mut new_body = original_body.clone();
        let mut new_instructions = Vec::with_capacity(original_body.instructions.len());
        let mut changed = false;
        let mut idx = 0usize;

        while idx < original_body.instructions.len() {
            let instr = &original_body.instructions[idx];
            if let Some(jump_instr) = original_body.instructions.get(idx + 1) {
                if matches!(instr.op, Opcode::PUSH(_) | Opcode::PUSH0)
                    && matches!(jump_instr.op, Opcode::JUMP | Opcode::JUMPI)
                    && instr.imm.is_some()
                {
                let target = usize::from_str_radix(instr.imm.as_deref().unwrap(), 16).map_err(
                    |_| Error::InvalidImmediate("failed to parse jump immediate".into()),
                )?;

                let original_width = match instr.op {
                    Opcode::PUSH(width) => width as usize,
                    Opcode::PUSH0 => 0,
                    _ => unreachable!(),
                };

                let (mut lhs_width, mut rhs_width) = self.choose_widths(original_width, rng);
                let mut lhs_capacity = Self::capacity_for_width(lhs_width);
                let mut rhs_capacity = Self::capacity_for_width(rhs_width);

                if target > lhs_capacity.saturating_add(rhs_capacity) {
                    rhs_width = 8;
                    rhs_capacity = Self::capacity_for_width(rhs_width);
                }

                if target > lhs_capacity.saturating_add(rhs_capacity) {
                    lhs_width = lhs_width.max(8);
                    lhs_capacity = Self::capacity_for_width(lhs_width);
                }

                if target > lhs_capacity.saturating_add(rhs_capacity) {
                    debug!(
                        "Skipping jump split for block {} at pc 0x{:x}: target 0x{:x} too large",
                        node_idx.index(),
                        instr.pc,
                        target
                    );
                    new_instructions.push(instr.clone());
                    idx += 1;
                    continue;
                }

                let min_lhs = target.saturating_sub(rhs_capacity);
                let max_lhs = lhs_capacity.min(target);
                let lhs_value = if min_lhs >= max_lhs {
                    max_lhs
                } else {
                    rng.random_range(min_lhs..=max_lhs)
                };
                let rhs_value = target - lhs_value;

                let push_a = Instruction {
                    pc: instr.pc,
                    op: Opcode::PUSH(lhs_width as u8),
                    imm: Some(Self::format_immediate(lhs_value, lhs_width)?),
                };
                let push_b = Instruction {
                    pc: instr.pc,
                    op: Opcode::PUSH(rhs_width as u8),
                    imm: Some(Self::format_immediate(rhs_value, rhs_width)?),
                };
                let add = Instruction {
                    pc: instr.pc,
                    op: Opcode::ADD,
                    imm: None,
                };

                new_instructions.push(push_a);
                new_instructions.push(push_b);
                new_instructions.push(add);
                new_instructions.push(jump_instr.clone());

                    changed = true;
                    idx += 2;
                    continue;
                }
            }

            new_instructions.push(instr.clone());
            idx += 1;
        }

        if !changed {
            return Ok(false);
        }

        Self::assign_block_pcs(original_body.start_pc, &mut new_instructions);
        new_body.instructions = new_instructions;
        new_body.max_stack = original_body.max_stack.saturating_add(1);

        ir.overwrite_block(node_idx, new_body)
            .map_err(|e| Error::CoreError(e.to_string()))?;
        Ok(true)
    }
}

impl Transform for JumpAddressTransformer {
    fn name(&self) -> &'static str {
        "JumpAddressTransformer"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== JumpAddressTransformer Transform Start ===");

        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        let mut modified = false;

        for node in nodes {
            modified |= self.transform_block(ir, node, rng)?;
        }

        if modified {
            debug!("JumpAddressTransformer modified CFG; reindexing PCs");
            ir.reindex_pcs()
                .map_err(|e| Error::CoreError(e.to_string()))?;
        }

        Ok(modified)
    }
}
