//! Context-dependent storage gates.
//!
//! This transform makes selected call paths depend on storage mutations:
//! dispatcher/controllers set a slot, later controllers verify it before
//! routing, forcing stateful execution order.
//!
//! Assembly example:
//! ```assembly
//! // Dispatcher path for `bond` (sets gate)
//! PUSH1  0x01
//! PUSH32 gate_slot
//! SSTORE           // mark slot
//! JUMP controller_bond
//!
//! // Controller head for `collect` (checks gate)
//! PUSH32 gate_slot
//! SLOAD
//! ISZERO
//! PUSH2 revert_pc  // if unset
//! JUMPI
//! ...              // real body
//! ```

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use tracing::debug;

/// Storage mutation + gate insertion.
#[derive(Default)]
pub struct StorageGates;

impl StorageGates {
    const JUMP_WIDTH: u8 = 4;

    pub fn new() -> Self {
        Self
    }

    fn next_available_pc(ir: &CfgIrBundle) -> usize {
        ir.cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => body
                    .instructions
                    .last()
                    .map(|instr| instr.pc + instr.byte_size()),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }

    fn encode_jump_target(ir: &CfgIrBundle, target_pc: usize) -> usize {
        if let Some((start, _)) = ir.runtime_bounds {
            target_pc.saturating_sub(start)
        } else {
            target_pc
        }
    }

    fn format_jump_immediate(value: usize) -> String {
        format!("{:0width$x}", value, width = Self::JUMP_WIDTH as usize * 2)
    }

    fn block_start_pc(ir: &CfgIrBundle, node: NodeIndex) -> Option<usize> {
        match &ir.cfg[node] {
            Block::Body(body) => Some(body.start_pc),
            _ => None,
        }
    }

    fn gate_slot_hex(rng: &mut StdRng) -> String {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if bytes.iter().all(|b| *b == 0) {
            bytes[0] = 1;
        }
        hex::encode(bytes)
    }

    fn gate_set_block(
        start_pc: usize,
        gate_slot: &str,
        target_pc: usize,
        ir: &CfgIrBundle,
    ) -> BlockBody {
        let mut pc = start_pc;
        let mut instructions = Vec::new();

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMPDEST,
            imm: None,
        });
        pc += 1;

        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(1),
            imm: Some("01".to_string()),
        });
        pc += 2;

        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(32),
            imm: Some(gate_slot.to_string()),
        });
        pc += 33;

        instructions.push(Instruction {
            pc,
            op: Opcode::SSTORE,
            imm: None,
        });
        pc += 1;

        let encoded = Self::format_jump_immediate(Self::encode_jump_target(ir, target_pc));
        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(Self::JUMP_WIDTH),
            imm: Some(encoded),
        });
        pc += 1 + Self::JUMP_WIDTH as usize;

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMP,
            imm: None,
        });

        BlockBody {
            start_pc,
            instructions,
            max_stack: 2,
            control: BlockControl::Unknown,
        }
    }

    fn gate_check_block(
        start_pc: usize,
        gate_slot: &str,
        revert_pc: usize,
        ir: &CfgIrBundle,
    ) -> BlockBody {
        let mut pc = start_pc;
        let mut instructions = Vec::new();

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMPDEST,
            imm: None,
        });
        pc += 1;

        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(32),
            imm: Some(gate_slot.to_string()),
        });
        pc += 33;

        instructions.push(Instruction {
            pc,
            op: Opcode::SLOAD,
            imm: None,
        });
        pc += 1;

        instructions.push(Instruction {
            pc,
            op: Opcode::ISZERO,
            imm: None,
        });
        pc += 1;

        let encoded = Self::format_jump_immediate(Self::encode_jump_target(ir, revert_pc));
        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(Self::JUMP_WIDTH),
            imm: Some(encoded),
        });
        pc += 1 + Self::JUMP_WIDTH as usize;

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMPI,
            imm: None,
        });

        BlockBody {
            start_pc,
            instructions,
            max_stack: 2,
            control: BlockControl::Unknown,
        }
    }

    fn gate_pass_block(start_pc: usize, target_pc: usize, ir: &CfgIrBundle) -> BlockBody {
        let mut pc = start_pc;
        let mut instructions = Vec::new();

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMPDEST,
            imm: None,
        });
        pc += 1;

        let encoded = Self::format_jump_immediate(Self::encode_jump_target(ir, target_pc));
        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(Self::JUMP_WIDTH),
            imm: Some(encoded),
        });
        pc += 1 + Self::JUMP_WIDTH as usize;

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMP,
            imm: None,
        });

        BlockBody {
            start_pc,
            instructions,
            max_stack: 1,
            control: BlockControl::Unknown,
        }
    }

    fn revert_block(start_pc: usize) -> BlockBody {
        let mut pc = start_pc;
        let mut instructions = Vec::new();

        instructions.push(Instruction {
            pc,
            op: Opcode::JUMPDEST,
            imm: None,
        });
        pc += 1;

        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(1),
            imm: Some("00".to_string()),
        });
        pc += 2;

        instructions.push(Instruction {
            pc,
            op: Opcode::PUSH(1),
            imm: Some("00".to_string()),
        });
        pc += 2;

        instructions.push(Instruction {
            pc,
            op: Opcode::REVERT,
            imm: None,
        });

        BlockBody {
            start_pc,
            instructions,
            max_stack: 2,
            control: BlockControl::Terminal,
        }
    }
}

impl Transform for StorageGates {
    fn name(&self) -> &'static str {
        "StorageGates"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== StorageGates Transform Start ===");

        let Some(controller_pcs) = ir.dispatcher_controller_pcs.clone() else {
            debug!("StorageGates: no dispatcher controller map; skipping");
            return Ok(false);
        };

        let mut controllers = Vec::new();
        for (selector, pc) in controller_pcs {
            if let Some(node) = ir.pc_to_block.get(&pc).copied() {
                controllers.push((selector, pc, node));
            } else {
                debug!(
                    "StorageGates: controller pc 0x{:x} missing node; skipping selector 0x{:08x}",
                    pc, selector
                );
            }
        }

        if controllers.len() < 2 {
            debug!(
                "StorageGates: need at least 2 controllers, found {}",
                controllers.len()
            );
            return Ok(false);
        }

        controllers.shuffle(rng);
        let (setter_selector, _, setter_node) = controllers[0];
        let (checker_selector, _, checker_node) = controllers[1];

        let gate_slot = Self::gate_slot_hex(rng);
        debug!(
            "StorageGates: gating selector 0x{:08x} with setter 0x{:08x} (slot=0x{})",
            checker_selector, setter_selector, gate_slot
        );

        let setter_target = Self::block_start_pc(ir, setter_node)
            .ok_or_else(|| Error::Generic("setter target is not a body block".into()))?;
        let checker_target = Self::block_start_pc(ir, checker_node)
            .ok_or_else(|| Error::Generic("checker target is not a body block".into()))?;

        let mut next_pc = Self::next_available_pc(ir);

        let set_block = Self::gate_set_block(next_pc, &gate_slot, setter_target, ir);
        let set_block_size: usize = set_block.instructions.iter().map(|i| i.byte_size()).sum();
        next_pc += set_block_size;

        let check_block = Self::gate_check_block(next_pc, &gate_slot, 0, ir);
        let check_block_size: usize = check_block.instructions.iter().map(|i| i.byte_size()).sum();
        next_pc += check_block_size;

        let pass_block = Self::gate_pass_block(next_pc, checker_target, ir);
        let pass_block_size: usize = pass_block.instructions.iter().map(|i| i.byte_size()).sum();
        next_pc += pass_block_size;

        let revert_block = Self::revert_block(next_pc);
        let revert_block_size: usize = revert_block
            .instructions
            .iter()
            .map(|i| i.byte_size())
            .sum();
        let new_end = next_pc + revert_block_size;

        if let Some((start, end)) = ir.runtime_bounds {
            if new_end > end {
                ir.runtime_bounds = Some((start, new_end));
            }
        }

        let set_node = ir.add_block(Block::Body(set_block));
        ir.pc_to_block
            .insert(Self::block_start_pc(ir, set_node).unwrap_or(0), set_node);

        let mut check_block = check_block;
        let revert_start = next_pc;
        let encoded = Self::format_jump_immediate(Self::encode_jump_target(ir, revert_start));
        if let Some(push) = check_block
            .instructions
            .iter_mut()
            .find(|i| matches!(i.op, Opcode::PUSH(width) if *width == Self::JUMP_WIDTH))
        {
            push.imm = Some(encoded);
        }

        let check_node = ir.add_block(Block::Body(check_block));
        ir.pc_to_block.insert(
            Self::block_start_pc(ir, check_node).unwrap_or(0),
            check_node,
        );

        let pass_node = ir.add_block(Block::Body(pass_block));
        ir.pc_to_block
            .insert(Self::block_start_pc(ir, pass_node).unwrap_or(0), pass_node);

        let revert_node = ir.add_block(Block::Body(revert_block));
        ir.pc_to_block.insert(
            Self::block_start_pc(ir, revert_node).unwrap_or(0),
            revert_node,
        );

        ir.rebuild_edges_for_block(set_node)
            .map_err(|e| Error::CoreError(e.to_string()))?;
        ir.rebuild_edges_for_block(check_node)
            .map_err(|e| Error::CoreError(e.to_string()))?;
        ir.rebuild_edges_for_block(pass_node)
            .map_err(|e| Error::CoreError(e.to_string()))?;
        ir.rebuild_edges_for_block(revert_node)
            .map_err(|e| Error::CoreError(e.to_string()))?;

        if let Some(controller_pcs) = ir.dispatcher_controller_pcs.as_mut() {
            if let Some(set_start) = Self::block_start_pc(ir, set_node) {
                controller_pcs.insert(setter_selector, set_start);
            }
            if let Some(check_start) = Self::block_start_pc(ir, check_node) {
                controller_pcs.insert(checker_selector, check_start);
            }
        }

        debug!("=== StorageGates Transform Complete ===");
        Ok(true)
    }
}
