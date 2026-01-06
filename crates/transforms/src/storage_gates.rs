//! Context-dependent storage gates.
//!
//! This transform makes selected call paths depend on storage mutations:
//! dispatcher/controllers set a slot, later controllers verify it before
//! routing, forcing stateful execution order.
//!
//! Only controllers whose reachable blocks contain at least
//! one of `SSTORE`, `CALL`, `DELEGATECALL`, `CREATE`, or `CREATE2` can be
//! selected as setters or checkers. (Static calls and logs do not qualify.)
//! This prevents gating view/read-only functions (which would make them revert
//! before any state mutation) and avoids turning view calls into SSTORE-heavy
//! setters that break `eth_call` expectations.
//!
//! Assembly example:
//! ```assembly
//! // Dispatcher path for `transfer` (sets gate)
//! PUSH1  0x01
//! PUSH32 gate_slot
//! SSTORE           // mark slot
//! JUMP controller_transfer
//!
//! // Controller head for `withdraw` (checks gate)
//! PUSH32 gate_slot
//! SLOAD
//! ISZERO
//! PUSH2 revert_pc  // if unset
//! JUMPI
//! JUMP controller_withdraw
//! ```

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::{is_terminal_opcode, Opcode};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use std::collections::HashSet;
use tracing::debug;

/// Storage mutation + gate insertion.
#[derive(Default)]
pub struct StorageGates;

impl StorageGates {
    const JUMP_WIDTH: u8 = 4;
    const STATE_MUTATING_OPCODES: &'static [Opcode] = &[
        Opcode::SSTORE,
        Opcode::CALL,
        Opcode::DELEGATECALL,
        Opcode::CREATE,
        Opcode::CREATE2,
    ];

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

    fn controller_is_state_mutating(ir: &CfgIrBundle, entry: NodeIndex) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![entry];
        visited.insert(entry);

        while let Some(node) = stack.pop() {
            if let Block::Body(body) = &ir.cfg[node] {
                if body
                    .instructions
                    .iter()
                    .any(|instr| Self::STATE_MUTATING_OPCODES.contains(&instr.op))
                {
                    return true;
                }
            }

            let edges: Vec<_> = ir.cfg.edges_directed(node, petgraph::Outgoing).collect();
            let mut successors = Vec::new();
            if edges.is_empty() {
                if let Block::Body(body) = &ir.cfg[node] {
                    successors.extend(Self::infer_successors(ir, body));
                }
            } else {
                successors.extend(edges.into_iter().map(|edge| edge.target()));
            }

            for target in successors {
                if visited.insert(target) {
                    stack.push(target);
                }
            }
        }

        false
    }

    fn controller_entry_is_state_mutating(
        ir: &CfgIrBundle,
        selector: u32,
        controller_node: NodeIndex,
    ) -> bool {
        if let Some(target_node) = Self::controller_target_node_from_patches(ir, controller_node) {
            debug!(
                "selector 0x{:08x} uses controller patch target node {} for mutation scan",
                selector,
                target_node.index()
            );
            return Self::controller_is_state_mutating(ir, target_node);
        }

        debug!(
            "selector 0x{:08x} falling back to controller node {}",
            selector,
            controller_node.index()
        );
        Self::controller_is_state_mutating(ir, controller_node)
    }

    /// Trace the full dispatcher chain to find the original function entry.
    ///
    /// The dispatcher creates a chain: controller → stub → decoy → original function.
    /// - controller_patches: (controller_node, _, _, stub_pc)
    /// - stub_patches: (stub_node, _, _, decoy_node)
    /// - decoy_patches: (decoy_node, _, _, original_pc)
    fn controller_target_node_from_patches(
        ir: &CfgIrBundle,
        controller_node: NodeIndex,
    ) -> Option<NodeIndex> {
        // Step 1: controller → stub_pc
        let controller_patches = ir.controller_patches.as_ref()?;
        let stub_pc = controller_patches
            .iter()
            .find(|(node, _, _, _)| *node == controller_node)
            .map(|(_, _, _, target_pc)| *target_pc)?;

        // Find stub node from stub_pc
        let stub_node = Self::find_node_by_pc(ir, stub_pc)?;

        // Step 2: stub → decoy_node
        let stub_patches = ir.stub_patches.as_ref()?;
        let decoy_node = stub_patches
            .iter()
            .find(|(node, _, _, _)| *node == stub_node)
            .map(|(_, _, _, decoy)| *decoy)?;

        // Step 3: decoy → original_pc
        let decoy_patches = ir.decoy_patches.as_ref()?;
        let original_pc = decoy_patches
            .iter()
            .find(|(node, _, _, _)| *node == decoy_node)
            .map(|(_, _, _, target_pc)| *target_pc)?;

        // Find original function node
        let result = Self::find_node_by_pc(ir, original_pc);
        if result.is_some() {
            debug!(
                "controller {} -> stub 0x{:x} -> decoy {} -> original 0x{:x}",
                controller_node.index(),
                stub_pc,
                decoy_node.index(),
                original_pc
            );
        } else {
            debug!(
                "controller {} chain traced to original_pc 0x{:x} but node not found",
                controller_node.index(),
                original_pc
            );
        }
        result
    }

    fn find_node_by_pc(ir: &CfgIrBundle, pc: usize) -> Option<NodeIndex> {
        // Try direct lookup first
        if let Some(node) = ir.pc_to_block.get(&pc).copied() {
            return Some(node);
        }
        // Try with runtime offset
        if let Some((start, _)) = ir.runtime_bounds {
            let adjusted = start.saturating_add(pc);
            if let Some(node) = ir.pc_to_block.get(&adjusted).copied() {
                return Some(node);
            }
            // Try finding block containing the PC
            if let Some(node) = Self::node_containing_pc(ir, adjusted) {
                return Some(node);
            }
        }
        // Try finding block containing the raw PC
        Self::node_containing_pc(ir, pc)
    }

    fn infer_successors(ir: &CfgIrBundle, body: &BlockBody) -> Vec<NodeIndex> {
        let mut successors = Vec::new();
        if body.instructions.is_empty() {
            if let Some(next) = Self::next_body_node(ir, body.start_pc) {
                successors.push(next);
            }
            return successors;
        }

        let mut jump_targets = Self::collect_jump_targets(ir, body);
        if !jump_targets.is_empty() {
            successors.append(&mut jump_targets);
            if let Some(next) = Self::next_body_node(ir, body.start_pc) {
                successors.push(next);
            }
            successors.sort_by_key(|node| node.index());
            successors.dedup();
            return successors;
        }

        let last = body.instructions.last().unwrap();
        match last.op {
            Opcode::JUMP => {
                if let Some(target) =
                    Self::resolve_jump_target(ir, body, body.instructions.len().saturating_sub(1))
                {
                    successors.push(target);
                }
            }
            Opcode::JUMPI => {
                if let Some(target) =
                    Self::resolve_jump_target(ir, body, body.instructions.len().saturating_sub(1))
                {
                    successors.push(target);
                }
                if let Some(next) = Self::next_body_node(ir, body.start_pc) {
                    successors.push(next);
                }
            }
            opcode if is_terminal_opcode(opcode) => {}
            _ => {
                if let Some(next) = Self::next_body_node(ir, body.start_pc) {
                    successors.push(next);
                }
            }
        }

        successors
    }

    fn collect_jump_targets(ir: &CfgIrBundle, body: &BlockBody) -> Vec<NodeIndex> {
        let mut targets = Vec::new();
        for (idx, instr) in body.instructions.iter().enumerate() {
            if matches!(instr.op, Opcode::JUMP | Opcode::JUMPI) {
                if let Some(target) = Self::resolve_jump_target(ir, body, idx) {
                    targets.push(target);
                }
            }
        }
        targets.sort_by_key(|node| node.index());
        targets.dedup();
        targets
    }

    fn resolve_jump_target(
        ir: &CfgIrBundle,
        body: &BlockBody,
        jump_idx: usize,
    ) -> Option<NodeIndex> {
        if jump_idx == 0 {
            return None;
        }
        let instructions = &body.instructions;
        let immediate = if jump_idx >= 1
            && matches!(
                instructions[jump_idx - 1].op,
                Opcode::PUSH(_) | Opcode::PUSH0
            ) {
            Self::parse_immediate(&instructions[jump_idx - 1])
        } else if jump_idx >= 3
            && instructions[jump_idx - 1].op == Opcode::ADD
            && matches!(
                instructions[jump_idx - 2].op,
                Opcode::PUSH(_) | Opcode::PUSH0
            )
            && matches!(
                instructions[jump_idx - 3].op,
                Opcode::PUSH(_) | Opcode::PUSH0
            )
        {
            let first = Self::parse_immediate(&instructions[jump_idx - 3])?;
            let second = Self::parse_immediate(&instructions[jump_idx - 2])?;
            first.checked_add(second)
        } else {
            None
        }?;

        let absolute = if let Some((start, end)) = ir.runtime_bounds {
            if body.start_pc >= start && body.start_pc < end {
                start + immediate
            } else {
                immediate
            }
        } else {
            immediate
        };

        ir.pc_to_block.get(&absolute).copied()
    }

    fn parse_immediate(instr: &Instruction) -> Option<usize> {
        instr
            .imm
            .as_ref()
            .and_then(|imm| usize::from_str_radix(imm, 16).ok())
    }

    fn next_body_node(ir: &CfgIrBundle, start_pc: usize) -> Option<NodeIndex> {
        let mut bodies: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|idx| match &ir.cfg[idx] {
                Block::Body(body) => Some((idx, body.start_pc)),
                _ => None,
            })
            .collect();
        bodies.sort_by_key(|(_, pc)| *pc);
        for (i, (_, pc)) in bodies.iter().enumerate() {
            if *pc == start_pc {
                return bodies.get(i + 1).map(|(idx, _)| *idx);
            }
        }
        None
    }

    fn node_containing_pc(ir: &CfgIrBundle, pc: usize) -> Option<NodeIndex> {
        for idx in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[idx] {
                let size: usize = body.instructions.iter().map(|i| i.byte_size()).sum();
                let end = body.start_pc + size;
                if pc >= body.start_pc && pc < end {
                    return Some(idx);
                }
            }
        }
        None
    }
}

impl Transform for StorageGates {
    fn name(&self) -> &'static str {
        "StorageGates"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== StorageGates Transform Start ===");

        // Find all blocks with state-mutating opcodes (used for fallback heuristic)
        let mutating_block_count = ir
            .cfg
            .node_indices()
            .filter(|node| {
                if let Block::Body(body) = &ir.cfg[*node] {
                    body.instructions
                        .iter()
                        .any(|instr| Self::STATE_MUTATING_OPCODES.contains(&instr.op))
                } else {
                    false
                }
            })
            .count();

        let Some(controller_pcs) = ir.dispatcher_controller_pcs.clone() else {
            debug!("StorageGates: no dispatcher controller map; skipping");
            return Ok(false);
        };

        let mut controllers = Vec::new();
        for (selector, pc) in controller_pcs {
            if let Some(node) = ir.pc_to_block.get(&pc).copied() {
                controllers.push((selector, pc, node));
            }
        }

        if controllers.len() < 2 {
            debug!(
                "StorageGates: need at least 2 controllers, found {}",
                controllers.len()
            );
            return Ok(false);
        }

        // Try traversal-based detection first
        let mut eligible_checkers: Vec<_> = controllers
            .iter()
            .copied()
            .filter(|(selector, _, node)| {
                Self::controller_entry_is_state_mutating(ir, *selector, *node)
            })
            .collect();

        // Note: We intentionally do NOT use a fallback heuristic here. If traversal
        // cannot find state-mutating controllers, we skip the transform rather than
        // risk gating arbitrary functions which can break call order assumptions.
        // The traversal may fail to find controllers after FunctionDispatcher because
        // the controller target PCs from dispatcher patches don't map cleanly in the CFG.
        if eligible_checkers.is_empty() {
            if mutating_block_count > 0 {
                debug!(
                    "StorageGates: traversal found 0 eligible controllers despite {} state-mutating blocks; skipping (traversal limitation)",
                    mutating_block_count
                );
            } else {
                debug!("StorageGates: no state-mutating controllers available; skipping");
            }
            return Ok(false);
        }

        eligible_checkers.shuffle(rng);
        let (checker_selector, _, checker_node) = eligible_checkers[0];

        // Find setters: state-mutating controllers that are not the checker
        let mut eligible_setters: Vec<_> = controllers
            .iter()
            .copied()
            .filter(|(selector, _, node)| {
                *selector != checker_selector
                    && Self::controller_entry_is_state_mutating(ir, *selector, *node)
            })
            .collect();

        if eligible_setters.is_empty() {
            debug!("StorageGates: no distinct state-mutating setter available; skipping");
            return Ok(false);
        }

        eligible_setters.shuffle(rng);
        let (setter_selector, _, setter_node) = eligible_setters[0];

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
            .find(|i| matches!(i.op, Opcode::PUSH(width) if width == Self::JUMP_WIDTH))
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

        let set_start = Self::block_start_pc(ir, set_node);
        let check_start = Self::block_start_pc(ir, check_node);
        if let Some(controller_pcs) = ir.dispatcher_controller_pcs.as_mut() {
            if let Some(set_start) = set_start {
                controller_pcs.insert(setter_selector, set_start);
            }
            if let Some(check_start) = check_start {
                controller_pcs.insert(checker_selector, check_start);
            }
        }

        debug!("=== StorageGates Transform Complete ===");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::process_bytecode_to_cfg;
    use rand::SeedableRng;
    use std::collections::HashMap;

    const STORAGE_BYTECODE: &str = include_str!("../../../tests/bytecode/storage.hex");
    const COUNTER_DEPLOYMENT_BYTECODE: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME_BYTECODE: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

    fn has_gate_set_pattern(body: &BlockBody) -> bool {
        if body.instructions.len() < 6 {
            return false;
        }
        matches!(body.instructions[0].op, Opcode::JUMPDEST)
            && matches!(body.instructions[1].op, Opcode::PUSH(1))
            && body.instructions[1].imm.as_deref() == Some("01")
            && matches!(body.instructions[2].op, Opcode::PUSH(32))
            && matches!(body.instructions[3].op, Opcode::SSTORE)
            && matches!(
                body.instructions[4].op,
                Opcode::PUSH(width) if width == StorageGates::JUMP_WIDTH
            )
            && matches!(body.instructions[5].op, Opcode::JUMP)
    }

    fn has_gate_check_pattern(body: &BlockBody) -> bool {
        if body.instructions.len() < 6 {
            return false;
        }
        matches!(body.instructions[0].op, Opcode::JUMPDEST)
            && matches!(body.instructions[1].op, Opcode::PUSH(32))
            && matches!(body.instructions[2].op, Opcode::SLOAD)
            && matches!(body.instructions[3].op, Opcode::ISZERO)
            && matches!(
                body.instructions[4].op,
                Opcode::PUSH(width) if width == StorageGates::JUMP_WIDTH
            )
            && matches!(body.instructions[5].op, Opcode::JUMPI)
    }

    fn seed_mutating_controllers(cfg_ir: &mut CfgIrBundle) -> HashMap<u32, usize> {
        let mut next_pc = StorageGates::next_available_pc(cfg_ir);

        let make_mutating_block = |start_pc| {
            let mut pc = start_pc;
            let instructions = vec![
                Instruction {
                    pc,
                    op: Opcode::JUMPDEST,
                    imm: None,
                },
                Instruction {
                    pc: {
                        pc += 1;
                        pc
                    },
                    op: Opcode::PUSH(1),
                    imm: Some("01".to_string()),
                },
                Instruction {
                    pc: {
                        pc += 2;
                        pc
                    },
                    op: Opcode::PUSH(1),
                    imm: Some("00".to_string()),
                },
                Instruction {
                    pc: {
                        pc += 2;
                        pc
                    },
                    op: Opcode::SSTORE,
                    imm: None,
                },
                Instruction {
                    pc: {
                        pc += 1;
                        pc
                    },
                    op: Opcode::STOP,
                    imm: None,
                },
            ];
            BlockBody {
                start_pc,
                instructions,
                max_stack: 2,
                control: BlockControl::Terminal,
            }
        };

        let block_a = make_mutating_block(next_pc);
        next_pc += block_a
            .instructions
            .iter()
            .map(|i| i.byte_size())
            .sum::<usize>();
        let block_b = make_mutating_block(next_pc);
        next_pc += block_b
            .instructions
            .iter()
            .map(|i| i.byte_size())
            .sum::<usize>();

        if let Some((start, end)) = cfg_ir.runtime_bounds {
            if next_pc > end {
                cfg_ir.runtime_bounds = Some((start, next_pc));
            }
        }

        let node_a = cfg_ir.add_block(Block::Body(block_a));
        cfg_ir.pc_to_block.insert(
            StorageGates::block_start_pc(cfg_ir, node_a).unwrap(),
            node_a,
        );
        let node_b = cfg_ir.add_block(Block::Body(block_b));
        cfg_ir.pc_to_block.insert(
            StorageGates::block_start_pc(cfg_ir, node_b).unwrap(),
            node_b,
        );

        let mut controller_pcs = HashMap::new();
        controller_pcs.insert(
            0xaaaaaaaa,
            StorageGates::block_start_pc(cfg_ir, node_a).unwrap(),
        );
        controller_pcs.insert(
            0xbbbbbbbb,
            StorageGates::block_start_pc(cfg_ir, node_b).unwrap(),
        );
        controller_pcs
    }

    #[tokio::test]
    async fn storage_gates_injects_gate_blocks() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        cfg_ir.dispatcher_controller_pcs = Some(seed_mutating_controllers(&mut cfg_ir));

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(
            changed,
            "storage gates should apply when eligible controllers exist"
        );

        let mut saw_set = false;
        let mut saw_check = false;
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                saw_set |= has_gate_set_pattern(body);
                saw_check |= has_gate_check_pattern(body);
            }
        }

        assert!(saw_set, "expected gate setter block pattern to be present");
        assert!(
            saw_check,
            "expected gate checker block pattern to be present"
        );
    }

    #[tokio::test]
    async fn storage_gates_injects_gate_blocks_on_counter_bytecode() {
        let deployment = COUNTER_DEPLOYMENT_BYTECODE.trim();
        let runtime = COUNTER_RUNTIME_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(deployment, false, runtime, false)
            .await
            .unwrap();

        cfg_ir.dispatcher_controller_pcs = Some(seed_mutating_controllers(&mut cfg_ir));

        let mut rng = StdRng::seed_from_u64(7);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "storage gates should apply on counter fixture");

        let mut saw_set = false;
        let mut saw_check = false;
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                saw_set |= has_gate_set_pattern(body);
                saw_check |= has_gate_check_pattern(body);
            }
        }

        assert!(saw_set, "expected gate setter block pattern to be present");
        assert!(
            saw_check,
            "expected gate checker block pattern to be present"
        );
    }

    #[tokio::test]
    async fn storage_gates_skips_without_dispatcher_metadata() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // Ensure no dispatcher_controller_pcs is set
        cfg_ir.dispatcher_controller_pcs = None;

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();

        assert!(
            !changed,
            "storage gates should skip when no dispatcher metadata exists"
        );
    }

    #[tokio::test]
    async fn storage_gates_skips_with_only_one_controller() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // Create only one mutating controller
        let next_pc = StorageGates::next_available_pc(&cfg_ir);
        let block = BlockBody {
            start_pc: next_pc,
            instructions: vec![
                Instruction {
                    pc: next_pc,
                    op: Opcode::JUMPDEST,
                    imm: None,
                },
                Instruction {
                    pc: next_pc + 1,
                    op: Opcode::PUSH(1),
                    imm: Some("01".to_string()),
                },
                Instruction {
                    pc: next_pc + 3,
                    op: Opcode::PUSH(1),
                    imm: Some("00".to_string()),
                },
                Instruction {
                    pc: next_pc + 5,
                    op: Opcode::SSTORE,
                    imm: None,
                },
                Instruction {
                    pc: next_pc + 6,
                    op: Opcode::STOP,
                    imm: None,
                },
            ],
            max_stack: 2,
            control: BlockControl::Terminal,
        };

        let node = cfg_ir.add_block(Block::Body(block));
        cfg_ir
            .pc_to_block
            .insert(StorageGates::block_start_pc(&cfg_ir, node).unwrap(), node);

        let mut controller_pcs = HashMap::new();
        controller_pcs.insert(
            0xaaaaaaaa,
            StorageGates::block_start_pc(&cfg_ir, node).unwrap(),
        );
        cfg_ir.dispatcher_controller_pcs = Some(controller_pcs);

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();

        assert!(
            !changed,
            "storage gates should skip when only one controller exists"
        );
    }

    #[tokio::test]
    async fn storage_gates_skips_with_only_readonly_controllers() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // Create two read-only controllers (no state-mutating opcodes)
        let mut next_pc = StorageGates::next_available_pc(&cfg_ir);

        let make_readonly_block = |start_pc: usize| BlockBody {
            start_pc,
            instructions: vec![
                Instruction {
                    pc: start_pc,
                    op: Opcode::JUMPDEST,
                    imm: None,
                },
                Instruction {
                    pc: start_pc + 1,
                    op: Opcode::PUSH(1),
                    imm: Some("00".to_string()),
                },
                Instruction {
                    pc: start_pc + 3,
                    op: Opcode::SLOAD, // Read-only, not SSTORE
                    imm: None,
                },
                Instruction {
                    pc: start_pc + 4,
                    op: Opcode::STOP,
                    imm: None,
                },
            ],
            max_stack: 1,
            control: BlockControl::Terminal,
        };

        let block_a = make_readonly_block(next_pc);
        next_pc += block_a
            .instructions
            .iter()
            .map(|i| i.byte_size())
            .sum::<usize>();
        let block_b = make_readonly_block(next_pc);

        let node_a = cfg_ir.add_block(Block::Body(block_a));
        cfg_ir.pc_to_block.insert(
            StorageGates::block_start_pc(&cfg_ir, node_a).unwrap(),
            node_a,
        );
        let node_b = cfg_ir.add_block(Block::Body(block_b));
        cfg_ir.pc_to_block.insert(
            StorageGates::block_start_pc(&cfg_ir, node_b).unwrap(),
            node_b,
        );

        let mut controller_pcs = HashMap::new();
        controller_pcs.insert(
            0xaaaaaaaa,
            StorageGates::block_start_pc(&cfg_ir, node_a).unwrap(),
        );
        controller_pcs.insert(
            0xbbbbbbbb,
            StorageGates::block_start_pc(&cfg_ir, node_b).unwrap(),
        );
        cfg_ir.dispatcher_controller_pcs = Some(controller_pcs);

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();

        assert!(
            !changed,
            "storage gates should skip when all controllers are read-only"
        );
    }

    #[tokio::test]
    async fn storage_gates_updates_controller_pcs() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        let original_pcs = seed_mutating_controllers(&mut cfg_ir);
        let original_pc_a = original_pcs[&0xaaaaaaaa];
        let original_pc_b = original_pcs[&0xbbbbbbbb];
        cfg_ir.dispatcher_controller_pcs = Some(original_pcs);

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "transform should apply");

        let updated_pcs = cfg_ir
            .dispatcher_controller_pcs
            .as_ref()
            .expect("dispatcher_controller_pcs should exist");

        // At least one of the controller PCs should have changed (redirected to gate block)
        let pc_a_changed = updated_pcs[&0xaaaaaaaa] != original_pc_a;
        let pc_b_changed = updated_pcs[&0xbbbbbbbb] != original_pc_b;

        assert!(
            pc_a_changed || pc_b_changed,
            "at least one controller PC should be redirected to a gate block"
        );
    }

    #[tokio::test]
    async fn storage_gates_creates_all_four_blocks() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        cfg_ir.dispatcher_controller_pcs = Some(seed_mutating_controllers(&mut cfg_ir));

        let blocks_before = cfg_ir.cfg.node_count();

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "transform should apply");

        let blocks_after = cfg_ir.cfg.node_count();

        // Should add exactly 4 new blocks: gate_set, gate_check, gate_pass, revert
        assert_eq!(
            blocks_after - blocks_before,
            4,
            "should add exactly 4 new blocks"
        );

        // Verify each block type exists
        let mut saw_set = false;
        let mut saw_check = false;
        let mut saw_pass = false;
        let mut saw_revert = false;

        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                saw_set |= has_gate_set_pattern(body);
                saw_check |= has_gate_check_pattern(body);
                saw_pass |= has_gate_pass_pattern(body);
                saw_revert |= has_revert_pattern(body);
            }
        }

        assert!(saw_set, "gate_set block should exist");
        assert!(saw_check, "gate_check block should exist");
        assert!(saw_pass, "gate_pass block should exist");
        assert!(saw_revert, "revert block should exist");
    }

    fn has_gate_pass_pattern(body: &BlockBody) -> bool {
        if body.instructions.len() < 3 {
            return false;
        }
        matches!(body.instructions[0].op, Opcode::JUMPDEST)
            && matches!(
                body.instructions[1].op,
                Opcode::PUSH(width) if width == StorageGates::JUMP_WIDTH
            )
            && matches!(body.instructions[2].op, Opcode::JUMP)
    }

    fn has_revert_pattern(body: &BlockBody) -> bool {
        if body.instructions.len() < 4 {
            return false;
        }
        matches!(body.instructions[0].op, Opcode::JUMPDEST)
            && matches!(body.instructions[1].op, Opcode::PUSH(1))
            && body.instructions[1].imm.as_deref() == Some("00")
            && matches!(body.instructions[2].op, Opcode::PUSH(1))
            && body.instructions[2].imm.as_deref() == Some("00")
            && matches!(body.instructions[3].op, Opcode::REVERT)
    }

    #[tokio::test]
    async fn storage_gates_extends_runtime_bounds() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        cfg_ir.dispatcher_controller_pcs = Some(seed_mutating_controllers(&mut cfg_ir));

        let original_bounds = cfg_ir.runtime_bounds;

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "transform should apply");

        if let (Some((orig_start, orig_end)), Some((new_start, new_end))) =
            (original_bounds, cfg_ir.runtime_bounds)
        {
            assert_eq!(orig_start, new_start, "runtime start should not change");
            assert!(
                new_end >= orig_end,
                "runtime end should be extended or unchanged"
            );
        }
    }

    #[tokio::test]
    async fn storage_gates_setter_and_checker_are_different() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        let original_pcs = seed_mutating_controllers(&mut cfg_ir);
        let original_pc_a = original_pcs[&0xaaaaaaaa];
        let original_pc_b = original_pcs[&0xbbbbbbbb];
        cfg_ir.dispatcher_controller_pcs = Some(original_pcs);

        let mut rng = StdRng::seed_from_u64(42);
        let changed = StorageGates::new().apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "transform should apply");

        let updated_pcs = cfg_ir
            .dispatcher_controller_pcs
            .as_ref()
            .expect("dispatcher_controller_pcs should exist");

        let new_pc_a = updated_pcs[&0xaaaaaaaa];
        let new_pc_b = updated_pcs[&0xbbbbbbbb];

        // If both were redirected, they should point to different gate blocks
        if new_pc_a != original_pc_a && new_pc_b != original_pc_b {
            assert_ne!(
                new_pc_a, new_pc_b,
                "setter and checker should point to different gate blocks"
            );
        }

        // Verify one points to gate_set and one points to gate_check
        let mut set_pc = None;
        let mut check_pc = None;
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                if has_gate_set_pattern(body) {
                    set_pc = Some(body.start_pc);
                }
                if has_gate_check_pattern(body) {
                    check_pc = Some(body.start_pc);
                }
            }
        }

        let set_pc = set_pc.expect("gate_set block should exist");
        let check_pc = check_pc.expect("gate_check block should exist");

        // One controller should point to set, the other to check
        let a_is_setter = new_pc_a == set_pc;
        let b_is_setter = new_pc_b == set_pc;
        let a_is_checker = new_pc_a == check_pc;
        let b_is_checker = new_pc_b == check_pc;

        assert!(
            (a_is_setter && b_is_checker) || (b_is_setter && a_is_checker),
            "one controller should be setter, the other checker"
        );
    }
}
