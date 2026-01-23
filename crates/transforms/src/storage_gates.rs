//! Context-dependent storage gates.
//!
//! This transform makes selected call paths depend on storage mutations:
//! dispatcher/controllers set a slot, later controllers verify it before
//! routing, forcing stateful execution order.
//!
//! ## Auto-Generated Policy
//!
//! The transform auto-generates a `GatePolicy` by randomly splitting the selectors
//! from `dispatcher_controller_pcs` into setters (must be called first) and checkers
//! (require setters to be called first). This avoids the need to trace through
//! obfuscated dispatcher chains to detect state-mutating functions.
//!
//! ## Gate Injection at Controller Level
//!
//! Gates are injected at the controller block level, before the controller jumps
//! into the stub/decoy chain. This avoids the need to trace through the obfuscated
//! control flow to find the actual function body.
//!
//! Assembly example:
//! ```assembly
//! // Controller for setter selector (sets gate before jumping to stub)
//! JUMPDEST
//! PUSH1  0x01
//! PUSH32 gate_slot
//! SSTORE           // mark slot
//! PUSH2  stub_pc   // original controller code continues
//! JUMP
//!
//! // Controller for checker selector (checks gate before jumping to stub)
//! JUMPDEST
//! PUSH32 gate_slot
//! SLOAD
//! ISZERO
//! PUSH2 revert_pc  // if unset, revert
//! JUMPI
//! PUSH2  stub_pc   // original controller code continues
//! JUMP
//! ```

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::RngCore;
use tracing::debug;

/// Policy defining which selectors are setters and which are checkers.
///
/// Setters must be called before checkers. When a checker is called without
/// a prior setter call, the transaction reverts.
#[derive(Debug, Clone, Default)]
pub struct GatePolicy {
    /// Selectors that set the gate (must be called first).
    pub setters: Vec<u32>,
    /// Selectors that check the gate (require setters to be called first).
    pub checkers: Vec<u32>,
}

impl GatePolicy {
    /// Creates a new gate policy with the specified setters and checkers.
    pub fn new(setters: Vec<u32>, checkers: Vec<u32>) -> Self {
        Self { setters, checkers }
    }
}

/// Storage mutation + gate insertion.
///
/// Auto-generates a `GatePolicy` by randomly splitting selectors from
/// `dispatcher_controller_pcs` into setters and checkers. This avoids
/// unreliable traversal-based detection that fails after FunctionDispatcher
/// obfuscation.
#[derive(Default)]
pub struct StorageGates;

impl StorageGates {
    const JUMP_WIDTH: u8 = 4;

    /// Creates a new StorageGates transform.
    pub fn new() -> Self {
        Self
    }

    /// Auto-generates a gate policy by randomly picking one setter and one checker.
    ///
    /// Only picks ONE setter and ONE checker to minimize impact on contract behavior.
    /// Other selectors remain ungated.
    fn generate_policy(selectors: &[u32], rng: &mut StdRng) -> GatePolicy {
        use rand::seq::SliceRandom;

        let mut selectors: Vec<u32> = selectors.to_vec();
        selectors.shuffle(rng);

        // Pick only ONE setter and ONE checker to minimize breakage
        if selectors.len() >= 2 {
            let setters = vec![selectors[0]];
            let checkers = vec![selectors[1]];
            GatePolicy::new(setters, checkers)
        } else {
            GatePolicy::default()
        }
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

        // Build controller lookup: selector -> (pc, node)
        let mut controllers = Vec::new();
        for (selector, pc) in &controller_pcs {
            if let Some(node) = ir.pc_to_block.get(pc).copied() {
                controllers.push((*selector, *pc, node));
            }
        }

        if controllers.len() < 2 {
            debug!(
                "StorageGates: need at least 2 controllers, found {}",
                controllers.len()
            );
            return Ok(false);
        }

        // Auto-generate policy by randomly splitting selectors
        let selectors: Vec<u32> = controller_pcs.keys().copied().collect();
        let policy = Self::generate_policy(&selectors, rng);

        if policy.setters.is_empty() || policy.checkers.is_empty() {
            debug!("StorageGates: generated policy has empty setters or checkers; skipping");
            return Ok(false);
        }

        debug!(
            "StorageGates: auto-generated policy with {} setters, {} checkers",
            policy.setters.len(),
            policy.checkers.len()
        );

        // Find first valid setter from policy
        let setter = policy.setters.iter().find_map(|sel| {
            controller_pcs
                .get(sel)
                .and_then(|pc| ir.pc_to_block.get(pc).map(|node| (*sel, *node)))
        });

        // Find first valid checker from policy
        let checker = policy.checkers.iter().find_map(|sel| {
            controller_pcs
                .get(sel)
                .and_then(|pc| ir.pc_to_block.get(pc).map(|node| (*sel, *node)))
        });

        let (setter_selector, setter_node, checker_selector, checker_node) = match (setter, checker)
        {
            (Some((set_sel, set_node)), Some((chk_sel, chk_node))) => {
                debug!(
                    "StorageGates: setter=0x{:08x}, checker=0x{:08x}",
                    set_sel, chk_sel
                );
                (set_sel, set_node, chk_sel, chk_node)
            }
            _ => {
                debug!("StorageGates: selectors not found in controller map; skipping");
                return Ok(false);
            }
        };

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
