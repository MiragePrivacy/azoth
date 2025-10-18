//! Builder utilities for constructing obfuscation mappings from CFG state.
//!
//! This module provides helper functions to extract bytecode snapshots from
//! CFG-IR bundles and construct comprehensive transformation mappings.

use crate::mapping::*;
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use std::collections::HashMap;

/// Extracts a bytecode snapshot from the current CFG-IR state.
///
/// Analyzes the CFG to collect all blocks and instructions, computing
/// metrics and structural information for the snapshot.
///
/// # Arguments
/// * `cfg_ir` - The CFG-IR bundle to snapshot
///
/// # Returns
/// A complete bytecode snapshot representing the current state.
pub fn extract_snapshot(cfg_ir: &CfgIrBundle) -> BytecodeSnapshot {
    let mut blocks = Vec::new();
    let mut total_instructions = 0;
    let mut total_bytes = 0;

    // Collect all body blocks sorted by start PC
    let mut body_blocks: Vec<_> = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|idx| {
            if let Block::Body {
                logical_id,
                start_pc,
                instructions,
                ..
            } = &cfg_ir.cfg[idx]
            {
                Some((*logical_id, *start_pc, instructions.clone()))
            } else {
                None
            }
        })
        .collect();

    body_blocks.sort_by_key(|(_, start_pc, _)| *start_pc);

    for (logical_id, start_pc, instructions) in body_blocks {
        let instruction_count = instructions.len();
        let byte_size: usize = instructions.iter().map(|i| i.byte_size()).sum();
        let end_pc = start_pc + byte_size;

        let instruction_infos: Vec<InstructionInfo> = instructions
            .iter()
            .map(instruction_to_info)
            .collect();

        blocks.push(BlockInfo {
            block_id: logical_id,
            start_pc,
            end_pc,
            instruction_count,
            byte_size,
            instructions: instruction_infos,
        });

        total_instructions += instruction_count;
        total_bytes += byte_size;
    }

    BytecodeSnapshot {
        block_count: blocks.len(),
        instruction_count: total_instructions,
        byte_size: total_bytes,
        blocks,
    }
}

/// Converts an instruction to its serializable info representation.
///
/// # Arguments
/// * `instr` - The instruction to convert
///
/// # Returns
/// An `InstructionInfo` struct containing all instruction details.
fn instruction_to_info(instr: &Instruction) -> InstructionInfo {
    InstructionInfo {
        pc: instr.pc,
        opcode: format!("{}", instr.op),
        immediate: instr.imm.clone(),
        byte_size: instr.byte_size(),
    }
}

/// Computes the difference between two bytecode snapshots.
///
/// Analyzes before and after snapshots to identify blocks that were added,
/// removed, or modified during a transformation.
///
/// # Arguments
/// * `before` - Snapshot before transformation
/// * `after` - Snapshot after transformation
///
/// # Returns
/// A tuple containing:
/// - Vector of blocks added
/// - Vector of blocks removed
/// - Vector of block modifications
pub fn compute_snapshot_diff(
    before: &BytecodeSnapshot,
    after: &BytecodeSnapshot,
) -> (
    Vec<BlockInfo>,
    Vec<BlockInfo>,
    Vec<BlockModification>,
) {
    let mut blocks_added = Vec::new();
    let mut blocks_removed = Vec::new();
    let mut blocks_modified = Vec::new();

    // Create maps for efficient lookup
    let before_blocks: HashMap<usize, &BlockInfo> =
        before.blocks.iter().map(|b| (b.block_id, b)).collect();
    let after_blocks: HashMap<usize, &BlockInfo> =
        after.blocks.iter().map(|b| (b.block_id, b)).collect();

    // Find blocks that exist in after but not before (added)
    for block in &after.blocks {
        if !before_blocks.contains_key(&block.block_id) {
            blocks_added.push(block.clone());
        }
    }

    // Find blocks that exist in before but not after (removed)
    for block in &before.blocks {
        if !after_blocks.contains_key(&block.block_id) {
            blocks_removed.push(block.clone());
        }
    }

    // Find blocks that exist in both but may be modified
    for (block_id, before_block) in &before_blocks {
        if let Some(after_block) = after_blocks.get(block_id) {
            // Check if the block changed
            let instruction_delta =
                after_block.instruction_count as i32 - before_block.instruction_count as i32;
            let byte_delta = after_block.byte_size as i32 - before_block.byte_size as i32;
            let pc_changed = before_block.start_pc != after_block.start_pc;

            if instruction_delta != 0 || byte_delta != 0 || pc_changed {
                let instruction_changes =
                    compute_instruction_changes(&before_block.instructions, &after_block.instructions);

                blocks_modified.push(BlockModification {
                    block_id: *block_id,
                    old_start_pc: before_block.start_pc,
                    new_start_pc: after_block.start_pc,
                    instruction_delta,
                    byte_delta,
                    instruction_changes,
                });
            }
        }
    }

    (blocks_added, blocks_removed, blocks_modified)
}

/// Computes instruction-level changes within a block.
///
/// Compares two instruction sequences to identify insertions, deletions,
/// and modifications at the instruction level.
///
/// # Arguments
/// * `before` - Instructions before transformation
/// * `after` - Instructions after transformation
///
/// # Returns
/// A vector of instruction changes describing the differences.
fn compute_instruction_changes(
    before: &[InstructionInfo],
    after: &[InstructionInfo],
) -> Vec<InstructionChange> {
    let mut changes = Vec::new();

    // Simple diff: compare by PC and identify changes
    let before_map: HashMap<usize, &InstructionInfo> = before.iter().map(|i| (i.pc, i)).collect();
    let after_map: HashMap<usize, &InstructionInfo> = after.iter().map(|i| (i.pc, i)).collect();

    // Find removed instructions (in before but not after)
    for instr in before {
        if !after_map.contains_key(&instr.pc) {
            changes.push(InstructionChange {
                change_type: InstructionChangeType::Removed,
                before: Some(instr.clone()),
                after: None,
            });
        }
    }

    // Find added or modified instructions
    for instr in after {
        if let Some(before_instr) = before_map.get(&instr.pc) {
            // Instruction exists at same PC - check if modified
            if before_instr.opcode != instr.opcode {
                changes.push(InstructionChange {
                    change_type: InstructionChangeType::OpcodeModified,
                    before: Some((*before_instr).clone()),
                    after: Some(instr.clone()),
                });
            } else if before_instr.immediate != instr.immediate {
                changes.push(InstructionChange {
                    change_type: InstructionChangeType::ImmediateModified,
                    before: Some((*before_instr).clone()),
                    after: Some(instr.clone()),
                });
            }
        } else {
            // Instruction is new
            changes.push(InstructionChange {
                change_type: InstructionChangeType::Inserted,
                before: None,
                after: Some(instr.clone()),
            });
        }
    }

    changes
}

/// Creates a transform step from before/after CFG states and metadata.
///
/// This is the primary function for recording a transformation step in the
/// obfuscation pipeline. It captures complete state information and computes
/// all deltas and modifications.
///
/// # Arguments
/// * `transform_name` - Name of the transform
/// * `step_number` - Step number in the sequence
/// * `changed` - Whether the transform actually modified the bytecode
/// * `before_snapshot` - CFG state before the transform
/// * `after_snapshot` - CFG state after the transform
/// * `pc_mapping` - Program counter mapping from the transform
/// * `cfg_ir` - Current CFG-IR bundle (for extracting semantic changes)
///
/// # Returns
/// A complete `TransformStep` ready to add to the mapping.
pub fn create_transform_step(
    transform_name: String,
    step_number: usize,
    changed: bool,
    before_snapshot: BytecodeSnapshot,
    after_snapshot: BytecodeSnapshot,
    pc_mapping: HashMap<usize, usize>,
    cfg_ir: &CfgIrBundle,
) -> TransformStep {
    let (blocks_added, blocks_removed, blocks_modified) =
        compute_snapshot_diff(&before_snapshot, &after_snapshot);

    let statistics = TransformStatistics {
        blocks_before: before_snapshot.block_count,
        blocks_after: after_snapshot.block_count,
        blocks_delta: after_snapshot.block_count as i32 - before_snapshot.block_count as i32,
        instructions_before: before_snapshot.instruction_count,
        instructions_after: after_snapshot.instruction_count,
        instructions_delta: after_snapshot.instruction_count as i32
            - before_snapshot.instruction_count as i32,
        bytes_before: before_snapshot.byte_size,
        bytes_after: after_snapshot.byte_size,
        bytes_delta: after_snapshot.byte_size as i32 - before_snapshot.byte_size as i32,
    };

    let semantic_changes = extract_semantic_changes(&transform_name, cfg_ir, &pc_mapping);

    TransformStep {
        transform_name,
        step_number,
        changed,
        before: before_snapshot,
        after: after_snapshot,
        pc_mapping,
        blocks_added,
        blocks_removed,
        blocks_modified,
        semantic_changes,
        statistics,
    }
}

/// Extracts semantic changes specific to a transform type.
///
/// Different transforms produce different semantic changes (e.g., function
/// dispatcher creates selector mappings, opaque predicates don't).
///
/// # Arguments
/// * `transform_name` - Name of the transform
/// * `cfg_ir` - Current CFG-IR bundle
/// * `pc_mapping` - Program counter mapping
///
/// # Returns
/// Optional semantic changes if applicable to this transform.
fn extract_semantic_changes(
    transform_name: &str,
    cfg_ir: &CfgIrBundle,
    pc_mapping: &HashMap<usize, usize>,
) -> Option<SemanticChanges> {
    let mut has_changes = false;
    let mut selector_mapping = None;
    let mut jump_target_remapping = HashMap::new();
    let mut annotations = HashMap::new();

    // Extract function selector mapping for FunctionDispatcher transform
    if transform_name == "FunctionDispatcher" {
        if let Some(ref selectors) = cfg_ir.selector_mapping {
            let mapped: HashMap<String, Vec<u8>> = selectors
                .iter()
                .map(|(k, v)| (format!("{:08x}", k), v.clone()))
                .collect();
            selector_mapping = Some(mapped);
            has_changes = true;
        }

        // Add dispatcher block information to annotations
        if !cfg_ir.dispatcher_blocks.is_empty() {
            let block_ids: Vec<String> = cfg_ir
                .dispatcher_blocks
                .iter()
                .map(|id| id.to_string())
                .collect();
            annotations.insert(
                "dispatcher_blocks".to_string(),
                block_ids.join(","),
            );
            has_changes = true;
        }
    }

    // Extract jump target remappings from PC mapping
    // (only include entries where the target actually changed)
    for (&old_pc, &new_pc) in pc_mapping {
        if old_pc != new_pc {
            jump_target_remapping.insert(old_pc, new_pc);
            has_changes = true;
        }
    }

    if has_changes {
        Some(SemanticChanges {
            selector_mapping,
            jump_target_remapping,
            annotations,
        })
    } else {
        None
    }
}

/// Extracts all instructions from a CFG in sorted order by PC.
///
/// # Arguments
/// * `cfg_ir` - The CFG-IR bundle
///
/// # Returns
/// A vector of all instructions sorted by program counter.
pub fn extract_sorted_instructions(cfg_ir: &CfgIrBundle) -> Vec<Instruction> {
    let mut instructions = Vec::new();

    for node_idx in cfg_ir.cfg.node_indices() {
        if let Block::Body {
            instructions: block_instructions,
            ..
        } = &cfg_ir.cfg[node_idx]
        {
            instructions.extend(block_instructions.clone());
        }
    }

    instructions.sort_by_key(|i| i.pc);
    instructions
}
