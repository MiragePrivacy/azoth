use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng};
use tracing::debug;

/// Jump Address Transformer obfuscates JUMP/JUMPI targets by splitting addresses
/// into arithmetic operations that compute the original target at runtime.
///
/// Instead of: PUSH1 0x42 JUMPI
/// Produces:   PUSH1 0x20 PUSH1 0x22 ADD JUMPI
/// Where 0x20 + 0x22 = 0x42
#[derive(Default)]
pub struct JumpAddressTransformer;

impl JumpAddressTransformer {
    pub fn new() -> Self {
        Self
    }

    /// Finds PUSH + JUMP/JUMPI patterns and transforms them
    pub fn find_jump_patterns(&self, instructions: &[Instruction]) -> Vec<usize> {
        let mut patterns = Vec::new();

        for i in 0..instructions.len().saturating_sub(1) {
            if let (Some(push_instr), Some(jump_instr)) =
                (instructions.get(i), instructions.get(i + 1))
            {
                // Look for PUSH followed by JUMP or JUMPI
                if matches!(push_instr.op, Opcode::PUSH(_) | Opcode::PUSH0)
                    && matches!(jump_instr.op, Opcode::JUMP | Opcode::JUMPI)
                {
                    patterns.push(i);
                }
            }
        }

        patterns
    }

    /// Splits a jump target into two values that add up to the original
    pub fn split_jump_target(&self, target: u64, rng: &mut StdRng) -> (u64, u64) {
        // Generate a random value less than the target
        let split_point = if target > 1 {
            rng.random_range(1..target)
        } else {
            0
        };

        let part1 = split_point;
        let part2 = target - split_point;

        (part1, part2)
    }

    /// Formats a value as hex string with appropriate padding
    fn format_hex_value(&self, value: u64, bytes: usize) -> String {
        format!("{:0width$x}", value, width = bytes * 2)
    }
}

impl Transform for JumpAddressTransformer {
    fn name(&self) -> &'static str {
        "JumpAddressTransformer"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== JumpAddressTransformer Transform Start ===");

        let mut changed = false;
        let mut transformations = Vec::new();

        // Process each block to find and transform jump patterns
        for node_idx in ir.cfg.node_indices().collect::<Vec<_>>() {
            if let Block::Body(body) = &ir.cfg[node_idx] {
                let patterns = self.find_jump_patterns(&body.instructions);

                if !patterns.is_empty() {
                    debug!(
                        "Found {} jump patterns in block {} (node_idx={})",
                        patterns.len(),
                        node_idx.index(),
                        node_idx.index()
                    );
                    transformations.push((node_idx, patterns));
                }
            }
        }

        debug!("Total blocks with jump patterns: {}", transformations.len());

        // Use config to limit the number of transformations
        if !transformations.is_empty() {
            // Flatten all patterns with their block indices
            let mut all_patterns: Vec<(NodeIndex, usize)> = Vec::new(); // (node_idx, pattern_idx)
            for (node_idx, patterns) in &transformations {
                for &pattern_idx in patterns {
                    all_patterns.push((*node_idx, pattern_idx));
                }
            }

            // Shuffle to introduce some variability but keep all patterns
            all_patterns.shuffle(rng);
            debug!("Selected {} patterns to transform", all_patterns.len());

            // Rebuild transformations list with limited patterns
            let mut limited_transformations: Vec<(NodeIndex, Vec<usize>)> = Vec::new();
            for (node_idx, pattern_idx) in all_patterns {
                // Find or create entry for this node
                if let Some((_, patterns)) = limited_transformations
                    .iter_mut()
                    .find(|(index, _)| *index == node_idx)
                {
                    patterns.push(pattern_idx);
                } else {
                    limited_transformations.push((node_idx, vec![pattern_idx]));
                }
            }

            transformations = limited_transformations;
        }

        // Apply transformations (iterate in reverse to maintain indices)
        for (block_num, (node_idx, patterns)) in transformations.iter().enumerate() {
            debug!(
                "Transforming block {}/{} (node_idx={})",
                block_num + 1,
                transformations.len(),
                node_idx.index()
            );

            if let Block::Body(body) = &mut ir.cfg[*node_idx] {
                let instructions = &mut body.instructions;
                let max_stack = &mut body.max_stack;
                let start_pc = body.start_pc;
                debug!(
                    "  Block start_pc: {:#x}, {} instructions",
                    start_pc,
                    instructions.len()
                );

                // Process patterns in reverse order to maintain indices
                for (pat_num, &pattern_idx) in patterns.iter().rev().enumerate() {
                    debug!(
                        "  Processing pattern {}/{} at instruction index {}",
                        pat_num + 1,
                        patterns.len(),
                        pattern_idx
                    );
                    if let Some(push_instr) = instructions.get(pattern_idx) {
                        if let Some(target_hex) = &push_instr.imm {
                            // Parse the jump target
                            if let Ok(target) = u64::from_str_radix(target_hex, 16) {
                                let (part1, part2) = self.split_jump_target(target, rng);

                                // Calculate byte sizes for formatting
                                let part1_bytes = if part1 == 0 {
                                    1
                                } else {
                                    (64 - part1.leading_zeros()).div_ceil(8) as usize
                                };
                                let part2_bytes = if part2 == 0 {
                                    1
                                } else {
                                    (64 - part2.leading_zeros()).div_ceil(8) as usize
                                };

                                // Create new instruction sequence
                                let new_instructions = vec![
                                    Instruction {
                                        pc: push_instr.pc,
                                        op: Opcode::PUSH(part1_bytes as u8),
                                        imm: Some(self.format_hex_value(part1, part1_bytes)),
                                    },
                                    Instruction {
                                        pc: push_instr.pc + part1_bytes + 1,
                                        op: Opcode::PUSH(part2_bytes as u8),
                                        imm: Some(self.format_hex_value(part2, part2_bytes)),
                                    },
                                    Instruction {
                                        pc: push_instr.pc + part1_bytes + part2_bytes + 2,
                                        op: Opcode::ADD,
                                        imm: None,
                                    },
                                ];

                                // Replace the original PUSH instruction with the sequence
                                instructions.remove(pattern_idx);
                                for (offset, new_instr) in new_instructions.into_iter().enumerate()
                                {
                                    instructions.insert(pattern_idx + offset, new_instr);
                                }

                                // Update max_stack if needed (we temporarily use one extra stack slot)
                                *max_stack = (*max_stack).max(2);
                                changed = true;

                                debug!(
                                    "Transformed jump target 0x{:x} into 0x{:x} + 0x{:x}",
                                    target, part1, part2
                                );
                            }
                        }
                    }
                }
            }
        }

        if changed {
            let total_transformed = transformations
                .iter()
                .map(|(_, patterns)| patterns.len())
                .sum::<usize>();
            debug!(
                "Applied jump address transformation to {} patterns",
                total_transformed
            );
            debug!("Reindexing PCs...");
            ir.reindex_pcs()
                .map_err(|e| Error::CoreError(e.to_string()))?;
            debug!("=== JumpAddressTransformer Transform Complete ===");
        }

        Ok(changed)
    }
}
