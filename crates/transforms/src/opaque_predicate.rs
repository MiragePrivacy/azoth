use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle, EdgeType};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rand::prelude::SliceRandom;
use rand::{rngs::StdRng, Rng};
use sha3::{Digest, Keccak256};
use tracing::debug;

/// Injects opaque predicates to increase control flow complexity and potency.
#[derive(Default)]
pub struct OpaquePredicate;

impl OpaquePredicate {
    const MAX_RATIO: f32 = 0.2;

    pub fn new() -> Self {
        Self
    }

    fn generate_constant(&self, seed: u64) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(seed.to_le_bytes());
        hasher.finalize().into()
    }

    fn is_non_terminal(&self, instruction: &Instruction) -> bool {
        !Opcode::is_control_flow(&instruction.op)
    }
}

impl Transform for OpaquePredicate {
    fn name(&self) -> &'static str {
        "OpaquePredicate"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== OpaquePredicate Transform Start ===");

        let mut changed = false;
        let mut eligible_blocks: Vec<NodeIndex> = ir
            .cfg
            .node_indices()
            .filter(|&n| {
                if let Block::Body(body) = &ir.cfg[n] {
                    body.instructions
                        .last()
                        .is_some_and(|instruction| self.is_non_terminal(instruction))
                } else {
                    false
                }
            })
            .collect();

        debug!(
            "Found {} eligible blocks for opaque predicates",
            eligible_blocks.len()
        );

        let max_predicates = ((eligible_blocks.len() as f32) * Self::MAX_RATIO).ceil() as usize;
        if max_predicates == 0 || eligible_blocks.is_empty() {
            debug!("No eligible blocks - skipping");
            return Ok(false);
        }
        let predicate_count = rng.random_range(1..=max_predicates.min(eligible_blocks.len()));
        debug!("Will insert {} opaque predicates", predicate_count);

        eligible_blocks.shuffle(rng);
        let selected: Vec<NodeIndex> = eligible_blocks.into_iter().take(predicate_count).collect();

        for (index, block_id) in selected.iter().enumerate() {
            debug!(
                "Processing block {}/{} (node_idx={})",
                index + 1,
                selected.len(),
                block_id.index()
            );

            let original_fallthrough = ir
                .cfg
                .edges_directed(*block_id, petgraph::Outgoing)
                .find(|e| *e.weight() == EdgeType::Fallthrough)
                .map(|e| e.target());

            debug!(
                "  Original fallthrough: {:?}",
                original_fallthrough.map(|n| n.index())
            );

            let true_start_pc = ir.pc_to_block.keys().max().map_or(0, |&pc| pc + 1);
            let false_start_pc = true_start_pc + 1;

            debug!(
                "  Creating predicate branches at PCs: true={:#x}, false={:#x}",
                true_start_pc, false_start_pc
            );

            let true_label = ir.cfg.add_node(Block::Body(BlockBody {
                start_pc: true_start_pc,
                instructions: vec![Instruction {
                    pc: true_start_pc,
                    op: Opcode::JUMPDEST,
                    imm: None,
                }],
                max_stack: 0,
                control: BlockControl::Unknown,
            }));
            ir.pc_to_block.insert(true_start_pc, true_label);

            let false_label = ir.cfg.add_node(Block::Body(BlockBody {
                start_pc: false_start_pc,
                instructions: vec![
                    Instruction {
                        pc: 0, // Will be reassigned by reindex_pcs
                        op: Opcode::JUMPDEST,
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::PUSH(32), // Use PUSH32 for maximum capacity
                        imm: Some("00".repeat(32)), // Placeholder
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::JUMP,
                        imm: None, // No immediate - will be set by symbolic target
                    },
                ],
                max_stack: 1,
                control: BlockControl::Unknown, // Will be set below
            }));
            ir.pc_to_block.insert(false_start_pc, false_label);

            // Prepare the new body with opaque predicate instructions
            let mut new_body = if let Block::Body(body) = &ir.cfg[*block_id] {
                let mut body_copy = body.clone();
                let seed = rng.random::<u64>();
                let constant = self.generate_constant(seed);
                let constant_hex = hex::encode(constant);

                debug!(
                    "  Block start_pc: {:#x}, {} instructions",
                    body_copy.start_pc,
                    body_copy.instructions.len()
                );

                body_copy.instructions.extend(vec![
                    Instruction {
                        pc: 0, // Will be reassigned by reindex_pcs
                        op: Opcode::PUSH(32),
                        imm: Some(constant_hex.clone()),
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::PUSH(32),
                        imm: Some(constant_hex),
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::EQ,
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::PUSH(32), // Use PUSH32 for maximum capacity
                        imm: Some("00".repeat(32)), // Placeholder
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::JUMPI,
                        imm: None,
                    },
                ]);
                body_copy.max_stack = body_copy.max_stack.max(4);
                body_copy
            } else {
                continue;
            };

            if let Some(target) = original_fallthrough {
                let edge = ir.cfg.find_edge(*block_id, target).unwrap();
                ir.cfg.remove_edge(edge);
                debug!("  Removed original fallthrough edge");
            }
            ir.cfg.add_edge(*block_id, true_label, EdgeType::BranchTrue);
            ir.cfg
                .add_edge(*block_id, false_label, EdgeType::BranchFalse);
            debug!("  Added branch edges to true and false labels");

            if let Some(target) = original_fallthrough {
                ir.cfg.add_edge(false_label, target, EdgeType::Jump);
                ir.cfg.add_edge(true_label, target, EdgeType::Fallthrough);
                debug!("  Connected branches back to original fallthrough");

                // Determine encoding based on runtime bounds
                let source_in_runtime = match (ir.runtime_bounds, ir.cfg.node_weight(*block_id)) {
                    (Some((start, end)), Some(Block::Body(body))) => {
                        body.start_pc >= start && body.start_pc < end
                    }
                    _ => false,
                };
                let encoding = if source_in_runtime {
                    azoth_core::cfg_ir::JumpEncoding::RuntimeRelative
                } else {
                    azoth_core::cfg_ir::JumpEncoding::Absolute
                };

                // Set the BlockControl for the false label to jump symbolically
                if let Some(Block::Body(body)) = ir.cfg.node_weight_mut(false_label) {
                    body.control = BlockControl::Jump {
                        target: azoth_core::cfg_ir::JumpTarget::Block {
                            node: target,
                            encoding,
                        },
                    };
                }

                // Set the BlockControl for the original block - it ends with JUMPI
                new_body.control = BlockControl::Branch {
                    true_target: azoth_core::cfg_ir::JumpTarget::Block {
                        node: true_label,
                        encoding,
                    },
                    false_target: azoth_core::cfg_ir::JumpTarget::Block {
                        node: false_label,
                        encoding,
                    },
                };
            }

            // Update the original block with the new body
            ir.overwrite_block(*block_id, new_body)
                .map_err(|e| crate::Error::CoreError(e.to_string()))?;

            changed = true;
            debug!("  ✓ Opaque predicate inserted successfully");
        }

        if changed {
            debug!("Inserted {} opaque predicates", predicate_count);
            debug!("Reindexing PCs...");
            let _ = ir
                .reindex_pcs()
                .map_err(|e| Error::CoreError(e.to_string()))?;
            debug!("=== OpaquePredicate Transform Complete ===");
        }
        Ok(changed)
    }
}
