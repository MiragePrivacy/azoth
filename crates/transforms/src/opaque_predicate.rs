use crate::{Error, Result};
use crate::{PassConfig, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rand::prelude::SliceRandom;
use rand::{rngs::StdRng, Rng};
use sha3::{Digest, Keccak256};
use tracing::debug;

/// Injects opaque predicates to increase control flow complexity and potency.
pub struct OpaquePredicate {
    config: PassConfig,
}

impl OpaquePredicate {
    pub fn new(config: PassConfig) -> Self {
        Self { config }
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
        let max_opaque = self.config.max_opaque_ratio;
        let mut eligible_blocks: Vec<NodeIndex> = ir
            .cfg
            .node_indices()
            .filter(|&n| {
                if let Block::Body { instructions, .. } = &ir.cfg[n] {
                    instructions
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

        let max_predicates = ((eligible_blocks.len() as f32) * max_opaque).ceil() as usize;
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

            let true_label = ir.cfg.add_node(Block::Body {
                start_pc: true_start_pc,
                instructions: vec![Instruction {
                    pc: true_start_pc,
                    op: Opcode::JUMPDEST,
                    imm: None,
                }],
                max_stack: 0,
            });

            let false_label = ir.cfg.add_node(Block::Body {
                start_pc: false_start_pc,
                instructions: vec![
                    Instruction {
                        pc: false_start_pc,
                        op: Opcode::JUMPDEST,
                        imm: None,
                    },
                    Instruction {
                        pc: false_start_pc + 1,
                        op: Opcode::PUSH(1),
                        imm: Some("00".to_string()),
                    },
                    Instruction {
                        pc: false_start_pc + 2,
                        op: Opcode::JUMP,
                        imm: Some(
                            original_fallthrough
                                .map(|n| {
                                    if let Block::Body { start_pc, .. } = &ir.cfg[n] {
                                        format!("{start_pc:x}")
                                    } else {
                                        "0".to_string()
                                    }
                                })
                                .unwrap_or("0".to_string()),
                        ),
                    },
                ],
                max_stack: 1,
            });

            if let Block::Body {
                instructions,
                start_pc,
                ..
            } = &mut ir.cfg[*block_id]
            {
                debug!(
                    "  Block start_pc: {:#x}, {} instructions",
                    start_pc,
                    instructions.len()
                );
                let seed = rng.random::<u64>();
                let constant = self.generate_constant(seed);
                let constant_hex = hex::encode(constant);
                instructions.extend(vec![
                    Instruction {
                        pc: 0,
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
                        op: Opcode::PUSH(2),
                        imm: Some(format!("{true_start_pc:x}")),
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::JUMPI,
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::JUMPDEST,
                        imm: None,
                    },
                    Instruction {
                        pc: 0,
                        op: Opcode::JUMP,
                        imm: Some(format!("{false_start_pc:x}")),
                    },
                ]);
            }

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
            }

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
