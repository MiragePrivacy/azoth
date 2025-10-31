use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockControl, CfgIrBundle, JumpEncoding, JumpTarget};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::Rng;
use tracing::debug;

/// Obfuscates direct `PUSH <target>; JUMP/JUMPI` patterns by rewriting them to a
/// XOR sequence (`PUSH mask; PUSH (target ^ mask); XOR; JUMP/JUMPI`) so the jump
/// target is computed at runtime.
#[derive(Default)]
pub struct JumpAddressTransformer;

/// Metadata for a pending XOR transformation that needs to be updated after reindex_pcs
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingXor {
    node: NodeIndex,
    target_node: Option<NodeIndex>,
    mask_idx: usize,
    masked_idx: usize,
    mask: usize,
    target_encoding: JumpEncoding,
    raw_target: usize,
}

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

    /// Generate a random XOR mask for obfuscation
    fn generate_mask(&self, rng: &mut StdRng, width: usize) -> usize {
        let max = Self::capacity_for_width(width);
        if max == usize::MAX || width >= 4 {
            // Use 32-bit mask for larger widths
            rng.random::<u32>() as usize
        } else {
            // For smaller widths, generate within capacity
            rng.random_range(1..=max.max(1))
        }
    }

    fn transform_block(
        &self,
        ir: &mut CfgIrBundle,
        node_idx: NodeIndex,
        rng: &mut StdRng,
    ) -> Result<(bool, Vec<PendingXor>)> {
        let original_body = match ir.cfg.node_weight(node_idx) {
            Some(Block::Body(body)) => body.clone(),
            _ => return Ok((false, Vec::new())),
        };

        // Only transform blocks in the runtime section, not init code
        if !original_body.is_runtime(ir.runtime_bounds) {
            debug!(
                "Skipping block at pc 0x{:x} (not in runtime section), runtime_bounds={:?}",
                original_body.start_pc, ir.runtime_bounds
            );
            return Ok((false, Vec::new()));
        }

        debug!(
            "Transforming block at pc 0x{:x} (in runtime section), runtime_bounds={:?}",
            original_body.start_pc, ir.runtime_bounds
        );

        // Extract encoding, target node, and raw target from BlockControl for later metadata
        let (target_encoding, target_node, raw_target) = match &original_body.control {
            BlockControl::Jump { target }
            | BlockControl::Branch {
                true_target: target,
                ..
            } => match target {
                JumpTarget::Block { node, encoding } => (*encoding, Some(*node), None),
                JumpTarget::Raw { value, encoding } => (*encoding, None, Some(*value)),
            },
            _ => (JumpEncoding::Absolute, None, None),
        };

        let mut new_instructions = Vec::with_capacity(original_body.instructions.len());
        let mut pending_xors = Vec::new();
        let mut changed = false;
        let mut idx = 0usize;

        while idx < original_body.instructions.len() {
            let instr = &original_body.instructions[idx];

            if idx + 1 < original_body.instructions.len() {
                let jump_instr = &original_body.instructions[idx + 1];
                if matches!(instr.op, Opcode::PUSH(_) | Opcode::PUSH0)
                    && matches!(jump_instr.op, Opcode::JUMP | Opcode::JUMPI)
                    && instr.imm.is_some()
                {
                    let target =
                        usize::from_str_radix(instr.imm.as_deref().unwrap(), 16).map_err(|_| {
                            Error::InvalidImmediate("failed to parse jump immediate".into())
                        })?;

                    // Log what we're about to transform
                    let jump_type = match jump_instr.op {
                        Opcode::JUMP => "JUMP (unconditional)",
                        Opcode::JUMPI => "JUMPI (conditional)",
                        _ => "unknown",
                    };
                    let control_type = match &original_body.control {
                        BlockControl::Terminal => "Terminal",
                        BlockControl::Jump { .. } => "Jump",
                        BlockControl::Branch { .. } => "Branch",
                        BlockControl::Fallthrough => "Fallthrough",
                        BlockControl::Unknown => "Unknown",
                    };

                    debug!(
                        "🔄 TRANSFORMING: block_pc=0x{:x}, instr_pc=0x{:x} -> target=0x{:x}, jump_type={}, control={}, has_target_node={}",
                        original_body.start_pc,
                        instr.pc,
                        target,
                        jump_type,
                        control_type,
                        target_node.is_some()
                    );

                    // Generate random mask and compute masked value
                    let mask = self.generate_mask(rng, 4);
                    let masked_value = target ^ mask;

                    debug!(
                        "  XOR details: mask=0x{:x}, masked=0x{:x}",
                        mask, masked_value
                    );

                    // Use PUSH4 which can fit addresses up to 0xFFFFFFFF (16MB)
                    let mask_idx = new_instructions.len();
                    let push_mask = Instruction {
                        pc: instr.pc,
                        op: Opcode::PUSH(4),
                        imm: Some(Self::format_immediate(mask, 4)?),
                    };

                    let masked_idx = new_instructions.len() + 1;
                    let push_masked = Instruction {
                        pc: instr.pc,
                        op: Opcode::PUSH(4),
                        imm: Some(Self::format_immediate(masked_value, 4)?),
                    };

                    let xor = Instruction {
                        pc: instr.pc,
                        op: Opcode::XOR,
                        imm: None,
                    };

                    new_instructions.push(push_mask);
                    new_instructions.push(push_masked);
                    new_instructions.push(xor);
                    new_instructions.push(jump_instr.clone());

                    // Record metadata for post-reindex recalculation
                    pending_xors.push(PendingXor {
                        node: node_idx,
                        target_node,
                        mask_idx,
                        masked_idx,
                        mask,
                        target_encoding,
                        raw_target: raw_target.unwrap_or(target),
                    });

                    changed = true;
                    idx += 2;
                    continue;
                }
            }

            new_instructions.push(instr.clone());
            idx += 1;
        }

        if !changed {
            return Ok((false, Vec::new()));
        }

        let mut new_body = match ir.cfg.node_weight(node_idx) {
            Some(Block::Body(body)) => body.clone(),
            _ => return Ok((false, Vec::new())),
        };

        new_body.instructions = new_instructions;
        new_body.max_stack = new_body.max_stack.max(2);

        ir.overwrite_block(node_idx, new_body)
            .map_err(|e| Error::CoreError(e.to_string()))?;

        Ok((true, pending_xors))
    }
}

impl Transform for JumpAddressTransformer {
    fn name(&self) -> &'static str {
        "JumpAddressTransformer"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== JumpAddressTransformer Transform Start ===");

        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        let mut all_pending_xors = Vec::new();
        let mut modified = false;

        // Step 1 & 2: Transform blocks and collect metadata
        for node in nodes {
            let (changed, mut pending_xors) = self.transform_block(ir, node, rng)?;
            if changed {
                modified = true;
                all_pending_xors.append(&mut pending_xors);
            }
        }

        debug!(
            "JumpAddressTransformer created {} XOR patterns, NOT calling reindex_pcs (letting obfuscator handle it)",
            all_pending_xors.len()
        );

        Ok(modified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::{BlockBody, BlockControl, EdgeType, JumpEncoding, JumpTarget};
    use azoth_core::detection::{Section, SectionKind};
    use azoth_core::strip::CleanReport;
    use rand::SeedableRng;
    use std::collections::HashMap;

    fn instruction(op: Opcode, pc: usize, imm: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: imm.map(|s| s.to_string()),
        }
    }

    fn empty_clean_report() -> CleanReport {
        CleanReport {
            runtime_layout: Vec::new(),
            removed: Vec::new(),
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: 0,
            clean_keccak: Default::default(),
            program_counter_mapping: Vec::new(),
        }
    }

    #[test]
    fn rewrites_direct_jump_into_xor_sequence() {
        let mut cfg = petgraph::stable_graph::StableDiGraph::new();
        let entry = cfg.add_node(Block::Entry);
        let exit = cfg.add_node(Block::Exit);

        let dest_body = BlockBody {
            start_pc: 0x150,
            instructions: vec![
                instruction(Opcode::JUMPDEST, 0x150, None),
                instruction(Opcode::STOP, 0x151, None),
            ],
            max_stack: 0,
            control: BlockControl::Terminal,
        };
        let dest_node = cfg.add_node(Block::Body(dest_body));

        let source_body = BlockBody {
            start_pc: 0x100,
            instructions: vec![
                instruction(Opcode::PUSH(2), 0x100, Some("0150")),
                instruction(Opcode::JUMPI, 0x103, None),
            ],
            max_stack: 1,
            control: BlockControl::Branch {
                true_target: JumpTarget::Block {
                    node: dest_node,
                    encoding: JumpEncoding::Absolute,
                },
                false_target: JumpTarget::Raw {
                    value: 0,
                    encoding: JumpEncoding::Absolute,
                },
            },
        };
        let source_node = cfg.add_node(Block::Body(source_body));

        cfg.add_edge(entry, source_node, EdgeType::Fallthrough);
        cfg.add_edge(source_node, dest_node, EdgeType::BranchTrue);
        cfg.add_edge(dest_node, exit, EdgeType::Fallthrough);

        let mut pc_to_block = HashMap::new();
        pc_to_block.insert(0x100, source_node);
        pc_to_block.insert(0x150, dest_node);

        let sections = vec![Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 0x200,
        }];

        let mut bundle = CfgIrBundle {
            cfg,
            pc_to_block,
            clean_report: empty_clean_report(),
            sections,
            selector_mapping: None,
            original_bytecode: vec![0u8; 0x300],
            runtime_bounds: Some((0, 0x200)),
            trace: Vec::new(),
        };

        let mut rng = StdRng::seed_from_u64(42);
        let transformer = JumpAddressTransformer::new();
        let changed = transformer
            .apply(&mut bundle, &mut rng)
            .expect("transform should succeed");
        assert!(changed, "transform must report modifications");

        let source_body = match bundle.cfg.node_weight(source_node) {
            Some(Block::Body(body)) => body,
            _ => panic!("source node should remain a body"),
        };
        assert_eq!(
            source_body.instructions.len(),
            4,
            "direct jump should expand to PUSH mask; PUSH masked; XOR; JUMPI"
        );
        assert!(
            matches!(source_body.instructions[0].op, Opcode::PUSH(_)),
            "first instruction should push the XOR mask"
        );
        assert!(
            matches!(source_body.instructions[1].op, Opcode::PUSH(_)),
            "second instruction should push the masked value"
        );
        assert_eq!(
            source_body.instructions[2].op,
            Opcode::XOR,
            "third instruction should XOR to recover the target"
        );
        assert_eq!(
            source_body.instructions[3].op,
            Opcode::JUMPI,
            "terminator should remain the conditional jump"
        );

        let mask = usize::from_str_radix(
            source_body.instructions[0]
                .imm
                .as_ref()
                .expect("missing mask immediate"),
            16,
        )
        .expect("parse mask");
        let masked_value = usize::from_str_radix(
            source_body.instructions[1]
                .imm
                .as_ref()
                .expect("missing masked immediate"),
            16,
        )
        .expect("parse masked value");

        let dest_body = match bundle.cfg.node_weight(dest_node) {
            Some(Block::Body(body)) => body,
            _ => panic!("destination node missing"),
        };

        assert_eq!(
            mask ^ masked_value,
            dest_body.start_pc,
            "XOR operation should reconstruct destination PC"
        );
    }
}
