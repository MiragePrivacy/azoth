//! Function dispatcher transform.

mod patterns;

use patterns::{ByteSelectorPattern, PatchPlan, MAX_SELECTOR_COUNT};

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, DispatcherInfo};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;
use tracing::debug;

#[derive(Default)]
pub struct FunctionDispatcher {
    cached_dispatcher: Option<DispatcherInfo>,
}

impl FunctionDispatcher {
    /// Creates an empty dispatcher transform without cached metadata.
    pub fn new() -> Self {
        Self {
            cached_dispatcher: None,
        }
    }

    /// Seeds the transform with a pre-detected dispatcher description.
    pub fn with_dispatcher_info(dispatcher_info: DispatcherInfo) -> Self {
        Self {
            cached_dispatcher: Some(dispatcher_info),
        }
    }

    /// Flattens runtime blocks into a linear instruction list plus CFG index map.
    fn collect_runtime_instructions(
        &self,
        ir: &CfgIrBundle,
    ) -> (Vec<Instruction>, HashMap<usize, (NodeIndex, usize)>) {
        let (runtime_start, runtime_end) = ir.runtime_bounds.unwrap_or((0, usize::MAX));

        let mut nodes: Vec<_> = ir.cfg.node_indices().collect();
        nodes.sort_by_key(|idx| match &ir.cfg[*idx] {
            Block::Body(body) => body.start_pc,
            _ => usize::MAX,
        });

        let mut runtime_instructions = Vec::new();
        let mut index_by_pc = HashMap::new();

        for node in nodes {
            if let Block::Body(body) = &ir.cfg[node] {
                for (offset, instruction) in body.instructions.iter().enumerate() {
                    if instruction.pc >= runtime_start && instruction.pc < runtime_end {
                        index_by_pc.insert(instruction.pc, (node, offset));
                        runtime_instructions.push(instruction.clone());
                    }
                }
            }
        }

        (runtime_instructions, index_by_pc)
    }

    /// Returns cached dispatcher metadata or detects it from the runtime slice.
    fn dispatcher_info(&self, runtime: &[Instruction]) -> Option<DispatcherInfo> {
        if let Some(info) = &self.cached_dispatcher {
            Some(info.clone())
        } else {
            detect_function_dispatcher(runtime)
        }
    }

    /// Applies a set of instruction-level edits returned by a dispatcher pattern.
    ///
    /// Each entry in the plan maps a block to the list of `(offset, opcode, immediate)`
    /// replacements that should be applied inside that block.
    /// Applies a set of instruction-level edits returned by a dispatcher pattern.
    ///
    /// Each entry in the plan maps a block to the list of `(offset, opcode, immediate)`
    /// replacements that should be applied inside that block.
    fn apply_instruction_patches(
        &self,
        ir: &mut CfgIrBundle,
        patch_plan: PatchPlan,
    ) -> Result<bool> {
        let mut modified = false;

        for (node, patches) in patch_plan {
            let changed = self.patch_block(ir, node, |body| {
                let mut changed = false;
                for (offset, opcode, immediate) in &patches {
                    if let Some(instr) = body.instructions.get_mut(*offset) {
                        let immediate_matches = match (&immediate, &instr.imm) {
                            (Some(expected), Some(actual)) => actual == expected,
                            (None, None) => true,
                            _ => false,
                        };

                        if instr.op != *opcode || !immediate_matches {
                            instr.op = *opcode;
                            instr.imm = immediate.clone();
                            changed = true;
                        }
                    }
                }
                changed
            })?;
            modified |= changed;
        }

        Ok(modified)
    }

    /// Syncs internal CALL sites with dispatcher tokens so remapped selectors still fire.
    fn update_internal_calls(
        &self,
        ir: &mut CfgIrBundle,
        mapping: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        let mut modified = false;

        for node in nodes {
            let original = match ir.cfg.node_weight(node) {
                Some(Block::Body(body)) => body.clone(),
                _ => continue,
            };

            let mut new_body = original.clone();
            let mut changed = false;

            for idx in 0..new_body.instructions.len().saturating_sub(1) {
                let Opcode::PUSH(_) = new_body.instructions[idx].op else {
                    continue;
                };

                if !matches!(
                    new_body.instructions[idx + 1].op,
                    Opcode::CALL | Opcode::DELEGATECALL | Opcode::STATICCALL
                ) {
                    continue;
                }

                let Some(ref immediate) = new_body.instructions[idx].imm else {
                    continue;
                };

                let Ok(selector) = u32::from_str_radix(immediate, 16) else {
                    continue;
                };

                let Some(token) = mapping.get(&selector) else {
                    continue;
                };

                let token_hex = hex::encode(token);
                if new_body.instructions[idx].imm.as_deref() != Some(token_hex.as_str()) {
                    let push_width = token.len() as u8;
                    new_body.instructions[idx].op = Opcode::PUSH(push_width);
                    new_body.instructions[idx].imm = Some(token_hex);
                    changed = true;
                }
            }

            if changed {
                ir.overwrite_block(node, new_body)
                    .map_err(|e| Error::CoreError(e.to_string()))?;
                modified = true;
            }
        }

        Ok(modified)
    }

    /// Overwrites a CFG block.
    fn patch_block<F>(&self, ir: &mut CfgIrBundle, node: NodeIndex, mut f: F) -> Result<bool>
    where
        F: FnMut(&mut BlockBody) -> bool,
    {
        let original = match ir.cfg.node_weight(node) {
            Some(Block::Body(body)) => body.clone(),
            _ => return Ok(false),
        };

        let mut new_body = original.clone();
        if f(&mut new_body) {
            ir.overwrite_block(node, new_body)
                .map_err(|e| Error::CoreError(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Transform for FunctionDispatcher {
    fn name(&self) -> &'static str {
        "FunctionDispatcher"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        let (runtime_instructions, index_by_pc) = self.collect_runtime_instructions(ir);
        if runtime_instructions.is_empty() {
            debug!("No runtime instructions available; skipping dispatcher transform");
            return Ok(false);
        }

        let dispatcher_info = match self.dispatcher_info(&runtime_instructions) {
            Some(info) => info,
            None => {
                debug!("Dispatcher not detected; skipping transform");
                return Ok(false);
            }
        };

        if dispatcher_info.selectors.is_empty() {
            debug!("Dispatcher detection produced no selectors; skipping transform");
            return Ok(false);
        }

        if dispatcher_info.selectors.len() > MAX_SELECTOR_COUNT {
            debug!(
                "Dispatcher has {} selectors; skipping byte-selector pattern",
                dispatcher_info.selectors.len()
            );
            return Ok(false);
        }

        let extraction_plan = ByteSelectorPattern::plan_extraction_patches(
            &runtime_instructions,
            &index_by_pc,
            &dispatcher_info,
        )?;
        let extraction_modified = self.apply_instruction_patches(ir, extraction_plan)?;

        let mapping = ByteSelectorPattern::generate_mapping(&dispatcher_info.selectors, rng)?;
        debug!("Remapping {} selectors", mapping.len());

        let dispatcher_plan = ByteSelectorPattern::plan_dispatcher_patches(
            &runtime_instructions,
            &index_by_pc,
            &dispatcher_info,
            &mapping,
        )?;
        let dispatcher_modified = self.apply_instruction_patches(ir, dispatcher_plan)?;

        let calls_modified = self.update_internal_calls(ir, &mapping)?;

        if extraction_modified || dispatcher_modified || calls_modified {
            ir.selector_mapping = Some(mapping);
            debug!("Function dispatcher obfuscation applied successfully");
            Ok(true)
        } else {
            debug!("Dispatcher mapping produced no changes");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionDispatcher;
    use crate::Transform;
    use azoth_core::process_bytecode_to_cfg;
    use hex::encode as hex_encode;
    use rand::{rngs::StdRng, SeedableRng};

    static COUNTER_DEPLOYMENT: &str =
        include_str!("../../../../tests/bytecode/counter/counter_deployment.hex");

    #[tokio::test]
    async fn prints_obfuscated_runtime_dispatcher() {
        let (mut bundle, _, _, _) = process_bytecode_to_cfg(COUNTER_DEPLOYMENT, false)
            .await
            .expect("cfg construction");
        let mut rng = StdRng::seed_from_u64(0xdead_beef_cafe_babe);

        let transform = FunctionDispatcher::new();
        let changed = transform
            .apply(&mut bundle, &mut rng)
            .expect("dispatcher transform succeeds");
        assert!(changed, "transform should mutate dispatcher");

        let runtime_bounds = bundle.runtime_bounds().expect("runtime bounds");

        let mut runtime_instrs = Vec::new();
        for node in bundle.cfg.node_indices() {
            if let Some(block) = bundle.cfg.node_weight(node) {
                if let azoth_core::cfg_ir::Block::Body(body) = block {
                    if body.start_pc >= runtime_bounds.0 && body.start_pc < runtime_bounds.1 {
                        for instr in &body.instructions {
                            if instr.pc >= runtime_bounds.0 && instr.pc < runtime_bounds.1 {
                                runtime_instrs.push(instr.clone());
                            }
                        }
                    }
                }
            }
        }

        runtime_instrs.sort_by_key(|ins| ins.pc);

        println!("\n=== Obfuscated dispatcher runtime slice ===");
        for instr in runtime_instrs.iter() {
            let imm = instr.imm.as_deref().unwrap_or("");
            println!("{:04x}: {:<8} {}", instr.pc, instr.op, imm);
        }

        let mapping = bundle
            .selector_mapping
            .as_ref()
            .expect("selector mapping should be populated");

        println!("\nSelector mapping:");
        for (selector, token) in mapping {
            println!("  0x{selector:08x} -> {}", hex_encode(token));
        }
    }
}
