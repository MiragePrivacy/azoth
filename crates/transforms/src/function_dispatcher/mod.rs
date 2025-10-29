//! Function dispatcher transform.

mod patterns;

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, DispatcherInfo};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;
use tracing::debug;

pub(super) const SELECTOR_TOKEN_LEN: usize = 4;
pub(super) const MAX_BYTE_TOKEN_SELECTORS: usize = 256;
pub(super) const MAX_PACKED_TOKEN_SELECTORS: usize = 16;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
enum DispatcherPattern {
    Packed,
    Byte,
}

#[derive(Default)]
pub struct FunctionDispatcher {
    cached_dispatcher: Option<DispatcherInfo>,
}

impl FunctionDispatcher {
    pub fn new() -> Self {
        Self {
            cached_dispatcher: None,
        }
    }

    pub fn with_dispatcher_info(dispatcher_info: DispatcherInfo) -> Self {
        Self {
            cached_dispatcher: Some(dispatcher_info),
        }
    }

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

    fn dispatcher_info(&self, runtime: &[Instruction]) -> Option<DispatcherInfo> {
        if let Some(info) = &self.cached_dispatcher {
            Some(info.clone())
        } else {
            detect_function_dispatcher(runtime)
        }
    }

    fn apply_instruction_replacements(
        &self,
        ir: &mut CfgIrBundle,
        edits: Vec<(NodeIndex, usize, Opcode, Option<String>)>,
    ) -> Result<bool> {
        let mut modified = false;

        for (node, pc, opcode, immediate) in edits {
            let changed = self.patch_block(ir, node, |body| {
                if let Some(instr) = body.instructions.iter_mut().find(|ins| ins.pc == pc) {
                    let immediate_matches = match (&immediate, &instr.imm) {
                        (Some(expected), Some(actual)) => actual == expected,
                        (None, None) => true,
                        _ => false,
                    };

                    if instr.op != opcode || !immediate_matches {
                        instr.op = opcode;
                        instr.imm = immediate.clone();
                        return true;
                    }
                }
                false
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

    fn apply_dispatcher_patches(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        info: &DispatcherInfo,
        mapping: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let mut edits = Vec::with_capacity(info.selectors.len());

        for selector in &info.selectors {
            let instruction = runtime.get(selector.instruction_index).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: selector index {} out of bounds",
                    selector.instruction_index
                ))
            })?;

            let (node, _) = match index_by_pc.get(&instruction.pc) {
                Some(pair) => *pair,
                None => {
                    return Err(Error::Generic(format!(
                        "dispatcher: instruction at pc {} not found in CFG",
                        instruction.pc
                    )))
                }
            };

            let token = mapping.get(&selector.selector).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: missing token for selector 0x{:08x}",
                    selector.selector
                ))
            })?;

            if token.is_empty() || token.len() > 32 {
                return Err(Error::Generic(format!(
                    "dispatcher: token for selector 0x{:08x} has invalid length {}",
                    selector.selector,
                    token.len()
                )));
            }

            edits.push((
                node,
                instruction.pc,
                Opcode::PUSH(token.len() as u8),
                Some(hex::encode(token)),
            ));
        }

        self.apply_instruction_replacements(ir, edits)
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

        let pattern_order = vec![DispatcherPattern::Packed];

        let mut selected_mapping: Option<HashMap<u32, Vec<u8>>> = None;
        let mut extraction_modified = false;
        let mut dispatcher_modified = false;
        let mut used_pattern: Option<&'static str> = None;

        for pattern in pattern_order {
            let result = match pattern {
                DispatcherPattern::Packed => self.try_apply_packed_pattern(
                    ir,
                    &runtime_instructions,
                    &index_by_pc,
                    &dispatcher_info,
                    rng,
                )?,
                DispatcherPattern::Byte => {
                    // Byte-selector pattern disabled while testing packed jump-table implementation.
                    continue;
                }
            };

            if let Some((mapping, extraction, dispatcher)) = result {
                selected_mapping = Some(mapping);
                extraction_modified = extraction;
                dispatcher_modified = dispatcher;
                used_pattern = Some(match pattern {
                    DispatcherPattern::Packed => "PackedJumpTable",
                    DispatcherPattern::Byte => "ByteSelector",
                });
                break;
            }
        }

        let Some(mapping) = selected_mapping else {
            debug!("No dispatcher pattern applied; skipping transform");
            return Ok(false);
        };

        let calls_modified = self.update_internal_calls(ir, &mapping)?;

        if extraction_modified || dispatcher_modified || calls_modified {
            ir.selector_mapping = Some(mapping);
            if let Some(pattern_name) = used_pattern {
                debug!("Function dispatcher obfuscated via {pattern_name}");
            }
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
