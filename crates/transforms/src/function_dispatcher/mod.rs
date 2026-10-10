//! Function dispatcher transform.

mod patterns;
pub(crate) mod token;

use crate::function_dispatcher::token::generate_selector_token_mapping;
use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, DispatcherInfo};
use azoth_core::seed::Seed;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DispatcherStyle {
    /// Replace selector literals without adding new control-flow or storage dependencies.
    #[default]
    SelectorOnly,
    /// Retain the legacy multi-tier controller layout for explicit experimentation only.
    ExperimentalMultiTier,
}

#[derive(Default)]
pub struct FunctionDispatcher {
    cached_dispatcher: Option<DispatcherInfo>,
    seed: Option<Seed>,
    style: DispatcherStyle,
}

impl FunctionDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs the legacy multi-tier dispatcher transform.
    ///
    /// This mode adds controller, decoy, and storage-dependent blocks and is intentionally
    /// excluded from the default path. It is retained only for explicit experimentation.
    pub fn experimental_multi_tier() -> Self {
        Self {
            style: DispatcherStyle::ExperimentalMultiTier,
            ..Self::default()
        }
    }

    pub fn with_dispatcher_info_and_seed(dispatcher_info: DispatcherInfo, seed: Seed) -> Self {
        Self {
            cached_dispatcher: Some(dispatcher_info),
            seed: Some(seed),
            ..Self::default()
        }
    }

    /// Constructs the legacy multi-tier dispatcher transform with precomputed detection data.
    ///
    /// Unlike [`Self::with_dispatcher_info_and_seed`], this opts into controller, decoy, and
    /// storage-dependent blocks and should be used only for experiments.
    pub fn experimental_multi_tier_with_dispatcher_info_and_seed(
        dispatcher_info: DispatcherInfo,
        seed: Seed,
    ) -> Self {
        Self {
            cached_dispatcher: Some(dispatcher_info),
            seed: Some(seed),
            style: DispatcherStyle::ExperimentalMultiTier,
        }
    }

    pub(crate) fn seed(&self) -> Option<&Seed> {
        self.seed.as_ref()
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

    fn reject_ambiguous_selector_uses(
        &self,
        runtime: &[Instruction],
        info: &DispatcherInfo,
    ) -> Result<()> {
        let dispatcher_pcs: HashSet<_> = info
            .selectors
            .iter()
            .filter_map(|selector| runtime.get(selector.instruction_index))
            .map(|instruction| instruction.pc)
            .collect();
        let selectors: HashSet<_> = info
            .selectors
            .iter()
            .map(|selector| selector.selector)
            .collect();

        for instruction in runtime {
            if dispatcher_pcs.contains(&instruction.pc)
                || !matches!(instruction.op, Opcode::PUSH(4))
            {
                continue;
            }
            let Some(immediate) = instruction.imm.as_deref() else {
                continue;
            };
            let Ok(value) = u32::from_str_radix(immediate, 16) else {
                continue;
            };
            if selectors.contains(&value) {
                return Err(Error::Generic(format!(
                    "dispatcher: selector 0x{value:08x} is also used outside the dispatcher at pc 0x{:x}; self-call/interface dataflow is ambiguous",
                    instruction.pc
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn apply_instruction_replacements(
        &self,
        ir: &mut CfgIrBundle,
        edits: Vec<(NodeIndex, usize, Opcode, Option<String>)>,
    ) -> Result<bool> {
        // Group edits by node to batch modifications
        let mut edits_by_node: HashMap<NodeIndex, Vec<(usize, Opcode, Option<String>)>> =
            HashMap::new();
        for (node, pc, opcode, immediate) in edits {
            edits_by_node
                .entry(node)
                .or_default()
                .push((pc, opcode, immediate));
        }

        // Build batch modifications
        let mut modifications = Vec::new();
        for (node, node_edits) in edits_by_node {
            let original = match ir.cfg.node_weight(node) {
                Some(Block::Body(body)) => body.clone(),
                _ => continue,
            };

            let mut new_body = original.clone();
            let mut changed = false;

            for (pc, opcode, immediate) in node_edits {
                if let Some(instr) = new_body.instructions.iter_mut().find(|ins| ins.pc == pc) {
                    let immediate_matches = match (&immediate, &instr.imm) {
                        (Some(expected), Some(actual)) => actual == expected,
                        (None, None) => true,
                        _ => false,
                    };

                    if instr.op != opcode || !immediate_matches {
                        instr.op = opcode;
                        instr.imm = immediate;
                        changed = true;
                    }
                }
            }

            if changed {
                modifications.push((node, new_body));
            }
        }

        if modifications.is_empty() {
            return Ok(false);
        }

        ir.patch_dispatcher_blocks(modifications)
            .map_err(|e| Error::CoreError(e.to_string()))?;

        Ok(true)
    }

    /// Re-applies dispatcher patches after PC reindexing with remapped controller PCs.
    ///
    /// This method updates the dispatcher's PUSH instructions to jump to the correct
    /// controller addresses after PC reindexing has shifted all PCs. It takes the
    /// original controller PCs, looks them up in the PC mapping, and updates the
    /// dispatcher instructions with the new relative addresses.
    pub fn reapply_dispatcher_patches(
        &self,
        ir: &mut CfgIrBundle,
        controller_pcs: &HashMap<u32, usize>,
        dispatcher_patches: &[(NodeIndex, usize, u8, u32)],
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<bool> {
        let mut edits = Vec::new();

        for &(node, old_pc, push_width, selector) in dispatcher_patches {
            let Some(&old_controller_pc) = controller_pcs.get(&selector) else {
                debug!(
                    selector = format_args!("0x{:08x}", selector),
                    "reapply_dispatcher_patches: missing controller PC for selector"
                );
                continue;
            };

            // Look up the new controller PC after reindexing
            let new_controller_pc = pc_mapping
                .get(&old_controller_pc)
                .copied()
                .unwrap_or(old_controller_pc);

            // Also need to map the dispatcher instruction's PC
            let new_pc = pc_mapping.get(&old_pc).copied().unwrap_or(old_pc);

            // Calculate the new relative address
            let controller_rel = if let Some((start, _)) = ir.runtime_bounds {
                new_controller_pc.saturating_sub(start)
            } else {
                new_controller_pc
            };

            let formatted = format!(
                "{:0width$x}",
                controller_rel,
                width = push_width as usize * 2
            );

            debug!(
                selector = format_args!("0x{:08x}", selector),
                old_controller_pc = format_args!("0x{:04x}", old_controller_pc),
                new_controller_pc = format_args!("0x{:04x}", new_controller_pc),
                old_pc = format_args!("0x{:04x}", old_pc),
                new_pc = format_args!("0x{:04x}", new_pc),
                controller_rel = format_args!("0x{:04x}", controller_rel),
                "reapply_dispatcher_patches: updating dispatcher PUSH instruction"
            );

            edits.push((node, new_pc, Opcode::PUSH(push_width), Some(formatted)));
        }

        if !edits.is_empty() {
            self.apply_instruction_replacements(ir, edits)
        } else {
            Ok(false)
        }
    }

    /// Re-applies controller patches after PC reindexing with remapped jump targets.
    ///
    /// This method updates the controller's PUSH instructions (for stub/invalid jumps) to point
    /// to the correct addresses after PC reindexing has shifted all PCs. It takes the original
    /// target PCs, looks them up in the PC mapping, and updates the controller instructions
    /// with the new relative addresses.
    pub fn reapply_controller_patches(
        &self,
        ir: &mut CfgIrBundle,
        controller_patches: &[(NodeIndex, usize, u8, usize)],
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<bool> {
        let mut edits = Vec::new();

        for &(node, old_push_pc, push_width, old_target_pc) in controller_patches {
            // Look up the new target PC after reindexing
            let new_target_pc = pc_mapping
                .get(&old_target_pc)
                .copied()
                .unwrap_or(old_target_pc);

            // Also need to map the PUSH instruction's PC
            let new_push_pc = pc_mapping.get(&old_push_pc).copied().unwrap_or(old_push_pc);

            // Calculate the new relative address
            let target_rel = if let Some((start, _)) = ir.runtime_bounds {
                new_target_pc.saturating_sub(start)
            } else {
                new_target_pc
            };

            let formatted = format!("{:0width$x}", target_rel, width = push_width as usize * 2);

            debug!(
                old_target_pc = format_args!("0x{:04x}", old_target_pc),
                new_target_pc = format_args!("0x{:04x}", new_target_pc),
                old_push_pc = format_args!("0x{:04x}", old_push_pc),
                new_push_pc = format_args!("0x{:04x}", new_push_pc),
                target_rel = format_args!("0x{:04x}", target_rel),
                "reapply_controller_patches: updating controller PUSH instruction"
            );

            edits.push((node, new_push_pc, Opcode::PUSH(push_width), Some(formatted)));
        }

        if !edits.is_empty() {
            self.apply_instruction_replacements(ir, edits)
        } else {
            Ok(false)
        }
    }

    /// Syncs internal CALL sites with dispatcher tokens so remapped selectors still fire.
    fn update_internal_calls(
        &self,
        ir: &mut CfgIrBundle,
        mapping: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        let mut modifications = Vec::new();

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
                modifications.push((node, new_body));
            }
        }

        if modifications.is_empty() {
            return Ok(false);
        }

        ir.patch_dispatcher_blocks(modifications)
            .map_err(|e| Error::CoreError(e.to_string()))?;

        Ok(true)
    }

    pub(crate) fn apply_dispatcher_patches(
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
                    )));
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

    fn supports_gas_observation(&self) -> bool {
        // SelectorOnly replaces PUSH4 immediates in place and leaves the exact
        // executed opcode sequence unchanged. Multi-tier adds executed blocks.
        self.style == DispatcherStyle::SelectorOnly
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

        if self.style == DispatcherStyle::SelectorOnly {
            debug!(
                selectors = dispatcher_info.selectors.len(),
                "Using selector-only dispatcher obfuscation path"
            );
            self.reject_ambiguous_selector_uses(&runtime_instructions, &dispatcher_info)?;
            let preserve_bytes = HashMap::new();
            let seed = self.seed.as_ref().ok_or_else(|| {
                Error::Generic("dispatcher: seed required for token mapping".into())
            })?;
            let mapping =
                generate_selector_token_mapping(&dispatcher_info.selectors, seed, &preserve_bytes)?;
            if self.apply_dispatcher_patches(
                ir,
                &runtime_instructions,
                &index_by_pc,
                &dispatcher_info,
                &mapping,
            )? {
                ir.selector_mapping = Some(mapping);
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        let blueprint = self.build_blueprint(&dispatcher_info, rng);
        let original_selector_count = blueprint.dispatcher.selectors.len();
        let selector_assignment_count = blueprint.selectors.len();
        let tier_count = blueprint
            .selectors
            .iter()
            .map(|assignment| assignment.tier_index + 1)
            .max()
            .unwrap_or(0);
        debug!(
            tiers = tier_count,
            selectors = original_selector_count,
            assignments = selector_assignment_count,
            "Prepared multi-tier dispatcher blueprint"
        );

        let Some(plan) = self.apply_layout_plan(
            ir,
            &runtime_instructions,
            &index_by_pc,
            &dispatcher_info,
            &blueprint,
        )?
        else {
            debug!("Multi-tier dispatcher layout not applied; skipping transform");
            return Ok(false);
        };

        let calls_modified = self.update_internal_calls(ir, &plan.mapping)?;

        if plan.dispatcher_modified || calls_modified {
            ir.selector_mapping = Some(plan.mapping);
            // Store dispatcher patch info for post-reindex patching
            ir.dispatcher_controller_pcs = Some(plan.controller_pcs);
            ir.dispatcher_patches = Some(plan.dispatcher_patches);
            ir.stub_patches = Some(plan.stub_patches);
            ir.decoy_patches = Some(plan.decoy_patches);
            ir.controller_patches = Some(plan.controller_patches);
            debug!("Function dispatcher obfuscated via multi-tier layout");
            Ok(true)
        } else {
            debug!("Dispatcher mapping produced no changes");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::process_bytecode_to_cfg;

    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../../tests/bytecode/counter/counter_runtime.hex");
    const FIXED_SEED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn dispatcher_styles_require_explicit_multi_tier_opt_in() {
        assert_eq!(
            FunctionDispatcher::new().style,
            DispatcherStyle::SelectorOnly
        );
        assert_eq!(
            FunctionDispatcher::experimental_multi_tier().style,
            DispatcherStyle::ExperimentalMultiTier
        );

        let info = DispatcherInfo {
            start_offset: 0,
            end_offset: 0,
            selectors: Vec::new(),
            extraction_pattern: azoth_core::detection::ExtractionPattern::Standard,
        };
        let seed = Seed::from_hex(FIXED_SEED).expect("valid fixed seed");
        assert_eq!(
            FunctionDispatcher::with_dispatcher_info_and_seed(info.clone(), seed.clone()).style,
            DispatcherStyle::SelectorOnly
        );
        assert_eq!(
            FunctionDispatcher::experimental_multi_tier_with_dispatcher_info_and_seed(info, seed)
                .style,
            DispatcherStyle::ExperimentalMultiTier
        );
    }

    #[tokio::test]
    async fn default_dispatcher_only_replaces_selectors_on_large_dispatcher() {
        let deployment = COUNTER_DEPLOYMENT.trim();
        let runtime = COUNTER_RUNTIME.trim();
        let (mut ir, _, _, _) = process_bytecode_to_cfg(deployment, false, runtime, false)
            .await
            .expect("counter bytecode should produce a CFG");

        let detector = FunctionDispatcher::new();
        let (runtime_instructions, _) = detector.collect_runtime_instructions(&ir);
        let info = detect_function_dispatcher(&runtime_instructions)
            .expect("counter runtime should contain a dispatcher");
        assert!(
            info.selectors.len() > 2,
            "fixture must exercise the former multi-tier heuristic"
        );

        let original_node_count = ir.cfg.node_count();
        let original_runtime_bounds = ir.runtime_bounds;
        let seed = Seed::from_hex(FIXED_SEED).expect("valid fixed seed");
        let mut rng = seed.create_deterministic_rng();
        let dispatcher = FunctionDispatcher::with_dispatcher_info_and_seed(info.clone(), seed);

        assert!(dispatcher
            .apply(&mut ir, &mut rng)
            .expect("selector-only dispatcher transform should succeed"));
        assert_eq!(ir.cfg.node_count(), original_node_count);
        assert_eq!(ir.runtime_bounds, original_runtime_bounds);
        assert!(ir.dispatcher_controller_pcs.is_none());
        assert!(ir.dispatcher_patches.is_none());
        assert!(ir.stub_patches.is_none());
        assert!(ir.decoy_patches.is_none());
        assert!(ir.controller_patches.is_none());
        assert_eq!(
            ir.selector_mapping.as_ref().map(HashMap::len),
            Some(info.selectors.len())
        );
    }
}
