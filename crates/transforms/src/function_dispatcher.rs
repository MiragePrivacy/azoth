//! Function dispatcher transforma

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{detect_function_dispatcher, DispatcherInfo, FunctionSelector};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::{rngs::StdRng, RngCore};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Function dispatcher transform
///
/// The transform remaps each 4-byte selector used in the dispatcher and in
/// internal call sites to a deterministic but secret token.  The dispatcher
/// layout is preserved – we only patch the immediate values – which keeps the
/// original control-flow graph intact and avoids introducing brittle jump
/// rewriting.
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

    /// Builds a deterministic selector→token mapping anchored by a random secret.
    fn generate_mapping(
        &self,
        selectors: &[FunctionSelector],
        rng: &mut StdRng,
    ) -> Result<HashMap<u32, Vec<u8>>> {
        if selectors.is_empty() {
            return Ok(HashMap::new());
        }

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        let mut mapping = HashMap::with_capacity(selectors.len());
        let mut used_tokens = HashSet::with_capacity(selectors.len());

        for selector in selectors {
            let token = self.derive_unique_token(selector.selector, &secret, &mut used_tokens)?;
            mapping.insert(selector.selector, token);
        }

        Ok(mapping)
    }

    /// Derives a 4 byte token for a selector while avoiding collisions and identity.
    fn derive_unique_token(
        &self,
        selector: u32,
        secret: &[u8; 32],
        used_tokens: &mut HashSet<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        const TOKEN_LEN: usize = 4;
        const MAX_ATTEMPTS: u32 = 1_000;

        let selector_bytes = selector.to_be_bytes();

        for counter in 0..MAX_ATTEMPTS {
            let mut hasher = Keccak256::new();
            hasher.update(secret);
            hasher.update(&selector_bytes);
            hasher.update(counter.to_be_bytes());
            let hash = hasher.finalize();

            let token = hash[..TOKEN_LEN].to_vec();
            if token != selector_bytes && used_tokens.insert(token.clone()) {
                return Ok(token);
            }
        }

        Err(Error::Generic(
            "dispatcher: failed to derive unique selector token".into(),
        ))
    }

    /// Rewrites dispatcher PUSH4 immediates to their tokens without touching layout.
    fn apply_dispatcher_patches(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        info: &DispatcherInfo,
        mapping: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let mut per_block: HashMap<NodeIndex, Vec<(usize, String)>> = HashMap::new();

        for selector in &info.selectors {
            let instruction = runtime.get(selector.instruction_index).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: selector index {} out of bounds",
                    selector.instruction_index
                ))
            })?;

            let (node, offset) = index_by_pc.get(&instruction.pc).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: instruction at pc {} not found in CFG",
                    instruction.pc
                ))
            })?;

            let token = mapping.get(&selector.selector).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: missing token for selector 0x{:08x}",
                    selector.selector
                ))
            })?;

            per_block
                .entry(*node)
                .or_default()
                .push((*offset, hex::encode(token)));
        }

        let mut modified = false;

        for (node, patches) in per_block {
            let changed = self.patch_block(ir, node, |body| {
                let mut changed = false;
                for (offset, token_hex) in &patches {
                    if let Some(instr) = body.instructions.get_mut(*offset) {
                        let needs_update = instr.imm.as_deref() != Some(token_hex.as_str())
                            || !matches!(instr.op, Opcode::PUSH(4));
                        if needs_update {
                            instr.op = Opcode::PUSH(4);
                            instr.imm = Some(token_hex.clone());
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
                if new_body.instructions[idx].op != Opcode::PUSH(4) {
                    continue;
                }

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

    /// Overwrites a CFG block
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
    /// Identifies the transform in logging and registries.
    fn name(&self) -> &'static str {
        "FunctionDispatcher"
    }

    /// Detects the dispatcher, remaps selectors, and patches dispatcher + call sites.
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

        let mapping = self.generate_mapping(&dispatcher_info.selectors, rng)?;
        debug!("Remapping {} selectors", mapping.len());

        let dispatcher_modified = self.apply_dispatcher_patches(
            ir,
            &runtime_instructions,
            &index_by_pc,
            &dispatcher_info,
            &mapping,
        )?;

        let calls_modified = self.update_internal_calls(ir, &mapping)?;

        if dispatcher_modified || calls_modified {
            ir.selector_mapping = Some(mapping);
            debug!("Function dispatcher tokens applied successfully");
            Ok(true)
        } else {
            debug!("Dispatcher mapping produced no changes");
            Ok(false)
        }
    }
}
