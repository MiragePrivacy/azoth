use super::super::{FunctionDispatcher, MAX_BYTE_TOKEN_SELECTORS, SELECTOR_TOKEN_LEN};
use crate::{Error, Result};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::decoder::Instruction;
use azoth_core::detection::{
    find_extraction_pattern, DispatcherInfo, ExtractionPattern, FunctionSelector,
};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::{rngs::StdRng, RngCore};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[allow(dead_code)]
impl FunctionDispatcher {
    pub(crate) fn try_apply_byte_pattern(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        info: &DispatcherInfo,
        rng: &mut StdRng,
    ) -> Result<Option<BytePatternApplication>> {
        if info.selectors.len() > MAX_BYTE_TOKEN_SELECTORS {
            debug!(
                "Byte dispatcher pattern skipped: {} selectors exceed limit {}",
                info.selectors.len(),
                MAX_BYTE_TOKEN_SELECTORS
            );
            return Ok(None);
        }

        let extraction_modified =
            self.rewrite_selector_extraction(ir, runtime, index_by_pc, info)?;
        if !extraction_modified {
            debug!("Byte dispatcher pattern: extraction rewrite not applied");
            return Ok(None);
        }

        let mapping = self.generate_byte_mapping(&info.selectors, rng)?;
        let dispatcher_modified =
            self.apply_dispatcher_patches(ir, runtime, index_by_pc, info, &mapping)?;

        Ok(Some(BytePatternApplication {
            mapping,
            extraction_modified,
            dispatcher_modified,
        }))
    }

    pub(super) fn rewrite_selector_extraction(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        _info: &DispatcherInfo,
    ) -> Result<bool> {
        let Some((start, _, pattern)) = find_extraction_pattern(runtime) else {
            debug!("Byte dispatcher pattern: extraction sequence not found");
            return Ok(false);
        };

        let patches: Vec<(usize, Opcode, Option<String>)> = match pattern {
            ExtractionPattern::Standard => vec![
                (start + 2, Opcode::PUSH(1), Some("03".to_string())),
                (start + 3, Opcode::BYTE, None),
            ],
            ExtractionPattern::Newer => vec![
                (start + 1, Opcode::PUSH(1), Some("03".to_string())),
                (start + 2, Opcode::BYTE, None),
            ],
            other => {
                debug!(
                    "Byte dispatcher pattern: unsupported extraction pattern {:?}",
                    other
                );
                return Ok(false);
            }
        };

        let mut edits = Vec::with_capacity(patches.len());
        for (instruction_index, opcode, immediate) in patches {
            let instruction = runtime.get(instruction_index).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: extraction instruction index {} out of bounds",
                    instruction_index
                ))
            })?;

            let (node, _) = match index_by_pc.get(&instruction.pc) {
                Some(pair) => *pair,
                None => {
                    return Err(Error::Generic(format!(
                        "dispatcher: extraction instruction at pc {} not present in CFG",
                        instruction.pc
                    )))
                }
            };

            edits.push((node, instruction.pc, opcode, immediate.clone()));
        }

        self.apply_instruction_replacements(ir, edits)
    }

    pub(super) fn generate_byte_mapping(
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
        let mut used_bytes = HashSet::with_capacity(selectors.len());

        for selector in selectors {
            let token = derive_unique_selector_byte(selector.selector, &secret, &mut used_bytes)?;
            let mut bytes = vec![0u8; SELECTOR_TOKEN_LEN];
            bytes[SELECTOR_TOKEN_LEN - 1] = token;
            mapping.insert(selector.selector, bytes);
        }

        Ok(mapping)
    }
}

fn derive_unique_selector_byte(
    selector: u32,
    secret: &[u8; 32],
    used_bytes: &mut HashSet<u8>,
) -> Result<u8> {
    const MAX_ATTEMPTS: u32 = 1_000;

    let selector_bytes = selector.to_be_bytes();

    for counter in 0..MAX_ATTEMPTS {
        let mut hasher = Keccak256::new();
        hasher.update(secret);
        hasher.update(selector_bytes);
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();

        let candidate = hash[hash.len() - 1];

        if candidate == selector_bytes[selector_bytes.len() - 1] {
            continue;
        }

        if used_bytes.insert(candidate) {
            return Ok(candidate);
        }
    }

    Err(Error::Generic(
        "dispatcher: failed to derive unique selector token".into(),
    ))
}

pub struct BytePatternApplication {
    pub mapping: HashMap<u32, Vec<u8>>,
    pub extraction_modified: bool,
    pub dispatcher_modified: bool,
}
