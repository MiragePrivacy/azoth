use super::super::{FunctionDispatcher, MAX_PACKED_TOKEN_SELECTORS, SELECTOR_TOKEN_LEN};
use crate::{Error, Result};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use azoth_core::Opcode;
use hex;
use petgraph::graph::NodeIndex;
use rand::{rngs::StdRng, RngCore};
use std::collections::HashMap;
use tracing::debug;

impl FunctionDispatcher {
    pub(crate) fn try_apply_packed_pattern(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        info: &DispatcherInfo,
        rng: &mut StdRng,
    ) -> Result<Option<(HashMap<u32, Vec<u8>>, bool, bool)>> {
        if info.selectors.is_empty() {
            return Ok(None);
        }

        if info.selectors.len() > MAX_PACKED_TOKEN_SELECTORS {
            debug!(
                "Packed dispatcher pattern skipped: {} selectors exceed limit {}",
                info.selectors.len(),
                MAX_PACKED_TOKEN_SELECTORS
            );
            return Ok(None);
        }

        #[cfg(test)]
        {
            for selector in &info.selectors {
                println!(
                    "[packed] selector 0x{:08x} -> target 0x{:x}",
                    selector.selector, selector.target_address
                );
            }
        }

        let extraction_modified =
            self.rewrite_selector_extraction(ir, runtime, index_by_pc, info)?;

        let mapping = self.generate_packed_mapping(&info.selectors, rng)?;

        let dispatcher_modified =
            self.rewrite_jump_table_dispatcher(ir, runtime, index_by_pc, info, &mapping)?;

        if !dispatcher_modified {
            debug!("Packed dispatcher pattern: dispatcher rewrite not applied");
            return Ok(None);
        }

        Ok(Some((mapping, extraction_modified, dispatcher_modified)))
    }

    fn generate_packed_mapping(
        &self,
        selectors: &[FunctionSelector],
        rng: &mut StdRng,
    ) -> Result<HashMap<u32, Vec<u8>>> {
        let mut mapping = HashMap::with_capacity(selectors.len());

        for (idx, selector) in selectors.iter().enumerate() {
            if idx >= 256 {
                return Err(Error::Generic(
                    "dispatcher: selector index exceeds single-byte token space".into(),
                ));
            }

            let mut token = vec![0u8; SELECTOR_TOKEN_LEN];
            if SELECTOR_TOKEN_LEN > 1 {
                rng.fill_bytes(&mut token[..SELECTOR_TOKEN_LEN - 1]);
            }
            token[SELECTOR_TOKEN_LEN - 1] = idx as u8;
            mapping.insert(selector.selector, token);
        }

        Ok(mapping)
    }

    fn rewrite_jump_table_dispatcher(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        info: &DispatcherInfo,
        mapping: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let first_selector = match info.selectors.first() {
            Some(selector) => selector,
            None => return Ok(false),
        };

        let selector_instruction =
            runtime
                .get(first_selector.instruction_index)
                .ok_or_else(|| {
                    Error::Generic(format!(
                        "dispatcher: selector index {} out of bounds",
                        first_selector.instruction_index
                    ))
                })?;

        let (node, start_offset_ref) =
            index_by_pc.get(&selector_instruction.pc).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: selector instruction at pc {} not present in CFG",
                    selector_instruction.pc
                ))
            })?;

        let start_offset = *start_offset_ref;
        let rewrite_offset = start_offset.saturating_sub(1);
        let original_block = match ir.cfg.node_weight(*node) {
            Some(Block::Body(body)) => body.clone(),
            _ => {
                return Err(Error::Generic(
                    "dispatcher: expected body block for jump-table rewrite".into(),
                ))
            }
        };

        let local_revert = find_revert_block(&original_block, start_offset);
        let (suffix, revert_pc) = if let Some(offset) = local_revert {
            (
                original_block.instructions[offset..].to_vec(),
                original_block.instructions[offset].pc,
            )
        } else {
            let revert_pc = find_revert_pc(runtime).ok_or_else(|| {
                Error::Generic("dispatcher: failed to locate fallback revert pc".into())
            })?;
            (Vec::new(), revert_pc)
        };
        let table_hex = build_jump_table(info)?;
        let selector_count = info.selectors.len();
        #[cfg(test)]
        {
            let table_bytes = hex::decode(&table_hex).expect("table hex");
            for idx in 0..selector_count {
                let start = table_bytes.len().saturating_sub((idx + 1) * 2);
                let dest = u16::from_be_bytes([table_bytes[start], table_bytes[start + 1]]);
                println!("[packed] table[{}] -> 0x{:04x}", idx, dest);
            }
        }

        let mut modified = self.patch_block(ir, *node, move |body| {
            if rewrite_offset >= body.instructions.len() {
                return false;
            }

            let mut new_body = body.instructions[..rewrite_offset].to_vec();

            let mut next_pc = body.instructions[rewrite_offset].pc;
            let mut push_instr = |op: Opcode, imm: Option<String>| {
                let instr = Instruction {
                    pc: next_pc,
                    op,
                    imm,
                };
                next_pc = next_pc.saturating_add(1);
                new_body.push(instr);
            };

            push_instr(Opcode::PUSH(1), Some("ff".to_string()));
            push_instr(Opcode::AND, None);
            push_instr(Opcode::DUP(1), None);
            push_instr(Opcode::PUSH(1), Some(format!("{:02x}", selector_count)));
            push_instr(Opcode::LT, None);
            push_instr(Opcode::ISZERO, None);
            push_instr(Opcode::PUSH(2), Some(format!("{:04x}", revert_pc)));
            push_instr(Opcode::JUMPI, None);

            push_instr(Opcode::PUSH(32), Some(table_hex.clone()));
            push_instr(Opcode::SWAP(1), None);
            push_instr(Opcode::PUSH(1), Some("10".to_string()));
            push_instr(Opcode::MUL, None);
            push_instr(Opcode::SWAP(1), None);
            push_instr(Opcode::SHR, None);
            push_instr(Opcode::PUSH(2), Some("ffff".to_string()));
            push_instr(Opcode::AND, None);
            push_instr(Opcode::JUMP, None);

            if !suffix.is_empty() {
                new_body.extend_from_slice(&suffix);
            }

            if new_body != body.instructions {
                body.instructions = new_body;
                true
            } else {
                false
            }
        })?;

        let mut edits = Vec::new();
        for selector in info.selectors.iter().skip(1) {
            let instruction = runtime.get(selector.instruction_index).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: selector index {} out of bounds",
                    selector.instruction_index
                ))
            })?;

            let (sel_node, _) = index_by_pc.get(&instruction.pc).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: selector instruction at pc {} not present in CFG",
                    instruction.pc
                ))
            })?;

            let token = mapping.get(&selector.selector).ok_or_else(|| {
                Error::Generic(format!(
                    "dispatcher: missing token for selector 0x{:08x}",
                    selector.selector
                ))
            })?;

            edits.push((
                *sel_node,
                instruction.pc,
                Opcode::PUSH(token.len() as u8),
                Some(hex::encode(token)),
            ));
        }

        if !edits.is_empty() {
            modified |= self.apply_instruction_replacements(ir, edits)?;
        }

        Ok(modified)
    }
}

fn find_revert_block(body: &BlockBody, start: usize) -> Option<usize> {
    for idx in start..body.instructions.len().saturating_sub(3) {
        let inst0 = &body.instructions[idx];
        let inst1 = &body.instructions[idx + 1];
        let inst2 = &body.instructions[idx + 2];
        let inst3 = &body.instructions[idx + 3];

        if matches!(inst0.op, Opcode::JUMPDEST)
            && matches!(inst1.op, Opcode::PUSH0)
            && matches!(inst2.op, Opcode::PUSH0)
            && matches!(inst3.op, Opcode::REVERT)
        {
            return Some(idx);
        }
    }
    None
}

fn find_revert_pc(runtime: &[Instruction]) -> Option<usize> {
    for idx in 0..runtime.len().saturating_sub(3) {
        if matches!(runtime[idx].op, Opcode::JUMPDEST)
            && matches!(runtime[idx + 1].op, Opcode::PUSH0)
            && matches!(runtime[idx + 2].op, Opcode::PUSH0)
            && matches!(runtime[idx + 3].op, Opcode::REVERT)
        {
            return Some(runtime[idx].pc);
        }
    }
    None
}

fn build_jump_table(info: &DispatcherInfo) -> Result<String> {
    let mut table = [0u8; 32];

    for (idx, selector) in info.selectors.iter().enumerate() {
        let dest = selector.target_address;
        if dest > u16::MAX as u64 {
            return Err(Error::Generic(format!(
                "dispatcher: target pc 0x{:x} exceeds 16-bit packed table capacity",
                dest
            )));
        }

        let offset = 32usize
            .checked_sub((idx + 1) * 2)
            .ok_or_else(|| Error::Generic("dispatcher: packed table overflow".into()))?;
        table[offset] = ((dest >> 8) & 0xff) as u8;
        table[offset + 1] = (dest & 0xff) as u8;
    }

    Ok(hex::encode(table))
}
