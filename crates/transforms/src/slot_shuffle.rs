//! Storage slot shuffler.
//!
//! This transform does **not** move or rewrite storage itself. Instead, it rewrites
//! the *literal slot indices* used in bytecode so the contract reads/writes a
//! permuted layout. It looks for PUSH immediates that are used as slot selectors
//! for `SLOAD`/`SSTORE`, then applies a random per-width bijection to those
//! immediates (e.g., 1-byte slots are permuted among 1-byte slots, 2-byte slots
//! among 2-byte slots, etc.). The semantics are preserved because every slot
//! reference is rewritten consistently.
//!
//! We only touch obvious literal slot patterns:
//! - `PUSH <slot> ; SLOAD`
//! - `PUSH <slot> ; PUSH <value> ; SSTORE`
//! - `PUSH <slot> ; SSTORE` (when the value is already on the stack)
//!   and we skip protected PCs (dispatcher/controller regions).
//!
//! Assembly example:
//! ```assembly
//! // Original
//! PUSH1 0x00
//! SLOAD
//!
//! // Transformed (slot remapped to 0xbeef)
//! PUSH2 0xbeef
//! SLOAD
//! ```

use crate::{collect_protected_pcs, Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Late-stage storage slot permutation.
#[derive(Default)]
pub struct SlotShuffle;

impl SlotShuffle {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for SlotShuffle {
    fn name(&self) -> &'static str {
        "SlotShuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("SlotShuffle: scanning for storage slot literals");

        let protected_pcs = collect_protected_pcs(ir);
        let mut slots_by_width: HashMap<usize, Vec<Vec<u8>>> = HashMap::new();
        let mut seen_by_width: HashMap<usize, HashSet<Vec<u8>>> = HashMap::new();
        let mut unsupported_sstores: Vec<usize> = Vec::new();

        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        for node in &nodes {
            let Some(Block::Body(body)) = ir.cfg.node_weight(*node) else {
                continue;
            };

            for idx in 0..body.instructions.len() {
                let instr = &body.instructions[idx];

                if matches!(instr.op, Opcode::SSTORE) {
                    if protected_pcs.contains(&instr.pc) {
                        continue;
                    }
                    match sstore_slot_push_index(&body.instructions, idx) {
                        Some(slot_idx) => {
                            let slot_instr = &body.instructions[slot_idx];
                            if protected_pcs.contains(&slot_instr.pc) {
                                continue;
                            }
                        }
                        None => unsupported_sstores.push(instr.pc),
                    }
                }

                if protected_pcs.contains(&instr.pc) {
                    continue;
                }
                let Some((width, slot_bytes)) = parse_slot_candidate(&body.instructions, idx)
                else {
                    continue;
                };

                let seen = seen_by_width.entry(width).or_default();
                if seen.insert(slot_bytes.clone()) {
                    slots_by_width.entry(width).or_default().push(slot_bytes);
                }
            }
        }

        if !unsupported_sstores.is_empty() {
            unsupported_sstores.sort_unstable();
            unsupported_sstores.dedup();
            let pcs = unsupported_sstores
                .iter()
                .map(|pc| format!("0x{pc:04x}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::Generic(format!(
                "SlotShuffle: unsupported SSTORE(s) without literal slot immediate at pc(s): {pcs}"
            )));
        }

        if slots_by_width.is_empty() {
            debug!("SlotShuffle: no eligible slot literals found");
            return Ok(false);
        }

        let mut mapping: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut mapping_changed = false;

        for (width, slots) in &slots_by_width {
            let mut shuffled = slots.clone();
            shuffled.shuffle(rng);
            if shuffled == *slots && slots.len() > 1 {
                shuffled.rotate_left(1);
            }
            let mut width_changed = false;
            for (from, to) in slots.iter().zip(shuffled.iter()) {
                if from != to {
                    width_changed = true;
                    mapping_changed = true;
                }
                mapping.insert(from.clone(), to.clone());
            }
            debug!(
                "SlotShuffle: width={} bytes, slots={}, changed={}",
                width,
                slots.len(),
                width_changed
            );
            if width_changed {
                for (from, to) in slots.iter().zip(shuffled.iter()) {
                    if from != to {
                        debug!(
                            "SlotShuffle: width={} remap 0x{} -> 0x{}",
                            width,
                            format_slot_immediate(from, *width),
                            format_slot_immediate(to, *width)
                        );
                    }
                }
            }
        }

        if !mapping_changed {
            debug!("SlotShuffle: mapping is identity; nothing to rewrite");
            return Ok(false);
        }

        let mut changed = false;

        for node in nodes {
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };

            let original = body.instructions.clone();
            let mut rewritten = original.clone();
            let mut block_changed = false;

            for idx in 0..rewritten.len() {
                let instr = &rewritten[idx];
                if protected_pcs.contains(&instr.pc) {
                    continue;
                }
                let Some((width, slot_bytes)) = parse_slot_candidate(&rewritten, idx) else {
                    continue;
                };
                let Some(new_slot) = mapping.get(&slot_bytes) else {
                    continue;
                };
                if new_slot == &slot_bytes {
                    continue;
                }

                debug!(
                    "SlotShuffle: block_pc=0x{:x} instr_pc=0x{:x} width={} 0x{} -> 0x{}",
                    body.start_pc,
                    instr.pc,
                    width,
                    format_slot_immediate(&slot_bytes, width),
                    format_slot_immediate(new_slot, width)
                );
                rewritten[idx].imm = Some(format_slot_immediate(new_slot, width));
                block_changed = true;
            }

            if block_changed {
                let mut new_body = body.clone();
                new_body.instructions = rewritten;
                ir.overwrite_block(node, new_body)
                    .map_err(|e| Error::CoreError(e.to_string()))?;
                changed = true;
            }
        }

        if changed {
            debug!(
                "SlotShuffle: applied remapping to {} width buckets",
                slots_by_width.len()
            );
        }
        Ok(changed)
    }
}

fn parse_slot_candidate(instructions: &[Instruction], idx: usize) -> Option<(usize, Vec<u8>)> {
    let instr = instructions.get(idx)?;
    let width = match instr.op {
        Opcode::PUSH(width) => width as usize,
        _ => return None,
    };
    if !is_storage_slot_push(instructions, idx) {
        return None;
    }
    let imm = instr.imm.as_deref()?;
    normalize_slot_immediate(imm, width).map(|bytes| (width, bytes))
}

fn is_storage_slot_push(instructions: &[Instruction], idx: usize) -> bool {
    if instructions
        .get(idx + 1)
        .is_some_and(|next| matches!(next.op, Opcode::SLOAD))
    {
        return true;
    }

    if instructions
        .get(idx + 2)
        .is_some_and(|next| matches!(next.op, Opcode::SSTORE))
        && instructions
            .get(idx + 1)
            .is_some_and(|next| is_push_any(&next.op))
    {
        return true;
    }

    if instructions
        .get(idx + 1)
        .is_some_and(|next| matches!(next.op, Opcode::SSTORE))
    {
        let prev_is_push = idx
            .checked_sub(1)
            .and_then(|prev| instructions.get(prev))
            .is_some_and(|prev| is_push_any(&prev.op));
        return !prev_is_push;
    }

    false
}

fn sstore_slot_push_index(instructions: &[Instruction], idx: usize) -> Option<usize> {
    let instr = instructions.get(idx)?;
    if !matches!(instr.op, Opcode::SSTORE) {
        return None;
    }
    if let Some(slot_idx) = idx.checked_sub(1) {
        if parse_slot_candidate(instructions, slot_idx).is_some() {
            debug!(
                "SlotShuffle: matched SSTORE slot push (slot_pc=0x{:04x}, sstore_pc=0x{:04x})",
                instructions[slot_idx].pc,
                instr.pc
            );
            return Some(slot_idx);
        }
    }
    if let Some(slot_idx) = idx.checked_sub(2) {
        if parse_slot_candidate(instructions, slot_idx).is_some() {
            debug!(
                "SlotShuffle: matched SSTORE slot push (slot_pc=0x{:04x}, sstore_pc=0x{:04x})",
                instructions[slot_idx].pc,
                instr.pc
            );
            return Some(slot_idx);
        }
    }
    None
}

fn is_push_any(op: &Opcode) -> bool {
    matches!(op, Opcode::PUSH(_) | Opcode::PUSH0)
}

fn normalize_slot_immediate(imm: &str, width: usize) -> Option<Vec<u8>> {
    let mut hex = imm.to_ascii_lowercase();
    if !hex.len().is_multiple_of(2) {
        hex.insert(0, '0');
    }
    let mut bytes = hex::decode(hex).ok()?;
    if bytes.len() > width {
        return None;
    }
    if bytes.len() < width {
        let mut padded = vec![0u8; width - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    Some(bytes)
}

fn format_slot_immediate(bytes: &[u8], width: usize) -> String {
    if bytes.len() == width {
        return hex::encode(bytes);
    }
    if bytes.len() < width {
        let mut padded = vec![0u8; width - bytes.len()];
        padded.extend_from_slice(bytes);
        return hex::encode(padded);
    }
    let start = bytes.len().saturating_sub(width);
    hex::encode(&bytes[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    fn init_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("debug")
                .with_test_writer()
                .try_init();
        });
    }

    fn instr(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: imm.map(|s| s.to_string()),
        }
    }

    #[test]
    fn normalize_slot_immediate_pads_and_rejects_oversized() {
        let bytes = normalize_slot_immediate("1", 2).expect("normalized");
        assert_eq!(bytes, vec![0x00, 0x01]);

        let bytes = normalize_slot_immediate("0a0b", 2).expect("normalized");
        assert_eq!(bytes, vec![0x0a, 0x0b]);

        assert!(normalize_slot_immediate("0a0b0c", 2).is_none());
    }

    #[test]
    fn format_slot_immediate_truncates_and_pads() {
        assert_eq!(format_slot_immediate(&[0x01], 2), "0001");
        assert_eq!(format_slot_immediate(&[0x0a, 0x0b], 2), "0a0b");
        assert_eq!(format_slot_immediate(&[0x01, 0x02, 0x03], 2), "0203");
    }

    #[test]
    fn detects_storage_slot_push_patterns() {
        let sload = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SLOAD, None),
        ];
        assert!(is_storage_slot_push(&sload, 0));

        let sstore = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::PUSH(1), Some("0a")),
            instr(4, Opcode::SSTORE, None),
        ];
        assert!(is_storage_slot_push(&sstore, 0));
        assert!(!is_storage_slot_push(&sstore, 1));

        let sstore_no_prev_push = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SSTORE, None),
        ];
        assert!(is_storage_slot_push(&sstore_no_prev_push, 0));
    }

    #[test]
    fn parses_slot_candidates_from_instructions() {
        let sload = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SLOAD, None),
        ];
        let parsed = parse_slot_candidate(&sload, 0).expect("slot candidate");
        assert_eq!(parsed.0, 1);
        assert_eq!(parsed.1, vec![0x01]);

        let sstore = vec![
            instr(0, Opcode::PUSH(2), Some("0002")),
            instr(3, Opcode::PUSH(1), Some("0a")),
            instr(5, Opcode::SSTORE, None),
        ];
        let parsed = parse_slot_candidate(&sstore, 0).expect("slot candidate");
        assert_eq!(parsed.0, 2);
        assert_eq!(parsed.1, vec![0x00, 0x02]);
    }

    #[test]
    fn detects_sstore_slot_push_indices() {
        init_tracing();
        let sstore = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::PUSH(1), Some("0a")),
            instr(4, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore, 2), Some(0));

        let sstore_no_prev_push = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore_no_prev_push, 1), Some(0));

        let sstore_dynamic = vec![
            instr(0, Opcode::DUP(1), None),
            instr(1, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore_dynamic, 1), None);
    }
}
