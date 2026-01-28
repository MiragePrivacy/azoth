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
//! - `PUSH <value> ; PUSH <slot> ; SSTORE` (slot is on top of stack for SSTORE)
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
use tracing::{debug, warn};

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
            // Cross-block patterns (e.g., Solidity's counter++) can't be safely traced.
            // Skip shuffling to avoid breaking contracts where we can't track all slot refs.
            warn!(
                "SlotShuffle: skipping due to untraced SSTORE(s) at pc(s): {}",
                pcs
            );
            return Ok(false);
        }

        if slots_by_width.is_empty() {
            warn!("SlotShuffle: no eligible slot literals found");
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
                if matches!(rewritten[idx].op, Opcode::PUSH0) {
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
    if !is_storage_slot_push(instructions, idx) {
        return None;
    }
    match instr.op {
        Opcode::PUSH(width) => {
            let width = width as usize;
            let imm = instr.imm.as_deref()?;
            normalize_slot_immediate(imm, width).map(|bytes| (width, bytes))
        }
        Opcode::PUSH0 => Some((0, Vec::new())),
        _ => None,
    }
}

fn is_storage_slot_push(instructions: &[Instruction], idx: usize) -> bool {
    // Pattern 1: PUSH <slot> ; SLOAD
    if instructions
        .get(idx + 1)
        .is_some_and(|next| matches!(next.op, Opcode::SLOAD))
    {
        return true;
    }

    // Pattern 2: PUSH <slot> ; SSTORE
    // SSTORE takes slot from µs[0] (top of stack), so the PUSH immediately
    // before SSTORE is always the slot. This handles both:
    // - `PUSH <slot> ; SSTORE` (value already on stack)
    // - `PUSH <value> ; PUSH <slot> ; SSTORE` (we match the second PUSH)
    if instructions
        .get(idx + 1)
        .is_some_and(|next| matches!(next.op, Opcode::SSTORE))
    {
        return true;
    }

    false
}

fn sstore_slot_push_index(instructions: &[Instruction], idx: usize) -> Option<usize> {
    let instr = instructions.get(idx)?;
    if !matches!(instr.op, Opcode::SSTORE) {
        return None;
    }
    // First try direct match: PUSH immediately before SSTORE
    let slot_idx = idx.checked_sub(1)?;
    if parse_slot_candidate(instructions, slot_idx).is_some() {
        debug!(
            "SlotShuffle: matched SSTORE slot push (slot_pc=0x{:04x}, sstore_pc=0x{:04x})",
            instructions[slot_idx].pc, instr.pc
        );
        return Some(slot_idx);
    }

    // Fallback: trace backwards through stack operations to find the slot PUSH
    if let Some(traced_idx) = trace_slot_source(instructions, idx) {
        // Verify the traced instruction is a valid slot candidate for SLOAD/SSTORE
        let traced_instr = &instructions[traced_idx];
        if matches!(traced_instr.op, Opcode::PUSH(_) | Opcode::PUSH0) {
            debug!(
                "SlotShuffle: traced SSTORE slot push (slot_pc=0x{:04x}, sstore_pc=0x{:04x})",
                traced_instr.pc, instr.pc
            );
            return Some(traced_idx);
        }
    }
    None
}

/// Trace backwards from an SSTORE to find the PUSH instruction that provides the slot.
///
/// SSTORE takes the slot from stack position 0 (top of stack). This function traces
/// backwards through DUP, SWAP, and other stack operations to find the original PUSH
/// that provided the slot value.
///
/// Returns the index of the PUSH instruction, or None if we can't determine it.
fn trace_slot_source(instructions: &[Instruction], sstore_idx: usize) -> Option<usize> {
    if sstore_idx == 0 {
        return None;
    }

    // Start tracing: slot is at stack position 0 at SSTORE
    let mut pos = 0usize;

    for idx in (0..sstore_idx).rev() {
        let op = &instructions[idx].op;

        match op {
            // PUSH operations: if we're tracking position 0, this is our source
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                if pos == 0 {
                    return Some(idx);
                }
                pos = pos.checked_sub(1)?;
            }

            // DUP(n): copies stack[n-1] to stack[0], shifts everything else up
            Opcode::DUP(n) => {
                let n = *n as usize;
                if pos == 0 {
                    // Value at position 0 was copied from position (n-1)
                    pos = n - 1;
                } else {
                    pos = pos.checked_sub(1)?;
                }
            }

            // SWAP(n): exchanges stack[0] with stack[n]
            Opcode::SWAP(n) => {
                let n = *n as usize;
                if pos == 0 {
                    pos = n;
                } else if pos == n {
                    pos = 0;
                }
            }

            // Operations that pop 1, push 1 (net 0): position unchanged
            Opcode::ISZERO
            | Opcode::NOT
            | Opcode::BALANCE
            | Opcode::CALLDATALOAD
            | Opcode::EXTCODESIZE
            | Opcode::BLOCKHASH
            | Opcode::MLOAD
            | Opcode::SLOAD
            | Opcode::EXTCODEHASH => {}

            // Binary operations: pop 2, push 1 (net -1)
            Opcode::ADD
            | Opcode::SUB
            | Opcode::MUL
            | Opcode::DIV
            | Opcode::SDIV
            | Opcode::MOD
            | Opcode::SMOD
            | Opcode::EXP
            | Opcode::SIGNEXTEND
            | Opcode::LT
            | Opcode::GT
            | Opcode::SLT
            | Opcode::SGT
            | Opcode::EQ
            | Opcode::AND
            | Opcode::OR
            | Opcode::XOR
            | Opcode::BYTE
            | Opcode::SHL
            | Opcode::SHR
            | Opcode::SAR
            | Opcode::KECCAK256 => {
                if pos == 0 {
                    // Result came from computation, not a literal - give up
                    return None;
                }
                pos += 1;
            }

            // Ternary: pop 3, push 1 (net -2)
            Opcode::ADDMOD | Opcode::MULMOD => {
                if pos == 0 {
                    return None;
                }
                pos += 2;
            }

            // POP: removes from stack (net -1)
            Opcode::POP => {
                pos += 1;
            }

            // Zero-argument pushes (net +1)
            Opcode::ADDRESS
            | Opcode::ORIGIN
            | Opcode::CALLER
            | Opcode::CALLVALUE
            | Opcode::CALLDATASIZE
            | Opcode::CODESIZE
            | Opcode::GASPRICE
            | Opcode::COINBASE
            | Opcode::TIMESTAMP
            | Opcode::NUMBER
            | Opcode::DIFFICULTY
            | Opcode::GASLIMIT
            | Opcode::CHAINID
            | Opcode::SELFBALANCE
            | Opcode::BASEFEE
            | Opcode::GAS
            | Opcode::RETURNDATASIZE
            | Opcode::PC
            | Opcode::MSIZE => {
                if pos == 0 {
                    return None; // Value from runtime, not literal
                }
                pos = pos.checked_sub(1)?;
            }

            // Memory/storage writes: pop 2, push 0 (net -2)
            Opcode::MSTORE | Opcode::MSTORE8 | Opcode::SSTORE => {
                pos += 2;
            }

            // Copy operations: pop 3, push 0 (net -3)
            Opcode::CODECOPY
            | Opcode::CALLDATACOPY
            | Opcode::EXTCODECOPY
            | Opcode::RETURNDATACOPY => {
                pos += 3;
            }

            // LOG0-4: pop 2+n, push 0
            Opcode::LOG0 => pos += 2,
            Opcode::LOG1 => pos += 3,
            Opcode::LOG2 => pos += 4,
            Opcode::LOG3 => pos += 5,
            Opcode::LOG4 => pos += 6,

            // Control flow: stop tracing
            Opcode::JUMP
            | Opcode::JUMPI
            | Opcode::STOP
            | Opcode::RETURN
            | Opcode::REVERT
            | Opcode::INVALID
            | Opcode::SELFDESTRUCT => {
                return None;
            }

            // JUMPDEST: no stack effect, continue
            Opcode::JUMPDEST => {}

            // Complex operations or unknown: give up
            _ => {
                return None;
            }
        }
    }

    None
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
    if width == 0 {
        return String::new();
    }
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
        // Pattern: PUSH <slot> ; SLOAD
        let sload = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SLOAD, None),
        ];
        assert!(is_storage_slot_push(&sload, 0));

        // Pattern: PUSH <value> ; PUSH <slot> ; SSTORE
        // The slot is the PUSH immediately before SSTORE (idx 1), not the value (idx 0)
        let sstore = vec![
            instr(0, Opcode::PUSH(1), Some("01")), // value
            instr(2, Opcode::PUSH(1), Some("0a")), // slot
            instr(4, Opcode::SSTORE, None),
        ];
        assert!(!is_storage_slot_push(&sstore, 0)); // value push is NOT a slot
        assert!(is_storage_slot_push(&sstore, 1)); // slot push IS a slot

        // Pattern: PUSH <slot> ; SSTORE (value already on stack)
        let sstore_no_prev_push = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SSTORE, None),
        ];
        assert!(is_storage_slot_push(&sstore_no_prev_push, 0));
    }

    #[test]
    fn parses_slot_candidates_from_instructions() {
        // SLOAD pattern
        let sload = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SLOAD, None),
        ];
        let parsed = parse_slot_candidate(&sload, 0).expect("slot candidate");
        assert_eq!(parsed.0, 1);
        assert_eq!(parsed.1, vec![0x01]);

        // SSTORE pattern: PUSH <value> ; PUSH <slot> ; SSTORE
        // The slot is at idx 1 (immediately before SSTORE), not idx 0
        let sstore = vec![
            instr(0, Opcode::PUSH(2), Some("0002")), // value
            instr(3, Opcode::PUSH(1), Some("0a")),   // slot
            instr(5, Opcode::SSTORE, None),
        ];
        assert!(parse_slot_candidate(&sstore, 0).is_none()); // value is not a slot candidate
        let parsed = parse_slot_candidate(&sstore, 1).expect("slot candidate");
        assert_eq!(parsed.0, 1);
        assert_eq!(parsed.1, vec![0x0a]);

        // PUSH0 as slot
        let sstore_zero = vec![
            instr(0, Opcode::PUSH0, None),
            instr(1, Opcode::SSTORE, None),
        ];
        let parsed = parse_slot_candidate(&sstore_zero, 0).expect("slot candidate");
        assert_eq!(parsed.0, 0);
        assert!(parsed.1.is_empty());
    }

    #[test]
    fn detects_sstore_slot_push_indices() {
        // PUSH <value> ; PUSH <slot> ; SSTORE - slot is at idx 1
        let sstore = vec![
            instr(0, Opcode::PUSH(1), Some("01")), // value
            instr(2, Opcode::PUSH(1), Some("0a")), // slot
            instr(4, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore, 2), Some(1)); // slot is idx 1, not 0

        // PUSH <slot> ; SSTORE - slot is at idx 0
        let sstore_no_prev_push = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore_no_prev_push, 1), Some(0));

        // Dynamic slot (DUP) - cannot identify literal slot
        let sstore_dynamic = vec![
            instr(0, Opcode::DUP(1), None),
            instr(1, Opcode::SSTORE, None),
        ];
        assert_eq!(sstore_slot_push_index(&sstore_dynamic, 1), None);
    }

    #[test]
    fn traces_slot_through_dup() {
        // PUSH0 ; DUP1 ; SSTORE - slot is PUSH0 at idx 0, traced through DUP1
        // Stack: PUSH0 -> [0], DUP1 -> [0, 0], SSTORE(slot=0, val=0)
        let instructions = vec![
            instr(0, Opcode::PUSH0, None),
            instr(1, Opcode::DUP(1), None),
            instr(2, Opcode::SSTORE, None),
        ];
        assert_eq!(trace_slot_source(&instructions, 2), Some(0));
        assert_eq!(sstore_slot_push_index(&instructions, 2), Some(0));
    }

    #[test]
    fn traces_slot_through_multiple_dups() {
        // PUSH0 ; DUP1 ; DUP1 ; SSTORE - slot traced through two DUPs
        // Stack: PUSH0 -> [0], DUP1 -> [0, 0], DUP1 -> [0, 0, 0], SSTORE(slot=0, val=0)
        let instructions = vec![
            instr(0, Opcode::PUSH0, None),
            instr(1, Opcode::DUP(1), None),
            instr(2, Opcode::DUP(1), None),
            instr(3, Opcode::SSTORE, None),
        ];
        assert_eq!(trace_slot_source(&instructions, 3), Some(0));
        assert_eq!(sstore_slot_push_index(&instructions, 3), Some(0));
    }

    #[test]
    fn traces_slot_through_swap() {
        // Read-modify-write pattern: PUSH slot ; DUP1 ; SLOAD ; NOT ; AND ; SWAP1 ; SSTORE
        // This clears bits in a storage slot
        // Array indices: 0=PUSH, 1=DUP, 2=SLOAD, 3=PUSH, 4=NOT, 5=AND, 6=SWAP, 7=SSTORE
        let instructions = vec![
            instr(0, Opcode::PUSH(1), Some("07")), // idx 0: slot = 7
            instr(2, Opcode::DUP(1), None),        // idx 1: [7, 7]
            instr(3, Opcode::SLOAD, None),         // idx 2: [7, old_val]
            instr(4, Opcode::PUSH(1), Some("ff")), // idx 3: [7, old_val, 0xff]
            instr(6, Opcode::NOT, None),           // idx 4: [7, old_val, ~0xff]
            instr(7, Opcode::AND, None),           // idx 5: [7, masked_val]
            instr(8, Opcode::SWAP(1), None),       // idx 6: [masked_val, 7]
            instr(9, Opcode::SSTORE, None),        // idx 7: SSTORE(7, masked_val)
        ];
        // SSTORE is at index 7, should trace back to PUSH at index 0
        assert_eq!(trace_slot_source(&instructions, 7), Some(0));
        assert_eq!(sstore_slot_push_index(&instructions, 7), Some(0));
    }

    #[test]
    fn traces_slot_through_dup2() {
        // Pattern where slot is accessed via DUP2
        // PUSH slot ; PUSH other ; DUP2 ; SSTORE
        // [slot], [slot, other], DUP2 copies position 1 (slot) -> [slot, other, slot]
        // SSTORE(slot, other)
        // Array indices: 0=PUSH(slot), 1=PUSH(val), 2=DUP2, 3=SSTORE
        let instructions = vec![
            instr(0, Opcode::PUSH(1), Some("07")), // idx 0: slot
            instr(2, Opcode::PUSH(1), Some("ff")), // idx 1: some value
            instr(4, Opcode::DUP(2), None),        // idx 2: copies slot to top
            instr(5, Opcode::SSTORE, None),        // idx 3: SSTORE
        ];
        // SSTORE is at index 3, should trace back to PUSH at index 0
        assert_eq!(trace_slot_source(&instructions, 3), Some(0));
        assert_eq!(sstore_slot_push_index(&instructions, 3), Some(0));
    }

    #[test]
    fn trace_fails_for_computed_slot() {
        // If slot comes from computation (ADD), we can't trace it
        let instructions = vec![
            instr(0, Opcode::PUSH(1), Some("01")),
            instr(2, Opcode::PUSH(1), Some("02")),
            instr(4, Opcode::ADD, None), // slot = 1 + 2 = 3, but computed
            instr(5, Opcode::SSTORE, None),
        ];
        assert_eq!(trace_slot_source(&instructions, 4), None);
    }

    #[test]
    fn trace_fails_for_runtime_value() {
        // If slot comes from CALLER or similar, we can't trace it
        let instructions = vec![
            instr(0, Opcode::PUSH(1), Some("ff")), // value
            instr(2, Opcode::CALLER, None),        // slot = caller address (runtime)
            instr(3, Opcode::SSTORE, None),
        ];
        assert_eq!(trace_slot_source(&instructions, 3), None);
    }
}
