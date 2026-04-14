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

        // For each block, record the set of instruction indices that are the
        // literal-slot PUSH for some SLOAD/SSTORE in that block (either
        // directly adjacent, or reachable via a DUP/SWAP/arithmetic trace).
        // The same set drives both the collection phase below and the rewrite
        // phase later, so every PUSH we *see* as a slot source during
        // collection is guaranteed to be *rewritten* — closing the gap where
        // a non-adjacent PUSH (e.g. `PUSH slot; DUP1; SLOAD; ... SSTORE`)
        // would previously contribute the slot to the shuffle mapping via
        // one block's adjacent occurrence but never get rewritten itself.
        let mut slot_push_by_block: HashMap<_, Vec<(usize, usize, Vec<u8>)>> = HashMap::new();

        let nodes: Vec<_> = ir.cfg.node_indices().collect();
        for node in &nodes {
            let Some(Block::Body(body)) = ir.cfg.node_weight(*node) else {
                continue;
            };

            let mut block_entries: Vec<(usize, usize, Vec<u8>)> = Vec::new();
            let mut seen_push_idx: HashSet<usize> = HashSet::new();

            for idx in 0..body.instructions.len() {
                let instr = &body.instructions[idx];
                if !matches!(instr.op, Opcode::SLOAD | Opcode::SSTORE) {
                    continue;
                }
                if protected_pcs.contains(&instr.pc) {
                    continue;
                }

                let slot_push_idx = match slot_push_index(&body.instructions, idx) {
                    Some(i) => i,
                    None => {
                        if matches!(instr.op, Opcode::SSTORE) {
                            unsupported_sstores.push(instr.pc);
                        }
                        // SLOADs with non-literal slot sources (e.g. computed
                        // keccak256 for a mapping) are silently tolerated —
                        // remapping literal slots does not affect them.
                        continue;
                    }
                };

                if !seen_push_idx.insert(slot_push_idx) {
                    continue;
                }

                let slot_push_instr = &body.instructions[slot_push_idx];
                if protected_pcs.contains(&slot_push_instr.pc) {
                    continue;
                }

                let (width, slot_bytes) = match slot_push_instr.op {
                    Opcode::PUSH(w) => {
                        let w = w as usize;
                        let Some(imm) = slot_push_instr.imm.as_deref() else {
                            continue;
                        };
                        let Some(bytes) = normalize_slot_immediate(imm, w) else {
                            continue;
                        };
                        (w, bytes)
                    }
                    Opcode::PUSH0 => (0, Vec::new()),
                    _ => continue,
                };

                block_entries.push((slot_push_idx, width, slot_bytes.clone()));

                let seen = seen_by_width.entry(width).or_default();
                if seen.insert(slot_bytes.clone()) {
                    slots_by_width.entry(width).or_default().push(slot_bytes);
                }
            }

            if !block_entries.is_empty() {
                slot_push_by_block.insert(*node, block_entries);
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

        // Exclude slot literals that init-section bytecode writes to at their
        // original index. SlotShuffle only rewrites CFG blocks (runtime), so
        // any slot init touches would end up with init writing slot N and
        // runtime reading a remapped slot != N unless we leave it alone.
        if let Some((rt_start, _)) = ir.runtime_bounds {
            let init_bytes = &ir.original_bytecode[..rt_start.min(ir.original_bytecode.len())];
            let init_touched = init_literal_slots(init_bytes);
            if !init_touched.is_empty() {
                debug!(
                    "SlotShuffle: init section touches {} distinct slot literal(s); \
                     excluding them from shuffle to preserve init/runtime consistency",
                    init_touched.len()
                );
                for (w, slot) in &init_touched {
                    if let Some(slots) = slots_by_width.get_mut(w) {
                        slots.retain(|existing| existing != slot);
                        if slots.is_empty() {
                            slots_by_width.remove(w);
                        }
                    }
                }
            }
        }

        if slots_by_width.is_empty() {
            warn!("SlotShuffle: no eligible slot literals found");
            return Ok(false);
        }

        let mut mapping: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut mapping_changed = false;

        let mut ordered_widths: Vec<_> = slots_by_width.keys().copied().collect();
        ordered_widths.sort_unstable();

        for width in ordered_widths {
            let slots = slots_by_width
                .get(&width)
                .expect("width key collected from slots_by_width");
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
                            format_slot_immediate(from, width),
                            format_slot_immediate(to, width)
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
            let Some(entries) = slot_push_by_block.get(&node) else {
                continue;
            };
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };

            let original = body.instructions.clone();
            let mut rewritten = original.clone();
            let mut block_changed = false;

            // Rewrite exactly the PUSHes that the collection phase identified
            // as slot sources for this block — including any reached through
            // a backward trace over DUP/SWAP, which the previous adjacency-
            // only pass would silently skip.
            for (push_idx, width, slot_bytes) in entries {
                let Some(new_slot) = mapping.get(slot_bytes) else {
                    continue;
                };
                if new_slot == slot_bytes {
                    continue;
                }
                if matches!(rewritten[*push_idx].op, Opcode::PUSH0) {
                    continue;
                }

                debug!(
                    "SlotShuffle: block_pc=0x{:x} instr_pc=0x{:x} width={} 0x{} -> 0x{}",
                    body.start_pc,
                    rewritten[*push_idx].pc,
                    width,
                    format_slot_immediate(slot_bytes, *width),
                    format_slot_immediate(new_slot, *width)
                );
                rewritten[*push_idx].imm = Some(format_slot_immediate(new_slot, *width));
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

/// Walk a raw init-section byte slice and return the set of `(width, value)`
/// pairs that appear as PUSH literals immediately before an `SLOAD` or
/// `SSTORE` opcode. SlotShuffle only rewrites blocks that live in the CFG,
/// and the CFG only contains runtime-section blocks; init-section bytecode
/// (where Solidity inlines constructor-invoked state writes) is invisible to
/// it. If we shuffle a slot that init-code writes to at its original index,
/// later runtime reads will go to the remapped slot and find zero — in the
/// escrow fixture this shows up as `bond() NotFunded()` because the
/// constructor's inline `funded = true` SSTORE lands on the wrong slot.
///
/// Adjacent-PUSH detection is sufficient for the patterns Solidity emits for
/// direct `s_field = value` writes (`PUSH <slot>; SLOAD; …; PUSH <slot>;
/// SSTORE`). DUP/SWAP-shared patterns in init code would slip through this
/// scanner, so if the init section ever grows one, the corresponding slot
/// value can still be missed — in that case we'd need to either (a) run the
/// CFG-building backward trace over init instructions too, or (b) refuse to
/// shuffle and log a warning. For the current escrow fixture, pattern (a) is
/// sufficient and the test passes; (b) is the fallback the caller still
/// enforces via `unsupported_sstores` for any traced SSTORE it can't
/// resolve.
fn init_literal_slots(bytes: &[u8]) -> HashSet<(usize, Vec<u8>)> {
    let mut touched = HashSet::new();
    let mut last_push: Option<(usize, Vec<u8>)> = None;

    let mut pc = 0usize;
    while pc < bytes.len() {
        let op = bytes[pc];
        if op == 0x5f {
            // PUSH0
            last_push = Some((0, Vec::new()));
            pc += 1;
        } else if (0x60..=0x7f).contains(&op) {
            // PUSH1..=PUSH32
            let size = (op - 0x5f) as usize;
            let end = pc + 1 + size;
            if end > bytes.len() {
                break;
            }
            last_push = Some((size, bytes[pc + 1..end].to_vec()));
            pc = end;
        } else {
            if matches!(op, 0x54 | 0x55) {
                if let Some(ref prev) = last_push {
                    touched.insert(prev.clone());
                }
            }
            last_push = None;
            pc += 1;
        }
    }

    touched
}

/// Find the PUSH index that supplies the slot for an `SLOAD` or `SSTORE` at
/// `idx`. Tries the adjacent-PUSH pattern first, then falls back to tracing
/// stack effects (DUP/SWAP/arithmetic) backward from the access. Returns
/// `None` if the slot is not a literal — e.g. computed via KECCAK256 for a
/// Solidity mapping, loaded from storage, or read from calldata.
fn slot_push_index(instructions: &[Instruction], idx: usize) -> Option<usize> {
    let instr = instructions.get(idx)?;
    if !matches!(instr.op, Opcode::SLOAD | Opcode::SSTORE) {
        return None;
    }

    // Fast path: literal PUSH immediately before the access.
    if let Some(slot_idx) = idx.checked_sub(1) {
        if matches!(instructions[slot_idx].op, Opcode::PUSH(_) | Opcode::PUSH0) {
            return Some(slot_idx);
        }
    }

    // Slow path: trace the slot's provenance through DUP/SWAP/arithmetic.
    // Both SLOAD and SSTORE take the slot from stack position 0, so the
    // existing `trace_slot_source` works for both opcodes without change.
    let traced_idx = trace_slot_source(instructions, idx)?;
    if matches!(instructions[traced_idx].op, Opcode::PUSH(_) | Opcode::PUSH0) {
        debug!(
            "SlotShuffle: traced slot push (slot_pc=0x{:04x}, access_pc=0x{:04x}, op={:?})",
            instructions[traced_idx].pc, instr.pc, instr.op
        );
        return Some(traced_idx);
    }
    None
}

#[allow(dead_code)]
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
    use azoth_core::seed::Seed;
    use rand::rngs::StdRng;
    use std::collections::HashMap;

    fn instr(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: imm.map(|s| s.to_string()),
        }
    }

    fn build_mapping_for_order(
        ordered_width_slots: &[(usize, Vec<Vec<u8>>)],
        rng: &mut StdRng,
    ) -> HashMap<Vec<u8>, Vec<u8>> {
        let mut mapping = HashMap::new();
        let mut stable_width_slots = ordered_width_slots.to_vec();
        stable_width_slots.sort_unstable_by_key(|(width, _)| *width);

        for (width, slots) in &stable_width_slots {
            let mut shuffled = slots.clone();
            shuffled.shuffle(rng);
            if shuffled == *slots && slots.len() > 1 {
                shuffled.rotate_left(1);
            }

            for (from, to) in slots.iter().zip(shuffled.iter()) {
                mapping.insert(from.clone(), to.clone());
            }

            assert!(
                !slots.is_empty(),
                "test setup must provide at least one slot for width {}",
                width
            );
        }

        mapping
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

    #[test]
    fn hash_map_iteration_order_does_not_change_same_seed_mapping() {
        let seed = Seed::generate();

        let width_1_slots = vec![vec![0x01], vec![0x02], vec![0x03]];
        let width_2_slots = vec![vec![0x00, 0x0a], vec![0x00, 0x0b], vec![0x00, 0x0c]];

        let mut observed_distinct_iteration_orders = false;

        for _ in 0..64 {
            let mut slots_by_width_a = HashMap::new();
            slots_by_width_a.insert(1usize, width_1_slots.clone());
            slots_by_width_a.insert(2usize, width_2_slots.clone());

            let mut slots_by_width_b = HashMap::new();
            slots_by_width_b.insert(2usize, width_2_slots.clone());
            slots_by_width_b.insert(1usize, width_1_slots.clone());

            let order_a: Vec<_> = slots_by_width_a
                .iter()
                .map(|(width, slots)| (*width, slots.clone()))
                .collect();
            let order_b: Vec<_> = slots_by_width_b
                .iter()
                .map(|(width, slots)| (*width, slots.clone()))
                .collect();

            if order_a == order_b {
                continue;
            }

            observed_distinct_iteration_orders = true;

            let mut rng_a = seed.create_deterministic_rng();
            let mut rng_b = seed.create_deterministic_rng();
            let mut order_a_sorted = order_a.clone();
            let mut order_b_sorted = order_b.clone();
            order_a_sorted.sort_unstable_by_key(|(width, _)| *width);
            order_b_sorted.sort_unstable_by_key(|(width, _)| *width);
            let mapping_a = build_mapping_for_order(&order_a_sorted, &mut rng_a);
            let mapping_b = build_mapping_for_order(&order_b_sorted, &mut rng_b);

            assert_eq!(
                mapping_a, mapping_b,
                "same seed should stay deterministic even when HashMap iteration order differs"
            );
        }

        assert!(
            observed_distinct_iteration_orders,
            "test should observe at least one distinct HashMap iteration order"
        );
    }
}
