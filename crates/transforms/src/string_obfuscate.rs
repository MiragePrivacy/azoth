//! Obfuscate revert payloads by sanitizing selectors and Error(string) data.
//!
//! This pass handles custom-error selectors and ABI-encoded Error(string)
//! payloads. Error(string) handling uses structural detection for two selector
//! patterns:
//! 1. Direct: `PUSH4 0x08c379a0`
//! 2. Computed: `PUSH3 0x461bcd ; PUSH1 0xe5 ; SHL` (Solidity optimization)
//!
//! And two memory addressing patterns:
//! 1. Absolute: `PUSH value ; PUSH offset ; MSTORE`
//! 2. Relative: `PUSH value ; PUSH offset ; DUP3 ; ADD ; MSTORE` (base pointer on stack)

use crate::{collect_protected_pcs, Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::{Rng, RngCore};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Obfuscate revert payloads by randomizing custom-error selectors and
/// scrambling Error(string) literals.
#[derive(Default)]
pub struct StringObfuscate;

impl StringObfuscate {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for StringObfuscate {
    fn name(&self) -> &'static str {
        "StringObfuscate"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("StringObfuscate: scanning revert payloads");

        let mut changed = randomize_custom_error_selectors(ir, rng)?;
        let mut used_selectors = collect_push4_values(ir);

        let protected_pcs = collect_protected_pcs(ir);
        let nodes: Vec<_> = ir.cfg.node_indices().collect();

        for node in nodes {
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };

            let mut rewritten = body.instructions.clone();
            let mut block_changed = false;

            let data_push_indices = collect_error_string_data_pushes(&rewritten);
            if data_push_indices.is_empty() {
                continue;
            }

            if randomize_error_string_selector(
                &mut rewritten,
                rng,
                &mut used_selectors,
                &protected_pcs,
            ) {
                block_changed = true;
            }

            for idx in data_push_indices {
                let instr = &rewritten[idx];
                if protected_pcs.contains(&instr.pc) {
                    continue;
                }
                let (width, mut bytes) = match parse_push_immediate(instr) {
                    Some(value) => value,
                    None => continue,
                };
                if width == 0 {
                    continue;
                }

                // Scramble the literal bytes in-place with a random mask.
                for byte in &mut bytes {
                    *byte ^= (rng.next_u32() & 0xff) as u8;
                }
                rewritten[idx].imm = Some(hex::encode(&bytes));
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
            debug!("StringObfuscate: obfuscated revert payloads");
        } else {
            debug!("StringObfuscate: no eligible revert payloads found");
        }
        Ok(changed)
    }
}

/// Randomize custom-error selectors in revert construction blocks.
///
/// This is owned by StringObfuscate because custom errors and Error(string)
/// payloads are both revert-data fingerprints.
fn randomize_custom_error_selectors(ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
    debug!("StringObfuscate: scanning custom-error selectors");

    let protected_pcs = collect_protected_pcs(ir);
    let mut used = collect_push4_values(ir);
    let nodes: Vec<_> = ir.cfg.node_indices().collect();
    let mut changed = false;

    for node in nodes {
        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };

        let mut rewritten = body.instructions.clone();
        let mut block_changed = false;

        for idx in 0..rewritten.len() {
            if protected_pcs.contains(&rewritten[idx].pc) {
                continue;
            }
            let Some((selector, value_idx, shift_idx)) = shifted_selector_at(&rewritten, idx)
            else {
                continue;
            };
            if protected_pcs.contains(&rewritten[shift_idx].pc) {
                continue;
            }
            if is_solidity_builtin_error_selector(selector) {
                continue;
            }
            if !has_nearby_mstore_then_revert(&rewritten, idx + 3) {
                continue;
            }

            used.insert(selector);
            let replacement = next_selector(rng, &mut used);
            debug!(
                "StringObfuscate: custom error selector pc=0x{:x} 0x{:08x} -> 0x{:08x}",
                rewritten[value_idx].pc, selector, replacement
            );
            rewritten[value_idx].op = Opcode::PUSH(4);
            rewritten[value_idx].imm = Some(format!("{replacement:08x}"));
            rewritten[shift_idx].imm = Some("e0".to_string());
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

    Ok(changed)
}

fn collect_push4_values(ir: &CfgIrBundle) -> HashSet<u32> {
    let mut values = HashSet::new();
    for node in ir.cfg.node_indices() {
        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };
        for instr in &body.instructions {
            if matches!(instr.op, Opcode::PUSH(4)) {
                if let Some(value) = parse_u32(instr.imm.as_deref()) {
                    values.insert(value);
                }
            }
        }
    }
    values
}

fn randomize_error_string_selector(
    instructions: &mut [Instruction],
    rng: &mut StdRng,
    used: &mut HashSet<u32>,
    protected_pcs: &HashSet<usize>,
) -> bool {
    let mut changed = false;

    for idx in 0..instructions.len() {
        if protected_pcs.contains(&instructions[idx].pc) {
            continue;
        }

        if matches!(instructions[idx].op, Opcode::PUSH(4)) {
            if let Some((_, bytes)) = parse_push_immediate(&instructions[idx]) {
                if is_error_selector(&bytes) {
                    let replacement = next_selector(rng, used);
                    instructions[idx].imm = Some(format!("{replacement:08x}"));
                    changed = true;
                    continue;
                }
            }
        }

        if matches!(instructions[idx].op, Opcode::SHL) && idx >= 2 {
            let shift_idx = idx - 1;
            let value_idx = idx - 2;
            if protected_pcs.contains(&instructions[value_idx].pc) {
                continue;
            }

            let shift_ok = matches!(
                parse_push_immediate(&instructions[shift_idx]),
                Some((_, bytes)) if parse_usize_be(&bytes) == Some(0xe5)
            );
            let value_ok = matches!(
                parse_push_immediate(&instructions[value_idx]),
                Some((_, bytes)) if bytes == [0x46, 0x1b, 0xcd] ||
                    (bytes.len() > 3 && bytes.ends_with(&[0x46, 0x1b, 0xcd]) &&
                     bytes[..bytes.len()-3].iter().all(|&b| b == 0))
            );
            if !shift_ok || !value_ok {
                continue;
            }

            let (replacement_push3, selector) = next_shifted_selector3(rng, used);
            instructions[value_idx].imm = Some(format!("{replacement_push3:06x}"));
            used.insert(selector);
            changed = true;
        }
    }

    changed
}

fn next_selector(rng: &mut StdRng, used: &mut HashSet<u32>) -> u32 {
    loop {
        let value = rng.random::<u32>();
        if value == 0 || is_solidity_builtin_error_selector(value) || used.contains(&value) {
            continue;
        }
        used.insert(value);
        return value;
    }
}

fn next_shifted_selector3(rng: &mut StdRng, used: &HashSet<u32>) -> (u32, u32) {
    loop {
        let value = rng.next_u32() & 0x00ff_ffff;
        let selector = value << 5;
        if value == 0 || is_solidity_builtin_error_selector(selector) || used.contains(&selector) {
            continue;
        }
        return (value, selector);
    }
}

fn parse_u32(imm: Option<&str>) -> Option<u32> {
    let imm = imm?;
    if imm.len() != 8 {
        return None;
    }
    u32::from_str_radix(imm, 16).ok()
}

fn is_solidity_builtin_error_selector(selector: u32) -> bool {
    matches!(selector, 0x08c3_79a0 | 0x4e48_7b71)
}

fn shifted_selector_at(instructions: &[Instruction], idx: usize) -> Option<(u32, usize, usize)> {
    let value = instructions.get(idx)?;
    let Some(shift) = instructions.get(idx + 1) else {
        return None;
    };
    let Some(shl) = instructions.get(idx + 2) else {
        return None;
    };
    if !matches!(value.op, Opcode::PUSH(1..=4))
        || !matches!(shift.op, Opcode::PUSH(1))
        || shl.op != Opcode::SHL
    {
        return None;
    }

    let (_, value_bytes) = parse_push_immediate(value)?;
    let (_, shift_bytes) = parse_push_immediate(shift)?;
    let value = parse_usize_be(&value_bytes)?;
    let shift = parse_usize_be(&shift_bytes)?;
    let selector = recover_left_aligned_selector(value, shift)?;
    Some((selector, idx, idx + 1))
}

fn recover_left_aligned_selector(value: usize, shift: usize) -> Option<u32> {
    if shift < 224 {
        return None;
    }
    let extra_shift = shift - 224;
    if extra_shift >= 32 {
        return None;
    }
    let selector = (value as u64).checked_shl(extra_shift as u32)?;
    if selector == 0 || selector > u32::MAX as u64 {
        return None;
    }
    Some(selector as u32)
}

fn has_nearby_mstore_then_revert(instructions: &[Instruction], start: usize) -> bool {
    let end = (start + 16).min(instructions.len());
    let mut saw_mstore = false;

    for instr in &instructions[start..end] {
        match instr.op {
            Opcode::MSTORE => saw_mstore = true,
            Opcode::REVERT => return saw_mstore,
            Opcode::JUMP
            | Opcode::JUMPI
            | Opcode::STOP
            | Opcode::RETURN
            | Opcode::CALL
            | Opcode::DELEGATECALL
            | Opcode::STATICCALL => return false,
            _ => {}
        }
    }

    false
}

fn collect_error_string_data_pushes(instructions: &[Instruction]) -> Vec<usize> {
    // Try structural detection first
    if let Some(indices) = try_structural_detection(instructions) {
        return indices;
    }

    // Fallback: heuristic detection for blocks without full Error(string) structure
    // This catches string data in blocks that were split by other transforms
    collect_ascii_string_pushes(instructions)
}

/// Structural detection: look for full Error(string) ABI pattern in block.
fn try_structural_detection(instructions: &[Instruction]) -> Option<Vec<usize>> {
    // Find if this block has an Error(string) selector pattern.
    let _selector_idx = find_error_selector_index(instructions)?;

    // Collect all MSTORE writes with their relative offsets.
    let mstore_writes = collect_mstore_writes(instructions);
    if mstore_writes.is_empty() {
        return None;
    }

    // Find the offset word (should be 0x20) at relative offset 0x04
    let offset_ok = matches!(
        mstore_writes.get(&0x04),
        Some((_, bytes)) if parse_usize_be(bytes) == Some(0x20)
    );
    if !offset_ok {
        return None;
    }

    // Find the length at relative offset 0x24
    let length = match mstore_writes.get(&0x24) {
        Some((_, bytes)) => parse_usize_be(bytes),
        _ => None,
    };
    let length = match length {
        Some(len) if len > 0 => len,
        _ => return None,
    };

    // String data starts at offset 0x44 and spans ceil(length/32)*32 bytes
    let data_start = 0x44usize;
    let data_end = data_start + length.div_ceil(32) * 32;
    let mut data_push_indices = Vec::new();

    for offset in (data_start..data_end).step_by(32) {
        if let Some((idx, _)) = mstore_writes.get(&offset) {
            data_push_indices.push(*idx);
        }
    }

    if data_push_indices.is_empty() {
        return None;
    }

    debug!(
        "StringObfuscate: structural detection found {} chunk(s) (length={})",
        data_push_indices.len(),
        length
    );

    Some(data_push_indices)
}

/// Heuristic detection: find PUSH instructions with high ASCII content.
/// Used as fallback when structural detection fails (e.g., after block splitting).
fn collect_ascii_string_pushes(instructions: &[Instruction]) -> Vec<usize> {
    let mut indices = Vec::new();

    for (idx, instr) in instructions.iter().enumerate() {
        // Only consider large PUSH instructions (PUSH16+)
        let Opcode::PUSH(width) = instr.op else {
            continue;
        };
        if width < 16 {
            continue;
        }

        let Some((_, bytes)) = parse_push_immediate(instr) else {
            continue;
        };

        // Check if this looks like ASCII string data
        if is_likely_ascii_string(&bytes) {
            debug!(
                "StringObfuscate: heuristic detection found string at idx {} (PC {:#x})",
                idx, instr.pc
            );
            indices.push(idx);
        }
    }

    indices
}

/// Check if bytes look like ASCII string data.
/// Returns true if the majority of non-null bytes are printable ASCII.
fn is_likely_ascii_string(bytes: &[u8]) -> bool {
    // Find where content ends (before null padding)
    let content_end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);

    if content_end < 4 {
        return false; // Too short to be meaningful string
    }

    let content = &bytes[..content_end];

    // Count printable ASCII characters (0x20-0x7E)
    let printable_count = content
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b))
        .count();

    // Require at least 60% printable characters
    let ratio = printable_count as f32 / content.len() as f32;
    ratio >= 0.6
}

/// Find the index of an Error(string) selector in the instruction stream.
/// Returns Some(idx) if found, None otherwise.
fn find_error_selector_index(instructions: &[Instruction]) -> Option<usize> {
    for (idx, instr) in instructions.iter().enumerate() {
        // Pattern 1: Direct PUSH4 0x08c379a0
        if let Some((_, bytes)) = parse_push_immediate(instr) {
            if is_error_selector(&bytes) {
                return Some(idx);
            }
        }

        // Pattern 2: Computed selector via SHL
        // PUSH3 0x461bcd ; PUSH1 0xe5 ; SHL
        // 0x461bcd << 0xe5 = 0x08c379a0 (left-aligned in 32-byte word)
        if matches!(instr.op, Opcode::SHL) && idx >= 2 {
            let shift_instr = &instructions[idx - 1];
            let value_instr = &instructions[idx - 2];

            // Check for PUSH1 0xe5 (shift amount 229)
            let shift_ok = matches!(
                parse_push_immediate(shift_instr),
                Some((_, bytes)) if parse_usize_be(&bytes) == Some(0xe5)
            );

            // Check for PUSH3 0x461bcd
            let value_ok = matches!(
                parse_push_immediate(value_instr),
                Some((_, bytes)) if bytes == [0x46, 0x1b, 0xcd] ||
                    (bytes.len() > 3 && bytes.ends_with(&[0x46, 0x1b, 0xcd]) &&
                     bytes[..bytes.len()-3].iter().all(|&b| b == 0))
            );

            if shift_ok && value_ok {
                return Some(idx - 2); // Return index of the value PUSH
            }
        }
    }
    None
}

/// Collect MSTORE writes, handling both absolute and relative addressing.
/// Returns a map of relative_offset -> (value_push_index, value_bytes).
fn collect_mstore_writes(instructions: &[Instruction]) -> HashMap<usize, (usize, Vec<u8>)> {
    let mut writes: HashMap<usize, (usize, Vec<u8>)> = HashMap::new();

    for idx in 0..instructions.len() {
        if !matches!(instructions[idx].op, Opcode::MSTORE) {
            continue;
        }

        // Try to match different MSTORE patterns
        if let Some((offset, value_idx, value_bytes)) = try_parse_mstore_pattern(instructions, idx)
        {
            writes.insert(offset, (value_idx, value_bytes));
        }
    }

    writes
}

/// Try to parse an MSTORE pattern at the given index.
/// Returns Some((relative_offset, value_push_index, value_bytes)) if successful.
fn try_parse_mstore_pattern(
    instructions: &[Instruction],
    mstore_idx: usize,
) -> Option<(usize, usize, Vec<u8>)> {
    // Pattern 1: Absolute addressing
    // PUSH <value> ; PUSH <offset> ; MSTORE
    if mstore_idx >= 2 {
        let offset_idx = mstore_idx - 1;
        let value_idx = mstore_idx - 2;

        if let (Some((_, value_bytes)), Some((_, offset_bytes))) = (
            parse_push_immediate(&instructions[value_idx]),
            parse_push_immediate(&instructions[offset_idx]),
        ) {
            if let Some(offset) = parse_usize_be(&offset_bytes) {
                return Some((offset, value_idx, value_bytes));
            }
        }
    }

    // Pattern 2: Relative addressing with DUP+ADD
    // PUSH <value> ; PUSH <offset> ; DUP3 ; ADD ; MSTORE
    if mstore_idx >= 4 {
        let add_idx = mstore_idx - 1;
        let dup_idx = mstore_idx - 2;
        let offset_idx = mstore_idx - 3;
        let value_idx = mstore_idx - 4;

        if matches!(instructions[add_idx].op, Opcode::ADD)
            && matches!(instructions[dup_idx].op, Opcode::DUP(_))
        {
            if let (Some((_, value_bytes)), Some((_, offset_bytes))) = (
                parse_push_immediate(&instructions[value_idx]),
                parse_push_immediate(&instructions[offset_idx]),
            ) {
                if let Some(offset) = parse_usize_be(&offset_bytes) {
                    return Some((offset, value_idx, value_bytes));
                }
            }
        }
    }

    // Pattern 3: Selector write with DUP2
    // <selector_computation> ; DUP2 ; MSTORE
    // The selector is written at offset 0 (base pointer)
    if mstore_idx >= 2 {
        let dup_idx = mstore_idx - 1;
        if matches!(instructions[dup_idx].op, Opcode::DUP(2)) {
            // Look back for the selector value (could be from SHL or direct PUSH)
            // For SHL pattern: ... ; SHL ; DUP2 ; MSTORE
            if mstore_idx >= 4 {
                let shl_idx = mstore_idx - 2;
                if matches!(instructions[shl_idx].op, Opcode::SHL) {
                    // This is the selector at offset 0
                    return Some((0, shl_idx, vec![0x08, 0xc3, 0x79, 0xa0]));
                }
            }
            // For direct PUSH: PUSH4 <selector> ; DUP2 ; MSTORE
            if mstore_idx >= 3 {
                let value_idx = mstore_idx - 2;
                if let Some((_, value_bytes)) = parse_push_immediate(&instructions[value_idx]) {
                    if is_error_selector(&value_bytes) {
                        return Some((0, value_idx, value_bytes));
                    }
                }
            }
        }
    }

    None
}

fn parse_push_immediate(instr: &Instruction) -> Option<(usize, Vec<u8>)> {
    match instr.op {
        Opcode::PUSH(width) => {
            let width = width as usize;
            let imm = instr.imm.as_deref()?;
            normalize_immediate(imm, width).map(|bytes| (width, bytes))
        }
        Opcode::PUSH0 => Some((0, Vec::new())),
        _ => None,
    }
}

fn normalize_immediate(imm: &str, width: usize) -> Option<Vec<u8>> {
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

fn parse_usize_be(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let trimmed = if bytes.len() > 8 {
        let (prefix, suffix) = bytes.split_at(bytes.len() - 8);
        if prefix.iter().any(|&b| b != 0) {
            return None;
        }
        suffix
    } else {
        bytes
    };
    let mut value: usize = 0;
    for &b in trimmed {
        value = (value << 8) | (b as usize);
    }
    Some(value)
}

fn is_error_selector(bytes: &[u8]) -> bool {
    const SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
    if bytes.len() < 4 {
        return false;
    }
    if bytes.starts_with(&SELECTOR) && bytes[4..].iter().all(|&b| b == 0) {
        return true;
    }
    if bytes.ends_with(&SELECTOR) && bytes[..bytes.len() - 4].iter().all(|&b| b == 0) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::Block;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;
    use std::collections::HashSet;

    const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn instr(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: imm.map(|s| s.to_string()),
        }
    }

    #[test]
    fn detects_direct_selector_absolute_addressing() {
        // Pattern: PUSH4 selector ; PUSH offset ; MSTORE (absolute)
        let instructions = vec![
            instr(0, Opcode::PUSH(4), Some("08c379a0")),
            instr(5, Opcode::PUSH(1), Some("00")),
            instr(7, Opcode::MSTORE, None),
            instr(8, Opcode::PUSH(1), Some("20")),
            instr(10, Opcode::PUSH(1), Some("04")),
            instr(12, Opcode::MSTORE, None),
            instr(13, Opcode::PUSH(1), Some("13")), // length = 19
            instr(15, Opcode::PUSH(1), Some("24")),
            instr(17, Opcode::MSTORE, None),
            instr(
                18,
                Opcode::PUSH(32),
                Some("436f6e7472616374206e6f742066756e64656400000000000000000000000000"),
            ),
            instr(51, Opcode::PUSH(1), Some("44")),
            instr(53, Opcode::MSTORE, None),
            instr(54, Opcode::REVERT, None),
        ];

        let indices = collect_error_string_data_pushes(&instructions);
        assert_eq!(indices, vec![9]); // index of string data PUSH
    }

    #[test]
    fn detects_computed_selector_relative_addressing() {
        // Pattern: PUSH3 0x461bcd ; PUSH1 0xe5 ; SHL ; DUP2 ; MSTORE (Solidity optimization)
        // Then relative addressing: PUSH value ; PUSH offset ; DUP3 ; ADD ; MSTORE
        let instructions = vec![
            // MLOAD for base pointer (simulated)
            instr(0, Opcode::PUSH(1), Some("40")),
            instr(2, Opcode::MLOAD, None),
            // Computed selector: 0x461bcd << 0xe5 = 0x08c379a0...
            instr(3, Opcode::PUSH(3), Some("461bcd")),
            instr(7, Opcode::PUSH(1), Some("e5")),
            instr(9, Opcode::SHL, None),
            instr(10, Opcode::DUP(2), None),
            instr(11, Opcode::MSTORE, None), // selector at base+0
            // Offset value (0x20) at base+0x04
            instr(12, Opcode::PUSH(1), Some("20")),
            instr(14, Opcode::PUSH(1), Some("04")),
            instr(16, Opcode::DUP(3), None),
            instr(17, Opcode::ADD, None),
            instr(18, Opcode::MSTORE, None),
            // Length (0x1d = 29) at base+0x24
            instr(19, Opcode::PUSH(1), Some("1d")),
            instr(21, Opcode::PUSH(1), Some("24")),
            instr(23, Opcode::DUP(3), None),
            instr(24, Opcode::ADD, None),
            instr(25, Opcode::MSTORE, None),
            // String data at base+0x44
            instr(
                26,
                Opcode::PUSH(32),
                Some("4f6e6c792063616c6c61626c6520627920746865206465706c6f796572000000"),
            ),
            instr(59, Opcode::PUSH(1), Some("44")),
            instr(61, Opcode::DUP(3), None),
            instr(62, Opcode::ADD, None),
            instr(63, Opcode::MSTORE, None),
            instr(64, Opcode::REVERT, None),
        ];

        let indices = collect_error_string_data_pushes(&instructions);
        assert_eq!(indices, vec![17]); // index of string data PUSH
    }

    #[test]
    fn ignores_panic_selector() {
        // Panic(uint256) selector: 0x4e487b71
        let instructions = vec![
            instr(0, Opcode::PUSH(4), Some("4e487b71")),
            instr(5, Opcode::PUSH(1), Some("00")),
            instr(7, Opcode::MSTORE, None),
            instr(8, Opcode::REVERT, None),
        ];

        let indices = collect_error_string_data_pushes(&instructions);
        assert!(indices.is_empty());
    }

    #[test]
    fn detects_multi_chunk_string() {
        // String longer than 32 bytes requires multiple PUSH32s
        let instructions = vec![
            instr(0, Opcode::PUSH(4), Some("08c379a0")),
            instr(5, Opcode::PUSH(1), Some("00")),
            instr(7, Opcode::MSTORE, None),
            instr(8, Opcode::PUSH(1), Some("20")),
            instr(10, Opcode::PUSH(1), Some("04")),
            instr(12, Opcode::MSTORE, None),
            instr(13, Opcode::PUSH(1), Some("40")), // length = 64 bytes
            instr(15, Opcode::PUSH(1), Some("24")),
            instr(17, Opcode::MSTORE, None),
            // First chunk at 0x44
            instr(
                18,
                Opcode::PUSH(32),
                Some("5468652063656e74726163742077617320616e6f7420706620756e6420646f72"),
            ),
            instr(51, Opcode::PUSH(1), Some("44")),
            instr(53, Opcode::MSTORE, None),
            // Second chunk at 0x64
            instr(
                54,
                Opcode::PUSH(32),
                Some("206861732070656e6520647261696e656420616c726561647900000000000000"),
            ),
            instr(87, Opcode::PUSH(1), Some("64")),
            instr(89, Opcode::MSTORE, None),
            instr(90, Opcode::REVERT, None),
        ];

        let indices = collect_error_string_data_pushes(&instructions);
        assert_eq!(indices, vec![9, 12]); // both chunk indices
    }

    #[test]
    fn randomizes_direct_error_string_selector() {
        let mut instructions = vec![
            instr(0, Opcode::PUSH(4), Some("08c379a0")),
            instr(5, Opcode::PUSH(1), Some("00")),
            instr(7, Opcode::MSTORE, None),
        ];
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();
        let mut used = HashSet::new();
        let protected = HashSet::new();

        let changed =
            randomize_error_string_selector(&mut instructions, &mut rng, &mut used, &protected);

        assert!(changed);
        assert_ne!(instructions[0].imm.as_deref(), Some("08c379a0"));
        assert_ne!(instructions[0].imm.as_deref(), Some("4e487b71"));
    }

    #[tokio::test]
    async fn string_obfuscate_randomizes_custom_error_selector() {
        let bytecode = "0x63d5ef09ba60e01b5f5260045ffd";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = StringObfuscate::new().apply(&mut ir, &mut rng).unwrap();
        assert!(changed);

        let mut selectors = Vec::new();
        for node in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node] {
                for instr in &body.instructions {
                    if matches!(instr.op, Opcode::PUSH(4)) {
                        selectors.push(instr.imm.clone().unwrap());
                    }
                }
            }
        }

        assert_eq!(selectors.len(), 1);
        assert_ne!(selectors[0], "d5ef09ba");
    }

    #[tokio::test]
    async fn string_obfuscate_randomizes_optimized_custom_error_selector() {
        // Solidity can compress a left-aligned selector when the low selector
        // bit is zero: 0x022e2581 << 0xe1 reconstructs 0x045c4b02.
        let bytecode = "0x63022e258160e11b5f5260045ffd";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = StringObfuscate::new().apply(&mut ir, &mut rng).unwrap();
        assert!(changed);

        let mut selector = None;
        let mut shift = None;
        for node in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node] {
                for instr in &body.instructions {
                    if matches!(instr.op, Opcode::PUSH(4)) {
                        selector = instr.imm.clone();
                    }
                    if matches!(instr.op, Opcode::PUSH(1)) && shift.is_none() {
                        shift = instr.imm.clone();
                    }
                }
            }
        }

        assert_ne!(selector.as_deref(), Some("045c4b02"));
        assert_ne!(selector.as_deref(), Some("022e2581"));
        assert_eq!(shift.as_deref(), Some("e0"));
    }
}
