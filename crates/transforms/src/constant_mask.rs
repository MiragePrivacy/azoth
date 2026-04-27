//! Constant masking.
//!
//! This pass hides eligible literal constants from both deployed runtime bytecode
//! and deployment bytecode. Init-code `PUSH4..PUSH32` literals are handled 
//! separately so constants that appear only in constructor/deployment code do not
//! remain greppable in transaction input.
//!
//! ```text
//! PUSH<n> share_0
//! <dynamic zero or identity noise>
//! PUSH<n> share_1
//! XOR
//! ...
//! PUSH<n> share_N
//! XOR
//! ```
//!
//! The stack result is identical to the original single PUSH, but the raw
//! constant no longer appears as a contiguous byte sequence and there is no
//! fixed masked/key reconstruction shape. Per-site templates use 3-5 XOR
//! shares and mix dynamic zero identities through ADD, SUB, XOR, OR, SHL, and
//! SHR. Jump-target literals and immutable placeholder writes are handled
//! conservatively so size-growing runtime rewrites remain compatible with the
//! final PC-remapping phase.

use crate::{collect_protected_pcs, Error, Result, Transform};
use azoth_core::cfg_ir::{push_reaches_jump, Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::detection::SectionKind;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::RngCore;
use std::collections::HashSet;
use tracing::debug;

/// Obfuscates literal constants via per-use runtime reconstruction.
#[derive(Debug, Clone)]
pub struct ConstantMask {
    min_width: u8,
    mask_runtime: bool,
}

impl Default for ConstantMask {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantMask {
    /// Creates a runtime + init-code literal-mask transform.
    pub fn new() -> Self {
        Self {
            min_width: 2,
            mask_runtime: true,
        }
    }

    /// Creates a literal-mask transform with a custom runtime minimum PUSH width.
    pub fn with_min_width(min_width: u8) -> Self {
        Self {
            min_width: min_width.clamp(1, 32),
            mask_runtime: true,
        }
    }
}

impl Transform for ConstantMask {
    fn name(&self) -> &'static str {
        "ConstantMask"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("ConstantMask: masking init literals");

        let mut changed = false;
        if rewrite_call_selector_mstores(ir, rng)? {
            changed = true;
        }

        if self.mask_runtime {
            if mask_runtime_literals(ir, rng, self.min_width)? {
                changed = true;
            }
        }

        if mask_init_literals(ir, rng)? {
            changed = true;
        }

        Ok(changed)
    }
}

fn rewrite_call_selector_mstores(ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
    let runtime_bounds = ir.runtime_bounds();
    let nodes: Vec<_> = ir.cfg.node_indices().collect();
    let mut changed = false;
    let mut next_synthetic_pc = next_available_pc(ir);

    for node in nodes {
        if ir.dispatcher_blocks.contains(&node.index()) {
            continue;
        }

        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };
        if !block_is_runtime(body.start_pc, runtime_bounds) {
            continue;
        }

        let original = body.instructions.clone();
        let mut rewritten = Vec::with_capacity(original.len());
        let mut idx = 0usize;
        let mut block_changed = false;

        while idx < original.len() {
            if let Some(pattern) = call_selector_mstore_at(&original, idx) {
                let decoy = random_decoy_selector(pattern.selector, rng);
                let mut selector_push = original[idx].clone();
                selector_push.op = Opcode::PUSH(4);
                selector_push.imm = Some(format!("{decoy:08x}"));
                rewritten.push(selector_push);
                if let (Some(shift_idx), Some(shl_idx)) = (pattern.shift_idx, pattern.shl_idx) {
                    let mut shift = original[shift_idx].clone();
                    shift.op = Opcode::PUSH(1);
                    shift.imm = Some("e0".to_string());
                    rewritten.push(shift);
                    rewritten.push(original[shl_idx].clone());
                } else {
                    rewritten.push(Instruction {
                        pc: next_synthetic_pc,
                        op: Opcode::PUSH(1),
                        imm: Some("e0".to_string()),
                    });
                    next_synthetic_pc = next_synthetic_pc.saturating_add(1);
                    rewritten.push(Instruction {
                        pc: next_synthetic_pc,
                        op: Opcode::SHL,
                        imm: None,
                    });
                    next_synthetic_pc = next_synthetic_pc.saturating_add(1);
                }
                rewritten.push(original[pattern.dup_idx].clone());
                rewritten.push(original[pattern.mstore_idx].clone());
                emit_selector_mstore8_patches(
                    pattern.selector,
                    decoy,
                    &mut next_synthetic_pc,
                    &mut rewritten,
                    rng,
                );
                block_changed = true;
                idx = pattern.end_idx;
                continue;
            }

            rewritten.push(original[idx].clone());
            idx += 1;
        }

        if block_changed {
            let mut new_body = body.clone();
            new_body.instructions = rewritten;
            new_body.max_stack = new_body.max_stack.saturating_add(3);
            ir.overwrite_block(node, new_body)
                .map_err(|e| Error::CoreError(e.to_string()))?;
            changed = true;
        }
    }

    Ok(changed)
}

#[derive(Clone, Copy)]
struct CallSelectorMstore {
    selector: u32,
    shift_idx: Option<usize>,
    shl_idx: Option<usize>,
    dup_idx: usize,
    mstore_idx: usize,
    end_idx: usize,
}

fn call_selector_mstore_at(instructions: &[Instruction], idx: usize) -> Option<CallSelectorMstore> {
    if let Some((selector, dup_idx, mstore_idx, end_idx)) =
        shifted_call_selector_mstore_at(instructions, idx)
    {
        if has_call_after(instructions, end_idx) {
            return Some(CallSelectorMstore {
                selector,
                shift_idx: Some(idx + 1),
                shl_idx: Some(idx + 2),
                dup_idx,
                mstore_idx,
                end_idx,
            });
        }
    }

    if let Some((selector, dup_idx, mstore_idx, end_idx)) =
        left_aligned_call_selector_mstore_at(instructions, idx)
    {
        if has_call_after(instructions, end_idx) {
            return Some(CallSelectorMstore {
                selector,
                shift_idx: None,
                shl_idx: None,
                dup_idx,
                mstore_idx,
                end_idx,
            });
        }
    }

    None
}

fn shifted_call_selector_mstore_at(
    instructions: &[Instruction],
    idx: usize,
) -> Option<(u32, usize, usize, usize)> {
    let value = instructions.get(idx)?;
    let shift = instructions.get(idx + 1)?;
    let shl = instructions.get(idx + 2)?;
    let dup = instructions.get(idx + 3)?;
    let mstore = instructions.get(idx + 4)?;

    if !matches!(value.op, Opcode::PUSH(1..=4))
        || !matches!(shift.op, Opcode::PUSH(1))
        || shl.op != Opcode::SHL
        || dup.op != Opcode::DUP(2)
        || mstore.op != Opcode::MSTORE
    {
        return None;
    }

    let value_bytes = parse_push_bytes(value, push_width(value)?)?;
    let shift_bytes = parse_push_bytes(shift, 1)?;
    let value = parse_usize_be(&value_bytes)?;
    let shift = parse_usize_be(&shift_bytes)?;
    let selector = recover_left_aligned_selector(value, shift)?;
    Some((selector, idx + 3, idx + 4, idx + 5))
}

fn left_aligned_call_selector_mstore_at(
    instructions: &[Instruction],
    idx: usize,
) -> Option<(u32, usize, usize, usize)> {
    let value = instructions.get(idx)?;
    let dup = instructions.get(idx + 1)?;
    let mstore = instructions.get(idx + 2)?;

    if !matches!(value.op, Opcode::PUSH(32))
        || dup.op != Opcode::DUP(2)
        || mstore.op != Opcode::MSTORE
    {
        return None;
    }

    let bytes = parse_push_bytes(value, 32)?;
    if bytes[4..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let selector = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if selector == 0 {
        return None;
    }

    Some((selector, idx + 1, idx + 2, idx + 3))
}

fn push_width(instr: &Instruction) -> Option<u8> {
    let Opcode::PUSH(width) = instr.op else {
        return None;
    };
    Some(width)
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

fn has_call_after(instructions: &[Instruction], start: usize) -> bool {
    for instr in instructions.iter().skip(start) {
        match instr.op {
            Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL => {
                return true;
            }
            Opcode::REVERT
            | Opcode::RETURN
            | Opcode::STOP
            | Opcode::JUMP
            | Opcode::JUMPI
            | Opcode::SELFDESTRUCT => return false,
            _ => {}
        }
    }
    false
}

fn random_decoy_selector(original: u32, rng: &mut StdRng) -> u32 {
    loop {
        let value = rng.next_u32();
        if value != 0 && value != original {
            return value;
        }
    }
}

fn emit_selector_mstore8_patches(
    selector: u32,
    decoy: u32,
    next_synthetic_pc: &mut usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    let real = selector.to_be_bytes();
    let decoy = decoy.to_be_bytes();
    let mut offsets = [0usize, 1, 2, 3];
    shuffle_offsets(&mut offsets, rng);

    for offset in offsets {
        if real[offset] == decoy[offset] {
            continue;
        }
        emit_selector_byte_patch(real[offset], offset, next_synthetic_pc, out, rng);
    }
}

fn shuffle_offsets(offsets: &mut [usize; 4], rng: &mut StdRng) {
    for i in (1..offsets.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        offsets.swap(i, j);
    }
}

fn emit_selector_byte_patch(
    byte: u8,
    offset: usize,
    next_synthetic_pc: &mut usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    let mut fresh_pc = || {
        let pc = *next_synthetic_pc;
        *next_synthetic_pc = next_synthetic_pc.saturating_add(1);
        pc
    };

    emit_reconstructed_value_with_fresh_pc(&[byte], 1, &mut fresh_pc, out, rng);

    if offset == 0 {
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::DUP(2),
            imm: None,
        });
    } else {
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::PUSH(1),
            imm: Some(format!("{offset:02x}")),
        });
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::DUP(3),
            imm: None,
        });
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::ADD,
            imm: None,
        });
    }

    out.push(Instruction {
        pc: fresh_pc(),
        op: Opcode::MSTORE8,
        imm: None,
    });
}

fn mask_runtime_literals(ir: &mut CfgIrBundle, rng: &mut StdRng, min_width: u8) -> Result<bool> {
    debug!("ConstantMask: scanning runtime PUSH{min_width}..PUSH32 literals");

    let protected_pcs = collect_protected_pcs(ir);
    let jumpdest_values = collect_jumpdest_values(ir);
    let immutable_offsets = collect_init_immutable_offsets(ir);
    let runtime_bounds = ir.runtime_bounds();
    let runtime_start = runtime_bounds.map(|(start, _)| start).unwrap_or(0);
    let nodes: Vec<_> = ir.cfg.node_indices().collect();
    let mut changed = false;
    let mut pending_immutable_masks: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut next_synthetic_pc = next_available_pc(ir);

    for node in nodes {
        if ir.dispatcher_blocks.contains(&node.index()) {
            continue;
        }

        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };
        if !block_is_runtime(body.start_pc, runtime_bounds) {
            continue;
        }

        let original = body.instructions.clone();
        let mut rewritten = Vec::with_capacity(original.len());
        let mut block_changed = false;
        let mut new_max_stack = body.max_stack.saturating_add(1);

        for (idx, instr) in original.iter().enumerate() {
            let Opcode::PUSH(width) = instr.op else {
                rewritten.push(instr.clone());
                continue;
            };
            let is_selector_shift = is_selector_shift_literal(&original, idx);
            if width < min_width && !is_selector_shift {
                rewritten.push(instr.clone());
                continue;
            }
            if protected_pcs.contains(&instr.pc)
                || is_jump_literal(&original, idx, &jumpdest_values)
            {
                rewritten.push(instr.clone());
                continue;
            }

            let Some(value) = parse_push_bytes(instr, width) else {
                rewritten.push(instr.clone());
                continue;
            };
            let old_immutable_offset = instr.pc.saturating_add(1).saturating_sub(runtime_start);
            let is_zero = value.iter().all(|byte| *byte == 0);
            let is_immutable_placeholder =
                width == 32 && is_zero && immutable_offsets.contains(&old_immutable_offset);
            if is_zero && !is_immutable_placeholder {
                rewritten.push(instr.clone());
                continue;
            }

            if is_immutable_placeholder {
                let key = random_nonzero_bytes(width as usize, rng);
                let masked = xor_bytes(&value, &key);
                if masked == value {
                    rewritten.push(instr.clone());
                    continue;
                }
                emit_xor_masked_literal(
                    instr.pc,
                    width,
                    &masked,
                    &key,
                    &mut rewritten,
                    &mut next_synthetic_pc,
                    rng,
                );
                pending_immutable_masks.push((old_immutable_offset, key));
            } else {
                emit_reconstructed_value(
                    instr.pc,
                    width,
                    &value,
                    &mut rewritten,
                    &mut next_synthetic_pc,
                    rng,
                );
            }
            block_changed = true;
            new_max_stack = new_max_stack.max(body.max_stack.saturating_add(5));
        }

        if block_changed {
            let mut new_body = body.clone();
            new_body.instructions = rewritten;
            new_body.max_stack = new_max_stack;
            ir.overwrite_block(node, new_body)
                .map_err(|e| Error::CoreError(e.to_string()))?;
            changed = true;
        }
    }

    for (offset, key) in pending_immutable_masks {
        ir.immutable_masks.insert(offset, key);
    }

    Ok(changed)
}

fn is_selector_shift_literal(instructions: &[Instruction], idx: usize) -> bool {
    let Some(instr) = instructions.get(idx) else {
        return false;
    };
    let Opcode::PUSH(1) = instr.op else {
        return false;
    };
    if !matches!(instr.imm.as_deref(), Some("e0" | "e5")) {
        return false;
    }
    instructions
        .get(idx + 1)
        .is_some_and(|next| next.op == Opcode::SHL)
}

fn block_is_runtime(start_pc: usize, runtime_bounds: Option<(usize, usize)>) -> bool {
    match runtime_bounds {
        Some((start, end)) => start_pc >= start && start_pc < end,
        None => true,
    }
}

fn collect_jumpdest_values(ir: &CfgIrBundle) -> HashSet<usize> {
    let mut values = HashSet::new();
    let runtime_start = ir.runtime_bounds().map(|(start, _)| start).unwrap_or(0);

    for node in ir.cfg.node_indices() {
        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };
        for instr in &body.instructions {
            if instr.op == Opcode::JUMPDEST {
                values.insert(instr.pc);
                values.insert(instr.pc.saturating_sub(runtime_start));
            }
        }
    }

    values
}

fn collect_init_immutable_offsets(ir: &CfgIrBundle) -> HashSet<usize> {
    let mut offsets = HashSet::new();
    let Some((runtime_start, _)) = ir.runtime_bounds() else {
        return offsets;
    };

    for removed in &ir.clean_report.removed {
        if removed.kind != SectionKind::Init {
            continue;
        }

        let bytes = removed.data.as_ref();
        let mut idx = 0usize;
        while idx < bytes.len() {
            let opcode = bytes[idx];
            if !(0x60..=0x7f).contains(&opcode) {
                idx += 1;
                continue;
            }

            let width = (opcode - 0x5f) as usize;
            if idx + 1 + width > bytes.len() {
                idx += 1;
                continue;
            }

            let after = idx + 1 + width;
            let is_immutable_store = after + 1 < bytes.len()
                && bytes[after] == Opcode::ADD.to_byte()
                && bytes[after + 1] == Opcode::MSTORE.to_byte();
            if is_immutable_store {
                if let Some(value) = parse_usize_be(&bytes[idx + 1..idx + 1 + width]) {
                    if value >= 1 && value < ir.clean_report.clean_len {
                        offsets.insert(value);
                    }
                    if value > runtime_start && value - runtime_start < ir.clean_report.clean_len {
                        offsets.insert(value - runtime_start);
                    }
                }
            }

            idx += 1 + width;
        }
    }

    offsets
}

fn is_jump_literal(
    instructions: &[Instruction],
    idx: usize,
    jumpdest_values: &HashSet<usize>,
) -> bool {
    if instructions
        .get(idx + 1)
        .is_some_and(|next| matches!(next.op, Opcode::JUMP | Opcode::JUMPI))
    {
        return true;
    }

    if instructions
        .get(idx + 2)
        .is_some_and(|jump| matches!(jump.op, Opcode::JUMP | Opcode::JUMPI))
        && instructions
            .get(idx + 1)
            .is_some_and(|op| matches!(op.op, Opcode::ADD | Opcode::PC))
    {
        return true;
    }

    if instructions
        .get(idx + 3)
        .is_some_and(|jump| matches!(jump.op, Opcode::JUMP | Opcode::JUMPI))
    {
        let op1 = instructions.get(idx + 1).map(|instr| instr.op);
        let op2 = instructions.get(idx + 2).map(|instr| instr.op);
        if matches!(
            (op1, op2),
            (Some(Opcode::PUSH(_)), Some(Opcode::ADD)) | (Some(Opcode::PC), Some(Opcode::ADD))
        ) {
            return true;
        }
    }

    let Some(value) = parse_push_usize(&instructions[idx]) else {
        return false;
    };
    jumpdest_values.contains(&value) && push_reaches_jump(instructions, idx)
}

fn parse_push_bytes(instr: &Instruction, width: u8) -> Option<Vec<u8>> {
    let bytes = hex::decode(instr.imm.as_deref()?).ok()?;
    if bytes.len() != width as usize {
        return None;
    }
    Some(bytes)
}

fn parse_push_usize(instr: &Instruction) -> Option<usize> {
    let Opcode::PUSH(width) = instr.op else {
        return None;
    };
    let bytes = parse_push_bytes(instr, width)?;
    if bytes.len() > std::mem::size_of::<usize>()
        && bytes[..bytes.len() - std::mem::size_of::<usize>()]
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }

    let mut value = 0usize;
    for byte in bytes {
        value = value.checked_shl(8)? | byte as usize;
    }
    Some(value)
}

fn parse_usize_be(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > std::mem::size_of::<usize>()
        && bytes[..bytes.len() - std::mem::size_of::<usize>()]
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }

    let mut value = 0usize;
    for byte in bytes {
        value = value.checked_shl(8)? | *byte as usize;
    }
    Some(value)
}

fn random_nonzero_bytes(width: usize, rng: &mut StdRng) -> Vec<u8> {
    loop {
        let mut bytes = vec![0u8; width];
        rng.fill_bytes(&mut bytes);
        if bytes.iter().any(|byte| *byte != 0) {
            return bytes;
        }
    }
}

fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right.iter()).map(|(a, b)| a ^ b).collect()
}

fn emit_reconstructed_value(
    base_pc: usize,
    width: u8,
    value: &[u8],
    out: &mut Vec<Instruction>,
    next_synthetic_pc: &mut usize,
    rng: &mut StdRng,
) {
    let shares = random_xor_shares(value, rng);
    let mut first = true;
    out.push(Instruction {
        pc: base_pc,
        op: Opcode::PUSH(width),
        imm: Some(hex::encode(&shares[0])),
    });

    let mut fresh_pc = || {
        let pc = *next_synthetic_pc;
        *next_synthetic_pc = next_synthetic_pc.saturating_add(1);
        pc
    };

    for share in shares {
        if first {
            first = false;
            // The first share was emitted at the original PC to preserve local
            // source ordering. Apply identity noise before combining shares so
            // straight-line constant folders stop tracking it as a pure PUSH.
            emit_dynamic_accumulator_identity(&mut fresh_pc, out, rng);
            continue;
        }

        if rng.next_u32() & 1 == 0 {
            emit_accumulator_identity(&mut fresh_pc, out, rng);
        }
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::PUSH(width),
            imm: Some(hex::encode(&share)),
        });
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::XOR,
            imm: None,
        });
    }

    if rng.next_u32() & 1 == 0 {
        emit_accumulator_identity(&mut fresh_pc, out, rng);
    }
}

fn emit_reconstructed_value_with_fresh_pc(
    value: &[u8],
    width: u8,
    fresh_pc: &mut impl FnMut() -> usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    let shares = random_xor_shares(value, rng);
    out.push(Instruction {
        pc: fresh_pc(),
        op: Opcode::PUSH(width),
        imm: Some(hex::encode(&shares[0])),
    });
    emit_dynamic_accumulator_identity(fresh_pc, out, rng);

    for share in shares.iter().skip(1) {
        if rng.next_u32() & 1 == 0 {
            emit_accumulator_identity(fresh_pc, out, rng);
        }
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::PUSH(width),
            imm: Some(hex::encode(share)),
        });
        out.push(Instruction {
            pc: fresh_pc(),
            op: Opcode::XOR,
            imm: None,
        });
    }

    if rng.next_u32() & 1 == 0 {
        emit_accumulator_identity(fresh_pc, out, rng);
    }
}

fn emit_xor_masked_literal(
    base_pc: usize,
    width: u8,
    masked: &[u8],
    key: &[u8],
    out: &mut Vec<Instruction>,
    next_synthetic_pc: &mut usize,
    rng: &mut StdRng,
) {
    out.push(Instruction {
        pc: base_pc,
        op: Opcode::PUSH(width),
        imm: Some(hex::encode(masked)),
    });
    let mut fresh_pc = || {
        let pc = *next_synthetic_pc;
        *next_synthetic_pc = next_synthetic_pc.saturating_add(1);
        pc
    };

    emit_dynamic_zero(&mut fresh_pc, out, rng);
    out.push(Instruction {
        pc: fresh_pc(),
        op: Opcode::PUSH(width),
        imm: Some(hex::encode(key)),
    });
    out.push(Instruction {
        pc: fresh_pc(),
        op: Opcode::XOR,
        imm: None,
    });
    out.push(Instruction {
        pc: fresh_pc(),
        op: Opcode::XOR,
        imm: None,
    });
}

fn random_xor_shares(value: &[u8], rng: &mut StdRng) -> Vec<Vec<u8>> {
    let width = value.len();
    let share_count = 3 + (rng.next_u32() as usize % 3);

    for _ in 0..256 {
        let mut shares = Vec::with_capacity(share_count);
        let mut accumulator = vec![0u8; width];

        for _ in 0..share_count - 1 {
            let share = random_share(value, rng);
            xor_assign(&mut accumulator, &share);
            shares.push(share);
        }

        let final_share = xor_bytes(value, &accumulator);
        if final_share.iter().any(|byte| *byte != 0)
            && final_share != value
            && shares.iter().all(|share| share != value)
        {
            shares.push(final_share);
            return shares;
        }
    }

    let first = random_share(value, rng);
    let second = random_share(value, rng);
    vec![first.clone(), second.clone(), {
        let mut tail = xor_bytes(value, &first);
        xor_assign(&mut tail, &second);
        tail
    }]
}

fn random_share(value: &[u8], rng: &mut StdRng) -> Vec<u8> {
    for _ in 0..256 {
        let share = random_nonzero_bytes(value.len(), rng);
        if share != value {
            return share;
        }
    }
    random_nonzero_bytes(value.len(), rng)
}

fn xor_assign(left: &mut [u8], right: &[u8]) {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= *right;
    }
}

fn emit_accumulator_identity(
    fresh_pc: &mut impl FnMut() -> usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    match rng.next_u32() % 5 {
        0 => {
            emit_dynamic_zero(fresh_pc, out, rng);
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::ADD,
                imm: None,
            });
        }
        1 => {
            emit_dynamic_zero(fresh_pc, out, rng);
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::XOR,
                imm: None,
            });
        }
        2 => {
            emit_dynamic_zero(fresh_pc, out, rng);
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::OR,
                imm: None,
            });
        }
        3 => {
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::PUSH(1),
                imm: Some("00".to_string()),
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::SHL,
                imm: None,
            });
        }
        _ => {
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::PUSH(1),
                imm: Some("00".to_string()),
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::SHR,
                imm: None,
            });
        }
    }
}

fn emit_dynamic_accumulator_identity(
    fresh_pc: &mut impl FnMut() -> usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    emit_dynamic_zero(fresh_pc, out, rng);
    let op = match rng.next_u32() % 3 {
        0 => Opcode::ADD,
        1 => Opcode::XOR,
        _ => Opcode::OR,
    };
    out.push(Instruction {
        pc: fresh_pc(),
        op,
        imm: None,
    });
}

/// Emits a value that is unknown to simple static constant folders, then reduces
/// it to zero with an opaque identity such as `D - D` or `D < D`.
///
/// The dynamic source opcodes used here have no stack inputs and no side
/// effects, so the sequence is safe in both runtime and init code while still
/// preventing the accumulator from looking like a pure PUSH-only expression.
fn emit_dynamic_zero(
    fresh_pc: &mut impl FnMut() -> usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    let source = random_dynamic_source(rng);
    out.push(Instruction {
        pc: fresh_pc(),
        op: source.opcode(),
        imm: None,
    });
    emit_opaque_zero_tail(fresh_pc, out, rng);
}

fn emit_opaque_zero_tail(
    fresh_pc: &mut impl FnMut() -> usize,
    out: &mut Vec<Instruction>,
    rng: &mut StdRng,
) {
    // Stack before: [D, masked]. After: [0, masked].
    match rng.next_u32() % 5 {
        0 => {
            // D - D == 0
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::DUP(1),
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::SUB,
                imm: None,
            });
        }
        1 => {
            // D < D == 0
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::DUP(1),
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::LT,
                imm: None,
            });
        }
        2 => {
            // D > D == 0
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::DUP(1),
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::GT,
                imm: None,
            });
        }
        3 => {
            // iszero(D == D) == 0
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::DUP(1),
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::EQ,
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::ISZERO,
                imm: None,
            });
        }
        _ => {
            // NOT(D OR NOT(D)) == 0
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::DUP(1),
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::NOT,
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::OR,
                imm: None,
            });
            out.push(Instruction {
                pc: fresh_pc(),
                op: Opcode::NOT,
                imm: None,
            });
        }
    }
}

fn next_available_pc(ir: &CfgIrBundle) -> usize {
    ir.cfg
        .node_indices()
        .filter_map(|node| match ir.cfg.node_weight(node) {
            Some(Block::Body(body)) => body
                .instructions
                .iter()
                .map(|instr| instr.pc.saturating_add(instr.byte_size()))
                .max(),
            _ => None,
        })
        .max()
        .unwrap_or(0)
        .saturating_add(1_000_000)
}

/// Side-effect-free EVM context opcodes used as entropy sources for opaque
/// zero expressions.
///
/// Each variant maps to a zero-input opcode that pushes a context value onto
/// the stack. The transform immediately combines that value with itself to
/// produce zero, so the exact runtime value is irrelevant.
#[derive(Clone, Copy)]
enum DynamicSource {
    Address,
    Caller,
    CallValue,
    CalldataSize,
    CodeSize,
    GasPrice,
    Timestamp,
    Number,
    ReturndataSize,
    Pc,
    Msize,
    Gas,
}

impl DynamicSource {
    /// Returns the typed opcode for this context source.
    fn opcode(self) -> Opcode {
        match self {
            Self::Address => Opcode::ADDRESS,
            Self::Caller => Opcode::CALLER,
            Self::CallValue => Opcode::CALLVALUE,
            Self::CalldataSize => Opcode::CALLDATASIZE,
            Self::CodeSize => Opcode::CODESIZE,
            Self::GasPrice => Opcode::GASPRICE,
            Self::Timestamp => Opcode::TIMESTAMP,
            Self::Number => Opcode::NUMBER,
            Self::ReturndataSize => Opcode::RETURNDATASIZE,
            Self::Pc => Opcode::PC,
            Self::Msize => Opcode::MSIZE,
            Self::Gas => Opcode::GAS,
        }
    }

    fn byte(self) -> u8 {
        self.opcode().to_byte()
    }
}

fn random_dynamic_source(rng: &mut StdRng) -> DynamicSource {
    const SOURCES: &[DynamicSource] = &[
        DynamicSource::Address,
        DynamicSource::Caller,
        DynamicSource::CallValue,
        DynamicSource::CalldataSize,
        DynamicSource::CodeSize,
        DynamicSource::GasPrice,
        DynamicSource::Timestamp,
        DynamicSource::Number,
        DynamicSource::ReturndataSize,
        DynamicSource::Pc,
        DynamicSource::Msize,
        DynamicSource::Gas,
    ];
    let idx = (rng.next_u32() as usize) % SOURCES.len();
    SOURCES[idx]
}

fn mask_init_literals(ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
    let runtime_offset = ir
        .clean_report
        .runtime_layout
        .iter()
        .map(|span| span.offset)
        .min()
        .unwrap_or(0);
    let post_runtime_len: usize = ir
        .clean_report
        .removed
        .iter()
        .filter(|removed| removed.offset >= runtime_offset)
        .map(|removed| removed.data.len())
        .sum();
    let original_runtime_tail_len = ir.clean_report.clean_len + post_runtime_len;
    let original_total_len = runtime_offset + original_runtime_tail_len;

    let mut changed = false;
    for removed in &mut ir.clean_report.removed {
        if removed.kind != SectionKind::Init {
            continue;
        }

        let original = removed.data.to_vec();
        let jump_patches = collect_init_jump_patches(&original);
        let jump_targets = collect_init_jumpdest_values(&original);
        let mut rewritten = Vec::with_capacity(original.len());
        let mut insertions: Vec<(usize, usize)> = Vec::new();
        let mut idx = 0usize;

        while idx < original.len() {
            let opcode = original[idx];
            if !(0x60..=0x7f).contains(&opcode) {
                rewritten.push(opcode);
                idx += 1;
                continue;
            }

            let width = (opcode - 0x5f) as usize;
            let end = idx + 1 + width;
            if end > original.len() {
                rewritten.extend_from_slice(&original[idx..]);
                break;
            }
            if width < 4 {
                rewritten.extend_from_slice(&original[idx..end]);
                idx = end;
                continue;
            }

            let value = &original[idx + 1..end];
            if should_skip_init_literal(
                &original,
                idx,
                value,
                &jump_targets,
                runtime_offset,
                original_runtime_tail_len,
                original_total_len,
            ) {
                rewritten.extend_from_slice(&original[idx..end]);
                idx = end;
                continue;
            }

            let new_pos = rewritten.len();
            emit_reconstructed_value_bytes(width as u8, value, &mut rewritten, rng);
            let new_len = rewritten.len() - new_pos;
            insertions.push((idx, new_len - (1 + width)));
            debug!("ConstantMask: init PUSH{} at pc=0x{:x} masked", width, idx);
            idx = end;
        }

        if !insertions.is_empty() {
            patch_rewritten_init_jump_targets(&mut rewritten, &jump_patches, &insertions)?;
            removed.data = rewritten.into();
            changed = true;
        }
    }

    Ok(changed)
}

fn emit_opaque_zero_bytes(out: &mut Vec<u8>, rng: &mut StdRng) -> usize {
    match rng.next_u32() % 5 {
        0 => {
            out.extend_from_slice(&[Opcode::DUP(1).to_byte(), Opcode::SUB.to_byte()]);
            2
        }
        1 => {
            out.extend_from_slice(&[Opcode::DUP(1).to_byte(), Opcode::LT.to_byte()]);
            2
        }
        2 => {
            out.extend_from_slice(&[Opcode::DUP(1).to_byte(), Opcode::GT.to_byte()]);
            2
        }
        3 => {
            out.extend_from_slice(&[
                Opcode::DUP(1).to_byte(),
                Opcode::EQ.to_byte(),
                Opcode::ISZERO.to_byte(),
            ]);
            3
        }
        _ => {
            out.extend_from_slice(&[
                Opcode::DUP(1).to_byte(),
                Opcode::NOT.to_byte(),
                Opcode::OR.to_byte(),
                Opcode::NOT.to_byte(),
            ]);
            4
        }
    }
}

fn emit_reconstructed_value_bytes(width: u8, value: &[u8], out: &mut Vec<u8>, rng: &mut StdRng) {
    let shares = random_xor_shares(value, rng);
    emit_push_bytes(width, &shares[0], out);
    emit_dynamic_accumulator_identity_bytes(out, rng);

    for share in shares.iter().skip(1) {
        if rng.next_u32() & 1 == 0 {
            emit_accumulator_identity_bytes(out, rng);
        }
        emit_push_bytes(width, share, out);
        out.push(Opcode::XOR.to_byte());
    }

    if rng.next_u32() & 1 == 0 {
        emit_accumulator_identity_bytes(out, rng);
    }
}

fn emit_push_bytes(width: u8, value: &[u8], out: &mut Vec<u8>) {
    debug_assert_eq!(value.len(), width as usize);
    out.push(Opcode::PUSH(width).to_byte());
    out.extend_from_slice(value);
}

fn emit_accumulator_identity_bytes(out: &mut Vec<u8>, rng: &mut StdRng) {
    match rng.next_u32() % 5 {
        0 => {
            emit_dynamic_zero_bytes(out, rng);
            out.push(Opcode::ADD.to_byte());
        }
        1 => {
            emit_dynamic_zero_bytes(out, rng);
            out.push(Opcode::XOR.to_byte());
        }
        2 => {
            emit_dynamic_zero_bytes(out, rng);
            out.push(Opcode::OR.to_byte());
        }
        3 => {
            out.extend_from_slice(&[Opcode::PUSH(1).to_byte(), 0x00, Opcode::SHL.to_byte()]);
        }
        _ => {
            out.extend_from_slice(&[Opcode::PUSH(1).to_byte(), 0x00, Opcode::SHR.to_byte()]);
        }
    }
}

fn emit_dynamic_zero_bytes(out: &mut Vec<u8>, rng: &mut StdRng) {
    out.push(random_dynamic_source(rng).byte());
    emit_opaque_zero_bytes(out, rng);
}

fn emit_dynamic_accumulator_identity_bytes(out: &mut Vec<u8>, rng: &mut StdRng) {
    emit_dynamic_zero_bytes(out, rng);
    let op = match rng.next_u32() % 3 {
        0 => Opcode::ADD,
        1 => Opcode::XOR,
        _ => Opcode::OR,
    };
    out.push(op.to_byte());
}

fn should_skip_init_literal(
    bytes: &[u8],
    idx: usize,
    value: &[u8],
    jump_targets: &HashSet<usize>,
    runtime_offset: usize,
    original_runtime_tail_len: usize,
    original_total_len: usize,
) -> bool {
    if value.iter().all(|byte| *byte == 0) {
        return true;
    }

    if let Some(value_usize) = parse_usize_be(value) {
        if matches!(
            value_usize,
            v if v == runtime_offset || v == original_runtime_tail_len || v == original_total_len
        ) {
            return true;
        }

        if jump_targets.contains(&value_usize) {
            return true;
        }
    }

    let after = idx + 1 + value.len();
    if after < bytes.len() && matches!(bytes[after], 0x56 | 0x57) {
        return true;
    }
    if after + 1 < bytes.len() && bytes[after] == 0x01 && bytes[after + 1] == 0x52 {
        return true;
    }

    false
}

#[derive(Clone)]
struct InitJumpPatch {
    push_pos: usize,
    width: usize,
    old_target: usize,
}

fn collect_init_jumpdest_values(bytes: &[u8]) -> HashSet<usize> {
    let mut jumpdests = HashSet::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let opcode = bytes[idx];
        if opcode == Opcode::JUMPDEST.to_byte() {
            jumpdests.insert(idx);
            idx += 1;
        } else if (0x60..=0x7f).contains(&opcode) {
            idx += 1 + (opcode - 0x5f) as usize;
        } else {
            idx += 1;
        }
    }
    jumpdests
}

fn collect_init_jump_patches(bytes: &[u8]) -> Vec<InitJumpPatch> {
    let jumpdests = collect_init_jumpdest_values(bytes);

    let mut patches = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let opcode = bytes[idx];
        if !(0x60..=0x7f).contains(&opcode) {
            idx += 1;
            continue;
        }
        let width = (opcode - 0x5f) as usize;
        if idx + 1 + width > bytes.len() {
            break;
        }
        if let Some(value) = parse_usize_be(&bytes[idx + 1..idx + 1 + width]) {
            if jumpdests.contains(&value) {
                patches.push(InitJumpPatch {
                    push_pos: idx,
                    width,
                    old_target: value,
                });
            }
        }
        idx += 1 + width;
    }
    patches
}

fn patch_rewritten_init_jump_targets(
    bytes: &mut [u8],
    jump_patches: &[InitJumpPatch],
    insertions: &[(usize, usize)],
) -> Result<()> {
    for patch in jump_patches {
        let new_push_pos = init_pc_after_rewrites(patch.push_pos, insertions);
        let new_target = init_pc_after_rewrites(patch.old_target, insertions);
        if new_target == patch.old_target {
            continue;
        }
        if new_push_pos + 1 + patch.width > bytes.len() {
            return Err(Error::CoreError(format!(
                "init jump PUSH out of bounds at 0x{new_push_pos:x}"
            )));
        }
        if patch.width < std::mem::size_of::<usize>() {
            let max = (1usize << (patch.width * 8)) - 1;
            if new_target > max {
                return Err(Error::CoreError(format!(
                    "init jump target 0x{new_target:x} does not fit in PUSH{}",
                    patch.width
                )));
            }
        }
        for j in 0..patch.width {
            let shift = (patch.width - 1 - j) * 8;
            bytes[new_push_pos + 1 + j] = ((new_target >> shift) & 0xff) as u8;
        }
    }
    Ok(())
}

fn init_pc_after_rewrites(pc: usize, insertions: &[(usize, usize)]) -> usize {
    pc + insertions
        .iter()
        .filter(|(pos, _)| *pos <= pc)
        .map(|(_, len)| *len)
        .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::encoder;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;

    const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn runtime_mask_masks_push20_literal() {
        let constant = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let bytecode = format!("0x73{constant}00");
        let (mut ir, _, _, bytes) = process_bytecode_to_cfg(&bytecode, false, &bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = ConstantMask::with_min_width(20)
            .apply(&mut ir, &mut rng)
            .unwrap();
        assert!(changed);
        ir.reindex_pcs().unwrap();

        let mut instructions = Vec::new();
        for node in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node] {
                instructions.extend(body.instructions.clone());
            }
        }
        instructions.sort_by_key(|instr| instr.pc);
        let encoded = encoder::encode(&instructions, &bytes).unwrap();
        assert!(!hex::encode(encoded).contains(constant));
    }

    #[tokio::test]
    async fn skips_direct_jump_target() {
        // PUSH2 0x0006 ; JUMP ; JUMPDEST ; STOP
        let bytecode = "0x610006565b00";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = ConstantMask::new().apply(&mut ir, &mut rng).unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn lowers_call_selector_mstore_to_byte_patches() {
        // PUSH1 0x40; MLOAD; PUSH4 a9059cbb; PUSH1 e0; SHL; DUP2; MSTORE;
        // then enough zero args for CALL. The transform should decoy the
        // selector word and patch the actual four selector bytes with MSTORE8.
        let bytecode = "0x60405163a9059cbb60e01b8152600060006000600060006000f100";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = ConstantMask::new().apply(&mut ir, &mut rng).unwrap();
        assert!(changed);

        let mut saw_mstore8 = false;
        for node in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node] {
                for instr in &body.instructions {
                    assert_ne!(instr.imm.as_deref(), Some("a9059cbb"));
                    saw_mstore8 |= instr.op == Opcode::MSTORE8;
                }
            }
        }
        assert!(saw_mstore8);
    }

    #[tokio::test]
    async fn masks_wide_init_literal() {
        let constant = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        // Constructor-only PUSH20 constant followed by a minimal CODECOPY/RETURN
        // sequence that deploys a one-byte STOP runtime.
        let deployment = format!("0x73{constant}506001602260003960016000f300");
        let runtime = "0x00";
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let config = crate::obfuscator::ObfuscationConfig {
            seed,
            transforms: vec![Box::new(ConstantMask::new())],
            preserve_unknown_opcodes: true,
        };

        let result = crate::obfuscator::obfuscate_bytecode(&deployment, runtime, config)
            .await
            .unwrap();

        assert!(!result.obfuscated_bytecode.contains(constant));
    }

    #[tokio::test]
    async fn lowers_optimized_call_selector_mstore_to_byte_patches() {
        // 0x461bcd << 0xe5 reconstructs the left-aligned selector
        // 0x08c379a0. This is the same optimized selector shape solc can use
        // for revert selectors, but here it feeds an external CALL.
        let bytecode = "0x60405162461bcd60e51b8152600060006000600060006000f100";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();

        let changed = ConstantMask::new().apply(&mut ir, &mut rng).unwrap();
        assert!(changed);

        let mut saw_mstore8 = false;
        for node in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node] {
                for instr in &body.instructions {
                    assert_ne!(instr.imm.as_deref(), Some("461bcd"));
                    assert_ne!(instr.imm.as_deref(), Some("08c379a0"));
                    saw_mstore8 |= instr.op == Opcode::MSTORE8;
                }
            }
        }
        assert!(saw_mstore8);
    }
}
