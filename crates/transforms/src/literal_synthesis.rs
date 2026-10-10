//! Seed-varied, semantics-preserving synthesis of literal constants.
//!
//! Solidity bytecode contains a large amount of semantic information in `PUSH`
//! immediates: addresses, event topics, masks, bounds, and revert constants.  This
//! pass replaces a budgeted subset of those literals with one of several exact
//! stack expressions.  Unlike the historical string pass, every emitted expression
//! evaluates to the original 256-bit value and therefore preserves returndata and
//! revert bytes.
//!
//! The pass deliberately excludes dispatcher metadata, recognized jump addresses,
//! blocks which introspect their own code layout, and wide all-zero placeholders
//! used by Solidity immutables.  These exclusions are conservative: an unchanged
//! literal is preferable to corrupting a relocation that Azoth cannot prove safe.

use crate::{
    collect_protected_nodes, collect_protected_pcs, has_gas_observation,
    has_self_code_layout_semantics, Error, Result, Transform,
};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Maximum code growth attributable to literal synthesis.
const MAX_GROWTH_RATIO: f64 = 0.45;

/// Probability that an otherwise eligible literal enters the candidate set.
const TRANSFORM_PROBABILITY: f64 = 0.20;

/// Rewrites literal pushes as exact, seed-varied stack expressions.
#[derive(Debug, Default)]
pub struct LiteralSynthesis;

impl LiteralSynthesis {
    /// Creates the literal-synthesis pass with the production growth budget.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    Xor2,
    Xor3,
    ShiftOr,
}

#[derive(Clone, Debug)]
struct Candidate {
    node: NodeIndex,
    index: usize,
    width: u8,
    value: Vec<u8>,
}

impl Transform for LiteralSynthesis {
    fn name(&self) -> &'static str {
        "LiteralSynthesis"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        if has_self_code_layout_semantics(ir) {
            return Err(Error::Generic(
                "literal synthesis does not support PC/CODESIZE/CODECOPY or EXTCODE* introspection"
                    .into(),
            ));
        }
        if has_gas_observation(ir) {
            return Err(Error::Generic(
                "literal synthesis does not support runtimes that observe GAS".into(),
            ));
        }
        let protected_pcs = collect_protected_pcs(ir);
        let protected_nodes = collect_protected_nodes(ir);
        let jump_values = collect_jump_values(ir);
        let runtime_bounds = ir.runtime_bounds;

        let mut nodes: Vec<_> = ir.cfg.node_indices().collect();
        nodes.sort_by_key(|node| match &ir.cfg[*node] {
            Block::Body(body) => body.start_pc,
            Block::Entry | Block::Exit => usize::MAX,
        });

        let runtime_size: usize = nodes
            .iter()
            .filter_map(|node| match &ir.cfg[*node] {
                Block::Body(body) if in_runtime(body.start_pc, runtime_bounds) => Some(
                    body.instructions
                        .iter()
                        .map(Instruction::byte_size)
                        .sum::<usize>(),
                ),
                _ => None,
            })
            .sum();
        let growth_budget = ((runtime_size as f64) * MAX_GROWTH_RATIO).floor() as usize;
        if growth_budget == 0 {
            return Ok(false);
        }

        let mut candidates = Vec::new();
        for node in nodes {
            if protected_nodes.contains(&node) || ir.dispatcher_blocks.contains(&node.index()) {
                continue;
            }
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };
            if !in_runtime(body.start_pc, runtime_bounds)
                || code_layout_sensitive(body)
                || body.max_stack >= 1024
            {
                continue;
            }

            for (index, instruction) in body.instructions.iter().enumerate() {
                let Opcode::PUSH(width) = instruction.op else {
                    continue;
                };
                if protected_pcs.contains(&instruction.pc)
                    || is_jump_operand(&body.instructions, index)
                    || rng.random_bool(1.0 - TRANSFORM_PROBABILITY)
                {
                    continue;
                }
                let Some(value) = decode_immediate(instruction, width) else {
                    continue;
                };
                if jump_values.contains(&value_to_usize(&value)) {
                    continue;
                }
                // Solidity immutable placeholders are commonly emitted as a wide
                // all-zero PUSH whose bytes are overwritten by init code.
                if width >= 20 && value.iter().all(|byte| *byte == 0) {
                    continue;
                }
                candidates.push(Candidate {
                    node,
                    index,
                    width,
                    value,
                });
            }
        }

        if candidates.is_empty() {
            return Ok(false);
        }
        candidates.shuffle(rng);

        let mut fresh_pc = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => body
                    .instructions
                    .last()
                    .map(|instruction| instruction.pc + instruction.byte_size()),
                Block::Entry | Block::Exit => None,
            })
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let mut selected: HashMap<NodeIndex, HashMap<usize, Vec<Instruction>>> = HashMap::new();
        let mut growth = 0usize;
        for candidate in candidates {
            let variant = choose_variant(candidate.width, rng);
            let synthesis_width = choose_synthesis_width(candidate.width, variant, rng);
            let estimated_growth = variant_growth(candidate.width, synthesis_width, variant);
            if growth + estimated_growth > growth_budget {
                continue;
            }
            let original_pc = match &ir.cfg[candidate.node] {
                Block::Body(body) => body.instructions[candidate.index].pc,
                Block::Entry | Block::Exit => continue,
            };
            let replacement = synthesize(
                &candidate.value,
                candidate.width,
                synthesis_width,
                variant,
                original_pc,
                &mut fresh_pc,
                rng,
            );
            growth += replacement
                .iter()
                .map(Instruction::byte_size)
                .sum::<usize>()
                .saturating_sub(candidate.width as usize + 1);
            selected
                .entry(candidate.node)
                .or_default()
                .insert(candidate.index, replacement);
        }

        if selected.is_empty() {
            return Ok(false);
        }

        let mut changed = false;
        for (node, replacements) in selected {
            let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
                continue;
            };
            let mut rewritten =
                Vec::with_capacity(body.instructions.len() + replacements.len() * 3);
            for (index, instruction) in body.instructions.iter().enumerate() {
                if let Some(replacement) = replacements.get(&index) {
                    rewritten.extend(replacement.iter().cloned());
                } else {
                    rewritten.push(instruction.clone());
                }
            }
            let mut new_body = body.clone();
            new_body.instructions = rewritten;
            // XOR/SHL/OR synthesis temporarily needs at most one more stack slot
            // than the literal it replaces.
            new_body.max_stack = new_body.max_stack.saturating_add(1);
            ir.overwrite_block(node, new_body)
                .map_err(|error| Error::CoreError(error.to_string()))?;
            changed = true;
        }

        debug!(growth, growth_budget, "LiteralSynthesis applied");
        Ok(changed)
    }
}

fn in_runtime(pc: usize, bounds: Option<(usize, usize)>) -> bool {
    bounds.is_none_or(|(start, end)| pc >= start && pc < end)
}

fn code_layout_sensitive(body: &azoth_core::cfg_ir::BlockBody) -> bool {
    body.instructions.iter().any(|instruction| {
        matches!(
            instruction.op,
            Opcode::PC | Opcode::CODESIZE | Opcode::CODECOPY | Opcode::EXTCODECOPY
        )
    })
}

fn collect_jump_values(ir: &CfgIrBundle) -> HashSet<Option<usize>> {
    let runtime_start = ir.runtime_bounds.map(|(start, _)| start).unwrap_or(0);
    let mut values = HashSet::new();
    for node in ir.cfg.node_indices() {
        let Some(Block::Body(body)) = ir.cfg.node_weight(node) else {
            continue;
        };
        if body
            .instructions
            .first()
            .is_some_and(|instruction| matches!(instruction.op, Opcode::JUMPDEST))
        {
            values.insert(Some(body.start_pc));
            values.insert(Some(body.start_pc.saturating_sub(runtime_start)));
        }
    }
    values
}

fn is_jump_operand(instructions: &[Instruction], index: usize) -> bool {
    let end = (index + 6).min(instructions.len());
    instructions[index + 1..end]
        .iter()
        .any(|instruction| matches!(instruction.op, Opcode::JUMP | Opcode::JUMPI))
}

fn decode_immediate(instruction: &Instruction, width: u8) -> Option<Vec<u8>> {
    let mut bytes = hex::decode(instruction.imm.as_deref()?).ok()?;
    let width = width as usize;
    if bytes.len() > width {
        return None;
    }
    if bytes.len() < width {
        let mut padded = vec![0; width - bytes.len()];
        padded.append(&mut bytes);
        return Some(padded);
    }
    Some(bytes)
}

fn value_to_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > std::mem::size_of::<usize>() {
        let prefix = &bytes[..bytes.len() - std::mem::size_of::<usize>()];
        if prefix.iter().any(|byte| *byte != 0) {
            return None;
        }
    }
    Some(
        bytes[bytes.len().saturating_sub(std::mem::size_of::<usize>())..]
            .iter()
            .fold(0usize, |value, byte| (value << 8) | *byte as usize),
    )
}

fn choose_variant(width: u8, rng: &mut StdRng) -> Variant {
    if width >= 2 {
        match rng.random_range(0..3) {
            0 => Variant::Xor2,
            1 => Variant::Xor3,
            _ => Variant::ShiftOr,
        }
    } else if rng.random_bool(0.65) {
        Variant::Xor2
    } else {
        Variant::Xor3
    }
}

/// XOR operands may be wider than the source PUSH. Their randomized high bytes
/// cancel exactly, while changing both the literal bytes and the PUSH opcode
/// family. This avoids leaving a strong compiler-shaped opcode skeleton behind.
fn choose_synthesis_width(width: u8, variant: Variant, rng: &mut StdRng) -> u8 {
    if matches!(variant, Variant::ShiftOr) || width == 32 {
        return width;
    }
    rng.random_range(width + 1..=width.saturating_add(4).min(32))
}

fn variant_growth(original_width: u8, synthesis_width: u8, variant: Variant) -> usize {
    match variant {
        Variant::Xor2 => synthesis_width as usize * 2 - original_width as usize + 2,
        Variant::Xor3 => synthesis_width as usize * 3 - original_width as usize + 4,
        Variant::ShiftOr => 6,
    }
}

fn synthesize(
    value: &[u8],
    original_width: u8,
    synthesis_width: u8,
    variant: Variant,
    original_pc: usize,
    fresh_pc: &mut usize,
    rng: &mut StdRng,
) -> Vec<Instruction> {
    debug_assert!(synthesis_width >= original_width);
    let mut target = vec![0; synthesis_width as usize - value.len()];
    target.extend_from_slice(value);
    match variant {
        Variant::Xor2 => {
            let first = random_part(&target, rng);
            let second: Vec<_> = first
                .iter()
                .zip(&target)
                .map(|(left, right)| left ^ right)
                .collect();
            vec![
                push(synthesis_width, first, original_pc),
                push(synthesis_width, second, take_pc(fresh_pc)),
                op(Opcode::XOR, take_pc(fresh_pc)),
            ]
        }
        Variant::Xor3 => {
            let first = random_part(&target, rng);
            let second = random_part(&target, rng);
            let third: Vec<_> = first
                .iter()
                .zip(&second)
                .zip(&target)
                .map(|((a, b), target)| a ^ b ^ target)
                .collect();
            vec![
                push(synthesis_width, first, original_pc),
                push(synthesis_width, second, take_pc(fresh_pc)),
                op(Opcode::XOR, take_pc(fresh_pc)),
                push(synthesis_width, third, take_pc(fresh_pc)),
                op(Opcode::XOR, take_pc(fresh_pc)),
            ]
        }
        Variant::ShiftOr => {
            let split = rng.random_range(1..original_width as usize);
            let high = value[..split].to_vec();
            let low = value[split..].to_vec();
            let shift = ((original_width as usize - split) * 8) as u8;
            vec![
                push(split as u8, high, original_pc),
                push(1, vec![shift], take_pc(fresh_pc)),
                op(Opcode::SHL, take_pc(fresh_pc)),
                push(
                    (original_width as usize - split) as u8,
                    low,
                    take_pc(fresh_pc),
                ),
                op(Opcode::OR, take_pc(fresh_pc)),
            ]
        }
    }
}

fn random_part(value: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut part = vec![0u8; value.len()];
    for _ in 0..8 {
        rng.fill_bytes(&mut part);
        if part.first().copied().unwrap_or(0) != 0
            && part
                .first()
                .zip(value.first())
                .is_some_and(|(left, right)| left ^ right != 0)
        {
            break;
        }
    }
    part
}

fn take_pc(next: &mut usize) -> usize {
    let pc = *next;
    *next = next.saturating_add(1);
    pc
}

fn push(width: u8, bytes: Vec<u8>, pc: usize) -> Instruction {
    Instruction {
        pc,
        op: Opcode::PUSH(width),
        imm: Some(hex::encode(bytes)),
    }
}

fn op(opcode: Opcode, pc: usize) -> Instruction {
    Instruction {
        pc,
        op: opcode,
        imm: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::seed::Seed;

    const SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn evaluate(sequence: &[Instruction]) -> Vec<u8> {
        let mut stack: Vec<[u8; 32]> = Vec::new();
        for instruction in sequence {
            match instruction.op {
                Opcode::PUSH(width) => {
                    let bytes = hex::decode(instruction.imm.as_deref().unwrap()).unwrap();
                    let mut word = [0u8; 32];
                    word[32 - width as usize..].copy_from_slice(&bytes);
                    stack.push(word);
                }
                Opcode::XOR | Opcode::OR => {
                    let right = stack.pop().unwrap();
                    let left = stack.pop().unwrap();
                    let mut word = [0u8; 32];
                    for i in 0..32 {
                        word[i] = if matches!(instruction.op, Opcode::XOR) {
                            left[i] ^ right[i]
                        } else {
                            left[i] | right[i]
                        };
                    }
                    stack.push(word);
                }
                Opcode::SHL => {
                    let shift = stack.pop().unwrap()[31] as usize;
                    let value = stack.pop().unwrap();
                    let mut word = [0u8; 32];
                    let byte_shift = shift / 8;
                    let retained = 32usize.saturating_sub(byte_shift);
                    word[..retained].copy_from_slice(&value[byte_shift..byte_shift + retained]);
                    stack.push(word);
                }
                _ => panic!("unexpected opcode"),
            }
        }
        stack.pop().unwrap().to_vec()
    }

    #[test]
    fn every_variant_reconstructs_the_exact_word() {
        let value = hex::decode("1122334455667788").unwrap();
        let seed = Seed::from_hex(SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();
        for variant in [Variant::Xor2, Variant::Xor3, Variant::ShiftOr] {
            let mut fresh = 1_000;
            let synthesis_width = if matches!(variant, Variant::ShiftOr) {
                8
            } else {
                12
            };
            let sequence = synthesize(
                &value,
                8,
                synthesis_width,
                variant,
                10,
                &mut fresh,
                &mut rng,
            );
            assert_eq!(&evaluate(&sequence)[24..], value);
            assert!(evaluate(&sequence)[..24].iter().all(|byte| *byte == 0));
        }
    }
}
