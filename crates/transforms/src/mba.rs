//! Mixed Boolean Arithmetic (MBA) transform.
//!
//! Example identities (unsigned integers):
//!   x + y == (x ^ y) + ((x & y) << 1)
//!   x + y == (x | y) + (x & y)
//!   b - a == b + (~a + 1)

use crate::{collect_protected_nodes, collect_protected_pcs, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;
use rand::Rng;
use tracing::debug;

const MAX_INSTRUCTIONS_ADDED: usize = 24;

/// Mixed Boolean Arithmetic transform.
#[derive(Debug, Default)]
pub struct Mba {}

impl Mba {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Transform for Mba {
    fn name(&self) -> &'static str {
        "MBA"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== MBA Transform Start ===");

        let protected_pcs = collect_protected_pcs(ir);
        let protected_nodes = collect_protected_nodes(ir);

        let mut changed = false;
        let mut total_rewrites = 0usize;
        let mut total_noise = 0usize;

        let node_indices: Vec<_> = ir.cfg.node_indices().collect();
        for node_idx in node_indices {
            if protected_nodes.contains(&node_idx) {
                continue;
            }

            let Some(Block::Body(body)) = ir.cfg.node_weight_mut(node_idx) else {
                continue;
            };

            let mut edits: Vec<(usize, Vec<Instruction>, bool)> = Vec::new();
            let instructions = &body.instructions;

            for (idx, instr) in instructions.iter().enumerate() {
                if protected_pcs.contains(&instr.pc) {
                    continue;
                }

                let Some((rewrite, has_noise)) = self.pick_rewrite(instructions, idx, rng) else {
                    continue;
                };

                let added = rewrite.len().saturating_sub(1);
                if added > MAX_INSTRUCTIONS_ADDED {
                    continue;
                }

                edits.push((idx, rewrite, has_noise));
            }

            if edits.is_empty() {
                continue;
            }

            let instructions = &mut body.instructions;
            let mut block_changed = false;

            for (idx, mut replacement, has_noise) in edits.into_iter().rev() {
                let start_pc = instructions[idx].pc;
                assign_pcs(start_pc, &mut replacement);
                instructions.splice(idx..=idx, replacement);
                block_changed = true;
                total_rewrites += 1;
                if has_noise {
                    total_noise += 1;
                }
            }

            if block_changed {
                body.max_stack = body.max_stack.saturating_add(4);
                changed = true;
            }
        }

        if changed {
            debug!(
                "MBA rewrote {} instructions (noise appended: {})",
                total_rewrites, total_noise
            );
        }

        debug!("=== MBA Transform Complete ===");
        Ok(changed)
    }
}

#[derive(Clone, Copy, Debug)]
enum NoiseSource {
    CallData { offset: u8 },
    Caller,
    Number,
    Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum NoiseEncoding {
    XorZero,
    OrZero,
    AddZero,
    SubZero,
    AndNotZero,
}

impl NoiseSource {
    fn random(rng: &mut StdRng) -> Self {
        match rng.random_range(0..4) {
            0 => {
                let offsets = [0u8, 4u8, 0x20u8];
                let offset = offsets[rng.random_range(0..offsets.len())];
                NoiseSource::CallData { offset }
            }
            1 => NoiseSource::Caller,
            2 => NoiseSource::Number,
            _ => NoiseSource::Timestamp,
        }
    }

    fn emit(self, out: &mut Vec<Instruction>) {
        match self {
            NoiseSource::CallData { offset } => {
                if offset == 0 {
                    out.push(instr(Opcode::PUSH0, None));
                } else {
                    out.push(instr(Opcode::PUSH(1), Some(format!("{offset:02x}"))));
                }
                out.push(instr(Opcode::CALLDATALOAD, None));
            }
            NoiseSource::Caller => out.push(instr(Opcode::CALLER, None)),
            NoiseSource::Number => out.push(instr(Opcode::NUMBER, None)),
            NoiseSource::Timestamp => out.push(instr(Opcode::TIMESTAMP, None)),
        }
    }
}

impl NoiseEncoding {
    fn random(rng: &mut StdRng) -> Self {
        match rng.random_range(0..5) {
            0 => NoiseEncoding::XorZero,
            1 => NoiseEncoding::OrZero,
            2 => NoiseEncoding::AddZero,
            3 => NoiseEncoding::SubZero,
            _ => NoiseEncoding::AndNotZero,
        }
    }

    fn emit(self, out: &mut Vec<Instruction>) {
        match self {
            NoiseEncoding::XorZero => {
                out.push(instr(Opcode::PUSH0, None));
                out.push(instr(Opcode::XOR, None));
            }
            NoiseEncoding::OrZero => {
                out.push(instr(Opcode::PUSH0, None));
                out.push(instr(Opcode::OR, None));
            }
            NoiseEncoding::AddZero => {
                out.push(instr(Opcode::PUSH0, None));
                out.push(instr(Opcode::ADD, None));
            }
            NoiseEncoding::SubZero => {
                out.push(instr(Opcode::PUSH0, None));
                out.push(instr(Opcode::SUB, None));
            }
            NoiseEncoding::AndNotZero => {
                out.push(instr(Opcode::PUSH0, None));
                out.push(instr(Opcode::NOT, None));
                out.push(instr(Opcode::AND, None));
            }
        }
    }
}

fn instr(op: Opcode, imm: Option<String>) -> Instruction {
    Instruction { pc: 0, op, imm }
}

fn assign_pcs(start_pc: usize, instructions: &mut [Instruction]) {
    let mut pc = start_pc;
    for instr in instructions {
        instr.pc = pc;
        pc += instr.byte_size();
    }
}

impl Mba {
    fn pick_rewrite(
        &self,
        instructions: &[Instruction],
        idx: usize,
        rng: &mut StdRng,
    ) -> Option<(Vec<Instruction>, bool)> {
        let instr = instructions.get(idx)?;
        let opcode = instr.op;

        let eligible = match opcode {
            Opcode::ADD | Opcode::SUB => true,
            _ => false,
        };
        if !eligible {
            return None;
        }

        if instructions
            .get(idx + 1)
            .is_some_and(|next| matches!(next.op, Opcode::JUMP | Opcode::JUMPI))
        {
            return None;
        }

        let (mut rewrite, pattern_name) = match opcode {
            Opcode::ADD => {
                if rng.random::<bool>() {
                    (build_add_xor_and(), "add_xor_and")
                } else {
                    (build_add_or_and(), "add_or_and")
                }
            }
            Opcode::SUB => {
                if rng.random::<bool>() {
                    (build_sub_borrow(), "sub_borrow")
                } else {
                    (build_sub_twos_complement(), "sub_twos_complement")
                }
            }
            _ => return None,
        };

        debug!(
            "MBA rewrite pc={:#x} opcode={:?} pattern={}",
            instr.pc, opcode, pattern_name
        );
        append_noise(&mut rewrite, rng);

        Some((rewrite, true))
    }
}

fn build_add_xor_and() -> Vec<Instruction> {
    vec![
        // a + b = (a ^ b) + ((a & b) << 1)
        instr(Opcode::DUP(1), None),
        instr(Opcode::DUP(3), None),
        instr(Opcode::AND, None),
        instr(Opcode::SWAP(1), None),
        instr(Opcode::DUP(3), None),
        instr(Opcode::XOR, None),
        instr(Opcode::SWAP(2), None),
        instr(Opcode::POP, None),
        instr(Opcode::PUSH(1), Some("01".into())),
        instr(Opcode::SHL, None),
        instr(Opcode::ADD, None),
    ]
}

fn build_add_or_and() -> Vec<Instruction> {
    vec![
        // a + b = (a | b) + (a & b)
        instr(Opcode::DUP(1), None),
        instr(Opcode::DUP(3), None),
        instr(Opcode::AND, None),
        instr(Opcode::SWAP(1), None),
        instr(Opcode::DUP(3), None),
        instr(Opcode::OR, None),
        instr(Opcode::SWAP(2), None),
        instr(Opcode::POP, None),
        instr(Opcode::ADD, None),
    ]
}

fn build_sub_borrow() -> Vec<Instruction> {
    vec![
        // b - a = (a ^ b) - ((~b & a) << 1)
        instr(Opcode::DUP(2), None),
        instr(Opcode::NOT, None),
        instr(Opcode::DUP(2), None),
        instr(Opcode::AND, None),
        instr(Opcode::SWAP(1), None),
        instr(Opcode::DUP(3), None),
        instr(Opcode::XOR, None),
        instr(Opcode::SWAP(2), None),
        instr(Opcode::POP, None),
        instr(Opcode::PUSH(1), Some("01".into())),
        instr(Opcode::SHL, None),
        instr(Opcode::SUB, None),
    ]
}

fn build_sub_twos_complement() -> Vec<Instruction> {
    vec![
        // b - a = b + (~a + 1)
        instr(Opcode::DUP(1), None),
        instr(Opcode::NOT, None),
        instr(Opcode::PUSH(1), Some("01".into())),
        instr(Opcode::ADD, None),
        instr(Opcode::SWAP(1), None),
        instr(Opcode::POP, None),
        instr(Opcode::ADD, None),
    ]
}

fn append_noise(out: &mut Vec<Instruction>, rng: &mut StdRng) {
    let source = NoiseSource::random(rng);
    let encoding_a = NoiseEncoding::random(rng);
    let mut encoding_b = NoiseEncoding::random(rng);
    if encoding_b == encoding_a {
        encoding_b = NoiseEncoding::random(rng);
    }

    debug!(
        "MBA noise source={:?} enc_a={:?} enc_b={:?}",
        source, encoding_a, encoding_b
    );
    source.emit(out);
    encoding_a.emit(out);
    out.push(instr(Opcode::ADD, None));

    source.emit(out);
    encoding_b.emit(out);
    out.push(instr(Opcode::SUB, None));
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::Block;
    use azoth_core::cfg_ir::CfgIrBundle;
    use azoth_core::process_bytecode_to_cfg;
    use rand::SeedableRng;
    use tracing_subscriber::EnvFilter;

    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

    fn count_instructions(ir: &CfgIrBundle) -> usize {
        ir.cfg
            .node_indices()
            .filter_map(|n| match &ir.cfg[n] {
                Block::Body(body) => Some(body.instructions.len()),
                _ => None,
            })
            .sum()
    }

    fn count_ops(ir: &CfgIrBundle, f: impl Fn(Opcode) -> bool) -> usize {
        ir.cfg
            .node_indices()
            .filter_map(|n| match &ir.cfg[n] {
                Block::Body(body) => Some(body.instructions.iter().filter(|ins| f(ins.op)).count()),
                _ => None,
            })
            .sum()
    }

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("debug"))
            .with_test_writer()
            .try_init();
    }

    #[tokio::test]
    async fn mba_rewrites_and_injects_noise() {
        init_tracing();

        let (mut ir, _, _, _) =
            process_bytecode_to_cfg(COUNTER_DEPLOYMENT, false, COUNTER_RUNTIME, false)
                .await
                .unwrap();

        let add_sub_count = count_ops(&ir, |op| matches!(op, Opcode::ADD | Opcode::SUB));
        assert!(add_sub_count > 0, "fixture should contain ADD or SUB");

        let before_instrs = count_instructions(&ir);
        let before_noise = count_ops(&ir, |op| {
            matches!(
                op,
                Opcode::CALLDATALOAD | Opcode::CALLER | Opcode::NUMBER | Opcode::TIMESTAMP
            )
        });

        let mut rng = StdRng::seed_from_u64(0x5eed_u64);
        let mba = Mba::new();
        let changed = mba.apply(&mut ir, &mut rng).unwrap();

        let after_instrs = count_instructions(&ir);
        let after_noise = count_ops(&ir, |op| {
            matches!(
                op,
                Opcode::CALLDATALOAD | Opcode::CALLER | Opcode::NUMBER | Opcode::TIMESTAMP
            )
        });

        assert!(changed, "MBA should rewrite at least one instruction");
        assert!(
            after_instrs > before_instrs,
            "MBA should expand instruction count"
        );
        assert!(
            after_noise > before_noise,
            "MBA should inject runtime noise sources"
        );
    }
}
