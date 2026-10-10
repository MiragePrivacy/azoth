//! Low-density, compiler-shaped control-flow topology diversification.
//!
//! This pass reroutes a small seed-derived sample of existing symbolic runtime
//! jumps through ordinary `JUMPDEST; PUSH2; JUMP` forwarding blocks. The new
//! nodes change CFG topology without introducing dead branches, storage reads,
//! or environment-dependent predicates. The shape is deliberately one Solidity
//! and Yul already use for internal-function routing.

use crate::{
    collect_protected_nodes, has_gas_observation, has_self_code_layout_semantics, Error, Result,
    Transform,
};
use azoth_core::cfg_ir::{Block, BlockBody, BlockControl, CfgIrBundle, JumpTarget};
use azoth_core::decoder::Instruction;
use azoth_core::{is_terminal_opcode, Opcode};
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use tracing::debug;

/// Adds a small number of forwarding nodes to existing direct jump edges.
#[derive(Debug, Default)]
pub struct JumpTrampoline;

impl JumpTrampoline {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    source: NodeIndex,
    target: NodeIndex,
}

impl Transform for JumpTrampoline {
    fn name(&self) -> &'static str {
        "JumpTrampoline"
    }

    fn supports_gas_observation(&self) -> bool {
        // apply() detects any GAS opcode and returns no-change.
        true
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        if has_self_code_layout_semantics(ir) {
            return Err(Error::Generic(
                "jump trampolines do not support PC/CODESIZE/CODECOPY or EXTCODE* introspection"
                    .into(),
            ));
        }
        if has_gas_observation(ir) {
            debug!("JumpTrampoline skipped because runtime observes GAS");
            return Ok(false);
        }

        let protected = collect_protected_nodes(ir);
        let bounds = ir.runtime_bounds;
        let mut candidates: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|source| {
                if protected.contains(&source) || ir.dispatcher_blocks.contains(&source.index()) {
                    return None;
                }
                let Block::Body(body) = &ir.cfg[source] else {
                    return None;
                };
                if !bounds.is_none_or(|(start, end)| body.start_pc >= start && body.start_pc < end)
                    || !ends_in_wide_direct_jump(body)
                {
                    return None;
                }
                let BlockControl::Jump {
                    target: JumpTarget::Block { node: target, .. },
                } = body.control
                else {
                    return None;
                };
                Some(Candidate { source, target })
            })
            .collect();

        if candidates.is_empty() {
            return Ok(false);
        }
        if runtime_tail_falls_off(ir, bounds)
            && bounds.is_some_and(|(_, runtime_end)| runtime_end < ir.original_bytecode.len())
        {
            // Runtime fallthrough continues into deployed metadata/padding. An
            // inserted STOP would change that suffix's behavior, while appending
            // a trampoline directly would execute it. Leave this pass unchanged;
            // ClusterShuffle can still preserve the original suffix fallthrough.
            debug!("JumpTrampoline skipped because runtime falls into a deployed suffix");
            return Ok(false);
        }
        candidates.shuffle(rng);

        // Keep the pass low-density: one forwarding node for small contracts,
        // and at most three even for large contracts. Varying the count prevents
        // a fixed per-contract cardinality signature.
        let maximum = (1 + candidates.len() / 32).min(3);
        let count = rng.random_range(1..=maximum.min(candidates.len()));
        let selected = &candidates[..count];

        let mut cursor = next_runtime_pc(ir, bounds);
        // EOF behaves as an implicit STOP. Appending forwarding blocks would
        // otherwise turn a formerly harmless falloff (including a JUMPI false
        // path) into execution of the first trampoline.
        let stop_barrier_added = append_end_of_code_stop_barrier(ir, bounds, &mut cursor)?;
        for candidate in selected {
            let trampoline_value = runtime_target_value(cursor, bounds);
            let target_pc = match &ir.cfg[candidate.target] {
                Block::Body(body) => body.start_pc,
                Block::Entry | Block::Exit => continue,
            };
            let target_value = runtime_target_value(target_pc, bounds);
            if trampoline_value > u16::MAX as usize || target_value > u16::MAX as usize {
                return Err(Error::SizeLimitExceeded);
            }

            let trampoline = ir.add_block(Block::Body(BlockBody {
                start_pc: cursor,
                instructions: vec![
                    Instruction {
                        pc: cursor,
                        op: Opcode::JUMPDEST,
                        imm: None,
                    },
                    Instruction {
                        pc: cursor + 1,
                        op: Opcode::PUSH(2),
                        imm: Some(format!("{target_value:04x}")),
                    },
                    Instruction {
                        pc: cursor + 4,
                        op: Opcode::JUMP,
                        imm: None,
                    },
                ],
                max_stack: 1,
                control: BlockControl::Unknown,
            }));
            // `add_block` intentionally does not infer a PC mapping. Registering
            // the fresh label lets the symbolic CFG helper resolve the redirect.
            ir.pc_to_block.insert(cursor, trampoline);
            cursor += 5;
            if let Some((start, _)) = bounds {
                ir.runtime_bounds = Some((start, cursor));
            }

            // Both rewrites are symbolic and therefore participate in the normal
            // post-layout jump relocation instead of embedding stale raw PCs.
            ir.set_unconditional_jump(trampoline, candidate.target)
                .map_err(|error| Error::CoreError(error.to_string()))?;
            write_direct_jump_immediate(ir, candidate.source, trampoline_value)?;
            ir.set_unconditional_jump(candidate.source, trampoline)
                .map_err(|error| Error::CoreError(error.to_string()))?;
        }

        debug!(
            count,
            stop_barrier_added, "JumpTrampoline added forwarding CFG nodes"
        );
        Ok(true)
    }
}

fn append_end_of_code_stop_barrier(
    ir: &mut CfgIrBundle,
    bounds: Option<(usize, usize)>,
    cursor: &mut usize,
) -> Result<bool> {
    let tail = runtime_tail(ir, bounds);
    let Some(tail) = tail else {
        return Ok(false);
    };
    if !runtime_tail_falls_off(ir, bounds) {
        return Ok(false);
    }

    let stop_pc = *cursor;
    let barrier = ir.add_block(Block::Body(BlockBody {
        start_pc: stop_pc,
        instructions: vec![Instruction {
            pc: stop_pc,
            op: Opcode::STOP,
            imm: None,
        }],
        max_stack: 0,
        control: BlockControl::Terminal,
    }));
    ir.pc_to_block.insert(stop_pc, barrier);
    *cursor += 1;
    if let Some((start, _)) = bounds {
        ir.runtime_bounds = Some((start, *cursor));
    }
    // Rebuild after registering the barrier so a concrete fallthrough or a
    // JUMPI false edge points to it. Keeping JUMPI as the tail's final
    // instruction is essential for subsequent symbolic relocation.
    ir.rebuild_edges_for_block(tail)
        .map_err(|error| Error::CoreError(error.to_string()))?;
    ir.rebuild_edges_for_block(barrier)
        .map_err(|error| Error::CoreError(error.to_string()))?;
    Ok(true)
}

fn runtime_tail(ir: &CfgIrBundle, bounds: Option<(usize, usize)>) -> Option<NodeIndex> {
    ir.cfg
        .node_indices()
        .filter_map(|node| match &ir.cfg[node] {
            Block::Body(body)
                if bounds
                    .is_none_or(|(start, end)| body.start_pc >= start && body.start_pc < end) =>
            {
                Some((body.start_pc, node))
            }
            Block::Entry | Block::Exit | Block::Body(_) => None,
        })
        .max_by_key(|(start_pc, _)| *start_pc)
        .map(|(_, node)| node)
}

fn runtime_tail_falls_off(ir: &CfgIrBundle, bounds: Option<(usize, usize)>) -> bool {
    runtime_tail(ir, bounds).is_some_and(|tail| matches!(&ir.cfg[tail], Block::Body(body) if body.instructions.last().is_none_or(|instruction| {
        matches!(instruction.op, Opcode::JUMPI)
            || (!matches!(instruction.op, Opcode::JUMP)
                && !is_terminal_opcode(instruction.op))
    })))
}

fn runtime_target_value(pc: usize, bounds: Option<(usize, usize)>) -> usize {
    bounds.map_or(pc, |(start, _)| pc.saturating_sub(start))
}

fn write_direct_jump_immediate(
    ir: &mut CfgIrBundle,
    source: NodeIndex,
    value: usize,
) -> Result<()> {
    let Some(Block::Body(body)) = ir.cfg.node_weight_mut(source) else {
        return Err(Error::Generic("jump source is not a body block".into()));
    };
    let Some(instruction) = body.instructions.iter_mut().rev().nth(1) else {
        return Err(Error::Generic(
            "direct jump source has no target PUSH".into(),
        ));
    };
    let Opcode::PUSH(width) = instruction.op else {
        return Err(Error::Generic(
            "direct jump source target is not a PUSH".into(),
        ));
    };
    let digits = width as usize * 2;
    if digits < std::mem::size_of::<usize>() * 2 && value >= (1usize << (digits * 4)) {
        return Err(Error::SizeLimitExceeded);
    }
    instruction.imm = Some(format!("{value:0digits$x}"));
    Ok(())
}

fn ends_in_wide_direct_jump(body: &BlockBody) -> bool {
    matches!(
        body.instructions.as_slice(),
        [.., Instruction { op: Opcode::PUSH(width), .. }, Instruction { op: Opcode::JUMP, .. }]
            if *width >= 2
    )
}

fn next_runtime_pc(ir: &CfgIrBundle, bounds: Option<(usize, usize)>) -> usize {
    let runtime_start = bounds.map(|(start, _)| start).unwrap_or(0);
    let runtime_len: usize = ir
        .cfg
        .node_indices()
        .filter_map(|node| match &ir.cfg[node] {
            Block::Body(body)
                if bounds
                    .is_none_or(|(start, end)| body.start_pc >= start && body.start_pc < end) =>
            {
                Some(
                    body.instructions
                        .iter()
                        .map(Instruction::byte_size)
                        .sum::<usize>(),
                )
            }
            _ => None,
        })
        .sum();
    runtime_start + runtime_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;
    use petgraph::visit::EdgeRef;

    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");
    const TAIL_FALLOFF_DEPLOYMENT: &str = "0x600b600a5f39600b5ff3610008565bfe5bfe5b6002";
    const TAIL_FALLOFF_RUNTIME: &str = "0x610008565bfe5bfe5b6002";
    const JUMPI_TAIL_DEPLOYMENT: &str = "0x600c600a5f39600c5ff3610006565b005b6000600657";
    const JUMPI_TAIL_RUNTIME: &str = "0x610006565b005b6000600657";
    const SUFFIX_FALLOFF_DEPLOYMENT: &str = "0x600e600a5f39600e5ff3610008565bfe5bfe5b6002fe0001";
    const SUFFIX_FALLOFF_RUNTIME: &str = "0x610008565bfe5bfe5b6002fe0001";
    const GAS_DEPLOYMENT: &str = "0x6008600a5f3960085ff3610004565b5a5000";
    const GAS_RUNTIME: &str = "0x610004565b5a5000";

    #[tokio::test]
    async fn adds_real_forwarding_nodes_and_edges() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(
            COUNTER_DEPLOYMENT.trim(),
            false,
            COUNTER_RUNTIME.trim(),
            false,
        )
        .await
        .unwrap();
        let original_nodes = ir.cfg.node_count();
        let seed = Seed::from_bytes([0x42; 32]);
        let mut rng = seed.create_deterministic_rng();

        assert!(JumpTrampoline::new().apply(&mut ir, &mut rng).unwrap());
        assert!(ir.cfg.node_count() > original_nodes);
        assert!(ir.cfg.node_indices().any(|node| {
            let Block::Body(body) = &ir.cfg[node] else {
                return false;
            };
            matches!(
                body.instructions.as_slice(),
                [
                    Instruction {
                        op: Opcode::JUMPDEST,
                        ..
                    },
                    Instruction {
                        op: Opcode::PUSH(2),
                        ..
                    },
                    Instruction {
                        op: Opcode::JUMP,
                        ..
                    }
                ]
            ) && ir.cfg.edges(node).any(|edge| edge.target() != node)
        }));
    }

    #[tokio::test]
    async fn inserts_stop_before_trampolines_when_the_original_tail_falls_off() {
        let (mut ir, _, _, _) =
            process_bytecode_to_cfg(TAIL_FALLOFF_DEPLOYMENT, false, TAIL_FALLOFF_RUNTIME, false)
                .await
                .expect("tail fixture should produce a CFG");
        let (_, original_runtime_end) = ir.runtime_bounds.expect("runtime bounds");
        let original_tail = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                Block::Entry | Block::Exit => None,
            })
            .max_by_key(|(pc, _)| *pc)
            .expect("runtime tail")
            .1;
        let seed = Seed::from_bytes([0x42; 32]);
        let mut rng = seed.create_deterministic_rng();

        assert!(JumpTrampoline::new().apply(&mut ir, &mut rng).unwrap());
        let Block::Body(tail) = &ir.cfg[original_tail] else {
            unreachable!()
        };
        assert!(matches!(
            tail.instructions.last(),
            Some(Instruction {
                op: Opcode::PUSH(1),
                ..
            })
        ));
        assert!(ir.cfg.node_indices().any(|node| {
            matches!(&ir.cfg[node], Block::Body(body)
                if body.start_pc == original_runtime_end
                    && matches!(body.instructions.as_slice(), [Instruction { pc, op: Opcode::STOP, .. }] if *pc == original_runtime_end))
        }));
        assert!(ir.cfg.node_indices().any(|node| {
            matches!(&ir.cfg[node], Block::Body(body)
                if body.start_pc == original_runtime_end + 1
                    && matches!(body.instructions.first(), Some(Instruction { op: Opcode::JUMPDEST, .. })))
        }));
        assert_eq!(
            ir.runtime_bounds,
            Some((
                ir.runtime_bounds.expect("runtime bounds").0,
                original_runtime_end + 6
            ))
        );
    }

    #[tokio::test]
    async fn inserts_stop_for_a_jumpi_false_path_at_original_eof() {
        let (mut ir, _, _, _) =
            process_bytecode_to_cfg(JUMPI_TAIL_DEPLOYMENT, false, JUMPI_TAIL_RUNTIME, false)
                .await
                .expect("JUMPI-tail fixture should produce a CFG");
        let (_, original_runtime_end) = ir.runtime_bounds.expect("runtime bounds");
        let tail = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                Block::Entry | Block::Exit => None,
            })
            .max_by_key(|(pc, _)| *pc)
            .expect("runtime tail")
            .1;
        assert!(matches!(
            &ir.cfg[tail],
            Block::Body(body)
                if matches!(body.instructions.last(), Some(Instruction { op: Opcode::JUMPI, .. }))
        ));
        let seed = Seed::from_bytes([0x24; 32]);
        let mut rng = seed.create_deterministic_rng();

        assert!(JumpTrampoline::new().apply(&mut ir, &mut rng).unwrap());
        let Block::Body(body) = &ir.cfg[tail] else {
            unreachable!()
        };
        assert!(matches!(
            body.instructions.last(),
            Some(Instruction {
                op: Opcode::JUMPI,
                ..
            })
        ));
        let barrier = ir
            .cfg
            .node_indices()
            .find(|node| {
                matches!(&ir.cfg[*node], Block::Body(barrier)
                    if barrier.start_pc == original_runtime_end
                        && matches!(barrier.instructions.as_slice(), [Instruction { op: Opcode::STOP, .. }]))
            })
            .expect("explicit EOF STOP barrier");
        assert!(ir.cfg.edges(tail).any(|edge| {
            edge.target() == barrier
                && matches!(edge.weight(), azoth_core::cfg_ir::EdgeType::BranchFalse)
        }));
    }

    #[tokio::test]
    async fn skips_when_tail_fallthrough_executes_a_deployed_suffix() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(
            SUFFIX_FALLOFF_DEPLOYMENT,
            false,
            SUFFIX_FALLOFF_RUNTIME,
            false,
        )
        .await
        .expect("suffix fixture should produce a CFG");
        let before = ir.clone();
        let seed = Seed::from_bytes([0x42; 32]);
        let mut rng = seed.create_deterministic_rng();

        assert!(!JumpTrampoline::new().apply(&mut ir, &mut rng).unwrap());
        assert_eq!(ir.cfg.node_count(), before.cfg.node_count());
        assert_eq!(ir.runtime_bounds, before.runtime_bounds);
    }

    #[tokio::test]
    async fn skips_every_runtime_that_observes_gas() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(GAS_DEPLOYMENT, false, GAS_RUNTIME, false)
            .await
            .expect("GAS fixture should produce a CFG");
        let before = ir.clone();
        let seed = Seed::from_bytes([0x42; 32]);
        let mut rng = seed.create_deterministic_rng();

        assert!(!JumpTrampoline::new().apply(&mut ir, &mut rng).unwrap());
        assert_eq!(ir.cfg.node_count(), before.cfg.node_count());
        assert_eq!(ir.runtime_bounds, before.runtime_bounds);
    }
}
