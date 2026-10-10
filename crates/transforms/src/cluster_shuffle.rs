//! Cluster-aware CFG shuffler.
//!
//! Instead of shuffling individual blocks, this transform shuffles maximal
//! physical-fallthrough clusters. Concrete terminators, rather than potentially
//! incomplete CFG edges, decide which blocks must remain adjacent. Clusters
//! connected only by explicit jumps may move independently. This preserves EVM
//! fallthrough semantics without injecting a recognizable trampoline after every
//! block.
//!
//! To avoid weak seeds which accidentally leave most clusters in source order,
//! the selected permutation must retain at most half of the movable cluster
//! order.  Selection is still seed-derived and deterministic.

use crate::{has_self_code_layout_semantics, Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::{is_terminal_opcode, Opcode};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use tracing::debug;

const MAX_PERMUTATION_TRIALS: usize = 64;
// One bit-parallel LCS trial performs roughly `n * ceil(n / 64)` word
// operations. Bound aggregate search work so a near-limit runtime cannot turn
// obfuscation into an accidental CPU denial of service.
const LCS_WORD_OPERATION_BUDGET: usize = 32_000_000;

/// Cluster-level shuffle wrapper.
#[derive(Default)]
pub struct ClusterShuffle;

impl ClusterShuffle {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for ClusterShuffle {
    fn name(&self) -> &'static str {
        "ClusterShuffle"
    }

    fn supports_gas_observation(&self) -> bool {
        true
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        if has_self_code_layout_semantics(ir) {
            return Err(Error::Generic(
                "cluster shuffle requires typed relocation support for PC/CODESIZE/CODECOPY".into(),
            ));
        }
        let bounds = ir.runtime_bounds;
        let mut runtime_nodes: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body)
                    if bounds.is_none_or(|(start, end)| {
                        body.start_pc >= start && body.start_pc < end
                    }) =>
                {
                    Some((body.start_pc, node))
                }
                _ => None,
            })
            .collect();
        runtime_nodes.sort_by_key(|(pc, _)| *pc);
        if runtime_nodes.len() < 3 {
            return Ok(false);
        }

        let final_runtime_falls_off = runtime_nodes
            .last()
            .and_then(|(_, node)| match &ir.cfg[*node] {
                Block::Body(body) => Some(requires_physical_successor(body)),
                Block::Entry | Block::Exit => None,
            })
            .unwrap_or(false);

        // Form maximal sequences whose physical adjacency is semantically required.
        // CFG metadata can be Unknown for computed JUMPI targets, but the false
        // path still always continues at the following byte.
        let mut clusters: Vec<Vec<_>> = Vec::new();
        for (_, node) in runtime_nodes {
            let append_to_previous = clusters.last().is_some_and(|cluster| {
                let previous = *cluster.last().expect("non-empty cluster");
                matches!(&ir.cfg[previous], Block::Body(body) if requires_physical_successor(body))
            });
            if append_to_previous {
                clusters.last_mut().expect("cluster exists").push(node);
            } else {
                clusters.push(vec![node]);
            }
        }

        // Execution starts at runtime byte zero, so the cluster containing the entry
        // block is anchored. Only explicitly reached clusters may move around it.
        if clusters.len() < 3 {
            return Ok(false);
        }
        let entry_cluster = clusters.remove(0);
        // Falling off the original runtime executes the EVM's implicit STOP. If
        // that cluster moved ahead of another cluster, the old falloff would
        // instead execute those bytes. Keep the complete tail cluster last.
        let tail_cluster = final_runtime_falls_off.then(|| {
            clusters
                .pop()
                .expect("the original runtime tail belongs to a cluster")
        });
        if clusters.len() < 2 {
            return Ok(false);
        }
        let original_movable = clusters.clone();
        clusters = choose_strong_permutation(
            ir,
            &entry_cluster,
            tail_cluster.as_deref().unwrap_or(&[]),
            &original_movable,
            rng,
        );
        if clusters == original_movable {
            return Ok(false);
        }

        let runtime_start = bounds.map(|(start, _)| start).unwrap_or(0);
        let mut cursor = runtime_start;
        for node in entry_cluster
            .into_iter()
            .chain(clusters.into_iter().flatten())
            .chain(tail_cluster.into_iter().flatten())
        {
            let Some(Block::Body(body)) = ir.cfg.node_weight_mut(node) else {
                continue;
            };
            body.start_pc = cursor;
            cursor += body
                .instructions
                .iter()
                .map(azoth_core::decoder::Instruction::byte_size)
                .sum::<usize>();
        }
        if bounds.is_some() {
            // Literal synthesis may have grown the runtime before this pass.
            // Keeping the original end would make reindexing misclassify every
            // shuffled block placed beyond that stale boundary as init/data.
            ir.runtime_bounds = Some((runtime_start, cursor));
        }

        debug!("ClusterShuffle: safely reordered fallthrough-preserving clusters");
        Ok(true)
    }
}

/// Whether execution can reach the byte immediately following this concrete
/// block. JUMPI always has a physical false path, even when its true target is
/// unresolved and the high-level control descriptor is therefore `Unknown`.
fn requires_physical_successor(body: &BlockBody) -> bool {
    body.instructions.last().is_none_or(|instruction| {
        matches!(instruction.op, Opcode::JUMPI)
            || (!matches!(instruction.op, Opcode::JUMP) && !is_terminal_opcode(instruction.op))
    })
}

/// Pick a deterministic random permutation whose surviving source-order
/// subsequence is no larger than half of the movable clusters.  With very small
/// cluster sets, reversal is the exact strongest fallback.
fn choose_strong_permutation(
    ir: &CfgIrBundle,
    entry: &[petgraph::graph::NodeIndex],
    suffix: &[petgraph::graph::NodeIndex],
    original: &[Vec<petgraph::graph::NodeIndex>],
    rng: &mut StdRng,
) -> Vec<Vec<petgraph::graph::NodeIndex>> {
    debug_assert!(original.len() >= 2);
    let target = (original.len() / 2).max(1);
    let mut best = original.to_vec();
    let original_runtime = original_clean_runtime(ir);
    let byte_target = original_runtime
        .as_deref()
        .map_or(usize::MAX, |bytes| bytes.len() * 2 / 5);
    let mut best_score = usize::MAX;

    let trial_count = original_runtime
        .as_deref()
        .map_or(MAX_PERMUTATION_TRIALS, |bytes| {
            candidate_trial_budget(bytes.len())
        });
    for _ in 0..trial_count {
        let mut candidate = original.to_vec();
        candidate.shuffle(rng);
        let retained = retained_order_len(original, &candidate);
        if candidate == original || retained > target {
            continue;
        }

        let byte_score = original_runtime
            .as_deref()
            .and_then(|source| {
                encode_cluster_order(ir, entry, &candidate, suffix).map(|output| (source, output))
            })
            .map_or(retained, |(source, output)| lcs_len(source, &output));
        if byte_score < best_score {
            best = candidate.clone();
            best_score = byte_score;
        }
        // Accept the first sufficiently strong seed-derived permutation instead
        // of canonicalizing every output to the single global minimum.
        if byte_score <= byte_target {
            return candidate;
        }
    }

    if best != original {
        return best;
    }
    original.iter().rev().cloned().collect()
}

/// Recover the immutable clean-runtime source from the strip report. Runtime
/// bounds are mutable transform state, so using them after a size-changing pass
/// can accidentally score against auxdata or a constructor suffix.
fn original_clean_runtime(ir: &CfgIrBundle) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(ir.clean_report.clean_len);
    for span in &ir.clean_report.runtime_layout {
        let end = span.offset.checked_add(span.len)?;
        bytes.extend_from_slice(ir.original_bytecode.get(span.offset..end)?);
    }
    (bytes.len() == ir.clean_report.clean_len).then_some(bytes)
}

fn encode_cluster_order(
    ir: &CfgIrBundle,
    entry: &[petgraph::graph::NodeIndex],
    clusters: &[Vec<petgraph::graph::NodeIndex>],
    suffix: &[petgraph::graph::NodeIndex],
) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for node in entry.iter().chain(clusters.iter().flatten()).chain(suffix) {
        let Block::Body(body) = &ir.cfg[*node] else {
            continue;
        };
        for instruction in &body.instructions {
            if matches!(instruction.op, Opcode::INVALID) {
                if let Some(immediate) = &instruction.imm {
                    if let Ok(byte) = u8::from_str_radix(immediate, 16) {
                        bytes.push(byte);
                        continue;
                    }
                }
                bytes.push(*ir.original_bytecode.get(instruction.pc)?);
                continue;
            }
            bytes.push(instruction.op.to_byte());
            if let Opcode::PUSH(width) = instruction.op {
                let immediate = hex::decode(instruction.imm.as_deref()?).ok()?;
                if immediate.len() != width as usize {
                    return None;
                }
                bytes.extend_from_slice(&immediate);
            }
        }
    }
    Some(bytes)
}

fn lcs_len(left: &[u8], right: &[u8]) -> usize {
    if left.is_empty() || right.is_empty() {
        return 0;
    }

    // Exact bit-parallel LCS. Candidate count is size-budgeted above, and the
    // ordinary quadratic table would still be prohibitively slow near EIP-170.
    let (rows, columns) = if left.len() >= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let word_count = columns.len().div_ceil(u64::BITS as usize);
    let mut matches = vec![vec![0u64; word_count]; 256];
    for (index, byte) in columns.iter().copied().enumerate() {
        matches[byte as usize][index / 64] |= 1u64 << (index % 64);
    }

    let mut state = vec![0u64; word_count];
    let mut shifted = vec![0u64; word_count];
    for byte in rows {
        let mut carry = 1u64;
        for (source, target) in state.iter().copied().zip(&mut shifted) {
            *target = (source << 1) | carry;
            carry = source >> 63;
        }

        let mut borrow = false;
        for word in 0..word_count {
            let x = matches[*byte as usize][word] | state[word];
            let (partial, first_borrow) = x.overflowing_sub(shifted[word]);
            let (difference, second_borrow) = partial.overflowing_sub(u64::from(borrow));
            borrow = first_borrow || second_borrow;
            state[word] = x & !difference;
        }
    }

    state.iter().map(|word| word.count_ones() as usize).sum()
}

fn candidate_trial_budget(byte_len: usize) -> usize {
    let words = byte_len.div_ceil(u64::BITS as usize);
    let per_trial = byte_len.saturating_mul(words).max(1);
    (LCS_WORD_OPERATION_BUDGET / per_trial).clamp(4, MAX_PERMUTATION_TRIALS)
}

/// LCS length for two permutations of the same unique clusters.
///
/// Map each cluster to its source position, then compute the longest increasing
/// subsequence in `O(k log k)`. The first node is a stable identity because CFG
/// nodes occur in exactly one non-empty cluster.
fn retained_order_len(
    original: &[Vec<petgraph::graph::NodeIndex>],
    candidate: &[Vec<petgraph::graph::NodeIndex>],
) -> usize {
    let positions: HashMap<_, _> = original
        .iter()
        .enumerate()
        .map(|(position, cluster)| (*cluster.first().expect("clusters are non-empty"), position))
        .collect();
    let mut tails = Vec::<usize>::with_capacity(candidate.len());
    for cluster in candidate {
        let position = positions[cluster.first().expect("clusters are non-empty")];
        let insertion = tails.partition_point(|tail| *tail < position);
        if insertion == tails.len() {
            tails.push(position);
        } else {
            tails[insertion] = position;
        }
    }
    tails.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::literal_synthesis::LiteralSynthesis;
    use azoth_core::cfg_ir::{BlockControl, EdgeType};
    use azoth_core::decoder::Instruction;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;
    use petgraph::visit::{EdgeRef, IntoEdgeReferences};

    const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");
    const TAIL_FALLOFF_DEPLOYMENT: &str = "0x600b600a5f39600b5ff3610008565bfe5bfe5b6002";
    const TAIL_FALLOFF_RUNTIME: &str = "0x610008565bfe5bfe5b6002";
    const UNRESOLVED_JUMPI_DEPLOYMENT: &str =
        "0x6011600a5f3960115ff36000600f805057602a5f5260205ff35bfe";
    const UNRESOLVED_JUMPI_RUNTIME: &str = "0x6000600f805057602a5f5260205ff35bfe";

    #[tokio::test]
    async fn preserves_entry_and_every_physical_fallthrough_pair() {
        // Solidity-style branch diamonds with three independently jumped-to tails.
        let bytecode = "0x600b576005565b600e565b6011565b005b005b00";
        let (mut ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();
        let original_entry = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                _ => None,
            })
            .min_by_key(|(pc, _)| *pc)
            .unwrap()
            .1;
        let required_pairs: Vec<_> = ir
            .cfg
            .edge_references()
            .filter(|edge| {
                matches!(edge.weight(), EdgeType::Fallthrough | EdgeType::BranchFalse)
                    && matches!(ir.cfg[edge.source()], Block::Body(_))
                    && matches!(ir.cfg[edge.target()], Block::Body(_))
            })
            .map(|edge| (edge.source(), edge.target()))
            .collect();

        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut rng = seed.create_deterministic_rng();
        let _ = ClusterShuffle::new().apply(&mut ir, &mut rng).unwrap();

        let mut ordered: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                _ => None,
            })
            .collect();
        ordered.sort_by_key(|(pc, _)| *pc);
        assert_eq!(ordered.first().unwrap().1, original_entry);
        let positions: std::collections::HashMap<_, _> = ordered
            .iter()
            .enumerate()
            .map(|(index, (_, node))| (*node, index))
            .collect();
        for (source, target) in required_pairs {
            assert_eq!(positions[&target], positions[&source] + 1);
        }
    }

    #[tokio::test]
    async fn refreshes_runtime_bounds_after_literal_growth() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(
            COUNTER_DEPLOYMENT.trim(),
            false,
            COUNTER_RUNTIME.trim(),
            false,
        )
        .await
        .expect("counter bytecode should produce a CFG");
        let (runtime_start, stale_runtime_end) = ir.runtime_bounds.expect("runtime bounds");
        let seed = Seed::from_hex(FIXED_SEED).expect("valid fixed seed");
        let mut rng = seed.create_deterministic_rng();

        assert!(LiteralSynthesis::new()
            .apply(&mut ir, &mut rng)
            .expect("literal synthesis should succeed"));
        let grown_runtime_len: usize = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body)
                    if body.start_pc >= runtime_start && body.start_pc < stale_runtime_end =>
                {
                    Some(
                        body.instructions
                            .iter()
                            .map(azoth_core::decoder::Instruction::byte_size)
                            .sum::<usize>(),
                    )
                }
                _ => None,
            })
            .sum();
        let expected_runtime_end = runtime_start + grown_runtime_len;
        assert!(
            expected_runtime_end > stale_runtime_end,
            "fixture must make the pre-shuffle runtime bound stale"
        );

        assert!(ClusterShuffle::new()
            .apply(&mut ir, &mut rng)
            .expect("cluster shuffle should succeed"));
        assert_eq!(
            ir.runtime_bounds,
            Some((runtime_start, expected_runtime_end)),
            "all shuffled blocks, including the grown tail, must remain classified as runtime"
        );
        assert!(ir.cfg.node_indices().all(|node| match &ir.cfg[node] {
            Block::Body(body) => {
                body.start_pc >= runtime_start && body.start_pc < expected_runtime_end
            }
            Block::Entry | Block::Exit => true,
        }));

        let (_, old_bounds) = ir.reindex_pcs().expect("reindexing should succeed");
        assert_eq!(old_bounds, Some((runtime_start, expected_runtime_end)));
        assert_eq!(
            ir.runtime_bounds,
            Some((0, grown_runtime_len)),
            "reindexing must retain the complete grown runtime"
        );
    }

    #[tokio::test]
    async fn pins_an_original_falloff_tail_after_all_shuffled_clusters() {
        let (mut ir, _, _, _) =
            process_bytecode_to_cfg(TAIL_FALLOFF_DEPLOYMENT, false, TAIL_FALLOFF_RUNTIME, false)
                .await
                .expect("tail fixture should produce a CFG");
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
        let Block::Body(tail_body) = &ir.cfg[original_tail] else {
            unreachable!()
        };
        assert!(requires_physical_successor(tail_body));

        let seed = Seed::from_hex(FIXED_SEED).expect("fixed seed");
        let mut rng = seed.create_deterministic_rng();
        assert!(ClusterShuffle::new()
            .apply(&mut ir, &mut rng)
            .expect("shuffle should succeed"));

        let final_tail = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                Block::Entry | Block::Exit => None,
            })
            .max_by_key(|(pc, _)| *pc)
            .expect("runtime tail")
            .1;
        assert_eq!(final_tail, original_tail, "falloff must still reach EOF");
    }

    #[tokio::test]
    async fn unresolved_jumpi_keeps_its_concrete_false_path_adjacent() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(
            UNRESOLVED_JUMPI_DEPLOYMENT,
            false,
            UNRESOLVED_JUMPI_RUNTIME,
            false,
        )
        .await
        .expect("unresolved JUMPI fixture should produce a CFG");
        let mut ordered: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|node| match &ir.cfg[node] {
                Block::Body(body) => Some((body.start_pc, node)),
                Block::Entry | Block::Exit => None,
            })
            .collect();
        ordered.sort_by_key(|(pc, _)| *pc);
        let jumpi = ordered[0].1;
        let false_path = ordered[1].1;
        let Block::Body(jumpi_body) = &ir.cfg[jumpi] else {
            unreachable!()
        };
        assert!(matches!(jumpi_body.control, BlockControl::Unknown));
        assert!(matches!(
            jumpi_body.instructions.last(),
            Some(Instruction {
                op: Opcode::JUMPI,
                ..
            })
        ));
        assert!(requires_physical_successor(jumpi_body));

        let seed = Seed::from_hex(FIXED_SEED).expect("fixed seed");
        let mut rng = seed.create_deterministic_rng();
        let _ = ClusterShuffle::new()
            .apply(&mut ir, &mut rng)
            .expect("shuffle should not fail");
        let jumpi_pc = match &ir.cfg[jumpi] {
            Block::Body(body) => body.start_pc,
            Block::Entry | Block::Exit => unreachable!(),
        };
        let jumpi_len = match &ir.cfg[jumpi] {
            Block::Body(body) => body
                .instructions
                .iter()
                .map(Instruction::byte_size)
                .sum::<usize>(),
            Block::Entry | Block::Exit => unreachable!(),
        };
        let false_pc = match &ir.cfg[false_path] {
            Block::Body(body) => body.start_pc,
            Block::Entry | Block::Exit => unreachable!(),
        };
        assert_eq!(false_pc, jumpi_pc + jumpi_len);
    }

    #[tokio::test]
    async fn strong_permutation_limits_surviving_source_order() {
        let original: Vec<Vec<_>> = (0..12)
            .map(|value| vec![petgraph::graph::NodeIndex::new(value)])
            .collect();
        let seed = Seed::from_hex(FIXED_SEED).unwrap();
        let mut first_rng = seed.create_deterministic_rng();
        let mut second_rng = seed.create_deterministic_rng();
        let (ir, _, _, _) = process_bytecode_to_cfg(
            COUNTER_DEPLOYMENT.trim(),
            false,
            COUNTER_RUNTIME.trim(),
            false,
        )
        .await
        .unwrap();
        let entry = Vec::new();
        let first = choose_strong_permutation(&ir, &entry, &[], &original, &mut first_rng);
        let second = choose_strong_permutation(&ir, &entry, &[], &original, &mut second_rng);

        assert_eq!(first, second, "same seed must select the same permutation");
        assert_ne!(first, original);
        assert!(retained_order_len(&original, &first) <= original.len() / 2);
    }

    #[test]
    fn bit_parallel_lcs_is_exact_on_repeated_bytes() {
        assert_eq!(lcs_len(b"abcabcaa", b"acbacba"), 5);
        assert_eq!(lcs_len(b"", b"anything"), 0);
        assert_eq!(lcs_len(b"same", b"same"), 4);
    }

    #[test]
    fn candidate_search_is_bounded_for_near_limit_runtime() {
        assert_eq!(candidate_trial_budget(509), MAX_PERMUTATION_TRIALS);
        assert_eq!(candidate_trial_budget(24_576), 4);
        assert!((4..=MAX_PERMUTATION_TRIALS).contains(&candidate_trial_budget(8_192)));
    }

    #[tokio::test]
    async fn scoring_source_ignores_mutated_runtime_bounds() {
        let (mut ir, _, _, _) = process_bytecode_to_cfg(
            COUNTER_DEPLOYMENT.trim(),
            false,
            COUNTER_RUNTIME.trim(),
            false,
        )
        .await
        .expect("counter bytecode should produce a CFG");
        let original = original_clean_runtime(&ir).expect("original clean runtime");
        assert_eq!(original.len(), ir.clean_report.clean_len);

        let (start, end) = ir.runtime_bounds.expect("runtime bounds");
        ir.runtime_bounds = Some((start, end + 17));
        assert_eq!(
            original_clean_runtime(&ir).expect("source remains recoverable"),
            original
        );
    }
}
