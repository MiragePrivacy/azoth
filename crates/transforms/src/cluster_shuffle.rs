//! Cluster-aware CFG shuffler.
//!
//! Rather than shuffling individual body blocks (which breaks any block
//! whose control-flow exit is `Fallthrough` or `Branch`, because a
//! conditional JUMPI's false branch and an implicit fall-through both
//! require the next block to sit at the next PC), this transform groups
//! blocks into "clusters" that must stay adjacent and shuffles *those*.
//!
//! A cluster is a maximal run of blocks, in current `start_pc` order,
//! where every non-final block in the run ends in `Fallthrough` or
//! `Branch`. "Maximal" means the run is grown until it cannot be
//! extended: we keep absorbing the next block for as long as the
//! current cluster's tail ends in `Fallthrough` or `Branch`, and we
//! stop only when the tail ends in `Jump`, `Terminal`, or `Unknown` —
//! i.e. the first block whose successor-in-memory is irrelevant to
//! execution. Clusters naturally capture:
//!
//! * Dispatcher tiers emitted by `FunctionDispatcher` — each tier is a
//!   `Branch` block whose false branch falls through to the next tier,
//!   so fallthrough-clustering chains all tiers plus the fallback into
//!   one cluster.
//! * Compiler-emitted basic blocks where Solidity splits a function
//!   across a JUMPDEST without an intervening JUMP — the first block
//!   ends in `Fallthrough` into the JUMPDEST block.
//!
//! Dispatcher-synthesised stubs, decoys, controllers and invalid sinks
//! all end in `Jump`, `Terminal`, or `Unknown` control, so each is its
//! own singleton cluster. Pinning is handled by marking every cluster
//! that contains a dispatcher block as frozen, not by bundling them
//! into a single cluster.
//!
//! Blocks ending in `Jump`, `Terminal`, or `Unknown` are cluster
//! boundaries: execution either transfers via a PUSH target (resolved by
//! `patch_jump_immediates` + `remap_orphan_jump_pushes` after reindex)
//! or ends, so the next PC can be anywhere.
//!
//! The shuffle pins the cluster containing the smallest original
//! `start_pc` at position 0 — the deployed runtime starts executing at
//! runtime-relative PC 0, so that cluster must remain the entry point —
//! and randomises the order of the rest. Temporary `start_pc` values are
//! assigned with a large gap between clusters so `reindex_pcs` observes
//! the new ordering, then reindex compacts everything back to a
//! contiguous PC layout. Jump immediates are remapped by the existing
//! post-reindex pipeline (`patch_jump_immediates`,
//! `remap_orphan_jump_pushes`, and the dispatcher reapply passes), so
//! every `JUMP`/`JUMPI` target stays correct across the rearrangement.
//!
//! # Dispatcher coexistence
//!
//! When a `FunctionDispatcher` is present, the clusters containing
//! stub / decoy / invalid-sink / controller blocks are pinned in place
//! (frozen). Every other runtime cluster is still free to move, and
//! the dispatcher's stored `push_width`s absorb the resulting target-PC
//! shifts because `function_dispatcher::patterns::layout` now pre-sizes
//! those PUSHes via `safe_runtime_push_width` — typically PUSH2 — which
//! comfortably holds any EIP-170-compliant runtime PC. This removes the
//! earlier `OddLength` encoder failures from post-reindex width
//! overflow.
//!
//! For example:
//! ```assembly
//! // Blocks before
//! [runtime_entry][helper_a][helper_b][tail_revert]
//!
//! // After cluster shuffle (one variant)
//! [runtime_entry][tail_revert][helper_a][helper_b]
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::{Block, BlockControl, CfgIrBundle};
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use tracing::debug;

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

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        // Collect runtime body blocks in current PC order. Non-body nodes
        // (Entry / Exit) are not part of any cluster — they don't carry
        // bytecode and `reindex_pcs` leaves them alone. Non-runtime
        // bodies are explicitly excluded so this transform stays safe
        // even if a future change to `process_bytecode_to_cfg` starts
        // including init-code blocks in the graph; shuffling init into
        // the runtime range would silently corrupt the constructor.
        let runtime_bounds = ir.runtime_bounds;
        let in_runtime = |start_pc: usize| -> bool {
            match runtime_bounds {
                Some((start, end)) => start_pc >= start && start_pc < end,
                // When runtime_bounds is unknown, fall back to treating
                // every body as shuffle-eligible — matches the prior
                // behaviour of this transform before the filter was
                // added. Contracts without runtime_bounds don't go
                // through the dispatcher coexistence path anyway.
                None => true,
            }
        };
        let mut sorted: Vec<(usize, NodeIndex)> = ir
            .cfg
            .node_indices()
            .filter_map(|n| match ir.cfg.node_weight(n) {
                Some(Block::Body(body)) if in_runtime(body.start_pc) => Some((body.start_pc, n)),
                _ => None,
            })
            .collect();
        sorted.sort_by_key(|(pc, _)| *pc);

        if sorted.len() < 2 {
            debug!("ClusterShuffle: fewer than two body blocks, nothing to shuffle");
            return Ok(false);
        }

        // Build clusters as maximal fallthrough chains. Start each block
        // as its own singleton, then merge adjacent pairs where the
        // earlier cluster's tail exits via `Fallthrough` or `Branch`.
        // After this pass every cluster's tail has `Jump`, `Terminal`,
        // or `Unknown` control — meaning the next PC is irrelevant for
        // that cluster's execution, so it's safe to follow it with any
        // other cluster.
        let mut clusters: Vec<Vec<NodeIndex>> = sorted.iter().map(|(_, n)| vec![*n]).collect();

        let mut i = 0;
        while i + 1 < clusters.len() {
            let tail = *clusters[i]
                .last()
                .expect("cluster is never empty by construction");
            let needs_next = matches!(
                ir.cfg.node_weight(tail),
                Some(Block::Body(body))
                    if matches!(body.control, BlockControl::Fallthrough | BlockControl::Branch { .. })
            );
            if needs_next {
                let next = clusters.remove(i + 1);
                clusters[i].extend(next);
                // Don't advance: the new tail of clusters[i] might also
                // need merging with the (new) clusters[i + 1].
            } else {
                i += 1;
            }
        }

        if clusters.len() < 2 {
            debug!(
                "ClusterShuffle: fallthrough clustering collapsed into {} cluster(s); nothing to shuffle",
                clusters.len()
            );
            return Ok(false);
        }

        // Pin the runtime entry block and the dispatcher infrastructure.
        //
        // * Entry block: the deployed EVM executes from runtime-relative
        //   PC 0, so whatever block lands at slot 0 after reindex must
        //   be the original entry. For dispatcher-free contracts that's
        //   usually a free-standing constructor prologue or the first
        //   JUMPDEST; for dispatcher-present contracts it's the first
        //   tier of the selector cascade. Either way, we pin the cluster
        //   containing the block with the smallest pre-shuffle start_pc
        //   by adding that block's node to `pinned_nodes`.
        //
        // * Dispatcher blocks (stubs, decoys, controllers, invalid
        //   sinks) reference each other via relative PCs that Step 5's
        //   reapply_{stub,decoy,controller}_patches rewrites using the
        //   dispatcher's stored push_width. Since `safe_runtime_push_width`
        //   in function_dispatcher/patterns/layout.rs now pre-sizes every
        //   dispatcher PUSH to fit any runtime PC, the *targets* those
        //   PUSHes point at (function-body entries) are free to move —
        //   only the stubs/decoys themselves stay put so the dispatcher's
        //   internal layout invariants hold.
        let mut pinned_nodes: HashSet<NodeIndex> = ir
            .dispatcher_blocks
            .iter()
            .map(|&idx| NodeIndex::new(idx))
            .collect();
        if let Some(&(_, entry_node)) = sorted.first() {
            pinned_nodes.insert(entry_node);
        }

        // Mark each cluster as frozen if it contains any pinned node.
        // Frozen clusters stay in their original position slot in the
        // final layout; free clusters are shuffled among themselves,
        // filling the non-frozen slots in their new order.
        let frozen_mask: Vec<bool> = clusters
            .iter()
            .map(|c| c.iter().any(|n| pinned_nodes.contains(n)))
            .collect();

        let free_indices: Vec<usize> = (0..clusters.len()).filter(|i| !frozen_mask[*i]).collect();

        if free_indices.len() < 2 {
            debug!(
                "ClusterShuffle: only {} free cluster(s) after freezing dispatcher dependencies; nothing to shuffle",
                free_indices.len()
            );
            return Ok(false);
        }

        debug!(
            "ClusterShuffle: {} total cluster(s), {} frozen, {} free",
            clusters.len(),
            frozen_mask.iter().filter(|b| **b).count(),
            free_indices.len()
        );

        // Pull the free clusters out (preserving their original
        // ordering for the shuffle comparison), shuffle, and splice
        // back into the non-frozen slots.
        let free_original: Vec<Vec<NodeIndex>> =
            free_indices.iter().map(|&i| clusters[i].clone()).collect();
        let mut free_shuffled = free_original.clone();
        free_shuffled.shuffle(rng);
        if free_shuffled == free_original && free_shuffled.len() > 1 {
            free_shuffled.rotate_left(1);
            debug!("ClusterShuffle: shuffle was identity; rotated left by 1 to force change");
        }

        let mut final_order: Vec<Vec<NodeIndex>> = Vec::with_capacity(clusters.len());
        let mut free_iter = free_shuffled.into_iter();
        for (i, cluster) in clusters.into_iter().enumerate() {
            if frozen_mask[i] {
                final_order.push(cluster);
            } else {
                final_order.push(
                    free_iter
                        .next()
                        .expect("free_shuffled length matches free_indices length"),
                );
            }
        }

        // Detect whether the final order is a no-op (identical to the
        // starting arrangement). If so the whole transform has no
        // effect — skip reindex to avoid producing an empty trace event.
        let original_layout: Vec<NodeIndex> = sorted.iter().map(|(_, n)| *n).collect();
        let new_layout: Vec<NodeIndex> = final_order.iter().flatten().copied().collect();
        if new_layout == original_layout {
            debug!("ClusterShuffle: final layout matches original; nothing to do");
            return Ok(false);
        }

        // Assign temporary `start_pc` values with a large gap between
        // clusters so the obfuscator's Step 5 `reindex_pcs` observes
        // the new ordering. The gap is not a real byte offset — it
        // just has to be large enough that no two clusters' temp PCs
        // overlap after adding an intra-cluster delta. The subsequent
        // `reindex_pcs` will re-sort by `start_pc` and assign
        // contiguous new PCs, producing a single pc_mapping that
        // flows through `patch_jump_immediates`,
        // `remap_orphan_jump_pushes`, and the dispatcher reapply
        // passes — all the jump fix-up happens once in one pipeline
        // stage.
        //
        // Critically, we do NOT call `reindex_pcs()` here. Doing so
        // would consume the pc_mapping for our shuffle inside
        // `write_symbolic_immediates` (which only covers terminal
        // jumps), and the obfuscator's later Step 5 `reindex_pcs`
        // would then see already-contiguous PCs and produce an
        // identity mapping, leaving every non-terminal
        // return-address PUSH untouched. Letting Step 5 do the
        // single reindex ensures the full downstream patch chain
        // runs against our layout change.
        //
        // Temp PCs are anchored at the current runtime start so every
        // shuffled block still reports `is_runtime() == true` when
        // `reindex_pcs` recomputes `runtime_bounds` block-by-block.
        // Without this anchoring, cluster 0 would land at PC 0, which
        // is below any contract's runtime_start, and `reindex_pcs`
        // would misclassify shuffled bodies as init — wiping
        // `runtime_bounds` post-reindex and forcing `patch_jump_immediates`
        // / `remap_orphan_jump_pushes` to reinterpret every
        // runtime-relative PUSH immediate as an absolute PC. That was
        // the real cause of the "~500 stale jumps" regression
        // documented earlier: every direct `PUSH <rel>; JUMP` pattern
        // consulted the wrong base when looking up its old_pc.
        const CLUSTER_GAP: usize = 1_000_000;
        let runtime_start = ir.runtime_bounds.map(|(s, _)| s).unwrap_or(0);
        let mut max_temp_pc = runtime_start;
        for (cluster_idx, cluster) in final_order.iter().enumerate() {
            let base = runtime_start.saturating_add(cluster_idx.saturating_mul(CLUSTER_GAP));
            for (intra_idx, node) in cluster.iter().enumerate() {
                if let Some(Block::Body(body)) = ir.cfg.node_weight_mut(*node) {
                    let temp_pc = base.saturating_add(intra_idx);
                    body.start_pc = temp_pc;
                    max_temp_pc = max_temp_pc.max(temp_pc.saturating_add(1));
                }
            }
        }

        // Widen runtime_bounds so the shuffled blocks still fall inside
        // it during `reindex_pcs`'s per-block `is_runtime` check.
        // `reindex_pcs` overwrites `runtime_bounds` as soon as it finishes,
        // so this expansion is visible only within that pass.
        if let Some((start, end)) = ir.runtime_bounds {
            ir.runtime_bounds = Some((start, end.max(max_temp_pc)));
        }

        debug!(
            "ClusterShuffle: assigned temporary start_pcs for {} cluster(s); Step 5 reindex will compact",
            final_order.len()
        );

        Ok(true)
    }
}
