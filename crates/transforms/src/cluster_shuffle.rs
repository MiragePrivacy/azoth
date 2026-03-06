//! Cluster-aware CFG shuffler.
//!
//! Instead of shuffling individual blocks randomly, this transform groups logically
//! adjacent blocks into clusters and shuffles the clusters as atomic units. This
//! preserves intra-cluster relationships (fallthrough chains, dispatcher tiers,
//! stub+decoy pairs) while randomizing the overall layout.
//!
//! ## Cluster identification
//!
//! Blocks are grouped into clusters by:
//! 1. **Fallthrough chains** — blocks connected by `Fallthrough` edges form a single
//!    cluster because reordering them would break implicit control flow.
//! 2. **Dispatcher groups** — dispatcher, stub, decoy, and controller blocks are
//!    identified via [`collect_protected_nodes`] and grouped into their own cluster.
//!
//! Standalone blocks (no fallthrough predecessor or successor, not part of the
//! dispatcher) each become a single-block cluster.
//!
//! ## Example
//!
//! ```text
//! Before: [dispatcher][stub_a][decoy_a][func_entry→body→ret][helper_entry→ret]
//! After:  [helper_entry→ret][func_entry→body→ret][dispatcher][stub_a][decoy_a]
//! ```

use crate::{collect_protected_nodes, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Cluster-level block shuffler.
///
/// Groups logically adjacent blocks into clusters and shuffles the clusters
/// as units, preserving fallthrough chains and dispatcher block adjacency
/// while randomizing the overall bytecode layout.
#[derive(Default)]
pub struct ClusterShuffle;

impl ClusterShuffle {
    /// Creates a new ClusterShuffle transform.
    pub fn new() -> Self {
        Self
    }
}

impl Transform for ClusterShuffle {
    fn name(&self) -> &'static str {
        "ClusterShuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        let runtime_bounds = ir.runtime_bounds;

        // Collect all runtime body block nodes sorted by start_pc.
        let mut body_nodes: Vec<NodeIndex> = ir
            .cfg
            .node_indices()
            .filter(|&n| {
                if let Block::Body(body) = &ir.cfg[n] {
                    match runtime_bounds {
                        Some((start, end)) => body.start_pc >= start && body.start_pc < end,
                        None => true,
                    }
                } else {
                    false
                }
            })
            .collect();

        body_nodes.sort_by_key(|&n| {
            if let Block::Body(body) = &ir.cfg[n] {
                body.start_pc
            } else {
                0
            }
        });

        if body_nodes.len() <= 1 {
            debug!("ClusterShuffle: not enough runtime blocks to shuffle");
            return Ok(false);
        }

        // Build fallthrough successor map: node → next node via Fallthrough edge.
        let body_node_set: HashSet<NodeIndex> = body_nodes.iter().copied().collect();
        let mut fallthrough_succ: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut fallthrough_pred: HashSet<NodeIndex> = HashSet::new();
        for &node in &body_nodes {
            for edge in ir.cfg.edges(node) {
                if matches!(edge.weight(), EdgeType::Fallthrough) {
                    let target = edge.target();
                    if body_node_set.contains(&target) {
                        fallthrough_succ.insert(node, target);
                        fallthrough_pred.insert(target);
                    }
                }
            }
        }

        // Identify dispatcher-related blocks as a single cluster.
        let protected = collect_protected_nodes(ir);

        // Build clusters by walking fallthrough chains from their heads.
        let mut assigned: HashSet<NodeIndex> = HashSet::new();
        let mut clusters: Vec<Vec<NodeIndex>> = Vec::new();

        // First: group all protected (dispatcher) blocks into one cluster,
        // preserving their original relative order.
        let dispatcher_cluster: Vec<NodeIndex> = body_nodes
            .iter()
            .copied()
            .filter(|n| protected.contains(n))
            .collect();
        if !dispatcher_cluster.is_empty() {
            for &n in &dispatcher_cluster {
                assigned.insert(n);
            }
            clusters.push(dispatcher_cluster);
            debug!(
                "ClusterShuffle: dispatcher cluster with {} blocks",
                clusters[0].len()
            );
        }

        // Second: build fallthrough chain clusters from chain heads.
        // A chain head is a node that has a fallthrough successor but is NOT
        // a fallthrough predecessor (i.e., no one falls through into it).
        for &node in &body_nodes {
            if assigned.contains(&node) {
                continue;
            }
            // Only start chains from heads (not in the middle of a chain).
            if fallthrough_pred.contains(&node) {
                continue;
            }

            let mut chain = vec![node];
            assigned.insert(node);
            let mut cursor = node;
            while let Some(&next) = fallthrough_succ.get(&cursor) {
                if assigned.contains(&next) {
                    break;
                }
                chain.push(next);
                assigned.insert(next);
                cursor = next;
            }
            clusters.push(chain);
        }

        // Third: any remaining unassigned blocks become singleton clusters.
        for &node in &body_nodes {
            if !assigned.contains(&node) {
                clusters.push(vec![node]);
            }
        }

        if clusters.len() <= 1 {
            debug!("ClusterShuffle: only one cluster, nothing to shuffle");
            return Ok(false);
        }

        debug!(
            "ClusterShuffle: identified {} clusters across {} runtime blocks",
            clusters.len(),
            body_nodes.len()
        );
        for (i, cluster) in clusters.iter().enumerate() {
            let pcs: Vec<String> = cluster
                .iter()
                .map(|n| {
                    if let Block::Body(body) = &ir.cfg[*n] {
                        format!("0x{:x}", body.start_pc)
                    } else {
                        "?".into()
                    }
                })
                .collect();
            debug!(
                "  cluster[{}]: {} blocks [{}]",
                i,
                cluster.len(),
                pcs.join(", ")
            );
        }

        // Record the original cluster order for change detection.
        let original_order: Vec<Vec<usize>> = clusters
            .iter()
            .map(|c| {
                c.iter()
                    .map(|n| {
                        if let Block::Body(body) = &ir.cfg[*n] {
                            body.start_pc
                        } else {
                            0
                        }
                    })
                    .collect()
            })
            .collect();

        // Shuffle the clusters.
        clusters.shuffle(rng);

        // Check if order actually changed; if not, rotate to force a change.
        let new_order: Vec<Vec<usize>> = clusters
            .iter()
            .map(|c| {
                c.iter()
                    .map(|n| {
                        if let Block::Body(body) = &ir.cfg[*n] {
                            body.start_pc
                        } else {
                            0
                        }
                    })
                    .collect()
            })
            .collect();

        if original_order == new_order {
            debug!("ClusterShuffle: shuffle produced same order, rotating");
            clusters.rotate_left(1);
        }

        // Flatten clusters into the new block order and assign monotonically
        // increasing temporary PCs. The values don't matter as long as they
        // establish the desired ordering — the pipeline's final `reindex_pcs()`
        // will normalize them to sequential 0-based PCs.
        //
        // We use the original runtime start as a base and increment by the
        // block's actual byte size to keep PCs within a realistic range,
        // avoiding overflow in PUSH immediates during `write_symbolic_immediates`.
        let base_pc = runtime_bounds.map(|(s, _)| s).unwrap_or(0);
        let mut next_pc = base_pc;
        let mut pc_mapping: HashMap<usize, usize> = HashMap::new();
        for cluster in &clusters {
            for &node in cluster {
                if let Some(Block::Body(body)) = ir.cfg.node_weight_mut(node) {
                    body.start_pc = next_pc;
                    for instr in &mut body.instructions {
                        pc_mapping.insert(instr.pc, next_pc);
                        instr.pc = next_pc;
                        next_pc += instr.byte_size();
                    }
                }
            }
        }

        // Update stored dispatcher metadata PCs so that downstream reindex_pcs
        // can correctly map them through its own mapping.
        ir.remap_metadata_pcs(&pc_mapping);

        // Store the mapping so reindex_pcs can compose it with its own mapping,
        // giving patch_jump_immediates and remap_orphan_jump_pushes a full
        // original → final PC mapping for remapping PUSH immediate values.
        ir.pre_reindex_pc_mapping = Some(pc_mapping);

        // Update runtime bounds to reflect the new layout.
        if let Some((old_start, old_end)) = runtime_bounds {
            let old_size = old_end.saturating_sub(old_start);
            ir.runtime_bounds = Some((base_pc, base_pc + old_size.max(next_pc - base_pc)));
        }

        let total_blocks: usize = clusters.iter().map(|c| c.len()).sum();
        debug!(
            "ClusterShuffle: shuffled {} clusters ({} blocks)",
            clusters.len(),
            total_blocks
        );

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::process_bytecode_to_cfg;
    use azoth_core::seed::Seed;

    const STORAGE_BYTECODE: &str = include_str!("../../../tests/bytecode/storage.hex");

    #[tokio::test]
    async fn cluster_shuffle_reorders_blocks() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // Collect original block order.
        let mut original_pcs: Vec<usize> = cfg_ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &cfg_ir.cfg[n] {
                    Some(body.start_pc)
                } else {
                    None
                }
            })
            .collect();
        original_pcs.sort();

        let seed = Seed::generate();
        let mut rng = seed.create_deterministic_rng();
        let changed = ClusterShuffle::new().apply(&mut cfg_ir, &mut rng).unwrap();

        assert!(changed, "expected ClusterShuffle to reorder blocks");

        // Reindex PCs (normally done by the pipeline).
        cfg_ir.reindex_pcs().unwrap();

        // Collect new block order.
        let mut new_pcs: Vec<usize> = cfg_ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &cfg_ir.cfg[n] {
                    Some(body.start_pc)
                } else {
                    None
                }
            })
            .collect();
        new_pcs.sort();

        // Block count should be preserved.
        assert_eq!(
            original_pcs.len(),
            new_pcs.len(),
            "block count changed after shuffle"
        );
    }

    #[tokio::test]
    async fn cluster_shuffle_preserves_fallthrough_order() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // Record fallthrough pairs before shuffle.
        let mut ft_pairs_before: Vec<(usize, usize)> = Vec::new();
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                let src_pc = body.start_pc;
                for edge in cfg_ir.cfg.edges(node) {
                    if matches!(edge.weight(), EdgeType::Fallthrough) {
                        if let Block::Body(target_body) = &cfg_ir.cfg[edge.target()] {
                            ft_pairs_before.push((src_pc, target_body.start_pc));
                        }
                    }
                }
            }
        }

        let seed = Seed::generate();
        let mut rng = seed.create_deterministic_rng();
        ClusterShuffle::new().apply(&mut cfg_ir, &mut rng).unwrap();

        // Reindex PCs (normally done by the pipeline).
        cfg_ir.reindex_pcs().unwrap();

        // After shuffle, collect all body blocks sorted by new PC.
        let mut blocks_by_pc: Vec<(usize, NodeIndex)> = cfg_ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &cfg_ir.cfg[n] {
                    Some((body.start_pc, n))
                } else {
                    None
                }
            })
            .collect();
        blocks_by_pc.sort_by_key(|(pc, _)| *pc);

        // Build position map: node → sequential position in layout.
        let position: HashMap<NodeIndex, usize> = blocks_by_pc
            .iter()
            .enumerate()
            .map(|(i, (_, n))| (*n, i))
            .collect();

        // Verify: for every fallthrough edge, source must be immediately before target.
        for node in cfg_ir.cfg.node_indices() {
            for edge in cfg_ir.cfg.edges(node) {
                if matches!(edge.weight(), EdgeType::Fallthrough) {
                    let src_pos = position.get(&node);
                    let tgt_pos = position.get(&edge.target());
                    if let (Some(&s), Some(&t)) = (src_pos, tgt_pos) {
                        assert_eq!(
                            s + 1,
                            t,
                            "Fallthrough edge broken: block at position {} should be \
                             immediately before position {}, but got {} and {}",
                            s,
                            s + 1,
                            s,
                            t
                        );
                    }
                }
            }
        }
    }
}
