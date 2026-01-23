//! Cluster-aware CFG shuffler.
//!
//! Instead of shuffling individual blocks, this transform will shuffle block
//! clusters (dispatcher tiers, stub+decoy pairs, storage gates) to preserve
//! logical adjacency while changing layout.
//!
//! Assembly example:
//! ```assembly
//! // Blocks before
//! [dispatcher_tier_0][controller_real][decoy_stub][storage_gate]
//!
//! // After cluster shuffle (one variant)
//! [storage_gate][dispatcher_tier_0][decoy_stub][controller_real]
//! ```

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use petgraph::graph::NodeIndex;
use rand::{rngs::StdRng, seq::SliceRandom};
use std::collections::{HashMap, HashSet};
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
        let mut body_nodes: Vec<(usize, NodeIndex)> = ir
            .cfg
            .node_indices()
            .filter_map(|n| match &ir.cfg[n] {
                Block::Body(body) => Some((body.start_pc, n)),
                _ => None,
            })
            .collect();

        if body_nodes.len() <= 1 {
            debug!("ClusterShuffle: not enough blocks to shuffle");
            return Ok(false);
        }

        body_nodes.sort_by_key(|(pc, _)| *pc);
        let original_order: Vec<usize> = body_nodes.iter().map(|(pc, _)| *pc).collect();

        let mut clusters: Vec<Vec<NodeIndex>> = Vec::new();
        let mut assigned: HashSet<NodeIndex> = HashSet::new();
        let start_pc_map: HashMap<NodeIndex, usize> =
            body_nodes.iter().map(|(pc, n)| (*n, *pc)).collect();

        // Cluster 1: dispatcher blocks (kept adjacent as a group).
        if !ir.dispatcher_blocks.is_empty() {
            let mut dispatcher_cluster: Vec<NodeIndex> = body_nodes
                .iter()
                .filter_map(|(_, n)| {
                    if ir.dispatcher_blocks.contains(&n.index()) {
                        Some(*n)
                    } else {
                        None
                    }
                })
                .collect();
            if !dispatcher_cluster.is_empty() {
                dispatcher_cluster.sort_by_key(|n| start_pc_map[n]);
                assigned.extend(dispatcher_cluster.iter().copied());
                clusters.push(dispatcher_cluster);
            }
        }

        // Cluster 2: stub+decoy pairs.
        if let Some(stub_patches) = &ir.stub_patches {
            for (stub_node, _, _, decoy_node) in stub_patches {
                let mut cluster = Vec::new();
                for node in [*stub_node, *decoy_node] {
                    if assigned.contains(&node) {
                        continue;
                    }
                    if matches!(ir.cfg.node_weight(node), Some(Block::Body(_))) {
                        cluster.push(node);
                    }
                }
                if !cluster.is_empty() {
                    cluster.sort_by_key(|n| start_pc_map[n]);
                    assigned.extend(cluster.iter().copied());
                    clusters.push(cluster);
                }
            }
        }

        // Remaining nodes: singleton clusters.
        for (_, node) in &body_nodes {
            if assigned.contains(node) {
                continue;
            }
            clusters.push(vec![*node]);
        }

        let mut cluster_order: Vec<Vec<NodeIndex>> = clusters.clone();
        cluster_order.shuffle(rng);

        let mut new_order: Vec<usize> = Vec::with_capacity(body_nodes.len());
        for cluster in &cluster_order {
            let mut ordered = cluster.clone();
            ordered.sort_by_key(|n| start_pc_map[n]);
            new_order.extend(ordered.iter().map(|n| start_pc_map[n]));
        }

        if original_order == new_order && cluster_order.len() > 1 {
            debug!("ClusterShuffle: shuffle produced no change; rotating clusters");
            cluster_order.rotate_left(1);
        }

        debug!(
            "ClusterShuffle: original order (by start_pc): {:?}",
            original_order
        );
        debug!(
            "ClusterShuffle: cluster order (sizes): {:?}",
            cluster_order.iter().map(|c| c.len()).collect::<Vec<_>>()
        );

        // Assign temporary PCs to enforce cluster order.
        let mut pos = 0usize;
        for cluster in &cluster_order {
            let mut ordered = cluster.clone();
            ordered.sort_by_key(|n| start_pc_map[n]);
            for node in ordered {
                if let Some(Block::Body(body)) = ir.cfg.node_weight_mut(node) {
                    let temp_pc = pos * 1_000_000;
                    body.start_pc = temp_pc;
                    pos += 1;
                }
            }
        }

        ir.reindex_pcs()
            .map_err(|e| Error::CoreError(e.to_string()))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::Block;
    use azoth_core::process_bytecode_to_cfg;
    use rand::SeedableRng;

    const STORAGE_BYTECODE: &str = include_str!("../../../tests/bytecode/storage.hex");

    fn contiguous_positions(nodes: &[NodeIndex], order: &[NodeIndex]) -> bool {
        let mut positions: Vec<usize> = nodes
            .iter()
            .filter_map(|n| order.iter().position(|o| o == n))
            .collect();
        positions.sort_unstable();
        if positions.len() <= 1 {
            return true;
        }
        let min = positions[0];
        let max = positions[positions.len() - 1];
        max - min + 1 == positions.len()
    }

    #[tokio::test]
    async fn keeps_clusters_adjacent() {
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        let mut bodies: Vec<_> = cfg_ir
            .cfg
            .node_indices()
            .filter(|n| matches!(cfg_ir.cfg[*n], Block::Body(_)))
            .collect();
        bodies.sort_by_key(|n| {
            if let Block::Body(ref b) = cfg_ir.cfg[*n] {
                b.start_pc
            } else {
                0
            }
        });

        assert!(bodies.len() >= 5, "storage fixture should have body blocks");

        // Mark first three blocks as dispatcher cluster.
        for node in bodies.iter().take(3) {
            cfg_ir.dispatcher_blocks.insert(node.index());
        }

        // Create one stub+decoy pair from the next two blocks.
        let stub = bodies[3];
        let decoy = bodies[4];
        cfg_ir.stub_patches = Some(vec![(stub, 0, 1, decoy)]);

        let mut rng = StdRng::seed_from_u64(0x5157_u64);
        let shuffle = ClusterShuffle::new();
        let changed = shuffle.apply(&mut cfg_ir, &mut rng).unwrap();
        assert!(changed, "cluster shuffle should report changes");

        let mut ordered: Vec<NodeIndex> = cfg_ir
            .cfg
            .node_indices()
            .filter(|n| matches!(cfg_ir.cfg[*n], Block::Body(_)))
            .collect();
        ordered.sort_by_key(|n| {
            if let Block::Body(ref b) = cfg_ir.cfg[*n] {
                b.start_pc
            } else {
                0
            }
        });

        let dispatcher_nodes: Vec<NodeIndex> = bodies.iter().take(3).copied().collect();
        assert!(
            contiguous_positions(&dispatcher_nodes, &ordered),
            "dispatcher cluster should stay adjacent"
        );

        let pair = vec![stub, decoy];
        assert!(
            contiguous_positions(&pair, &ordered),
            "stub+decoy cluster should stay adjacent"
        );
    }
}
