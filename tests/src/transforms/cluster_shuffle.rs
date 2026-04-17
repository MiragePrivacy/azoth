//! Behavioural tests for `ClusterShuffle`.
//!
//! This module focuses on what the transform actually *does*:
//!
//! * `cluster_shuffle_preserves_runtime_entry` — pins down the
//!   entry-cluster invariant (the block with the smallest pre-shuffle
//!   `start_pc` must stay at the smallest post-shuffle `start_pc`).
//! * `cluster_shuffle_relocates_clusters` — demonstrates and asserts
//!   that the transform actually moves clusters. Prints a before/after
//!   layout to stdout (`cargo nextest run cluster_shuffle_relocates_clusters
//!   --nocapture`) so the effect is visible without reading bytecode.

use crate::e2e::ESCROW_CONTRACT_RUNTIME_BYTECODE;
use azoth_core::cfg_ir::{Block, BlockControl, CfgIrBundle};
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::cluster_shuffle::ClusterShuffle;
use azoth_transform::Transform;
use petgraph::graph::NodeIndex;

const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn compute_clusters(cfg: &CfgIrBundle) -> Vec<Vec<NodeIndex>> {
    let runtime_bounds = cfg.runtime_bounds;
    let in_runtime = |start_pc: usize| match runtime_bounds {
        Some((s, e)) => start_pc >= s && start_pc < e,
        None => true,
    };
    let mut sorted: Vec<(usize, NodeIndex)> = cfg
        .cfg
        .node_indices()
        .filter_map(|n| match &cfg.cfg[n] {
            Block::Body(body) if in_runtime(body.start_pc) => Some((body.start_pc, n)),
            _ => None,
        })
        .collect();
    sorted.sort_by_key(|(pc, _)| *pc);
    let mut clusters: Vec<Vec<NodeIndex>> = sorted.iter().map(|(_, n)| vec![*n]).collect();
    let mut i = 0;
    while i + 1 < clusters.len() {
        let tail = *clusters[i].last().unwrap();
        let needs_next = matches!(
            &cfg.cfg[tail],
            Block::Body(body)
                if matches!(
                    body.control,
                    BlockControl::Fallthrough | BlockControl::Branch { .. }
                )
        );
        if needs_next {
            let next = clusters.remove(i + 1);
            clusters[i].extend(next);
        } else {
            i += 1;
        }
    }
    clusters
}

fn describe_cluster(cfg: &CfgIrBundle, cluster: &[NodeIndex]) -> String {
    let first_pc = match &cfg.cfg[cluster[0]] {
        Block::Body(body) => body.start_pc,
        _ => 0,
    };
    let last = cluster.last().unwrap();
    let tail_control = match &cfg.cfg[*last] {
        Block::Body(body) => format!("{:?}", body.control),
        _ => "?".into(),
    };
    format!(
        "pc=0x{:04x} len={:<2} tail={}",
        first_pc,
        cluster.len(),
        tail_control.chars().take(24).collect::<String>(),
    )
}

async fn load_escrow_runtime_cfg_without_dispatcher() -> CfgIrBundle {
    let (mut cfg, _, _, _) = process_bytecode_to_cfg(
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        false,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        false,
    )
    .await
    .unwrap();
    // Simulate a dispatcher-free contract: drop any pinning signals so
    // the entry-pinning in ClusterShuffle is exercised in isolation.
    cfg.dispatcher_blocks.clear();
    cfg.dispatcher_info = None;
    cfg
}

/// Runs `ClusterShuffle` on a CFG with no `dispatcher_blocks` (simulating
/// a dispatcher-free contract) and verifies the block with the smallest
/// pre-shuffle `start_pc` also carries the smallest post-shuffle
/// `start_pc`. Before the entry-pinning fix, the only pinning came from
/// dispatcher_blocks, so a dispatcher-free contract could have its entry
/// cluster shuffled off slot 0, silently redirecting the deployed
/// runtime's entrypoint.
#[tokio::test]
async fn cluster_shuffle_preserves_runtime_entry() {
    let seed = Seed::from_hex(FIXED_SEED).unwrap();
    let mut cfg = load_escrow_runtime_cfg_without_dispatcher().await;

    let original_entry_node = cfg
        .cfg
        .node_indices()
        .filter_map(|n| match &cfg.cfg[n] {
            Block::Body(body) => Some((body.start_pc, n)),
            _ => None,
        })
        .min_by_key(|(pc, _)| *pc)
        .map(|(_, node)| node)
        .expect("runtime CFG has at least one body block");

    let mut rng = seed.create_deterministic_rng();
    let changed = ClusterShuffle::new().apply(&mut cfg, &mut rng).unwrap();
    assert!(
        changed,
        "escrow runtime has enough free clusters that ClusterShuffle should always change something"
    );

    let post_shuffle_entry = cfg
        .cfg
        .node_indices()
        .filter_map(|n| match &cfg.cfg[n] {
            Block::Body(body) => Some((body.start_pc, n)),
            _ => None,
        })
        .min_by_key(|(pc, _)| *pc)
        .map(|(_, node)| node)
        .unwrap();

    assert_eq!(
        post_shuffle_entry, original_entry_node,
        "ClusterShuffle must pin the runtime entry block at the smallest \
         post-shuffle start_pc even when no dispatcher_blocks are present"
    );
}

/// Demonstrable cluster relocation. Prints the cluster layout before and
/// after `ClusterShuffle` on the escrow runtime (dispatcher-free) and
/// asserts that at least one cluster changed slots. Run with
/// `cargo nextest run cluster_shuffle_relocates_clusters --nocapture`
/// to see the pre/post layout.
///
/// This test bridges the gap that the e2e `collect_proof` probe leaves:
/// that test proves the obfuscated bytecode differs from a
/// dispatcher-only baseline, but doesn't pin down *what* changed at the
/// CFG level. Here we look at the cluster ordering directly.
#[tokio::test]
async fn cluster_shuffle_relocates_clusters() {
    let seed = Seed::from_hex(FIXED_SEED).unwrap();
    let mut cfg = load_escrow_runtime_cfg_without_dispatcher().await;

    let clusters_before = compute_clusters(&cfg);
    // Each cluster is identified by its lead NodeIndex; slot index
    // before the shuffle is cluster_id's position in start_pc order.
    let id_by_lead: std::collections::HashMap<NodeIndex, usize> = clusters_before
        .iter()
        .enumerate()
        .map(|(slot, cluster)| (cluster[0], slot))
        .collect();

    println!("=== ClusterShuffle demo on escrow runtime (dispatcher-free) ===");
    println!(
        "{} runtime body blocks organised into {} clusters before shuffle:",
        clusters_before.iter().map(Vec::len).sum::<usize>(),
        clusters_before.len()
    );
    for (slot, cluster) in clusters_before.iter().enumerate().take(10) {
        println!("  [{:>2}] {}", slot, describe_cluster(&cfg, cluster));
    }
    if clusters_before.len() > 10 {
        println!("  ... {} more clusters", clusters_before.len() - 10);
    }

    let mut rng = seed.create_deterministic_rng();
    let changed = ClusterShuffle::new().apply(&mut cfg, &mut rng).unwrap();
    assert!(changed);

    // Re-cluster in post-shuffle PC order. Cluster identities (lead
    // NodeIndex) are preserved; slot positions may have moved.
    let clusters_after = compute_clusters(&cfg);

    println!();
    println!("After shuffle (same cluster leads, new slots):");
    let mut moved_slots = 0usize;
    for (new_slot, cluster) in clusters_after.iter().enumerate().take(10) {
        let old_slot = id_by_lead
            .get(&cluster[0])
            .copied()
            .expect("cluster lead preserved across shuffle");
        let delta = if old_slot == new_slot {
            "      ".to_string()
        } else {
            moved_slots += 1;
            format!("({:+})", new_slot as isize - old_slot as isize)
        };
        println!(
            "  [{:>2} was {:>2}] {} {}",
            new_slot,
            old_slot,
            describe_cluster(&cfg, cluster),
            delta
        );
    }
    if clusters_after.len() > 10 {
        // Count remaining moves without printing.
        for (new_slot, cluster) in clusters_after.iter().enumerate().skip(10) {
            let old_slot = id_by_lead.get(&cluster[0]).copied().unwrap();
            if old_slot != new_slot {
                moved_slots += 1;
            }
        }
        println!("  ... {} more clusters", clusters_after.len() - 10);
    }
    println!();
    println!(
        "{} of {} clusters changed slots; cluster 0 (runtime entry) pinned at slot 0.",
        moved_slots,
        clusters_after.len()
    );

    // Entry cluster must stay at slot 0.
    assert_eq!(
        clusters_before[0][0], clusters_after[0][0],
        "entry cluster moved off slot 0"
    );

    // At least one non-entry cluster must have relocated. Under the
    // fixed seed the escrow runtime has dozens of free clusters, so
    // this is overwhelmingly the common case.
    assert!(
        moved_slots > 0,
        "ClusterShuffle didn't move any cluster — shuffle was a silent no-op"
    );
}
