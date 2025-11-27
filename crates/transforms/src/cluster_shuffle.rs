//! Cluster-aware CFG shuffler.
//!
//! Instead of shuffling individual blocks, this transform will shuffle block
//! clusters (dispatcher tiers, stub+decoy pairs, storage gates) to preserve
//! logical adjacency while changing layout.
//!
//! Assembly sketch:
//! ```assembly
//! // Blocks before
//! [dispatcher_tier_0][controller_real][decoy_stub][storage_gate]
//!
//! // After cluster shuffle (one variant)
//! [storage_gate][dispatcher_tier_0][decoy_stub][controller_real]
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;
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

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        debug!("ClusterShuffle: placeholder apply (no-op)");
        Ok(false)
    }
}
