//! Storage slot shuffler.
//!
//! This transform remaps all observed storage slot immediates (SLOAD/SSTORE
//! and gate metadata) through a random bijection to obscure layout.
//!
//! Assembly example:
//! ```assembly
//! // Original
//! PUSH32 0x00
//! SLOAD
//!
//! // Transformed (slot remapped to 0xbeef)
//! PUSH2 0xbeef
//! SLOAD
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;
use tracing::debug;

/// Late-stage storage slot permutation.
#[derive(Default)]
pub struct SlotShuffle;

impl SlotShuffle {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for SlotShuffle {
    fn name(&self) -> &'static str {
        "SlotShuffle"
    }

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        debug!("SlotShuffle: placeholder apply (no-op)");
        Ok(false)
    }
}
