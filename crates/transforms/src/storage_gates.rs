//! Context-dependent storage gates.
//!
//! This transform makes selected call paths depend on storage mutations:
//! dispatcher/controllers set a slot, later controllers verify it before
//! routing, forcing stateful execution order.
//!
//! Assembly example:
//! ```assembly
//! // Dispatcher path for `bond` (sets gate)
//! PUSH32 gate_slot
//! PUSH1  0x01
//! SSTORE           // mark slot
//! JUMP controller_bond
//!
//! // Controller head for `collect` (checks gate)
//! PUSH32 gate_slot
//! SLOAD
//! ISZERO
//! PUSH2 revert_pc  // if unset
//! JUMPI
//! ...              // real body
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;
use tracing::debug;

/// Storage mutation + gate insertion.
pub struct StorageGates;

impl StorageGates {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for StorageGates {
    fn name(&self) -> &'static str {
        "StorageGates"
    }

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        debug!("StorageGates: placeholder apply (no-op)");
        Ok(false)
    }
}
