//! Push splitting for medium-width literals.
//!
//! This transform replaces direct PUSH4–PUSH16 literals with multiple pushes
//! and a combine operation so the final constant is assembled on stack.
//!
//! Assembly example:
//! ```assembly
//! // Original
//! PUSH8 0x1122334455667788
//! SSTORE
//!
//! // Transformed (one possible variant)
//! PUSH4 0x11223344
//! PUSH4 0x55667788
//! ADD                // 0x1122334455667788
//! SSTORE
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;

/// Split medium-width PUSH immediates into multi-step arithmetic.
/// logic will select eligible pushes, generate random splits, and update metadata so later
/// passes can remap PCs safely.
#[derive(Default)]
pub struct PushSplit;

impl PushSplit {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for PushSplit {
    fn name(&self) -> &'static str {
        "PushSplit"
    }

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        Ok(false)
    }
}
