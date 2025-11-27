//! Stack-based reverse arithmetic chains.
//!
//! This transform wraps hardcoded literals or freshly loaded calldata words
//! behind short arithmetic chains (ADD/SUB/XOR/AND/MUL/DIV) so the observable
//! value only materializes at runtime.
//!
//! Assembly example:
//! ```assembly
//! // Original
//! PUSH4 0xa9059cbb
//! EQ
//! JUMPI
//!
//! // Transformed (one possible variant)
//! PUSH4 0x2a2a2a2a
//! PUSH4 0x83af76b1
//! XOR              // 0xa9059cbb
//! PUSH1 0x01
//! ADD              // small offset to vary the chain
//! PUSH1 0x01
//! SUB              // restore original
//! EQ
//! JUMPI
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;
use tracing::debug;

/// Randomized arithmetic chain wrapper.
#[derive(Default)]
pub struct ArithmeticChain;

impl ArithmeticChain {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for ArithmeticChain {
    fn name(&self) -> &'static str {
        "ArithmeticChain"
    }

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        debug!("ArithmeticChain: placeholder apply (no-op)");
        Ok(false)
    }
}

