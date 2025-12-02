//! Solc/Yul snippet splicing.
//!
//! This transform will inject precompiled helper snippets (dispatcher →
//! controller → body) into the CFG when size/gas budgets permit, expanding the
//! code surface with realistic function chains.
//!
//! Assembly example:
//! ```assembly
//! // Original dispatcher path
//! PUSH4 0xfeedbeef
//! EQ
//! JUMPI controller_main
//!
//! // After splicing helper path
//! PUSH4 0xabad1dea         // token for helper selector
//! EQ
//! JUMPI controller_helper
//! ...
//! controller_helper:
//!     JUMPDEST
//!     CALLER
//!     POP
//!     STOP                 // tiny snippet from catalog
//! ```

use crate::{Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use rand::rngs::StdRng;

/// Splice catalogued helper functions into the CFG.
#[derive(Default)]
pub struct Splice;

impl Splice {
    pub fn new() -> Self {
        Self
    }
}

impl Transform for Splice {
    fn name(&self) -> &'static str {
        "Splice"
    }

    fn apply(&self, _ir: &mut CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
        Ok(false)
    }
}
