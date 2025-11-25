//! Blueprint construction.
//!
//! This module is responsible for creating the abstract configuration and planning
//! structure for the multi-tier dispatcher obfuscation transform. It takes the original
//! dispatcher information detected from bytecode and produces a comprehensive blueprint
//! that specifies how each function selector should be obfuscated.

use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use rand::Rng;
use std::collections::HashMap;

/// Configuration for which controller patterns to apply.
#[derive(Clone, Debug)]
pub struct ControllerPatternConfig {
    /// Whether to include byte extraction pattern in this controller
    pub use_byte_extraction: bool,
    /// Byte index to extract if using byte extraction (0-3 for selector bytes)
    pub byte_index: u8,
    /// Whether to include storage check patterns
    pub use_storage_checks: bool,
    /// Random storage slot to check (if using storage checks)
    pub storage_slot: u64,
    /// Whether to include opaque predicates
    #[allow(dead_code)]
    pub use_opaque_predicates: bool,
}

/// Describes how the multi-tier dispatcher should be constructed.
pub struct DispatcherBlueprint {
    pub dispatcher: DispatcherInfo,
    pub selectors: Vec<TierAssignment>,
    /// Controller pattern configuration for each tier
    pub controller_patterns: HashMap<usize, ControllerPatternConfig>,
}

/// Associates an original selector with the tier that should handle it.
pub struct TierAssignment {
    pub selector: FunctionSelector,
    pub tier_index: usize,
}

pub fn build_blueprint<R: Rng>(dispatcher: &DispatcherInfo, rng: &mut R) -> DispatcherBlueprint {
    let mut assignments = Vec::with_capacity(dispatcher.selectors.len());
    let mut controller_patterns: HashMap<usize, ControllerPatternConfig> = HashMap::new();

    for (idx, selector) in dispatcher.selectors.iter().cloned().enumerate() {
        let tier_index = idx + 1; // reserve tier 0 for fallback / default routing

        assignments.push(TierAssignment {
            selector,
            tier_index,
        });

        // Generate random storage slot for this tier (avoid low slots used by common contracts)
        let random_slot = rng.random_range(0x1000..0xFFFF);

        // Vary the byte index to reduce collision probability
        // Use modulo to cycle through all 4 byte positions (0, 1, 2, 3)
        // This distributes the constraints more evenly across the selector space
        let byte_index = (tier_index % 4) as u8;

        // Configure controller patterns for this tier
        // Use byte extraction for even-numbered tiers, storage checks for odd, opaque predicates for tiers divisible by 3
        controller_patterns.insert(
            tier_index,
            ControllerPatternConfig {
                use_byte_extraction: tier_index % 2 == 0,
                byte_index,
                use_storage_checks: tier_index % 2 == 1,
                storage_slot: random_slot,
                use_opaque_predicates: tier_index % 3 == 0,
            },
        );
    }

    DispatcherBlueprint {
        dispatcher: dispatcher.clone(),
        selectors: assignments,
        controller_patterns,
    }
}
