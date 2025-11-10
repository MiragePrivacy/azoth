//! Blueprint construction.
//!
//! This module is responsible for creating the abstract configuration and planning
//! structure for the multi-tier dispatcher obfuscation transform. It takes the original
//! dispatcher information detected from bytecode and produces a comprehensive blueprint
//! that specifies how each function selector should be obfuscated.

use crate::function_dispatcher::storage::{RoutingDecision, SlotRoute, StorageRoutingConfig};
use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use rand::Rng;
use std::collections::{BTreeMap, HashMap};

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
    pub routing: StorageRoutingConfig,
    #[allow(dead_code)]
    pub routes: HashMap<usize, Vec<TierRoute>>,
    /// Controller pattern configuration for each tier
    pub controller_patterns: HashMap<usize, ControllerPatternConfig>,
}

/// Associates an original selector with the tier that should handle it.
pub struct TierAssignment {
    pub selector: FunctionSelector,
    pub tier_index: usize,
}

#[derive(Clone)]
pub struct TierRoute {
    pub slot: u64,
    pub value: u128,
    #[allow(dead_code)]
    pub destination: RouteDestination,
}

#[derive(Clone, Copy)]
pub enum RouteDestination {
    Real,
    Decoy,
}

pub fn build_blueprint<R: Rng>(dispatcher: &DispatcherInfo, rng: &mut R) -> DispatcherBlueprint {
    let mut slot_map: BTreeMap<u64, Vec<SlotRoute>> = BTreeMap::new();
    let mut assignments = Vec::with_capacity(dispatcher.selectors.len());
    let mut tier_routes: HashMap<usize, Vec<TierRoute>> = HashMap::new();
    let mut controller_patterns: HashMap<usize, ControllerPatternConfig> = HashMap::new();

    for (idx, selector) in dispatcher.selectors.iter().cloned().enumerate() {
        let tier_index = idx + 1; // reserve tier 0 for fallback / default routing

        assignments.push(TierAssignment {
            selector,
            tier_index,
        });

        // Generate random storage slot for this tier (avoid low slots used by common contracts)
        let random_slot = rng.random_range(0x1000..0xFFFF);

        // Configure controller patterns for this tier
        // Use byte extraction for even-numbered tiers, storage checks for odd, opaque predicates for tiers divisible by 3
        controller_patterns.insert(
            tier_index,
            ControllerPatternConfig {
                use_byte_extraction: tier_index % 2 == 0,
                byte_index: 3, // Extract the high byte of the selector
                use_storage_checks: tier_index % 2 == 1,
                storage_slot: random_slot,
                use_opaque_predicates: tier_index % 3 == 0,
            },
        );

        let primary_slot = random_slot;
        let primary_value = (tier_index as u128) * 3 + 1;
        slot_map.entry(primary_slot).or_default().push(SlotRoute {
            value: primary_value,
            tier_index,
        });
        tier_routes.entry(tier_index).or_default().push(TierRoute {
            slot: primary_slot,
            value: primary_value,
            destination: RouteDestination::Real,
        });

        if tier_index % 3 == 0 {
            let secondary_slot = rng.random_range(0x1000..0xFFFF);
            let secondary_value = ((tier_index as u128) << 4) ^ 0xabu128;
            slot_map.entry(secondary_slot).or_default().push(SlotRoute {
                value: secondary_value,
                tier_index,
            });
            tier_routes.entry(tier_index).or_default().push(TierRoute {
                slot: secondary_slot,
                value: secondary_value,
                destination: RouteDestination::Decoy,
            });
        }
    }

    let decisions = slot_map
        .into_iter()
        .map(|(slot, mut routes)| {
            routes.sort_by_key(|route| route.tier_index);
            RoutingDecision { slot, routes }
        })
        .collect();

    let routes = tier_routes
        .into_iter()
        .map(|(tier, mut routes)| {
            routes.sort_by_key(|route| (route.slot, route.value));
            (tier, routes)
        })
        .collect();

    DispatcherBlueprint {
        dispatcher: dispatcher.clone(),
        selectors: assignments,
        routing: StorageRoutingConfig {
            decisions,
            default_tier: 0,
        },
        routes,
        controller_patterns,
    }
}
