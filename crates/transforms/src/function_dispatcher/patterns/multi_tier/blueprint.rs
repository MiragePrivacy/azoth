use crate::function_dispatcher::storage::{RoutingDecision, SlotRoute, StorageRoutingConfig};
use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use std::collections::{BTreeMap, HashMap};

/// Describes how the multi-tier dispatcher should be constructed.
pub struct DispatcherBlueprint {
    pub dispatcher: DispatcherInfo,
    pub selectors: Vec<TierAssignment>,
    pub routing: StorageRoutingConfig,
    pub routes: HashMap<usize, Vec<TierRoute>>,
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
    pub destination: RouteDestination,
}

#[derive(Clone, Copy)]
pub enum RouteDestination {
    Real,
    Decoy,
}

pub fn build_blueprint(dispatcher: &DispatcherInfo) -> DispatcherBlueprint {
    let mut slot_map: BTreeMap<u64, Vec<SlotRoute>> = BTreeMap::new();
    let mut assignments = Vec::with_capacity(dispatcher.selectors.len());
    let mut tier_routes: HashMap<usize, Vec<TierRoute>> = HashMap::new();

    for (idx, selector) in dispatcher.selectors.iter().cloned().enumerate() {
        let tier_index = idx + 1; // reserve tier 0 for fallback / default routing

        assignments.push(TierAssignment {
            selector,
            tier_index,
        });

        let primary_slot = if tier_index % 2 == 0 { 593 } else { 5 };
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
            let secondary_slot = 943;
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
    }
}
