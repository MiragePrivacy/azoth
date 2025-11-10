use std::collections::HashMap;

/// Declarative routing based on storage slot values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageRoutingConfig {
    /// Ordered list of slot-based routing decisions.
    pub decisions: Vec<RoutingDecision>,
    /// Tier used when no decision matches.
    pub default_tier: usize,
}

impl StorageRoutingConfig {
    /// Returns the tier associated with the provided storage snapshot.
    #[allow(dead_code)]
    pub fn resolve_tier(&self, storage: &HashMap<u64, u128>) -> usize {
        for decision in &self.decisions {
            if let Some(value) = storage.get(&decision.slot) {
                if let Some(route) = decision.routes.iter().find(|r| r.value == *value) {
                    return route.tier_index;
                }
            }
        }
        self.default_tier
    }
}

/// Describes how a single storage slot influences routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Storage slot inspected by this decision.
    pub slot: u64,
    /// Mapping from storage values to tier indices.
    pub routes: Vec<SlotRoute>,
}

/// Associates a concrete storage value with the tier index it selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotRoute {
    /// Expected storage value.
    pub value: u128,
    /// Tier activated when the storage value matches.
    pub tier_index: usize,
}
