use azoth_core::detection::{DispatcherInfo, FunctionSelector};

/// Captures the inputs required to build a multi-tier dispatcher layout.
#[derive(Debug, Clone)]
pub struct MultiTierBlueprint {
    /// Original dispatcher metadata detected from the runtime slice.
    pub dispatcher: DispatcherInfo,
    /// Mapping from each original selector to the index of its assigned tier.
    pub selector_tiers: Vec<SelectorAssignment>,
}

/// Associates a function selector with a specific tier slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorAssignment {
    /// Selector being remapped.
    pub selector: u32,
    /// Index of the tier this selector routes through.
    pub tier_index: usize,
}

/// Builder responsible for crafting a multi-tier dispatcher blueprint.
pub struct MultiTierLayoutBuilder {
    dispatcher: DispatcherInfo,
}

impl MultiTierLayoutBuilder {
    /// Initializes the builder from detected dispatcher information.
    pub fn new(dispatcher: DispatcherInfo) -> Self {
        Self { dispatcher }
    }

    /// Assigns every selector to tier 0 by default, preserving original ordering.
    pub fn build(self) -> MultiTierBlueprint {
        let selector_tiers = self
            .dispatcher
            .selectors
            .iter()
            .map(|entry| SelectorAssignment {
                selector: entry.selector,
                tier_index: 0,
            })
            .collect();

        MultiTierBlueprint {
            dispatcher: self.dispatcher.clone(),
            selector_tiers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_selector(selector: u32, target: u64, index: usize) -> FunctionSelector {
        FunctionSelector {
            selector,
            target_address: target,
            instruction_index: index,
        }
    }

    fn make_dispatcher(selectors: Vec<FunctionSelector>) -> DispatcherInfo {
        DispatcherInfo {
            start_offset: 0,
            end_offset: selectors.len(),
            selectors,
            extraction_pattern: azoth_core::detection::ExtractionPattern::Standard,
        }
    }

    #[test]
    fn builder_preserves_selector_order_and_assigns_base_tier() {
        let dispatcher = make_dispatcher(vec![
            make_selector(0xaabbccdd, 100, 0),
            make_selector(0x11223344, 200, 1),
        ]);

        let blueprint = MultiTierLayoutBuilder::new(dispatcher.clone()).build();

        assert_eq!(blueprint.dispatcher.selectors.len(), 2);
        assert_eq!(blueprint.selector_tiers.len(), 2);

        for (idx, assignment) in blueprint.selector_tiers.iter().enumerate() {
            assert_eq!(
                assignment.selector, dispatcher.selectors[idx].selector,
                "selector order should match input"
            );
            assert_eq!(
                assignment.tier_index, 0,
                "default build should assign selectors to tier 0"
            );
        }
    }
}
