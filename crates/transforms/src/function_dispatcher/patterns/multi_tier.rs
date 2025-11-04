use super::super::storage::{RoutingDecision, SlotRoute, StorageRoutingConfig};
use super::super::FunctionDispatcher;
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::decoder::Instruction;
use azoth_core::detection::{DispatcherInfo, FunctionSelector};
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;
use tracing::debug;

/// Describes how the multi-tier dispatcher should be constructed.
pub struct DispatcherBlueprint {
    pub dispatcher: DispatcherInfo,
    pub selectors: Vec<TierAssignment>,
    pub routing: StorageRoutingConfig,
}

/// Associates an original selector with the tier that should handle it.
pub struct TierAssignment {
    pub selector: FunctionSelector,
    pub tier_index: usize,
}

/// Result produced when a dispatch layout has been synthesised.
pub struct LayoutPlan {
    pub mapping: HashMap<u32, Vec<u8>>,
    pub extraction_modified: bool,
    pub dispatcher_modified: bool,
    pub routing: StorageRoutingConfig,
}

impl FunctionDispatcher {
    pub(crate) fn build_blueprint(&self, dispatcher: &DispatcherInfo) -> DispatcherBlueprint {
        DispatcherBlueprint {
            dispatcher: dispatcher.clone(),
            selectors: dispatcher
                .selectors
                .iter()
                .cloned()
                .map(|selector| TierAssignment {
                    selector,
                    tier_index: 0,
                })
                .collect(),
            routing: StorageRoutingConfig {
                decisions: vec![
                    RoutingDecision {
                        slot: 5,
                        routes: vec![
                            SlotRoute {
                                value: 2,
                                tier_index: 1,
                            },
                            SlotRoute {
                                value: 4,
                                tier_index: 2,
                            },
                        ],
                    },
                    RoutingDecision {
                        slot: 593,
                        routes: vec![SlotRoute {
                            value: 4,
                            tier_index: 3,
                        }],
                    },
                ],
                default_tier: 0,
            },
        }
    }

    /// Wires the multi-tier layout by synthesising child dispatchers and integrating routing.
    pub(crate) fn apply_layout_plan(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        dispatcher: &DispatcherInfo,
        rng: &mut StdRng,
        blueprint: &DispatcherBlueprint,
    ) -> crate::Result<Option<LayoutPlan>> {
        if blueprint
            .selectors
            .iter()
            .any(|assignment| assignment.tier_index != 0)
        {
            debug!(
                "multi-tier layout wants {} tiers; synthesis not implemented yet",
                blueprint
                    .selectors
                    .iter()
                    .map(|assignment| assignment.tier_index + 1)
                    .max()
                    .unwrap_or(0)
            );
            return Ok(None);
        }

        let result = self.try_apply_byte_pattern(ir, runtime, index_by_pc, dispatcher, rng)?;

        Ok(result.map(|application| LayoutPlan {
            mapping: application.mapping,
            extraction_modified: application.extraction_modified,
            dispatcher_modified: application.dispatcher_modified,
            routing: blueprint.routing.clone(),
        }))
    }
}
