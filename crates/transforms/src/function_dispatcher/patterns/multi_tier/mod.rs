mod blueprint;
mod layout;

pub(crate) use blueprint::DispatcherBlueprint;
pub(crate) use layout::LayoutPlan;

use super::super::FunctionDispatcher;
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::decoder::Instruction;
use azoth_core::detection::DispatcherInfo;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;

impl FunctionDispatcher {
    pub(crate) fn build_blueprint(&self, dispatcher: &DispatcherInfo) -> DispatcherBlueprint {
        blueprint::build_blueprint(dispatcher)
    }

    pub(crate) fn apply_layout_plan(
        &self,
        ir: &mut CfgIrBundle,
        runtime: &[Instruction],
        index_by_pc: &HashMap<usize, (NodeIndex, usize)>,
        dispatcher: &DispatcherInfo,
        rng: &mut StdRng,
        blueprint: &DispatcherBlueprint,
    ) -> crate::Result<Option<LayoutPlan>> {
        layout::apply_layout_plan(self, ir, runtime, index_by_pc, dispatcher, rng, blueprint)
    }
}
