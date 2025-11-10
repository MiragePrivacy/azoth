//! Multi-tier function dispatcher obfuscation patterns.
//!
//! Implements a layered obfuscation strategy that replaces selectors with derived tokens,
//! redirects dispatcher jumps to multi-tier controllers, and applies modular obfuscation
//! patterns (byte extraction, storage checks, opaque predicates) within each tier.

mod blueprint;
pub(crate) mod controller;
mod layout;

pub(crate) use blueprint::DispatcherBlueprint;
pub(crate) use layout::LayoutPlan;

use super::FunctionDispatcher;
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::decoder::Instruction;
use azoth_core::detection::DispatcherInfo;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashMap;

impl FunctionDispatcher {
    pub(crate) fn build_blueprint(
        &self,
        dispatcher: &DispatcherInfo,
        rng: &mut StdRng,
    ) -> DispatcherBlueprint {
        blueprint::build_blueprint(dispatcher, rng)
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
