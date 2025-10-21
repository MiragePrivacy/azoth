use crate::Result;
use crate::Transform;
use azoth_analysis::{collect_metrics, compare};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::seed::Seed;
use tracing::info;

/// Trait for running a sequence of obfuscation transforms on a CFG IR.
pub trait Pass {
    fn run(&self, ir: &mut CfgIrBundle, passes: &[Box<dyn Transform>], seed: &Seed) -> Result<()>;
}

/// Default implementation of the Pass trait.
pub struct DefaultPass;

impl Pass for DefaultPass {
    fn run(&self, ir: &mut CfgIrBundle, passes: &[Box<dyn Transform>], seed: &Seed) -> Result<()> {
        let mut rng = seed.create_deterministic_rng();

        for pass in passes {
            let before = collect_metrics(ir, &ir.clean_report)?;
            let mut snapshot = ir.clone();

            let mutated = pass.apply(&mut snapshot, &mut rng)?;
            if !mutated {
                continue;
            }

            let after = collect_metrics(&snapshot, &snapshot.clean_report)?;
            let delta = compare(&before, &after);

            info!("{:>14} Δ{:+.2}", pass.name(), delta);
            *ir = snapshot;
        }
        Ok(())
    }
}
