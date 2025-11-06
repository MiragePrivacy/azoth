use crate::Transform;
use crate::Result;
use azoth_core::cfg_ir::{Block, CfgIrBundle};
use rand::{rngs::StdRng, seq::SliceRandom};
use tracing::debug;

pub struct Shuffle;

impl Transform for Shuffle {
    fn name(&self) -> &'static str {
        "Shuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        let mut block_indices: Vec<_> = ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &ir.cfg[n] {
                    Some((body.start_pc, n))
                } else {
                    None
                }
            })
            .collect();

        if block_indices.len() <= 1 {
            debug!("Not enough blocks to shuffle");
            return Ok(false);
        }

        let original_order: Vec<usize> = block_indices.iter().map(|(pc, _)| *pc).collect();
        debug!("Original block order (by start_pc): {:?}", original_order);

        block_indices.shuffle(rng);
        let new_order: Vec<usize> = block_indices.iter().map(|(pc, _)| *pc).collect();
        debug!("Shuffled block order (by start_pc): {:?}", new_order);

        if original_order == new_order {
            debug!("Shuffle produced no change (randomly picked same order)");
            return Ok(false);
        }

        // let's assign temporary start_pc values to establish the new order
        // using large gaps (1000000) so blocks don't overlap
        debug!("Assigning temporary PCs to establish new order:");
        for (i, (_, node_idx)) in block_indices.iter().enumerate() {
            if let Some(Block::Body(body)) = ir.cfg.node_weight_mut(*node_idx) {
                let temp_pc = i * 1000000;
                debug!("  Block at position {} → temp PC 0x{:x} ({})", i, temp_pc, temp_pc);
                body.start_pc = temp_pc;
            }
        }

        // this will sort blocks by their new start_pcs and renumber everything
        ir.reindex_pcs()
            .map_err(|e| crate::Error::CoreError(e.to_string()))?;

        // Show final block order after reindexing
        let final_order: Vec<usize> = ir
            .cfg
            .node_indices()
            .filter_map(|n| {
                if let Block::Body(body) = &ir.cfg[n] {
                    Some(body.start_pc)
                } else {
                    None
                }
            })
            .collect();
        debug!("Final block order after reindex: {:?}", final_order);

        Ok(true)
    }
}
