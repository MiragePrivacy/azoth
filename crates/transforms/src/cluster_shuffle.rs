//! Relationship-aware CFG layout diversification.
//!
//! This pass moves complete fallthrough/PC-relative clusters instead of individual blocks. The
//! instructions inside each cluster are left byte-for-byte intact, so local compiler idioms and
//! the opcode distribution remain those of the input contract. Stable graph identity is also
//! retained: concrete PCs are assigned once, during final lowering.

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::seed::DeterministicRng;
use rand::seq::SliceRandom;
use tracing::debug;

/// Deterministically permutes independently movable block clusters.
#[derive(Debug, Default)]
pub struct ClusterShuffle;

impl ClusterShuffle {
    /// Creates the relationship-aware layout pass.
    pub fn new() -> Self {
        Self
    }
}

impl Transform for ClusterShuffle {
    fn name(&self) -> &'static str {
        "ClusterShuffle"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut DeterministicRng) -> Result<bool> {
        ir.refresh_relationships()
            .map_err(|error| Error::CoreError(error.to_string()))?;
        let relationships = ir.relationships().clone();

        if !relationships.is_relocatable() {
            debug!(
                unresolved = relationships.unresolved_control.len(),
                position_sensitive = relationships.position_sensitive.len(),
                "ClusterShuffle: layout is not safely relocatable"
            );
            return Ok(false);
        }
        let entry_position = relationships
            .clusters
            .iter()
            .position(|cluster| cluster.anchors_entry)
            .ok_or_else(|| Error::CoreError("relationship index has no entry cluster".into()))?;
        if entry_position != 0 {
            return Err(Error::CoreError(
                "entry cluster is not first in current layout".into(),
            ));
        }

        let exit_position = relationships
            .clusters
            .iter()
            .position(|cluster| cluster.anchors_exit);
        if let Some(exit_position) = exit_position {
            if exit_position + 1 != relationships.clusters.len() {
                return Err(Error::CoreError(
                    "fallthrough-to-end cluster is not last in current layout".into(),
                ));
            }
        }

        // Shuffle only consecutive, single-section-region runs. Entry, end-of-code, and
        // mixed-region clusters remain fixed anchors. This keeps creation/runtime boundaries and
        // the semantic end-of-code halt intact even when this generic pass is used outside the
        // normal runtime-only pipeline.
        let mut shuffled = relationships.clusters.clone();
        let mut changed = false;
        let mut start = 0usize;
        while start < shuffled.len() {
            let cluster = &shuffled[start];
            let Some(region) = cluster.layout_region else {
                start += 1;
                continue;
            };
            if cluster.anchors_entry || cluster.anchors_exit {
                start += 1;
                continue;
            }

            let mut end = start + 1;
            while end < shuffled.len()
                && shuffled[end].layout_region == Some(region)
                && !shuffled[end].anchors_entry
                && !shuffled[end].anchors_exit
            {
                end += 1;
            }

            if end - start >= 2 {
                let original_ids: Vec<_> = shuffled[start..end]
                    .iter()
                    .map(|candidate| candidate.id)
                    .collect();
                shuffled[start..end].shuffle(rng);
                if shuffled[start..end]
                    .iter()
                    .map(|candidate| candidate.id)
                    .eq(original_ids.iter().copied())
                {
                    shuffled[start..end].rotate_left(1);
                }
                changed = true;
            }
            start = end;
        }

        if !changed {
            debug!(
                clusters = relationships.clusters.len(),
                "ClusterShuffle: not enough independently movable clusters"
            );
            return Ok(false);
        }

        let mut order = Vec::with_capacity(ir.layout_order().len());
        for cluster in &shuffled {
            order.extend(cluster.members.iter().copied());
        }

        if order == ir.layout_order() {
            return Ok(false);
        }
        relationships
            .validate_layout(&order)
            .map_err(Error::CoreError)?;
        ir.set_layout_order(order)
            .map_err(|error| Error::CoreError(error.to_string()))?;

        debug!(
            clusters = relationships.clusters.len(),
            moved = relationships
                .clusters
                .iter()
                .zip(&shuffled)
                .filter(|(before, after)| before.id != after.id)
                .count(),
            "ClusterShuffle: applied relationship-safe layout"
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::{build_cfg_ir, Block};
    use azoth_core::decoder::Instruction;
    use azoth_core::detection::{Section, SectionKind};
    use azoth_core::strip::{CleanReport, RuntimeSpan};
    use azoth_core::Opcode;
    use rand::SeedableRng;
    use revm::primitives::B256;

    fn instruction(pc: usize, op: Opcode, immediate: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: immediate.map(str::to_string),
        }
    }

    fn build(instructions: &[Instruction], sections: &[Section], code_len: usize) -> CfgIrBundle {
        let report = CleanReport {
            runtime_layout: vec![RuntimeSpan {
                offset: sections
                    .iter()
                    .find(|section| section.kind == SectionKind::Runtime)
                    .map_or(0, |section| section.offset),
                len: sections
                    .iter()
                    .find(|section| section.kind == SectionKind::Runtime)
                    .map_or(code_len, |section| section.len),
            }],
            removed: Vec::new(),
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: code_len,
            clean_keccak: B256::ZERO,
            program_counter_mapping: Vec::new(),
        };
        build_cfg_ir(instructions, sections, report, &vec![0; code_len]).expect("test CFG builds")
    }

    #[test]
    fn deterministic_shuffle_keeps_entry_and_end_of_code_anchors() {
        let instructions = vec![
            instruction(0, Opcode::JUMPDEST, None),
            instruction(1, Opcode::PUSH(1), Some("04")),
            instruction(3, Opcode::JUMP, None),
            instruction(4, Opcode::JUMPDEST, None),
            instruction(5, Opcode::STOP, None),
            instruction(6, Opcode::JUMPDEST, None),
            instruction(7, Opcode::STOP, None),
            instruction(8, Opcode::JUMPDEST, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 9,
        }];
        let original = build(&instructions, &sections, 9);
        let original_order = original.layout_order().to_vec();
        let mut first = original.clone();
        let mut second = original;
        let mut first_rng = DeterministicRng::seed_from_u64(7);
        let mut second_rng = DeterministicRng::seed_from_u64(7);

        assert!(ClusterShuffle::new()
            .apply(&mut first, &mut first_rng)
            .unwrap());
        assert!(ClusterShuffle::new()
            .apply(&mut second, &mut second_rng)
            .unwrap());
        assert_eq!(first.layout_order(), second.layout_order());
        assert_eq!(first.layout_order().first(), original_order.first());
        assert_eq!(first.layout_order().last(), original_order.last());
        assert_ne!(first.layout_order(), original_order);
    }

    #[test]
    fn combined_cfg_keeps_each_executable_region_entry_fixed() {
        let instructions = vec![
            instruction(0, Opcode::STOP, None),
            instruction(1, Opcode::JUMPDEST, None),
            instruction(2, Opcode::STOP, None),
            instruction(3, Opcode::JUMPDEST, None),
            instruction(4, Opcode::STOP, None),
            instruction(5, Opcode::JUMPDEST, None),
            instruction(6, Opcode::STOP, None),
        ];
        let sections = [
            Section {
                kind: SectionKind::Init,
                offset: 0,
                len: 1,
            },
            Section {
                kind: SectionKind::Runtime,
                offset: 1,
                len: 6,
            },
        ];
        let mut bundle = build(&instructions, &sections, 7);
        let original = bundle.layout_order().to_vec();
        let mut rng = DeterministicRng::seed_from_u64(11);

        assert!(ClusterShuffle::new().apply(&mut bundle, &mut rng).unwrap());
        assert_eq!(bundle.layout_order()[0], original[0]);
        assert_eq!(bundle.layout_order()[1], original[1]);
        assert_eq!(bundle.layout_order()[2..], [original[3], original[2]]);
        for node in bundle.layout_order() {
            assert!(matches!(bundle.cfg[*node], Block::Body(_)));
        }
    }

    #[test]
    fn unresolved_dynamic_control_fails_closed_without_mutating_layout() {
        let instructions = vec![instruction(0, Opcode::JUMP, None)];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 1,
        }];
        let mut bundle = build(&instructions, &sections, 1);
        let original = bundle.layout_order().to_vec();
        let mut rng = DeterministicRng::seed_from_u64(13);

        assert!(!ClusterShuffle::new().apply(&mut bundle, &mut rng).unwrap());
        assert_eq!(bundle.layout_order(), original);
        assert!(!bundle.relationships().unresolved_control.is_empty());
    }
}
