use crate::cfg_ir::{
    Block, BlockBody, BlockControl, CfgIrBundle, EdgeType, JumpEncoding, JumpTarget,
};
use crate::decoder::Instruction;
use crate::detection::{Section, SectionKind};
use crate::strip::CleanReport;
use petgraph::Direction;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};
use revm::primitives::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Operations recorded in the CFG trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationKind {
    Build {
        body_blocks: usize,
        sections: usize,
    },
    OverwriteBlock {
        node: usize,
    },
    SetUnconditionalJump {
        source: usize,
        target: usize,
    },
    SetConditionalJump {
        source: usize,
        true_target: usize,
        false_target: Option<usize>,
    },
    RebuildEdges {
        node: usize,
    },
    WriteSymbolicImmediates {
        node: usize,
    },
    ReindexPcs,
    PatchJumpImmediates,
    ReplaceBody {
        instruction_count: usize,
    },
    Finalize,
}

/// Trace entry describing an applied CFG operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub kind: OperationKind,
    pub diff: CfgIrDiff,
    pub remapped_pcs: Option<HashMap<usize, usize>>,
}

/// Snapshot of the IR bundle captured after a full replacement or initial build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgIrSnapshot {
    pub blocks: Vec<BlockSnapshot>,
    pub edges: Vec<EdgeSnapshot>,
    pub pc_to_block: HashMap<usize, usize>,
    pub clean_report: CleanReport,
    pub sections: Vec<SectionSnapshot>,
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
    pub original_bytecode: Bytes,
    pub runtime_bounds: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CfgIrDiff {
    None,
    BlockChanges(BlockChangeSet),
    EdgeChanges(EdgeChangeSet),
    PcsRemapped {
        blocks: Vec<BlockPcDiff>,
        instructions: Vec<InstructionPcDiff>,
    },
    FullSnapshot(Box<CfgIrSnapshot>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChangeSet {
    pub changes: Vec<BlockModification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockModification {
    pub node: usize,
    pub before: BlockBodySnapshot,
    pub after: BlockBodySnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeChangeSet {
    pub node: usize,
    pub removed: Vec<EdgeSnapshot>,
    pub added: Vec<EdgeSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPcDiff {
    pub node: usize,
    pub old_start_pc: usize,
    pub new_start_pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionPcDiff {
    pub old_pc: usize,
    pub new_pc: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockBodySnapshot {
    pub start_pc: usize,
    pub max_stack: usize,
    pub control: BlockControlSnapshot,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockControlSnapshot {
    Unknown,
    Fallthrough,
    Jump {
        target: JumpTargetSnapshot,
    },
    Branch {
        true_target: JumpTargetSnapshot,
        false_target: JumpTargetSnapshot,
    },
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JumpTargetSnapshot {
    pub encoding: JumpEncoding,
    pub kind: JumpTargetKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JumpTargetKind {
    Block { node: usize },
    Raw { value: usize },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockSnapshot {
    pub node: usize,
    pub kind: BlockSnapshotKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockSnapshotKind {
    Entry,
    Exit,
    Body(BlockBodySnapshot),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgeSnapshot {
    pub id: usize,
    pub source: usize,
    pub target: usize,
    pub kind: EdgeType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionSnapshot {
    pub kind: SectionKind,
    pub offset: usize,
    pub len: usize,
}

/// Captures a complete snapshot of the current CFG bundle.
pub fn snapshot_bundle(bundle: &CfgIrBundle) -> CfgIrSnapshot {
    let blocks = bundle
        .cfg
        .node_indices()
        .map(|idx| BlockSnapshot {
            node: idx.index(),
            kind: match &bundle.cfg[idx] {
                Block::Entry => BlockSnapshotKind::Entry,
                Block::Exit => BlockSnapshotKind::Exit,
                Block::Body(body) => BlockSnapshotKind::Body(block_body_snapshot(body)),
            },
        })
        .collect();

    let edges = bundle
        .cfg
        .edge_references()
        .map(|edge| EdgeSnapshot {
            id: edge.id().index(),
            source: edge.source().index(),
            target: edge.target().index(),
            kind: edge.weight().clone(),
        })
        .collect();

    let pc_to_block = bundle
        .pc_to_block
        .iter()
        .map(|(pc, node)| (*pc, node.index()))
        .collect();

    let sections = bundle.sections.iter().map(SectionSnapshot::from).collect();

    CfgIrSnapshot {
        blocks,
        edges,
        pc_to_block,
        clean_report: bundle.clean_report.clone(),
        sections,
        selector_mapping: bundle.selector_mapping.clone(),
        original_bytecode: Bytes::from(bundle.original_bytecode.clone()),
        runtime_bounds: bundle.runtime_bounds,
    }
}

/// Captures the body of a block for diffing.
pub fn snapshot_block_body(bundle: &CfgIrBundle, node: NodeIndex) -> Option<BlockBodySnapshot> {
    match bundle.cfg.node_weight(node) {
        Some(Block::Body(body)) => Some(block_body_snapshot(body)),
        _ => None,
    }
}

/// Captures the outgoing edges for a block.
pub fn snapshot_edges(bundle: &CfgIrBundle, node: NodeIndex) -> Vec<EdgeSnapshot> {
    bundle
        .cfg
        .edges_directed(node, Direction::Outgoing)
        .map(|edge| EdgeSnapshot {
            id: edge.id().index(),
            source: edge.source().index(),
            target: edge.target().index(),
            kind: edge.weight().clone(),
        })
        .collect()
}

/// Creates a diff describing modified block bodies.
pub fn diff_from_block_changes(changes: Vec<BlockModification>) -> CfgIrDiff {
    if changes.is_empty() {
        CfgIrDiff::None
    } else {
        CfgIrDiff::BlockChanges(BlockChangeSet { changes })
    }
}

/// Creates a diff describing updated edges.
pub fn diff_from_edge_changes(
    node: NodeIndex,
    removed: Vec<EdgeSnapshot>,
    added: Vec<EdgeSnapshot>,
) -> CfgIrDiff {
    if removed.is_empty() && added.is_empty() {
        CfgIrDiff::None
    } else {
        CfgIrDiff::EdgeChanges(EdgeChangeSet {
            node: node.index(),
            removed,
            added,
        })
    }
}

/// Creates a diff describing PC remapping.
pub fn diff_from_pc_remap(
    blocks: Vec<BlockPcDiff>,
    instructions: Vec<InstructionPcDiff>,
) -> CfgIrDiff {
    CfgIrDiff::PcsRemapped {
        blocks,
        instructions,
    }
}

/// Convenience helper to compare two block snapshots.
pub fn block_modification(
    node: NodeIndex,
    before: Option<BlockBodySnapshot>,
    after: Option<BlockBodySnapshot>,
) -> Option<BlockModification> {
    match (before, after) {
        (Some(before), Some(after)) if before != after => Some(BlockModification {
            node: node.index(),
            before,
            after,
        }),
        _ => None,
    }
}

/// Captures block start PCs for diffing reindex operations.
pub fn block_start_pcs(bundle: &CfgIrBundle) -> Vec<(NodeIndex, usize)> {
    bundle
        .cfg
        .node_indices()
        .filter_map(|idx| match bundle.cfg.node_weight(idx) {
            Some(Block::Body(body)) => Some((idx, body.start_pc)),
            _ => None,
        })
        .collect()
}

impl From<&Section> for SectionSnapshot {
    fn from(section: &Section) -> Self {
        Self {
            kind: section.kind,
            offset: section.offset,
            len: section.len,
        }
    }
}

fn block_body_snapshot(body: &BlockBody) -> BlockBodySnapshot {
    BlockBodySnapshot {
        start_pc: body.start_pc,
        max_stack: body.max_stack,
        control: block_control_snapshot(&body.control),
        instructions: body.instructions.clone(),
    }
}

fn block_control_snapshot(control: &BlockControl) -> BlockControlSnapshot {
    match control {
        BlockControl::Unknown => BlockControlSnapshot::Unknown,
        BlockControl::Fallthrough => BlockControlSnapshot::Fallthrough,
        BlockControl::Terminal => BlockControlSnapshot::Terminal,
        BlockControl::Jump { target } => BlockControlSnapshot::Jump {
            target: jump_target_snapshot(target),
        },
        BlockControl::Branch {
            true_target,
            false_target,
        } => BlockControlSnapshot::Branch {
            true_target: jump_target_snapshot(true_target),
            false_target: jump_target_snapshot(false_target),
        },
    }
}

fn jump_target_snapshot(target: &JumpTarget) -> JumpTargetSnapshot {
    match target {
        JumpTarget::Block { node, encoding } => JumpTargetSnapshot {
            encoding: *encoding,
            kind: JumpTargetKind::Block { node: node.index() },
        },
        JumpTarget::Raw { value, encoding } => JumpTargetSnapshot {
            encoding: *encoding,
            kind: JumpTargetKind::Raw { value: *value },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Opcode;
    use crate::cfg_ir::{BlockControl, JumpEncoding, JumpTarget, build_cfg_ir};
    use crate::decoder::Instruction;
    use crate::detection::Section;
    use crate::strip::{Removed, RuntimeSpan};
    use revm::primitives::B256;

    fn sample_bundle() -> CfgIrBundle {
        let instructions = vec![
            Instruction {
                pc: 0,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 1,
                op: Opcode::PUSH(1),
                imm: Some("02".into()),
            },
            Instruction {
                pc: 3,
                op: Opcode::JUMP,
                imm: None,
            },
            Instruction {
                pc: 4,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 5,
                op: Opcode::STOP,
                imm: None,
            },
        ];

        let sections = vec![Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: instructions.len(),
        }];

        let clean_report = CleanReport {
            runtime_layout: vec![RuntimeSpan {
                offset: 0,
                len: instructions.len(),
            }],
            removed: vec![Removed {
                offset: 10,
                kind: SectionKind::Init,
                data: Vec::new().into(),
            }],
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: instructions.len(),
            clean_keccak: B256::ZERO,
            program_counter_mapping: Vec::new(),
        };

        build_cfg_ir(
            &instructions,
            &sections,
            clean_report,
            &vec![0u8; instructions.len()],
        )
        .expect("bundle")
    }

    #[test]
    fn snapshot_bundle_contains_blocks() {
        let bundle = sample_bundle();
        let snapshot = snapshot_bundle(&bundle);
        dbg!(&snapshot);
        assert!(!snapshot.blocks.is_empty());
        assert_eq!(snapshot.runtime_bounds, bundle.runtime_bounds());
    }

    #[test]
    fn block_snapshot_matches_control() {
        let bundle = sample_bundle();
        let node = bundle
            .cfg
            .node_indices()
            .find(|idx| matches!(bundle.cfg[*idx], Block::Body(_)))
            .expect("body block exists");
        if let Some(body) = snapshot_block_body(&bundle, node) {
            dbg!(&body);
            assert_eq!(body.start_pc, 0);
        } else {
            panic!("missing block snapshot");
        }
    }

    #[test]
    fn block_modifications_detect_changes() {
        let mut bundle = sample_bundle();
        let node = bundle
            .cfg
            .node_indices()
            .find(|idx| matches!(bundle.cfg[*idx], Block::Body(_)))
            .expect("body block exists");
        let before = snapshot_block_body(&bundle, node);
        if let Some(Block::Body(body)) = bundle.cfg.node_weight_mut(node) {
            if let BlockControl::Jump { target } = &mut body.control {
                *target = JumpTarget::Raw {
                    value: 10,
                    encoding: JumpEncoding::Absolute,
                };
            }
        }
        let after = snapshot_block_body(&bundle, node);
        let change = block_modification(node, before, after).expect("change should be detected");
        dbg!(&change);
        assert_eq!(change.node, node.index());
    }
}
