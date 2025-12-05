//! Control Flow Graph Intermediate Representation
//!
//! This module provides a structured graph representation of EVM bytecode

use crate::Opcode;
use crate::decoder::Instruction;
use crate::detection::{Section, SectionKind};
use crate::is_terminal_opcode;
use crate::result::Error;
use crate::strip::CleanReport;
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

mod trace;

pub use trace::{
    BlockBodySnapshot, BlockChangeSet, BlockControlSnapshot, BlockModification, BlockPcDiff,
    BlockSnapshot, BlockSnapshotKind, CfgIrDiff, CfgIrSnapshot, EdgeChangeSet, EdgeSnapshot,
    InstructionPcDiff, JumpTargetKind as TraceJumpTargetKind, JumpTargetSnapshot, OperationKind,
    SectionSnapshot, TraceEvent, block_modification, block_start_pcs, diff_from_block_changes,
    diff_from_edge_changes, diff_from_pc_remap, snapshot_block_body, snapshot_bundle,
    snapshot_edges,
};

type PcRemap = HashMap<usize, usize>;
type RuntimeBounds = Option<(usize, usize)>;
type ReindexOutcome = (PcRemap, RuntimeBounds);

/// CFG node representation.
#[derive(Debug, Clone)]
pub enum Block {
    Entry,
    Exit,
    Body(BlockBody),
}

impl Default for Block {
    /// Default block variant used when a node is initialised without explicit contents.
    fn default() -> Self {
        Block::Entry
    }
}

/// Concrete contents of a body block.
#[derive(Debug, Clone)]
pub struct BlockBody {
    pub start_pc: usize,
    pub instructions: Vec<Instruction>,
    pub max_stack: usize,
    pub control: BlockControl,
}

impl BlockBody {
    /// Creates an empty body block starting at the supplied PC.
    fn new(start_pc: usize) -> Self {
        Self {
            start_pc,
            instructions: Vec::new(),
            max_stack: 0,
            control: BlockControl::Unknown,
        }
    }

    /// Returns true when this block resides inside the runtime section described by
    /// `runtime_start`.
    fn is_runtime(&self, runtime_start: Option<(usize, usize)>) -> bool {
        if let Some((start, end)) = runtime_start {
            return self.start_pc >= start && self.start_pc < end;
        }
        false
    }
}

/// High-level view of how a block exits.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockControl {
    /// The block has not been analysed yet.
    Unknown,
    /// Execution falls through to the next block.
    Fallthrough,
    /// An unconditional jump.
    Jump { target: JumpTarget },
    /// Conditional branch where `true_target` receives the BranchTrue edge and `false_target`
    /// receives BranchFalse (or fallthrough).
    Branch {
        true_target: JumpTarget,
        false_target: JumpTarget,
    },
    /// STOP/RETURN/REVERT/INVALID/etc.
    Terminal,
}

/// Encodes where a jump leads and which coordinate system the immediate expects.
#[derive(Debug, Clone, PartialEq)]
pub enum JumpTarget {
    /// Link to an actual block. The coordinate system indicates how the PUSH immediate should be
    /// encoded (absolute PC or runtime-relative offset).
    Block {
        node: NodeIndex,
        encoding: JumpEncoding,
    },
    /// Raw value recorded in the bytecode. Used when we cannot yet express the target in terms of a
    /// block (e.g., PC-relative patterns or indirect jumps).
    Raw {
        value: usize,
        encoding: JumpEncoding,
    },
}

/// Describes how to interpret the immediate used by a jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JumpEncoding {
    /// Immediate stores an absolute PC.
    Absolute,
    /// Immediate stores a runtime-relative offset (0 at start of runtime section).
    RuntimeRelative,
    /// PC-relative patterns (e.g., PUSH delta; PC; ADD; JUMP). These are symbolic already and must
    /// not be rewritten automatically.
    PcRelative,
}

/// Edge types mirror the legacy representation to avoid touching downstream consumers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EdgeType {
    Fallthrough,
    Jump,
    BranchTrue,
    BranchFalse,
}

/// Single SSA identifier (currently only used to track stack heights).
#[derive(Debug, Clone, PartialEq)]
pub struct ValueId(usize);

/// Bundle returned by `build_cfg_ir` and handed to every transform.
#[derive(Debug, Clone)]
pub struct CfgIrBundle {
    pub cfg: StableDiGraph<Block, EdgeType>,
    pub pc_to_block: HashMap<usize, NodeIndex>,
    pub clean_report: CleanReport,
    pub sections: Vec<Section>,
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
    pub original_bytecode: Vec<u8>,
    pub runtime_bounds: Option<(usize, usize)>,
    pub trace: Vec<TraceEvent>,
    pub dispatcher_controller_pcs: Option<HashMap<u32, usize>>,
    pub dispatcher_patches: Option<Vec<(NodeIndex, usize, u8, u32)>>,
    pub stub_patches: Option<Vec<(NodeIndex, usize, u8, NodeIndex)>>,
    pub decoy_patches: Option<Vec<(NodeIndex, usize, u8, usize)>>,
    pub controller_patches: Option<Vec<(NodeIndex, usize, u8, usize)>>,
}

impl CfgIrBundle {
    /// Returns cached runtime bounds (start inclusive, end exclusive) if the bytecode contains a
    /// runtime section.
    pub fn runtime_bounds(&self) -> Option<(usize, usize)> {
        self.runtime_bounds
    }

    /// Returns true when the block referenced by `node` sits inside the runtime section.
    fn block_runtime_status(&self, node: NodeIndex) -> bool {
        self.runtime_bounds
            .and_then(|(start, end)| {
                self.cfg.node_weight(node).map(|block| match block {
                    Block::Body(body) => body.start_pc >= start && body.start_pc < end,
                    _ => false,
                })
            })
            .unwrap_or(false)
    }

    /// Returns a copy of the block control descriptor, if the node is a body block.
    pub fn block_control(&self, node: NodeIndex) -> Option<BlockControl> {
        self.cfg.node_weight(node).and_then(|block| match block {
            Block::Body(body) => Some(body.control.clone()),
            _ => None,
        })
    }

    /// Records a trace event capturing how the bundle changed.
    pub fn record_operation(
        &mut self,
        kind: OperationKind,
        diff: CfgIrDiff,
        remapped_pcs: Option<HashMap<usize, usize>>,
    ) {
        if matches!(diff, CfgIrDiff::None) && remapped_pcs.is_none() {
            return;
        }
        self.trace.push(TraceEvent {
            kind,
            diff,
            remapped_pcs,
        });
    }

    /// Records the start of a transform phase for trace grouping.
    pub fn record_transform_start(&mut self, name: &str) {
        self.trace.push(TraceEvent {
            kind: OperationKind::TransformStart {
                name: name.to_string(),
            },
            diff: CfgIrDiff::None,
            remapped_pcs: None,
        });
    }

    /// Records the end of a transform phase for trace grouping.
    pub fn record_transform_end(&mut self, name: &str) {
        self.trace.push(TraceEvent {
            kind: OperationKind::TransformEnd {
                name: name.to_string(),
            },
            diff: CfgIrDiff::None,
            remapped_pcs: None,
        });
    }

    /// Replace the body of a block while keeping its connectivity metadata intact.
    pub fn overwrite_block(
        &mut self,
        node: NodeIndex,
        mut new_body: BlockBody,
    ) -> Result<(), Error> {
        let before = snapshot_block_body(self, node);
        let runtime_bounds = self.runtime_bounds;
        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node) {
            new_body.start_pc = body.start_pc;
            body.instructions = new_body.instructions.clone();
            body.max_stack = new_body.max_stack;
            body.control = new_body.control.clone();
        } else {
            return Err(Error::InvalidBlockStructure(format!(
                "attempted to overwrite non-body or removed block {}",
                node.index()
            )));
        }

        self.rebuild_edges_for_block(node)?;
        self.assign_block_control(node, runtime_bounds);
        let after = snapshot_block_body(self, node);
        let mut changes = Vec::new();
        if let Some(change) = block_modification(node, before, after) {
            changes.push(change);
        }
        let diff = diff_from_block_changes(changes);
        self.record_operation(
            OperationKind::OverwriteBlock { node: node.index() },
            diff,
            None,
        );
        Ok(())
    }

    /// Create or update an unconditional jump that ends the given block.
    pub fn set_unconditional_jump(
        &mut self,
        source: NodeIndex,
        target: NodeIndex,
    ) -> Result<(), Error> {
        self.ensure_block(&source)?;
        self.ensure_block(&target)?;

        let before = snapshot_block_body(self, source);
        let encoding = self.default_encoding_for(source);
        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(source) {
            ensure_jump_pattern(body, Opcode::JUMP)?;
            body.control = BlockControl::Jump {
                target: JumpTarget::Block {
                    node: target,
                    encoding,
                },
            };
        } else {
            unreachable!();
        }

        self.rebuild_edges_for_block(source)?;
        self.write_symbolic_immediates_for_block(source)?;
        let after = snapshot_block_body(self, source);
        let mut changes = Vec::new();
        if let Some(change) = block_modification(source, before, after) {
            changes.push(change);
        }
        let diff = diff_from_block_changes(changes);
        self.record_operation(
            OperationKind::SetUnconditionalJump {
                source: source.index(),
                target: target.index(),
            },
            diff,
            None,
        );
        Ok(())
    }

    /// Configure a conditional jump (JUMPI) for the given block.
    pub fn set_conditional_jump(
        &mut self,
        source: NodeIndex,
        true_target: NodeIndex,
        false_target: Option<NodeIndex>,
    ) -> Result<(), Error> {
        self.ensure_block(&source)?;
        self.ensure_block(&true_target)?;
        if let Some(false_node) = false_target {
            self.ensure_block(&false_node)?;
        }

        let before = snapshot_block_body(self, source);
        let encoding = self.default_encoding_for(source);
        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(source) {
            ensure_jump_pattern(body, Opcode::JUMPI)?;
            let fallthrough = false_target
                .map(|node| JumpTarget::Block { node, encoding })
                .unwrap_or_else(|| JumpTarget::Raw { value: 0, encoding });
            body.control = BlockControl::Branch {
                true_target: JumpTarget::Block {
                    node: true_target,
                    encoding,
                },
                false_target: fallthrough,
            };
        } else {
            unreachable!();
        }

        self.rebuild_edges_for_block(source)?;
        self.write_symbolic_immediates_for_block(source)?;
        let after = snapshot_block_body(self, source);
        let mut changes = Vec::new();
        if let Some(change) = block_modification(source, before, after) {
            changes.push(change);
        }
        let diff = diff_from_block_changes(changes);
        self.record_operation(
            OperationKind::SetConditionalJump {
                source: source.index(),
                true_target: true_target.index(),
                false_target: false_target.map(|idx| idx.index()),
            },
            diff,
            None,
        );
        Ok(())
    }

    /// Legacy fallback that rebuilds the CFG from a flat instruction stream.
    ///
    /// Prefer using block-level editing helpers (`overwrite_block`, `set_unconditional_jump`,
    /// etc.) whenever possible. This method exists so transforms that still operate on byte slices
    /// can continue to function while they are being ported.
    pub fn replace_body(
        &mut self,
        instructions: Vec<Instruction>,
        sections: &[Section],
    ) -> Result<(), Error> {
        let selector_mapping = self.selector_mapping.clone();
        let clean_report = self.clean_report.clone();
        let original_bytecode = self.original_bytecode.clone();

        let mut rebuilt = build_cfg_ir(&instructions, sections, clean_report, &original_bytecode)?;
        rebuilt.selector_mapping = selector_mapping;
        rebuilt.original_bytecode = original_bytecode;
        rebuilt.trace = self.trace.clone();

        *self = rebuilt;
        let snapshot = snapshot_bundle(self);
        self.record_operation(
            OperationKind::ReplaceBody {
                instruction_count: instructions.len(),
            },
            CfgIrDiff::FullSnapshot(Box::new(snapshot)),
            None,
        );
        Ok(())
    }

    /// Validates that the referenced node is a body block.
    fn ensure_block(&self, node: &NodeIndex) -> Result<(), Error> {
        if let Some(Block::Body(_)) = self.cfg.node_weight(*node) {
            Ok(())
        } else {
            Err(Error::InvalidBlockStructure(format!(
                "node {} is not a body block",
                node.index()
            )))
        }
    }

    /// Picks the appropriate jump encoding for a block based on whether it lives in runtime.
    fn default_encoding_for(&self, source: NodeIndex) -> JumpEncoding {
        if self.block_runtime_status(source) {
            JumpEncoding::RuntimeRelative
        } else {
            JumpEncoding::Absolute
        }
    }

    /// Re-evaluates the block’s control descriptor and updates the cached metadata in-place.
    fn assign_block_control(&mut self, node: NodeIndex, runtime_bounds: RuntimeBounds) {
        let next = self.find_next_body(node);
        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node)
            && let Some(control) =
                analyse_block_control(body, next, runtime_bounds, &self.pc_to_block)
        {
            body.control = control;
        }
    }

    /// Finds the next block in program counter order, if any.
    fn find_next_body(&self, node: NodeIndex) -> Option<NodeIndex> {
        let mut nodes: Vec<_> = self
            .cfg
            .node_references()
            .filter_map(|(idx, block)| match block {
                Block::Body(body) => Some((idx, body.start_pc)),
                _ => None,
            })
            .collect();
        nodes.sort_by_key(|(_, pc)| *pc);
        for (i, (idx, _)) in nodes.iter().enumerate() {
            if *idx == node {
                return nodes.get(i + 1).map(|(next_idx, _)| *next_idx);
            }
        }
        None
    }

    /// Reindexes PCs and refreshes the start_pc mapping. Unlike the legacy implementation this also
    /// writes symbolic jump immediates so a subsequent `patch_jump_immediates` call becomes a no-op
    /// for blocks using the new API.
    /// Renumbers program counters and returns a mapping from old PCs to their new positions.
    pub fn reindex_pcs(&mut self) -> Result<ReindexOutcome, Error> {
        let before_blocks = block_start_pcs(self);
        let mut mapping = HashMap::new();
        let old_runtime_bounds = self.runtime_bounds;
        let mut blocks: Vec<_> = self
            .cfg
            .node_indices()
            .filter_map(|idx| {
                self.cfg.node_weight(idx).and_then(|block| match block {
                    Block::Body(body) => Some((idx, body.start_pc)),
                    _ => None,
                })
            })
            .collect();
        blocks.sort_by_key(|(_, start_pc)| *start_pc);

        let mut next_pc = 0usize;
        let mut new_pc_to_block = HashMap::new();
        let runtime_bounds = self.runtime_bounds;
        let mut runtime_first_new_pc: Option<usize> = None;
        let mut runtime_last_new_pc: Option<usize> = None;

        for (idx, _) in blocks {
            if let Some(Block::Body(body)) = self.cfg.node_weight_mut(idx) {
                let old_block_pc = body.start_pc;
                let in_runtime = body.is_runtime(runtime_bounds);
                body.start_pc = next_pc;
                new_pc_to_block.insert(body.start_pc, idx);

                for instr in &mut body.instructions {
                    mapping.insert(instr.pc, next_pc);
                    // Preserve INVALID opcode bytes before we erase the original PC.
                    if matches!(instr.op, Opcode::INVALID)
                        && instr.imm.is_none()
                        && instr.pc < self.original_bytecode.len()
                    {
                        instr.imm = Some(format!("{:02x}", self.original_bytecode[instr.pc]));
                    }
                    instr.pc = next_pc;
                    next_pc += instr.byte_size();
                }

                if in_runtime {
                    runtime_first_new_pc.get_or_insert(body.start_pc);
                    runtime_last_new_pc = Some(next_pc);
                }

                tracing::debug!(
                    "Reindexed block {}: old start_pc=0x{:x} -> new start_pc=0x{:x}",
                    idx.index(),
                    old_block_pc,
                    body.start_pc
                );
            }
        }

        self.pc_to_block = new_pc_to_block;

        if let Some((old_start, old_end)) = runtime_bounds {
            match (runtime_first_new_pc, runtime_last_new_pc) {
                (Some(start), Some(end)) => {
                    debug_assert!(end >= start);
                    if old_start != start || old_end != end {
                        tracing::debug!(
                            "Remapped runtime bounds: 0x{:x}-0x{:x} -> 0x{:x}-0x{:x}",
                            old_start,
                            old_end,
                            start,
                            end
                        );
                    }
                    self.runtime_bounds = Some((start, end));
                }
                _ => {
                    tracing::warn!(
                        "runtime bounds unavailable after reindex; falling back to absolute encoding"
                    );
                    self.runtime_bounds = None;
                }
            }
        }

        let after_blocks = block_start_pcs(self);
        let after_lookup: HashMap<_, _> = after_blocks.iter().cloned().collect();
        let mut block_diffs = Vec::new();
        for (node, old_pc) in before_blocks {
            if let Some(new_pc) = after_lookup.get(&node)
                && old_pc != *new_pc
            {
                block_diffs.push(BlockPcDiff {
                    node: node.index(),
                    old_start_pc: old_pc,
                    new_start_pc: *new_pc,
                });
            }
        }

        let instruction_diffs: Vec<InstructionPcDiff> = mapping
            .iter()
            .filter_map(|(old_pc, new_pc)| {
                if old_pc != new_pc {
                    Some(InstructionPcDiff {
                        old_pc: *old_pc,
                        new_pc: *new_pc,
                    })
                } else {
                    None
                }
            })
            .collect();

        let diff = diff_from_pc_remap(block_diffs, instruction_diffs);

        self.write_symbolic_immediates()?;
        self.record_operation(OperationKind::ReindexPcs, diff, Some(mapping.clone()));

        Ok((mapping, old_runtime_bounds))
    }

    /// Rewrite jump immediates using the supplied PC mapping. This keeps the method signature used
    /// by older transforms, but the heavy lifting now happens during `reindex_pcs`. We only patch
    /// legacy blocks that still rely on raw immediates.
    pub fn patch_jump_immediates(
        &mut self,
        pc_mapping: &HashMap<usize, usize>,
        old_runtime_bounds: Option<(usize, usize)>,
    ) -> Result<(), Error> {
        let runtime_bounds = self.runtime_bounds;
        let old_runtime_start = old_runtime_bounds.map(|(start, _)| start);
        let nodes: Vec<_> = self.cfg.node_indices().collect();
        let mut block_changes = Vec::new();
        for node in nodes {
            let has_symbolic_target = matches!(
                self.block_control(node),
                Some(BlockControl::Jump {
                    target: JumpTarget::Block { .. },
                }) | Some(BlockControl::Branch {
                    true_target: JumpTarget::Block { .. },
                    ..
                })
            );

            tracing::debug!(
                node = node.index(),
                has_symbolic_target,
                "patch_jump_immediates: evaluating block",
            );

            if let Some(change) = self.patch_legacy_immediates_for_block(
                node,
                runtime_bounds,
                old_runtime_start,
                pc_mapping,
                has_symbolic_target,
            )? {
                block_changes.push(change);
            }
        }
        let diff = diff_from_block_changes(block_changes);
        self.record_operation(
            OperationKind::PatchJumpImmediates,
            diff,
            Some(pc_mapping.clone()),
        );
        Ok(())
    }

    /// Remap all stored metadata that references absolute PCs using the supplied mapping.
    ///
    /// This should be called any time a transform invokes `reindex_pcs` directly so that
    /// dispatcher metadata stays aligned with the updated instruction addresses.
    pub fn remap_metadata_pcs(&mut self, mapping: &HashMap<usize, usize>) {
        let remap_value = |value: &mut usize, context: &str| {
            if let Some(new_pc) = mapping.get(value) {
                *value = *new_pc;
            } else {
                tracing::debug!(
                    context = context,
                    old_pc = format_args!("0x{:x}", *value),
                    "remap_metadata_pcs: mapping missing for value"
                );
            }
        };

        if let Some(controller_pcs) = self.dispatcher_controller_pcs.as_mut() {
            for (selector, pc) in controller_pcs.iter_mut() {
                let ctx = format!("controller selector=0x{selector:08x}");
                remap_value(pc, &ctx);
            }
        }

        if let Some(dispatcher_patches) = self.dispatcher_patches.as_mut() {
            for (_, pc, _, selector) in dispatcher_patches.iter_mut() {
                let ctx = format!("dispatcher selector=0x{selector:08x}");
                remap_value(pc, &ctx);
            }
        }

        if let Some(stub_patches) = self.stub_patches.as_mut() {
            for (_, pc, _, _) in stub_patches.iter_mut() {
                remap_value(pc, "stub patch");
            }
        }

        if let Some(decoy_patches) = self.decoy_patches.as_mut() {
            for (_, push_pc, _, target_pc) in decoy_patches.iter_mut() {
                remap_value(push_pc, "decoy push");
                remap_value(target_pc, "decoy target");
            }
        }

        if let Some(controller_patches) = self.controller_patches.as_mut() {
            for (_, push_pc, _, target_pc) in controller_patches.iter_mut() {
                remap_value(push_pc, "controller push");
                remap_value(target_pc, "controller target");
            }
        }
    }

    fn patch_legacy_immediates_for_block(
        &mut self,
        node: NodeIndex,
        runtime_bounds: Option<(usize, usize)>,
        old_runtime_start: Option<usize>,
        mapping: &HashMap<usize, usize>,
        skip_symbolic_terminal: bool,
    ) -> Result<Option<BlockModification>, Error> {
        let control = self.block_control(node);
        let fallback_immediate = control.as_ref().and_then(|ctrl| match ctrl {
            BlockControl::Jump { target } => self.resolve_target_value(target),
            BlockControl::Branch { true_target, .. } => self.resolve_target_value(true_target),
            _ => None,
        });

        let before = snapshot_block_body(self, node);

        let Some(Block::Body(body)) = self.cfg.node_weight_mut(node) else {
            return Ok(None);
        };

        let in_runtime = body.is_runtime(runtime_bounds);
        let new_runtime_start = runtime_bounds.map(|(start, _)| start);
        let patterns = find_jump_patterns(&body.instructions);
        if patterns.is_empty() {
            return Ok(None);
        }

        let terminal_pattern = if skip_symbolic_terminal {
            detect_jump_pattern(&body.instructions)
        } else {
            None
        };

        tracing::debug!(
            node = node.index(),
            start_pc = format_args!("0x{:x}", body.start_pc),
            in_runtime,
            pattern_count = patterns.len(),
            skip_symbolic_terminal,
            "patch_legacy_immediates: visiting block",
        );

        for pattern in patterns {
            if skip_symbolic_terminal
                && terminal_pattern
                    .as_ref()
                    .is_some_and(|terminal| jump_patterns_match(&pattern, terminal))
            {
                tracing::debug!(
                    start_pc = format_args!("0x{:x}", body.start_pc),
                    "patch_legacy_immediates: skipping terminal symbolic pattern",
                );
                continue;
            }

            let Some(old_value) = pattern_immediate(&body.instructions, &pattern) else {
                tracing::debug!(
                    start_pc = format_args!("0x{:x}", body.start_pc),
                    "patch_legacy_immediates: unable to parse immediate, skipping pattern",
                );
                continue;
            };

            let old_pc = if in_runtime {
                old_runtime_start.unwrap_or(0).saturating_add(old_value)
            } else {
                old_value
            };

            tracing::debug!(
                start_pc = format_args!("0x{:x}", body.start_pc),
                pattern_old_value = format_args!("0x{:x}", old_value),
                pattern_old_pc = format_args!("0x{:x}", old_pc),
                "patch_legacy_immediates: resolved old PC",
            );

            let mut new_pc_abs = mapping.get(&old_pc).copied();
            if new_pc_abs.is_none()
                && let Some(val) = mapping.get(&old_value).copied()
            {
                tracing::debug!(
                    start_pc = format_args!("0x{:x}", body.start_pc),
                    pattern_old_pc = format_args!("0x{:x}", old_pc),
                    pattern_old_value = format_args!("0x{:x}", old_value),
                    "patch_legacy_immediates: mapped using raw value",
                );
                new_pc_abs = Some(val);
            }

            if let Some(mapped_pc) = new_pc_abs {
                let has_block = self.pc_to_block.contains_key(&mapped_pc);
                if !has_block {
                    tracing::debug!(
                        start_pc = format_args!("0x{:x}", body.start_pc),
                        pattern_old_pc = format_args!("0x{:x}", old_pc),
                        mapped_pc = format_args!("0x{:x}", mapped_pc),
                        "patch_legacy_immediates: mapped PC has no block; falling back",
                    );
                    new_pc_abs = None;
                }
            }

            if new_pc_abs.is_none()
                && let Some(fallback) = fallback_immediate
            {
                let absolute = if in_runtime {
                    new_runtime_start.unwrap_or(0).saturating_add(fallback)
                } else {
                    fallback
                };
                tracing::debug!(
                    start_pc = format_args!("0x{:x}", body.start_pc),
                    pattern_old_pc = format_args!("0x{:x}", old_pc),
                    fallback_value = format_args!("0x{:x}", fallback),
                    absolute = format_args!("0x{:x}", absolute),
                    "patch_legacy_immediates: using control fallback",
                );
                new_pc_abs = Some(absolute);
            }

            let Some(new_pc_abs) = new_pc_abs else {
                tracing::debug!(
                    start_pc = format_args!("0x{:x}", body.start_pc),
                    pattern_old_pc = format_args!("0x{:x}", old_pc),
                    "patch_legacy_immediates: no mapping or fallback; skipping",
                );
                continue;
            };

            let value_to_store = if in_runtime {
                new_runtime_start
                    .map(|start| new_pc_abs.saturating_sub(start))
                    .unwrap_or(new_pc_abs)
            } else {
                new_pc_abs
            };

            tracing::debug!(
                start_pc = format_args!("0x{:x}", body.start_pc),
                pattern_old_pc = format_args!("0x{:x}", old_pc),
                new_pc = format_args!("0x{:x}", new_pc_abs),
                value_to_store = format_args!("0x{:x}", value_to_store),
                "patch_legacy_immediates: rewriting pattern",
            );

            match pattern {
                JumpPattern::Direct { push_idx } => {
                    apply_immediate(&mut body.instructions[push_idx], value_to_store)?;
                }
                JumpPattern::SplitAdd {
                    push_a_idx,
                    push_b_idx,
                } => {
                    apply_split_add_immediate(
                        &mut body.instructions,
                        push_a_idx,
                        push_b_idx,
                        value_to_store,
                    )?;
                }
                JumpPattern::PcRelative { .. } => {}
            }
        }

        let after = snapshot_block_body(self, node);
        Ok(block_modification(node, before, after))
    }

    /// Drops and regenerates the outgoing edges for a particular block, keeping graph metadata in
    /// sync after instruction edits.
    pub fn rebuild_edges_for_block(&mut self, node_idx: NodeIndex) -> Result<(), Error> {
        let runtime_bounds = self.runtime_bounds;
        let removed_edges = snapshot_edges(self, node_idx);
        // remove existing outgoing edges
        let outgoing: Vec<_> = self
            .cfg
            .edges_directed(node_idx, petgraph::Outgoing)
            .map(|edge| edge.id())
            .collect();
        for edge in outgoing {
            self.cfg.remove_edge(edge);
        }

        let next = self.find_next_body(node_idx);
        let control = if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node_idx) {
            let control = analyse_block_control(body, next, runtime_bounds, &self.pc_to_block)
                .unwrap_or(BlockControl::Unknown);
            body.control = control.clone();
            control
        } else {
            BlockControl::Unknown
        };

        let added_edges = self.emit_edges(node_idx, &control)?;
        let diff = diff_from_edge_changes(node_idx, removed_edges, added_edges);

        self.record_operation(
            OperationKind::RebuildEdges {
                node: node_idx.index(),
            },
            diff,
            None,
        );
        Ok(())
    }

    /// Adds edges that reflect the supplied control descriptor.
    fn emit_edges(
        &mut self,
        node: NodeIndex,
        control: &BlockControl,
    ) -> Result<Vec<EdgeSnapshot>, Error> {
        let exit = self.find_exit_node();
        let mut added = Vec::new();
        match control {
            BlockControl::Unknown => Ok(added),
            BlockControl::Terminal => {
                let edge = self.cfg.add_edge(node, exit, EdgeType::Fallthrough);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: node.index(),
                    target: exit.index(),
                    kind: EdgeType::Fallthrough,
                });
                Ok(added)
            }
            BlockControl::Fallthrough => {
                if let Some(next) = self.find_next_body(node) {
                    let edge = self.cfg.add_edge(node, next, EdgeType::Fallthrough);
                    added.push(EdgeSnapshot {
                        id: edge.index(),
                        source: node.index(),
                        target: next.index(),
                        kind: EdgeType::Fallthrough,
                    });
                } else {
                    let edge = self.cfg.add_edge(node, exit, EdgeType::Fallthrough);
                    added.push(EdgeSnapshot {
                        id: edge.index(),
                        source: node.index(),
                        target: exit.index(),
                        kind: EdgeType::Fallthrough,
                    });
                }
                Ok(added)
            }
            BlockControl::Jump { target } => {
                if let Some(target_node) = target.as_block() {
                    let edge = self.cfg.add_edge(node, target_node, EdgeType::Jump);
                    added.push(EdgeSnapshot {
                        id: edge.index(),
                        source: node.index(),
                        target: target_node.index(),
                        kind: EdgeType::Jump,
                    });
                }
                Ok(added)
            }
            BlockControl::Branch {
                true_target,
                false_target,
            } => {
                if let Some(target_node) = true_target.as_block() {
                    let edge = self.cfg.add_edge(node, target_node, EdgeType::BranchTrue);
                    added.push(EdgeSnapshot {
                        id: edge.index(),
                        source: node.index(),
                        target: target_node.index(),
                        kind: EdgeType::BranchTrue,
                    });
                }

                match false_target.as_block() {
                    Some(node_idx) => {
                        let edge = self.cfg.add_edge(node, node_idx, EdgeType::BranchFalse);
                        added.push(EdgeSnapshot {
                            id: edge.index(),
                            source: node.index(),
                            target: node_idx.index(),
                            kind: EdgeType::BranchFalse,
                        });
                    }
                    None => {
                        if let Some(next) = self.find_next_body(node) {
                            let edge = self.cfg.add_edge(node, next, EdgeType::BranchFalse);
                            added.push(EdgeSnapshot {
                                id: edge.index(),
                                source: node.index(),
                                target: next.index(),
                                kind: EdgeType::BranchFalse,
                            });
                        } else {
                            let edge = self.cfg.add_edge(node, exit, EdgeType::BranchFalse);
                            added.push(EdgeSnapshot {
                                id: edge.index(),
                                source: node.index(),
                                target: exit.index(),
                                kind: EdgeType::BranchFalse,
                            });
                        }
                    }
                }
                Ok(added)
            }
        }
    }

    /// Iterates over all blocks writing PUSH immediates that correspond to symbolic jump targets.
    fn write_symbolic_immediates(&mut self) -> Result<(), Error> {
        let nodes: Vec<_> = self.cfg.node_indices().collect();
        for node in nodes {
            self.write_symbolic_immediates_for_block(node)?;
        }
        Ok(())
    }

    /// Writes the PUSH immediate for a single block if the target resolves to a concrete value.
    fn write_symbolic_immediates_for_block(&mut self, node: NodeIndex) -> Result<(), Error> {
        let target = match self.block_control(node) {
            Some(BlockControl::Jump { target }) => Some(target),
            Some(BlockControl::Branch { true_target, .. }) => Some(true_target),
            _ => None,
        };

        let Some(target) = target else {
            return Ok(());
        };

        let Some(value) = self.resolve_target_value(&target) else {
            return Ok(());
        };

        let before = snapshot_block_body(self, node);
        let mut changed = false;

        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node)
            && let Some(pattern) = detect_jump_pattern(&body.instructions)
        {
            match pattern {
                JumpPattern::Direct { push_idx } => {
                    apply_immediate(&mut body.instructions[push_idx], value)?;
                    changed = true;
                }
                JumpPattern::SplitAdd {
                    push_a_idx,
                    push_b_idx,
                } => {
                    apply_split_add_immediate(
                        &mut body.instructions,
                        push_a_idx,
                        push_b_idx,
                        value,
                    )?;
                    changed = true;
                }
                JumpPattern::PcRelative { .. } => {}
            }
        }

        if !changed {
            return Ok(());
        }

        let after = snapshot_block_body(self, node);
        let mut changes = Vec::new();
        if let Some(change) = block_modification(node, before, after) {
            changes.push(change);
        }
        let diff = diff_from_block_changes(changes);

        self.record_operation(
            OperationKind::WriteSymbolicImmediates { node: node.index() },
            diff,
            None,
        );
        Ok(())
    }

    /// Resolves a `JumpTarget` into the immediate value expected by the underlying PUSH opcode.
    fn resolve_target_value(&self, target: &JumpTarget) -> Option<usize> {
        match target {
            JumpTarget::Block { node, encoding } => {
                let target_pc = match self.cfg.node_weight(*node)? {
                    Block::Body(body) => body.start_pc,
                    _ => return None,
                };
                match encoding {
                    JumpEncoding::RuntimeRelative => self
                        .runtime_bounds
                        .map(|(start, _)| target_pc.saturating_sub(start)),
                    JumpEncoding::Absolute => Some(target_pc),
                    JumpEncoding::PcRelative => None,
                }
            }
            JumpTarget::Raw { value, encoding } => match encoding {
                JumpEncoding::PcRelative => None,
                _ => Some(*value),
            },
        }
    }

    /// Returns the Exit node, creating it lazily if the graph lacks one.
    fn find_exit_node(&mut self) -> NodeIndex {
        self.cfg
            .node_indices()
            .find(|idx| {
                self.cfg
                    .node_weight(*idx)
                    .is_some_and(|block| matches!(block, Block::Exit))
            })
            .unwrap_or_else(|| self.cfg.add_node(Block::Exit))
    }
}

impl JumpTarget {
    /// Returns the node index when the jump target references a CFG block.
    fn as_block(&self) -> Option<NodeIndex> {
        match self {
            JumpTarget::Block { node, .. } => Some(*node),
            _ => None,
        }
    }
}

/// Builds a CFG bundle from decoded instructions and section metadata.
pub fn build_cfg_ir(
    instructions: &[Instruction],
    sections: &[Section],
    clean_report: CleanReport,
    original_bytecode: &[u8],
) -> Result<CfgIrBundle, Error> {
    tracing::debug!(
        "Building CFG from {} instructions across {} sections",
        instructions.len(),
        sections.len()
    );

    let runtime_bounds = runtime_bounds(sections);
    let blocks = split_blocks(instructions)?;

    let mut cfg = StableDiGraph::new();
    let entry = cfg.add_node(Block::Entry);
    let exit = cfg.add_node(Block::Exit);

    let mut node_by_pc = HashMap::new();
    let mut ordered_nodes = Vec::new();

    for block in blocks {
        if let Block::Body(body) = block.clone() {
            let idx = cfg.add_node(block);
            node_by_pc.insert(body.start_pc, idx);
            ordered_nodes.push(idx);
        }
    }

    if let Some(first) = ordered_nodes.first() {
        cfg.add_edge(entry, *first, EdgeType::Fallthrough);
    } else {
        cfg.add_edge(entry, exit, EdgeType::Fallthrough);
    }

    analyse_and_connect(&mut cfg, &ordered_nodes, &node_by_pc, runtime_bounds)?;
    assign_ssa_values(&mut cfg)?;

    let pc_to_block = node_by_pc.clone();

    let mut bundle = CfgIrBundle {
        cfg,
        pc_to_block,
        clean_report,
        sections: sections.to_vec(),
        selector_mapping: None,
        original_bytecode: original_bytecode.to_vec(),
        runtime_bounds,
        trace: Vec::new(),
        dispatcher_controller_pcs: None,
        dispatcher_patches: None,
        stub_patches: None,
        decoy_patches: None,
        controller_patches: None,
    };
    let body_blocks = bundle
        .cfg
        .node_indices()
        .filter(|idx| matches!(bundle.cfg[*idx], Block::Body(_)))
        .count();
    let snapshot = snapshot_bundle(&bundle);
    bundle.record_operation(
        OperationKind::Build {
            body_blocks,
            sections: sections.len(),
        },
        CfgIrDiff::FullSnapshot(Box::new(snapshot)),
        None,
    );
    Ok(bundle)
}

/// Extracts runtime section bounds from the detection results.
fn runtime_bounds(sections: &[Section]) -> Option<(usize, usize)> {
    sections.iter().find_map(|section| {
        if section.kind == SectionKind::Runtime {
            Some((section.offset, section.offset + section.len))
        } else {
            None
        }
    })
}

/// Breaks the instruction stream into basic blocks and ensures branch boundaries are respected.
fn split_blocks(instructions: &[Instruction]) -> Result<Vec<Block>, Error> {
    let mut blocks = Vec::new();
    let mut current = BlockBody::new(0);

    let jumpdest_pcs: HashSet<usize> = instructions
        .iter()
        .filter(|ins| matches!(ins.op, Opcode::JUMPDEST))
        .map(|ins| ins.pc)
        .collect();

    for ins in instructions {
        if matches!(ins.op, Opcode::JUMPDEST) {
            if !current.instructions.is_empty() {
                blocks.push(Block::Body(current.clone()));
            }
            current = BlockBody {
                start_pc: ins.pc,
                instructions: vec![ins.clone()],
                max_stack: 0,
                control: BlockControl::Unknown,
            };
            continue;
        }

        if current.instructions.is_empty() {
            current.start_pc = ins.pc;
        }

        current.instructions.push(ins.clone());

        if is_terminal_opcode(ins.op) || matches!(ins.op, Opcode::JUMP | Opcode::JUMPI) {
            blocks.push(Block::Body(current.clone()));
            current = BlockBody::new(ins.pc + 1);
        }
    }

    if !current.instructions.is_empty() {
        blocks.push(Block::Body(current));
    }

    validate_jumpdests(&blocks, &jumpdest_pcs)?;
    Ok(blocks)
}

/// Ensures every `JUMPDEST` discovered in the bytecode starts a corresponding block.
fn validate_jumpdests(blocks: &[Block], jumpdest_pcs: &HashSet<usize>) -> Result<(), Error> {
    let mut block_starts = HashSet::new();
    for block in blocks {
        if let Block::Body(body) = block {
            block_starts.insert(body.start_pc);
        }
    }

    let orphaned: Vec<_> = jumpdest_pcs
        .iter()
        .filter(|pc| !block_starts.contains(pc))
        .cloned()
        .collect();

    if !orphaned.is_empty() {
        return Err(Error::InvalidBlockStructure(format!(
            "JUMPDESTs not aligned with block starts: {:?}",
            orphaned
        )));
    }

    Ok(())
}

/// Derives control descriptors for each block and wires up the corresponding edges.
fn analyse_and_connect(
    cfg: &mut StableDiGraph<Block, EdgeType>,
    ordered_nodes: &[NodeIndex],
    node_by_pc: &HashMap<usize, NodeIndex>,
    runtime_bounds: Option<(usize, usize)>,
) -> Result<(), Error> {
    for (idx, node) in ordered_nodes.iter().enumerate() {
        let next = ordered_nodes.get(idx + 1).copied();
        let control = if let Some(Block::Body(body)) = cfg.node_weight_mut(*node) {
            let control = analyse_block_control(body, next, runtime_bounds, node_by_pc)
                .unwrap_or(BlockControl::Unknown);
            body.control = control.clone();
            control
        } else {
            BlockControl::Unknown
        };

        let _ = emit_edges(cfg, *node, &control)?;
    }
    Ok(())
}

/// Adds outgoing edges that match the supplied control information.
fn emit_edges(
    cfg: &mut StableDiGraph<Block, EdgeType>,
    source: NodeIndex,
    control: &BlockControl,
) -> Result<Vec<EdgeSnapshot>, Error> {
    let exit = cfg
        .node_indices()
        .find(|idx| matches!(cfg[*idx], Block::Exit))
        .unwrap();

    let mut added = Vec::new();

    match control {
        BlockControl::Unknown => {}
        BlockControl::Terminal => {
            let edge = cfg.add_edge(source, exit, EdgeType::Fallthrough);
            added.push(EdgeSnapshot {
                id: edge.index(),
                source: source.index(),
                target: exit.index(),
                kind: EdgeType::Fallthrough,
            });
        }
        BlockControl::Fallthrough => {
            if let Some(next) = find_next(cfg, source) {
                let edge = cfg.add_edge(source, next, EdgeType::Fallthrough);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: next.index(),
                    kind: EdgeType::Fallthrough,
                });
            } else {
                let edge = cfg.add_edge(source, exit, EdgeType::Fallthrough);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: exit.index(),
                    kind: EdgeType::Fallthrough,
                });
            }
        }
        BlockControl::Jump { target } => {
            if let Some(target_node) = target.as_block() {
                let edge = cfg.add_edge(source, target_node, EdgeType::Jump);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: target_node.index(),
                    kind: EdgeType::Jump,
                });
            }
        }
        BlockControl::Branch {
            true_target,
            false_target,
        } => {
            if let Some(target_node) = true_target.as_block() {
                let edge = cfg.add_edge(source, target_node, EdgeType::BranchTrue);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: target_node.index(),
                    kind: EdgeType::BranchTrue,
                });
            }
            if let Some(target_node) = false_target.as_block() {
                let edge = cfg.add_edge(source, target_node, EdgeType::BranchFalse);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: target_node.index(),
                    kind: EdgeType::BranchFalse,
                });
            } else if let Some(next) = find_next(cfg, source) {
                let edge = cfg.add_edge(source, next, EdgeType::BranchFalse);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: next.index(),
                    kind: EdgeType::BranchFalse,
                });
            } else {
                let edge = cfg.add_edge(source, exit, EdgeType::BranchFalse);
                added.push(EdgeSnapshot {
                    id: edge.index(),
                    source: source.index(),
                    target: exit.index(),
                    kind: EdgeType::BranchFalse,
                });
            }
        }
    }

    Ok(added)
}

/// Finds the block that executes immediately after `node` based on program counter ordering.
fn find_next(cfg: &StableDiGraph<Block, EdgeType>, node: NodeIndex) -> Option<NodeIndex> {
    let mut blocks: Vec<_> = cfg
        .node_references()
        .filter_map(|(idx, block)| match block {
            Block::Body(body) => Some((idx, body.start_pc)),
            _ => None,
        })
        .collect();
    blocks.sort_by_key(|(_, pc)| *pc);
    for (i, (idx, _)) in blocks.iter().enumerate() {
        if *idx == node {
            return blocks.get(i + 1).map(|(next_idx, _)| *next_idx);
        }
    }
    None
}

/// Infers the `BlockControl` descriptor for a block using its terminator instruction.
fn analyse_block_control(
    body: &BlockBody,
    next: Option<NodeIndex>,
    runtime_bounds: Option<(usize, usize)>,
    node_by_pc: &HashMap<usize, NodeIndex>,
) -> Option<BlockControl> {
    if body.instructions.is_empty() {
        return Some(BlockControl::Fallthrough);
    }

    let last = body.instructions.last().unwrap();
    match last.op {
        Opcode::JUMP => build_jump_control(body, runtime_bounds, node_by_pc),
        Opcode::JUMPI => build_branch_control(body, next, runtime_bounds, node_by_pc),
        opcode if is_terminal_opcode(opcode) => Some(BlockControl::Terminal),
        _ => Some(BlockControl::Fallthrough),
    }
}

/// Builds the control descriptor for an unconditional jump.
fn build_jump_control(
    body: &BlockBody,
    runtime_bounds: Option<(usize, usize)>,
    node_by_pc: &HashMap<usize, NodeIndex>,
) -> Option<BlockControl> {
    analyse_jump_target(body, runtime_bounds, node_by_pc)
        .map(|target| BlockControl::Jump { target })
}

/// Builds the control descriptor for a conditional branch, including the fallthrough target.
fn build_branch_control(
    body: &BlockBody,
    next: Option<NodeIndex>,
    runtime_bounds: Option<(usize, usize)>,
    node_by_pc: &HashMap<usize, NodeIndex>,
) -> Option<BlockControl> {
    let true_target = analyse_jump_target(body, runtime_bounds, node_by_pc)?;
    let false_target = next
        .map(|node| JumpTarget::Block {
            node,
            encoding: match runtime_bounds {
                Some(_) if body.is_runtime(runtime_bounds) => JumpEncoding::RuntimeRelative,
                _ => JumpEncoding::Absolute,
            },
        })
        .unwrap_or_else(|| JumpTarget::Raw {
            value: 0,
            encoding: JumpEncoding::Absolute,
        });

    Some(BlockControl::Branch {
        true_target,
        false_target,
    })
}

/// Resolves the block referenced by the jump terminator into a symbolic `JumpTarget`.
fn analyse_jump_target(
    body: &BlockBody,
    runtime_bounds: Option<(usize, usize)>,
    node_by_pc: &HashMap<usize, NodeIndex>,
) -> Option<JumpTarget> {
    let pattern = detect_jump_pattern(&body.instructions)?;
    match pattern {
        JumpPattern::Direct { push_idx } => {
            let push = &body.instructions[push_idx];
            let immediate = parse_immediate(push)?;
            absolute_target_from_value(body, runtime_bounds, node_by_pc, immediate)
        }
        JumpPattern::SplitAdd {
            push_a_idx,
            push_b_idx,
        } => {
            let first = parse_immediate(&body.instructions[push_a_idx])?;
            let second = parse_immediate(&body.instructions[push_b_idx])?;
            let immediate = first.checked_add(second)?;
            absolute_target_from_value(body, runtime_bounds, node_by_pc, immediate)
        }
        JumpPattern::PcRelative { push_idx, pc_idx } => {
            let delta = parse_immediate(&body.instructions[push_idx])?;
            let pc_value = body.instructions[pc_idx].pc;
            let absolute_pc = pc_value + delta;
            let target_node = node_by_pc.get(&absolute_pc).copied();
            target_node.map(|node| JumpTarget::Block {
                node,
                encoding: JumpEncoding::PcRelative,
            })
        }
    }
}

fn absolute_target_from_value(
    body: &BlockBody,
    runtime_bounds: Option<(usize, usize)>,
    node_by_pc: &HashMap<usize, NodeIndex>,
    immediate: usize,
) -> Option<JumpTarget> {
    let encoding = if body.is_runtime(runtime_bounds) {
        JumpEncoding::RuntimeRelative
    } else {
        JumpEncoding::Absolute
    };

    let absolute_pc = match encoding {
        JumpEncoding::RuntimeRelative => runtime_bounds.map(|(start, _)| start + immediate)?,
        JumpEncoding::Absolute => immediate,
        JumpEncoding::PcRelative => unreachable!(),
    };

    let target_node = node_by_pc.get(&absolute_pc).copied();
    target_node
        .map(|node| JumpTarget::Block { node, encoding })
        .or({
            Some(JumpTarget::Raw {
                value: immediate,
                encoding,
            })
        })
}

// Jump pattern detection is used in two phases:
// 1. analyse_jump_target() classifies the terminator so we can store a symbolic
//    `JumpTarget` (block + encoding) during CFG construction.
// 2. patch_legacy_immediates() scans all instructions in a block to rewrite
//    their immediates using the old→new PC map. `find_jump_patterns` is the bulk
//    scanner for phase 2, while `detect_jump_pattern`/
//    `detect_jump_pattern_at` do the single-pattern lookup for phase 1 and for
//    the terminal check in `ensure_jump_pattern`.
// Keeping them together looks slightly repetitive, but they feed different workflows

enum JumpPattern {
    /// `PUSH <target>; JUMP/JUMPI`
    Direct { push_idx: usize },
    /// `PUSH <lhs>; PUSH <rhs>; ADD; JUMP/JUMPI`
    SplitAdd {
        push_a_idx: usize,
        push_b_idx: usize,
    },
    /// `PUSH <delta>; PC; ADD; JUMPI`
    PcRelative { push_idx: usize, pc_idx: usize },
}

/// Recognises the bytecode pattern that feeds the terminal `JUMP`/`JUMPI` in a block.
fn detect_jump_pattern(instructions: &[Instruction]) -> Option<JumpPattern> {
    instructions
        .len()
        .checked_sub(1)
        .and_then(|last| detect_jump_pattern_at(instructions, last))
}

fn detect_jump_pattern_at(instructions: &[Instruction], jump_idx: usize) -> Option<JumpPattern> {
    match instructions.get(jump_idx)?.op {
        Opcode::JUMP | Opcode::JUMPI => {}
        _ => return None,
    }

    if jump_idx >= 1 && is_push(&instructions[jump_idx - 1]) {
        return Some(JumpPattern::Direct {
            push_idx: jump_idx - 1,
        });
    }

    if jump_idx >= 3
        && instructions[jump_idx - 1].op == Opcode::ADD
        && is_push(&instructions[jump_idx - 2])
        && is_push(&instructions[jump_idx - 3])
    {
        return Some(JumpPattern::SplitAdd {
            push_a_idx: jump_idx - 3,
            push_b_idx: jump_idx - 2,
        });
    }

    if jump_idx >= 3
        && instructions[jump_idx - 1].op == Opcode::ADD
        && instructions[jump_idx - 2].op == Opcode::PC
        && is_push(&instructions[jump_idx - 3])
    {
        return Some(JumpPattern::PcRelative {
            push_idx: jump_idx - 3,
            pc_idx: jump_idx - 2,
        });
    }

    None
}

fn find_jump_patterns(instructions: &[Instruction]) -> Vec<JumpPattern> {
    let mut patterns = Vec::new();
    for idx in 0..instructions.len() {
        if let Some(pattern) = detect_jump_pattern_at(instructions, idx) {
            patterns.push(pattern);
        }
    }
    patterns
}

fn pattern_immediate(instructions: &[Instruction], pattern: &JumpPattern) -> Option<usize> {
    match pattern {
        JumpPattern::Direct { push_idx } => parse_immediate(&instructions[*push_idx]),
        JumpPattern::SplitAdd {
            push_a_idx,
            push_b_idx,
        } => {
            let first = parse_immediate(&instructions[*push_a_idx])?;
            let second = parse_immediate(&instructions[*push_b_idx])?;
            first.checked_add(second)
        }
        JumpPattern::PcRelative { .. } => None,
    }
}

/// Returns true when the instruction is any PUSH variant (including PUSH0).
fn is_push(ins: &Instruction) -> bool {
    matches!(ins.op, Opcode::PUSH(_) | Opcode::PUSH0)
}

/// Parses the immediate operand of a PUSH instruction into a machine integer.
fn parse_immediate(ins: &Instruction) -> Option<usize> {
    ins.imm
        .as_ref()
        .and_then(|imm| usize::from_str_radix(imm, 16).ok())
}

/// Verifies that the block ends with a direct jump pattern compatible with symbolic rewrites.
fn ensure_jump_pattern(body: &BlockBody, opcode: Opcode) -> Result<(), Error> {
    if body.instructions.is_empty() {
        return Err(Error::InvalidBlockStructure(
            "block is empty; cannot assign jump".into(),
        ));
    }

    match detect_jump_pattern(&body.instructions) {
        Some(JumpPattern::Direct { .. })
        | Some(JumpPattern::SplitAdd { .. })
        | Some(JumpPattern::PcRelative { .. }) => Ok(()),
        None => Err(Error::InvalidBlockStructure(format!(
            "block ending at pc 0x{:x} does not end with {:?}",
            body.start_pc, opcode
        ))),
    }
}

/// Rewrites the hexadecimal immediate of a PUSH instruction, preserving its byte width.
fn apply_immediate(instr: &mut Instruction, value: usize) -> Result<(), Error> {
    match instr.op {
        Opcode::PUSH0 => {
            if value != 0 {
                return Err(Error::InvalidImmediate(format!(
                    "value 0x{:x} does not fit PUSH0",
                    value
                )));
            }
            instr.imm = Some("00".into());
        }
        Opcode::PUSH(width) => {
            let width = width as usize;
            let max = if width == 32 {
                usize::MAX
            } else {
                (1usize << (width * 8)) - 1
            };
            if value > max {
                return Err(Error::InvalidImmediate(format!(
                    "value 0x{:x} exceeds PUSH{} capacity",
                    value, width
                )));
            }
            instr.imm = Some(format!("{:0width$x}", value, width = width * 2));
        }
        _ => {
            return Err(Error::InvalidImmediate(
                "attempted to write immediate into non-PUSH opcode".into(),
            ));
        }
    }

    Ok(())
}

fn apply_split_add_immediate(
    instructions: &mut [Instruction],
    push_a_idx: usize,
    push_b_idx: usize,
    total: usize,
) -> Result<(), Error> {
    let max_a = push_capacity(&instructions[push_a_idx].op)
        .ok_or_else(|| Error::InvalidImmediate("expected PUSH opcode before ADD".into()))?;
    let max_b = push_capacity(&instructions[push_b_idx].op)
        .ok_or_else(|| Error::InvalidImmediate("expected PUSH opcode before ADD".into()))?;

    let combined_capacity = if max_a == usize::MAX || max_b == usize::MAX {
        usize::MAX
    } else {
        max_a
            .checked_add(max_b)
            .ok_or_else(|| Error::InvalidImmediate("combined PUSH capacity overflowed".into()))?
    };

    if total > combined_capacity {
        return Err(Error::InvalidImmediate(format!(
            "value 0x{:x} exceeds combined PUSH capacity",
            total
        )));
    }

    let part_a = total.min(max_a);
    let part_b = total.saturating_sub(part_a);

    apply_immediate(&mut instructions[push_a_idx], part_a)?;
    apply_immediate(&mut instructions[push_b_idx], part_b)?;
    Ok(())
}

fn push_capacity(op: &Opcode) -> Option<usize> {
    match op {
        Opcode::PUSH0 => Some(0),
        Opcode::PUSH(width) => {
            let width = *width as usize;
            if width == 32 {
                Some(usize::MAX)
            } else {
                Some((1usize << (width * 8)) - 1)
            }
        }
        _ => None,
    }
}

fn jump_patterns_match(a: &JumpPattern, b: &JumpPattern) -> bool {
    match (a, b) {
        (JumpPattern::Direct { push_idx: a_idx }, JumpPattern::Direct { push_idx: b_idx }) => {
            a_idx == b_idx
        }
        (
            JumpPattern::SplitAdd {
                push_a_idx: a_a,
                push_b_idx: a_b,
            },
            JumpPattern::SplitAdd {
                push_a_idx: b_a,
                push_b_idx: b_b,
            },
        ) => a_a == b_a && a_b == b_b,
        (
            JumpPattern::PcRelative {
                push_idx: a_push,
                pc_idx: a_pc,
            },
            JumpPattern::PcRelative {
                push_idx: b_push,
                pc_idx: b_pc,
            },
        ) => a_push == b_push && a_pc == b_pc,
        _ => false,
    }
}

/// Computes a conservative stack-height bound for each block to maintain SSA metadata.
fn assign_ssa_values(cfg: &mut StableDiGraph<Block, EdgeType>) -> Result<(), Error> {
    let nodes: Vec<_> = cfg.node_indices().collect();
    for node in nodes {
        if let Some(Block::Body(body)) = cfg.node_weight_mut(node) {
            let mut max_stack = 0usize;
            let mut current_depth = 0isize;
            for instr in &body.instructions {
                match instr.op {
                    Opcode::PUSH(_) | Opcode::PUSH0 | Opcode::DUP(_) => {
                        current_depth += 1;
                        max_stack = max_stack.max(current_depth as usize);
                    }
                    Opcode::POP => current_depth = (current_depth - 1).max(0),
                    _ => {}
                }
            }
            body.max_stack = max_stack;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{Section, SectionKind};
    use crate::strip::RuntimeSpan;
    use revm::primitives::B256;

    fn sample_runtime_section(len: usize) -> Section {
        Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len,
        }
    }

    fn sample_bytecode(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    fn sample_clean_report(len: usize) -> CleanReport {
        CleanReport {
            runtime_layout: vec![RuntimeSpan { offset: 0, len }],
            removed: Vec::new(),
            swarm_hash: None,
            bytes_saved: 0,
            clean_len: len,
            clean_keccak: B256::ZERO,
            program_counter_mapping: Vec::new(),
        }
    }

    #[test]
    fn apply_immediate_respects_width() {
        let mut instr = Instruction {
            pc: 0,
            op: Opcode::PUSH(2),
            imm: Some("0000".into()),
        };
        apply_immediate(&mut instr, 0x12ab).unwrap();
        assert_eq!(instr.imm.as_deref(), Some("12ab"));
    }

    #[test]
    fn build_cfg_ir_creates_basic_blocks() {
        let instructions = vec![
            Instruction {
                pc: 0,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 1,
                op: Opcode::PUSH(1),
                imm: Some("04".into()),
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

        let sections = vec![sample_runtime_section(instructions.len())];
        let bundle = build_cfg_ir(
            &instructions,
            &sections,
            sample_clean_report(instructions.len()),
            &sample_bytecode(instructions.len()),
        )
        .expect("cfg build succeeds");

        let body_nodes: Vec<_> = bundle
            .cfg
            .node_indices()
            .filter(|&idx| matches!(bundle.cfg[idx], Block::Body(_)))
            .collect();

        assert_eq!(body_nodes.len(), 2);

        if let Block::Body(body) = &bundle.cfg[body_nodes[0]] {
            assert!(matches!(body.control, BlockControl::Jump { .. }));
        } else {
            panic!("first node should be a body block");
        }
    }

    #[test]
    fn reindex_pcs_returns_mapping() {
        let instructions = vec![
            Instruction {
                pc: 0,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 1,
                op: Opcode::PUSH(1),
                imm: Some("04".into()),
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

        let sections = vec![sample_runtime_section(instructions.len())];
        let mut bundle = build_cfg_ir(
            &instructions,
            &sections,
            sample_clean_report(instructions.len()),
            &sample_bytecode(instructions.len()),
        )
        .expect("cfg build succeeds");

        let (mapping, _) = bundle.reindex_pcs().expect("reindex succeeds");
        assert!(mapping.contains_key(&3));
        assert!(mapping.values().any(|&new_pc| new_pc != 3));
    }

    #[test]
    fn reindex_pcs_updates_runtime_relative_jumps() {
        let instructions = vec![
            // Runtime block starting at 0x20 with a jump that targets the second block via
            // runtime-relative encoding (offset 0x0005 -> absolute 0x25).
            Instruction {
                pc: 0x20,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 0x21,
                op: Opcode::PUSH(2),
                imm: Some("0005".into()),
            },
            Instruction {
                pc: 0x24,
                op: Opcode::JUMP,
                imm: None,
            },
            // Target block at 0x25.
            Instruction {
                pc: 0x25,
                op: Opcode::JUMPDEST,
                imm: None,
            },
            Instruction {
                pc: 0x26,
                op: Opcode::STOP,
                imm: None,
            },
        ];

        let sections = vec![Section {
            kind: SectionKind::Runtime,
            offset: 0x20,
            len: instructions.len(),
        }];

        let mut bundle = build_cfg_ir(
            &instructions,
            &sections,
            sample_clean_report(instructions.len()),
            &sample_bytecode(instructions.len() + 0x20),
        )
        .expect("cfg build succeeds");

        assert_eq!(
            bundle.runtime_bounds,
            Some((0x20, 0x20 + instructions.len()))
        );

        let _ = bundle.reindex_pcs().expect("reindex succeeds");

        // Runtime start should be remapped to zero after reindexing.
        let (start, _) = bundle.runtime_bounds.expect("runtime bounds present");
        assert_eq!(start, 0);

        // Collect the PUSH immediate after reindexing; it should encode the offset to the target
        // block relative to the new runtime start.
        let mut push_imm = None;
        let mut max_block_start = 0usize;
        for idx in bundle.cfg.node_indices() {
            if let Block::Body(body) = &bundle.cfg[idx] {
                max_block_start = max_block_start.max(body.start_pc);
                for instr in &body.instructions {
                    if instr.op == Opcode::PUSH(2) {
                        push_imm = instr.imm.clone();
                    }
                }
            }
        }

        let expected = format!("{:04x}", max_block_start.saturating_sub(start));
        assert_eq!(push_imm.as_deref(), Some(expected.as_str()));
    }
}
