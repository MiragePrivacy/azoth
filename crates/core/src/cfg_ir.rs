//! Control Flow Graph (CFG) construction and mutation utilities for Azoth.
//!
//! The original implementation blended low-level bytecode editing with graph updates, forcing
//! transforms to juggle program counters manually. This rewrite keeps the CFG as the source of
//! truth: blocks know how they connect, jump edges carry their coordinate system, and dedicated
//! helpers turn symbolic targets back into concrete immediates when bytecode gets re-emitted.
//!
//! The guiding principles are:
//! - **Block-first view.** Transforms describe control flow in terms of blocks. The module is
//!   responsible for turning those relationships into PUSH/JUMP sequences.
//! - **Single source of PC truth.** Reindexing, jump patching, and edge rebuilding all flow through
//!   a single set of utilities, removing duplicated offset math.
//! - **Graceful fallback.** When legacy patterns that we cannot symbolically track appear, we retain
//!   their raw immediates so existing transforms and analyses continue to work.

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

impl BlockControl {
    /// Returns true when the control descriptor references a symbolic jump target.
    #[allow(dead_code)]
    fn is_symbolic(&self) -> bool {
        match self {
            BlockControl::Jump { target }
            | BlockControl::Branch {
                true_target: target,
                false_target: _,
            } => target.is_symbolic(),
            _ => false,
        }
    }
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

impl JumpTarget {
    /// Returns true if the target points to another block rather than a raw immediate.
    fn is_symbolic(&self) -> bool {
        matches!(self, JumpTarget::Block { .. })
    }

    /// Returns the encoding mode used by this target when materialised.
    #[allow(dead_code)]
    fn encoding(&self) -> JumpEncoding {
        match self {
            JumpTarget::Block { encoding, .. } | JumpTarget::Raw { encoding, .. } => *encoding,
        }
    }
}

/// Describes how to interpret the immediate used by a jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Replace the body of a block while keeping its connectivity metadata intact.
    pub fn overwrite_block(
        &mut self,
        node: NodeIndex,
        mut new_body: BlockBody,
    ) -> Result<(), Error> {
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

        *self = rebuilt;
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
    fn assign_block_control(&mut self, node: NodeIndex, runtime_bounds: Option<(usize, usize)>) {
        let next = self.find_next_body(node);
        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node) {
            if let Some(control) =
                analyse_block_control(body, next, runtime_bounds, &self.pc_to_block)
            {
                body.control = control;
            }
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
    pub fn reindex_pcs(&mut self) -> Result<HashMap<usize, usize>, Error> {
        let mut mapping = HashMap::new();
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

        for (idx, _) in blocks {
            if let Some(Block::Body(body)) = self.cfg.node_weight_mut(idx) {
                let old_block_pc = body.start_pc;
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

                tracing::debug!(
                    "Reindexed block {}: old start_pc=0x{:x} -> new start_pc=0x{:x}",
                    idx.index(),
                    old_block_pc,
                    body.start_pc
                );
            }
        }

        self.pc_to_block = new_pc_to_block;
        self.write_symbolic_immediates()?;

        Ok(mapping)
    }

    /// Rewrite jump immediates using the supplied PC mapping. This keeps the method signature used
    /// by older transforms, but the heavy lifting now happens during `reindex_pcs`. We only patch
    /// legacy blocks that still rely on raw immediates.
    pub fn patch_jump_immediates(
        &mut self,
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<(), Error> {
        let runtime_bounds = self.runtime_bounds;
        let nodes: Vec<_> = self.cfg.node_indices().collect();
        for node in nodes {
            if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node) {
                patch_legacy_immediates(body, runtime_bounds, pc_mapping)?;
            }
        }
        Ok(())
    }

    /// Drops and regenerates the outgoing edges for a particular block, keeping graph metadata in
    /// sync after instruction edits.
    pub fn rebuild_edges_for_block(&mut self, node_idx: NodeIndex) -> Result<(), Error> {
        let runtime_bounds = self.runtime_bounds;
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
                .unwrap_or_else(|| BlockControl::Unknown);
            body.control = control.clone();
            control
        } else {
            BlockControl::Unknown
        };

        self.emit_edges(node_idx, &control)?;

        Ok(())
    }

    /// Adds edges that reflect the supplied control descriptor.
    fn emit_edges(&mut self, node: NodeIndex, control: &BlockControl) -> Result<(), Error> {
        let exit = self.find_exit_node();
        match control {
            BlockControl::Unknown => Ok(()),
            BlockControl::Terminal => {
                self.cfg.add_edge(node, exit, EdgeType::Fallthrough);
                Ok(())
            }
            BlockControl::Fallthrough => {
                if let Some(next) = self.find_next_body(node) {
                    self.cfg.add_edge(node, next, EdgeType::Fallthrough);
                } else {
                    self.cfg.add_edge(node, exit, EdgeType::Fallthrough);
                }
                Ok(())
            }
            BlockControl::Jump { target } => {
                if let Some(target_node) = target.as_block() {
                    self.cfg.add_edge(node, target_node, EdgeType::Jump);
                }
                Ok(())
            }
            BlockControl::Branch {
                true_target,
                false_target,
            } => {
                if let Some(target_node) = true_target.as_block() {
                    self.cfg.add_edge(node, target_node, EdgeType::BranchTrue);
                }

                match false_target.as_block() {
                    Some(node_idx) => {
                        self.cfg.add_edge(node, node_idx, EdgeType::BranchFalse);
                    }
                    None => {
                        if let Some(next) = self.find_next_body(node) {
                            self.cfg.add_edge(node, next, EdgeType::BranchFalse);
                        } else {
                            self.cfg.add_edge(node, exit, EdgeType::BranchFalse);
                        }
                    }
                }
                Ok(())
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

        if let Some(Block::Body(body)) = self.cfg.node_weight_mut(node) {
            if let Some(JumpPattern::Direct { push_idx }) = detect_jump_pattern(&body.instructions)
            {
                apply_immediate(&mut body.instructions[push_idx], value)?;
            }
        }

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
                    .map_or(false, |block| matches!(block, Block::Exit))
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

    Ok(CfgIrBundle {
        cfg,
        pc_to_block,
        clean_report,
        sections: sections.to_vec(),
        selector_mapping: None,
        original_bytecode: original_bytecode.to_vec(),
        runtime_bounds,
    })
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

        emit_edges(cfg, *node, &control)?;
    }
    Ok(())
}

/// Adds outgoing edges that match the supplied control information.
fn emit_edges(
    cfg: &mut StableDiGraph<Block, EdgeType>,
    source: NodeIndex,
    control: &BlockControl,
) -> Result<(), Error> {
    let exit = cfg
        .node_indices()
        .find(|idx| matches!(cfg[*idx], Block::Exit))
        .unwrap();

    match control {
        BlockControl::Unknown => {}
        BlockControl::Terminal => {
            cfg.add_edge(source, exit, EdgeType::Fallthrough);
        }
        BlockControl::Fallthrough => {
            if let Some(next) = find_next(cfg, source) {
                cfg.add_edge(source, next, EdgeType::Fallthrough);
            } else {
                cfg.add_edge(source, exit, EdgeType::Fallthrough);
            }
        }
        BlockControl::Jump { target } => {
            if let Some(target_node) = target.as_block() {
                cfg.add_edge(source, target_node, EdgeType::Jump);
            }
        }
        BlockControl::Branch {
            true_target,
            false_target,
        } => {
            if let Some(target_node) = true_target.as_block() {
                cfg.add_edge(source, target_node, EdgeType::BranchTrue);
            }
            if let Some(target_node) = false_target.as_block() {
                cfg.add_edge(source, target_node, EdgeType::BranchFalse);
            } else if let Some(next) = find_next(cfg, source) {
                cfg.add_edge(source, next, EdgeType::BranchFalse);
            } else {
                cfg.add_edge(source, exit, EdgeType::BranchFalse);
            }
        }
    }

    Ok(())
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
            let encoding = if body.is_runtime(runtime_bounds) {
                JumpEncoding::RuntimeRelative
            } else {
                JumpEncoding::Absolute
            };
            let absolute_pc = match encoding {
                JumpEncoding::RuntimeRelative => {
                    runtime_bounds.map(|(start, _)| start + immediate)?
                }
                JumpEncoding::Absolute => immediate,
                JumpEncoding::PcRelative => unreachable!(),
            };
            let target_node = node_by_pc.get(&absolute_pc).copied();
            target_node
                .map(|node| JumpTarget::Block { node, encoding })
                .or_else(|| {
                    Some(JumpTarget::Raw {
                        value: immediate,
                        encoding,
                    })
                })
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

enum JumpPattern {
    Direct { push_idx: usize },
    PcRelative { push_idx: usize, pc_idx: usize },
}

/// Recognises the bytecode pattern that feeds the terminal `JUMP`/`JUMPI` in a block.
fn detect_jump_pattern(instructions: &[Instruction]) -> Option<JumpPattern> {
    if instructions.is_empty() {
        return None;
    }

    let last = instructions.len() - 1;
    match instructions[last].op {
        Opcode::JUMP | Opcode::JUMPI => {}
        _ => return None,
    }

    if last >= 1 && is_push(&instructions[last - 1]) {
        return Some(JumpPattern::Direct { push_idx: last - 1 });
    }

    if last >= 3
        && instructions[last - 1].op == Opcode::ADD
        && instructions[last - 2].op == Opcode::PC
        && is_push(&instructions[last - 3])
    {
        return Some(JumpPattern::PcRelative {
            push_idx: last - 3,
            pc_idx: last - 2,
        });
    }

    None
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
        Some(JumpPattern::Direct { .. }) | Some(JumpPattern::PcRelative { .. }) => Ok(()),
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

/// Rewrites PUSH immediates for legacy blocks using the provided old→new PC mapping.
fn patch_legacy_immediates(
    body: &mut BlockBody,
    runtime_bounds: Option<(usize, usize)>,
    mapping: &HashMap<usize, usize>,
) -> Result<(), Error> {
    let in_runtime = body.is_runtime(runtime_bounds);
    let runtime_start = runtime_bounds.map(|(start, _)| start);
    let Some(JumpPattern::Direct { push_idx }) = detect_jump_pattern(&body.instructions) else {
        return Ok(());
    };
    let Some(old_value) = parse_immediate(&body.instructions[push_idx]) else {
        return Ok(());
    };

    let old_pc = if in_runtime {
        runtime_start.map(|start| start + old_value)
    } else {
        Some(old_value)
    };

    let Some(old_pc) = old_pc else {
        return Ok(());
    };
    let Some(new_pc) = mapping.get(&old_pc).copied() else {
        return Ok(());
    };

    let value_to_store = if in_runtime {
        runtime_start
            .map(|start| new_pc.saturating_sub(start))
            .unwrap_or(new_pc)
    } else {
        new_pc
    };

    let push = &mut body.instructions[push_idx];
    apply_immediate(push, value_to_store)
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
            clean_keccak: [0u8; 32],
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

        let mapping = bundle.reindex_pcs().expect("reindex succeeds");
        assert!(mapping.contains_key(&3));
        assert!(mapping.values().any(|&new_pc| new_pc != 3));
    }
}
