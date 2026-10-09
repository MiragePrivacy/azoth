//! Relationship index for the EVM control-flow intermediate representation.
//!
//! The CFG stores control-flow edges, while this module records the relationships that a
//! transform needs in order to change physical layout safely.  In particular, it distinguishes
//! stable block identity (`NodeIndex`) from byte offsets and groups blocks that must move together
//! because execution falls through between them or because they use PC-relative addressing.

use super::{Block, BlockControl, CfgIrBundle, EdgeType, JumpEncoding, JumpTarget};
use crate::Opcode;
use crate::detection::SectionKind;
use petgraph::Direction::{Incoming, Outgoing};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// Semantic role assigned to a body block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockRole {
    /// First executable body block.
    Entry,
    /// Block detected or synthesized as part of the function dispatcher.
    Dispatcher,
    /// Block begins with `JUMPDEST` and can therefore receive a dynamic jump.
    JumpDestination,
    /// Block ends execution.
    Terminal,
    /// Block ends in `JUMP` or `JUMPI`.
    Control,
    /// Block has no more specific role.
    Ordinary,
}

/// One typed relationship to another body block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLink {
    /// Related body block.
    pub block: NodeIndex,
    /// Control-flow relationship.
    pub kind: EdgeType,
}

/// A literal code pointer whose value must be relinked when physical layout changes.
///
/// The source is expressed as stable block identity plus instruction index. Concrete program
/// counters are deliberately absent: they are products of lowering, not object identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodePointerRelocation {
    /// Block containing the PUSH instruction.
    pub source: NodeIndex,
    /// Instruction index within `source`.
    pub instruction_index: usize,
    /// Body block whose `JUMPDEST` address is pushed.
    pub target: NodeIndex,
    /// Coordinate system used by the encoded immediate.
    pub encoding: JumpEncoding,
}

/// Relationship data retained for one body block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRelationships {
    /// Position in the intended physical bytecode layout.
    pub layout_position: usize,
    /// Code section that owns this block.
    pub section: SectionKind,
    /// Contiguous section region that owns this block in the source layout.
    ///
    /// The region is intentionally stronger than [`Self::section`]: two runtime spans separated
    /// by another section have distinct regions even though both have `SectionKind::Runtime`.
    pub layout_region: usize,
    /// Incoming control-flow links, sorted deterministically.
    pub predecessors: Vec<BlockLink>,
    /// Outgoing control-flow links, sorted deterministically.
    pub successors: Vec<BlockLink>,
    /// Cluster that must be laid out as one unit.
    pub cluster: usize,
    /// High-level semantic roles.
    pub roles: BTreeSet<BlockRole>,
}

/// A maximal set of blocks that must preserve internal physical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCluster {
    /// Stable index within this relationship snapshot.
    pub id: usize,
    /// Members in physical order.
    pub members: Vec<NodeIndex>,
    /// Control-flow links entering from another cluster.
    pub incoming: Vec<BlockLink>,
    /// Control-flow links leaving for another cluster.
    pub outgoing: Vec<BlockLink>,
    /// Whether this cluster contains an externally entered section-region start.
    pub anchors_entry: bool,
    /// Whether this cluster must remain last because it falls off the end of code.
    pub anchors_exit: bool,
    /// Contiguous section region for movable clusters. Mixed-region clusters are immovable.
    pub layout_region: Option<usize>,
}

/// Complete relationship snapshot derived from a CFG bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelationshipIndex {
    /// Per-block relationships.
    pub blocks: HashMap<NodeIndex, BlockRelationships>,
    /// Layout-safe clusters.
    pub clusters: Vec<BlockCluster>,
    /// Physical adjacency requirements expressed as `(before, after)`.
    pub adjacency: Vec<(NodeIndex, NodeIndex)>,
    /// Blocks whose control target could not be resolved symbolically.
    pub unresolved_control: Vec<NodeIndex>,
    /// Blocks containing code-introspection operations whose meaning may depend on byte offsets.
    pub position_sensitive: Vec<NodeIndex>,
    /// Stack-proven literal code pointers, including internal-call return addresses.
    pub code_pointer_relocations: Vec<CodePointerRelocation>,
    /// Blocks whose jump destination may depend on a constructor-materialized runtime word.
    ///
    /// Solidity represents an unlinked immutable as `PUSH32 0x00..00` in the creation
    /// artifact's runtime template and overwrites those 32 bytes during construction. Treating
    /// that zero as a literal program counter would make the CFG valid only for the template,
    /// not for the code that is actually deployed.
    pub constructor_materialized_control: Vec<NodeIndex>,
    /// First executable body block.
    pub entry_block: Option<NodeIndex>,
    /// Empty-stack external entry of each executable section region.
    pub region_entry_blocks: Vec<NodeIndex>,
    /// Last block when reaching the end of its instructions is a semantic halt.
    pub exit_fallthrough_block: Option<NodeIndex>,
}

impl RelationshipIndex {
    /// Derives a deterministic relationship snapshot from `bundle`.
    pub fn build(bundle: &CfgIrBundle) -> Result<Self, String> {
        validate_layout_members(bundle, bundle.layout_order())?;

        let layout = bundle.layout_order();
        let positions: HashMap<_, _> = layout
            .iter()
            .enumerate()
            .map(|(position, node)| (*node, position))
            .collect();
        let entry_block = find_entry_body(bundle).or_else(|| layout.first().copied());
        let region_entry_blocks = find_analysis_entries(bundle);
        let mut region_by_node = HashMap::new();
        let mut previous_section = None;
        let mut layout_region = 0usize;
        for node in layout.iter().copied() {
            let Some(Block::Body(body)) = bundle.cfg.node_weight(node) else {
                return Err(format!("layout contains non-body node {}", node.index()));
            };
            if previous_section.is_some_and(|section| section != body.section) {
                layout_region += 1;
            }
            previous_section = Some(body.section);
            region_by_node.insert(node, layout_region);
        }
        let exit_fallthrough_block = layout.last().copied().filter(|node| {
            matches!(
                bundle.cfg.node_weight(*node),
                Some(Block::Body(body))
                    if matches!(body.control, BlockControl::Fallthrough)
                        || body.instructions.last().is_some_and(|instruction| {
                            matches!(instruction.op, Opcode::JUMPI)
                        })
            )
        });

        let mut adjacency = Vec::new();
        let mut unresolved_control = Vec::new();
        let mut dynamically_resolvable_control = HashSet::new();
        let mut position_sensitive = Vec::new();
        let mut union = UnionFind::new(layout.len());

        let dynamic_control = analyze_dynamic_control(bundle, &positions);
        position_sensitive.extend(dynamic_control.observed_code_pointer_data.iter().copied());

        for (position, node) in layout.iter().copied().enumerate() {
            let Some(Block::Body(body)) = bundle.cfg.node_weight(node) else {
                return Err(format!("layout contains non-body node {}", node.index()));
            };

            // JUMPI always has a physical false path, even when its true destination is carried
            // through the stack and the cached BlockControl therefore remains Unknown. Preserve
            // that adjacency independently of target resolution and cached graph edges.
            if body
                .instructions
                .last()
                .is_some_and(|instruction| matches!(instruction.op, Opcode::JUMPI))
                && let Some(target) = layout.get(position + 1).copied()
            {
                adjacency.push((node, target));
                union.union(position, position + 1);
            }

            if body.instructions.iter().any(|instruction| {
                matches!(
                    instruction.op,
                    Opcode::PC
                        | Opcode::CODESIZE
                        | Opcode::CODECOPY
                        | Opcode::EXTCODESIZE
                        | Opcode::EXTCODECOPY
                        | Opcode::EXTCODEHASH
                )
            }) {
                position_sensitive.push(node);
            }

            match &body.control {
                BlockControl::Unknown => {
                    unresolved_control.push(node);
                    if body.instructions.last().is_some_and(|instruction| {
                        matches!(instruction.op, Opcode::JUMP | Opcode::JUMPI)
                    }) {
                        dynamically_resolvable_control.insert(node);
                    }
                }
                BlockControl::Fallthrough => {
                    if let Some(target) = layout.get(position + 1).copied() {
                        adjacency.push((node, target));
                        union.union(position, position + 1);
                    }
                }
                BlockControl::Jump { target } => {
                    register_target_constraint(
                        target,
                        node,
                        position,
                        &positions,
                        &mut union,
                        &mut unresolved_control,
                    );
                }
                BlockControl::Branch {
                    true_target,
                    false_target,
                } => {
                    register_target_constraint(
                        true_target,
                        node,
                        position,
                        &positions,
                        &mut union,
                        &mut unresolved_control,
                    );
                    register_target_constraint(
                        false_target,
                        node,
                        position,
                        &positions,
                        &mut union,
                        &mut unresolved_control,
                    );
                }
                _ => {}
            }

            for edge in bundle.cfg.edges_directed(node, Outgoing) {
                let target = edge.target();
                if !positions.contains_key(&target) {
                    continue;
                }
                if matches!(edge.weight(), EdgeType::Fallthrough | EdgeType::BranchFalse) {
                    adjacency.push((node, target));
                    let target_position = positions[&target];
                    union.union(position, target_position);
                }
            }
        }

        adjacency.sort_by_key(|(before, after)| (positions[before], positions[after]));
        adjacency.dedup();
        unresolved_control.sort_by_key(|node| positions.get(node).copied().unwrap_or(usize::MAX));
        unresolved_control.dedup();
        unresolved_control.retain(|node| {
            !dynamically_resolvable_control.contains(node)
                || !dynamic_control.resolved_sources.contains(node)
        });
        position_sensitive.sort_by_key(|node| positions.get(node).copied().unwrap_or(usize::MAX));
        position_sensitive.dedup();
        let mut constructor_materialized_control: Vec<_> = dynamic_control
            .constructor_materialized_control
            .into_iter()
            .collect();
        constructor_materialized_control
            .sort_by_key(|node| positions.get(node).copied().unwrap_or(usize::MAX));

        let mut members_by_root: HashMap<usize, Vec<NodeIndex>> = HashMap::new();
        for (position, node) in layout.iter().copied().enumerate() {
            members_by_root
                .entry(union.find(position))
                .or_default()
                .push(node);
        }
        let mut grouped: Vec<_> = members_by_root.into_values().collect();
        grouped.sort_by_key(|members| positions[&members[0]]);

        let mut cluster_by_node = HashMap::new();
        for (cluster_id, members) in grouped.iter().enumerate() {
            for node in members {
                cluster_by_node.insert(*node, cluster_id);
            }
        }

        let mut blocks = HashMap::new();
        for node in layout.iter().copied() {
            let Block::Body(body) = &bundle.cfg[node] else {
                unreachable!("layout membership was validated");
            };
            let mut predecessors = body_links(bundle, node, Incoming, &positions);
            let mut successors = body_links(bundle, node, Outgoing, &positions);
            for (source, target, kind) in &dynamic_control.links {
                if *target == node {
                    predecessors.push(BlockLink {
                        block: *source,
                        kind: *kind,
                    });
                }
                if *source == node {
                    successors.push(BlockLink {
                        block: *target,
                        kind: *kind,
                    });
                }
            }
            sort_links(&mut predecessors, &positions);
            sort_links(&mut successors, &positions);
            predecessors.dedup();
            successors.dedup();

            let mut roles = BTreeSet::new();
            if entry_block == Some(node) || region_entry_blocks.contains(&node) {
                roles.insert(BlockRole::Entry);
            }
            if bundle.dispatcher_blocks.contains(&node.index()) {
                roles.insert(BlockRole::Dispatcher);
            }
            if body
                .instructions
                .first()
                .is_some_and(|instruction| matches!(instruction.op, Opcode::JUMPDEST))
            {
                roles.insert(BlockRole::JumpDestination);
            }
            match body.control {
                BlockControl::Terminal => {
                    roles.insert(BlockRole::Terminal);
                }
                BlockControl::Jump { .. } | BlockControl::Branch { .. } => {
                    roles.insert(BlockRole::Control);
                }
                _ => {}
            }
            if roles.is_empty() {
                roles.insert(BlockRole::Ordinary);
            }

            blocks.insert(
                node,
                BlockRelationships {
                    layout_position: positions[&node],
                    section: body.section,
                    layout_region: region_by_node[&node],
                    predecessors,
                    successors,
                    cluster: cluster_by_node[&node],
                    roles,
                },
            );
        }

        let mut clusters = Vec::with_capacity(grouped.len());
        for (id, members) in grouped.into_iter().enumerate() {
            let member_set: HashSet<_> = members.iter().copied().collect();
            let member_regions: BTreeSet<_> = members
                .iter()
                .map(|member| region_by_node[member])
                .collect();
            let mut incoming = Vec::new();
            let mut outgoing = Vec::new();
            for member in &members {
                for link in &blocks[member].predecessors {
                    if !member_set.contains(&link.block) {
                        incoming.push(*link);
                    }
                }
                for link in &blocks[member].successors {
                    if !member_set.contains(&link.block) {
                        outgoing.push(*link);
                    }
                }
            }
            sort_links(&mut incoming, &positions);
            sort_links(&mut outgoing, &positions);
            incoming.dedup();
            outgoing.dedup();
            clusters.push(BlockCluster {
                id,
                anchors_entry: entry_block.is_some_and(|entry| member_set.contains(&entry))
                    || region_entry_blocks
                        .iter()
                        .any(|entry| member_set.contains(entry)),
                anchors_exit: exit_fallthrough_block.is_some_and(|exit| member_set.contains(&exit)),
                layout_region: (member_regions.len() == 1)
                    .then(|| *member_regions.first().expect("one member region")),
                members,
                incoming,
                outgoing,
            });
        }

        let index = Self {
            blocks,
            clusters,
            adjacency,
            unresolved_control,
            position_sensitive,
            code_pointer_relocations: dynamic_control.relocations,
            constructor_materialized_control,
            entry_block,
            region_entry_blocks,
            exit_fallthrough_block,
        };
        index.validate_layout(bundle.layout_order())?;
        Ok(index)
    }

    /// Returns true when all address-sensitive control flow was resolved and no code
    /// introspection operation prevents safe relocation.
    pub fn is_relocatable(&self) -> bool {
        self.unresolved_control.is_empty()
            && self.position_sensitive.is_empty()
            && self.constructor_materialized_control.is_empty()
    }

    /// Validates a proposed physical body-block order against this snapshot.
    pub fn validate_layout(&self, order: &[NodeIndex]) -> Result<(), String> {
        if order.len() != self.blocks.len() {
            return Err(format!(
                "layout has {} body blocks but relationship index has {}",
                order.len(),
                self.blocks.len()
            ));
        }
        let positions: HashMap<_, _> = order
            .iter()
            .enumerate()
            .map(|(position, node)| (*node, position))
            .collect();
        if positions.len() != order.len()
            || self.blocks.keys().any(|node| !positions.contains_key(node))
        {
            return Err("layout must contain every body block exactly once".to_string());
        }
        if let Some(entry) = self.entry_block
            && order.first().copied() != Some(entry)
        {
            return Err(format!(
                "entry block {} must remain first in physical layout",
                entry.index()
            ));
        }
        for entry in &self.region_entry_blocks {
            let entry_position = self.blocks[entry].layout_position;
            if order.get(entry_position).copied() != Some(*entry) {
                return Err(format!(
                    "section-region entry block {} must remain at layout position {}",
                    entry.index(),
                    entry_position
                ));
            }
        }
        if let Some(exit) = self.exit_fallthrough_block
            && order.last().copied() != Some(exit)
        {
            return Err(format!(
                "fallthrough-to-end block {} must remain last in physical layout",
                exit.index()
            ));
        }
        let mut expected_regions = vec![usize::MAX; self.blocks.len()];
        for relationships in self.blocks.values() {
            expected_regions[relationships.layout_position] = relationships.layout_region;
        }
        for (position, node) in order.iter().enumerate() {
            if self.blocks[node].layout_region != expected_regions[position] {
                return Err(format!(
                    "layout moves block {} across a section-region boundary",
                    node.index()
                ));
            }
        }
        for (before, after) in &self.adjacency {
            let before_position = positions[before];
            let after_position = positions[after];
            if after_position != before_position + 1 {
                return Err(format!(
                    "layout separates required adjacency {} -> {}",
                    before.index(),
                    after.index()
                ));
            }
        }
        for cluster in &self.clusters {
            let actual: Vec<_> = order
                .iter()
                .copied()
                .filter(|node| cluster.members.contains(node))
                .collect();
            if actual != cluster.members {
                return Err(format!("layout reorders members of cluster {}", cluster.id));
            }
            if let (Some(first), Some(last)) = (cluster.members.first(), cluster.members.last()) {
                let expected_len = positions[last] - positions[first] + 1;
                if expected_len != cluster.members.len() {
                    return Err(format!("layout splits cluster {}", cluster.id));
                }
            }
        }
        Ok(())
    }
}

fn validate_layout_members(bundle: &CfgIrBundle, order: &[NodeIndex]) -> Result<(), String> {
    let body_nodes: HashSet<_> = bundle
        .cfg
        .node_indices()
        .filter(|node| matches!(bundle.cfg[*node], Block::Body(_)))
        .collect();
    let layout_nodes: HashSet<_> = order.iter().copied().collect();
    if body_nodes != layout_nodes || layout_nodes.len() != order.len() {
        return Err("layout must contain every body block exactly once".to_string());
    }

    // Stable node identity is only meaningful when every decoded instruction owns one unique,
    // non-overlapping byte span. Check this independently of physical layout order: a shuffled
    // bundle intentionally retains its pre-lowering PCs until the atomic reindex step.
    let mut spans = Vec::new();
    for node in &body_nodes {
        let Block::Body(body) = &bundle.cfg[*node] else {
            unreachable!("body_nodes contains only body blocks");
        };
        let mut expected_pc = body.start_pc;
        for instruction in &body.instructions {
            if instruction.pc != expected_pc {
                return Err(format!(
                    "block {} has a gap or overlap before instruction 0x{:x}",
                    node.index(),
                    instruction.pc
                ));
            }
            let end = instruction
                .pc
                .checked_add(instruction.byte_size())
                .ok_or_else(|| format!("instruction span overflows at 0x{:x}", instruction.pc))?;
            spans.push((instruction.pc, end, *node));
            expected_pc = end;
        }
    }
    spans.sort_by_key(|(start, end, node)| (*start, *end, node.index()));
    for pair in spans.windows(2) {
        let (_, previous_end, previous_node) = pair[0];
        let (next_start, _, next_node) = pair[1];
        if next_start < previous_end {
            return Err(format!(
                "instruction spans overlap between blocks {} and {} at 0x{next_start:x}",
                previous_node.index(),
                next_node.index()
            ));
        }
    }
    Ok(())
}

fn find_entry_body(bundle: &CfgIrBundle) -> Option<NodeIndex> {
    let entry = bundle
        .cfg
        .node_indices()
        .find(|node| matches!(bundle.cfg[*node], Block::Entry))?;
    bundle
        .cfg
        .edges_directed(entry, Outgoing)
        .map(|edge| edge.target())
        .find(|target| matches!(bundle.cfg[*target], Block::Body(_)))
}

fn body_links(
    bundle: &CfgIrBundle,
    node: NodeIndex,
    direction: petgraph::Direction,
    positions: &HashMap<NodeIndex, usize>,
) -> Vec<BlockLink> {
    bundle
        .cfg
        .edges_directed(node, direction)
        .filter_map(|edge| {
            let other = if direction == Outgoing {
                edge.target()
            } else {
                edge.source()
            };
            positions.contains_key(&other).then_some(BlockLink {
                block: other,
                kind: *edge.weight(),
            })
        })
        .collect()
}

fn sort_links(links: &mut [BlockLink], positions: &HashMap<NodeIndex, usize>) {
    links.sort_by_key(|link| {
        (
            positions.get(&link.block).copied().unwrap_or(usize::MAX),
            edge_rank(&link.kind),
        )
    });
}

fn edge_rank(kind: &EdgeType) -> u8 {
    match kind {
        EdgeType::Fallthrough => 0,
        EdgeType::BranchFalse => 1,
        EdgeType::BranchTrue => 2,
        EdgeType::Jump => 3,
    }
}

fn register_target_constraint(
    target: &JumpTarget,
    source: NodeIndex,
    source_position: usize,
    positions: &HashMap<NodeIndex, usize>,
    union: &mut UnionFind,
    unresolved: &mut Vec<NodeIndex>,
) {
    match target {
        JumpTarget::Raw { .. } => unresolved.push(source),
        JumpTarget::Block {
            node,
            encoding: JumpEncoding::PcRelative,
        } => {
            let Some(&target_position) = positions.get(node) else {
                unresolved.push(source);
                return;
            };
            // Preserving a PC-relative delta requires preserving every byte between source and
            // target, so the whole physical interval becomes one cluster.
            let (start, end) = if source_position <= target_position {
                (source_position, target_position)
            } else {
                (target_position, source_position)
            };
            for position in start..end {
                union.union(position, position + 1);
            }
        }
        JumpTarget::Block { node, .. } if !positions.contains_key(node) => unresolved.push(source),
        JumpTarget::Block { .. } => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractValue {
    Unknown,
    ConstructorMaterialized {
        origins: BTreeSet<(NodeIndex, usize)>,
    },
    CodePointer {
        origins: BTreeSet<(NodeIndex, usize)>,
        targets: BTreeSet<NodeIndex>,
    },
}

#[derive(Debug, Clone)]
struct JumpResolution {
    kind: EdgeType,
    value: AbstractValue,
}

#[derive(Debug, Clone)]
struct BlockTransfer {
    output: Vec<AbstractValue>,
    jumps: Vec<JumpResolution>,
    observed_code_pointer_origins: BTreeSet<(NodeIndex, usize)>,
}

#[derive(Debug, Clone, Default)]
struct DynamicControlAnalysis {
    resolved_sources: HashSet<NodeIndex>,
    links: Vec<(NodeIndex, NodeIndex, EdgeType)>,
    relocations: Vec<CodePointerRelocation>,
    observed_code_pointer_data: HashSet<NodeIndex>,
    constructor_materialized_control: HashSet<NodeIndex>,
}

/// Tracks literal code pointers through the cross-block EVM stack.
///
/// Solidity's legacy internal-call convention carries a return `JUMPDEST` on the stack. Those
/// jumps look dynamic if each block is inspected in isolation, but the value still originates in
/// a concrete PUSH. This analysis follows PUSH/DUP/SWAP and exact CFG joins. Any unsupported
/// instruction, stack underflow, mismatched join height, or non-literal destination leaves the
/// jump unresolved, which in turn prevents layout transformation.
fn analyze_dynamic_control(
    bundle: &CfgIrBundle,
    positions: &HashMap<NodeIndex, usize>,
) -> DynamicControlAnalysis {
    const MAX_ABSTRACT_CONTEXTS: usize = 8_192;

    let entries = find_analysis_entries(bundle);
    if entries.is_empty() {
        return DynamicControlAnalysis::default();
    }

    // A legacy EVM block may intentionally be shared by callers with different return addresses
    // or unrelated values below its arguments. Keep those abstract contexts separate: joining a
    // code pointer with arbitrary data would erase exactly the relationship we need to prove.
    let mut states: HashMap<NodeIndex, BTreeSet<Vec<AbstractValue>>> = HashMap::new();
    let mut worklist = VecDeque::new();
    for entry in entries {
        states.entry(entry).or_default().insert(Vec::new());
        worklist.push_back((entry, Vec::new()));
    }
    let mut state_count = worklist.len();
    let mut analysis_sound = true;
    let mut observed_origins_by_node: HashMap<NodeIndex, BTreeSet<(NodeIndex, usize)>> =
        HashMap::new();
    let mut constructor_materialized_control = HashSet::new();

    while let Some((node, input)) = worklist.pop_front() {
        let Some(transfer) = transfer_block(bundle, node, input) else {
            tracing::debug!(
                node = node.index(),
                "code-pointer analysis could not model a reachable block"
            );
            analysis_sound = false;
            continue;
        };
        if !transfer.observed_code_pointer_origins.is_empty() {
            observed_origins_by_node
                .entry(node)
                .or_default()
                .extend(transfer.observed_code_pointer_origins.iter().copied());
        }
        if transfer
            .jumps
            .iter()
            .any(|jump| matches!(&jump.value, AbstractValue::ConstructorMaterialized { .. }))
        {
            constructor_materialized_control.insert(node);
        }

        let mut successors: Vec<NodeIndex> = bundle
            .cfg
            .edges_directed(node, Outgoing)
            .map(|edge| edge.target())
            .filter(|target| positions.contains_key(target))
            .collect();
        // A stack-carried destination leaves BlockControl as Unknown, so the CFG has no cached
        // BranchFalse edge. JUMPI nevertheless always propagates its post-pop stack to the next
        // physical block when the condition is false. Analyze that context before deciding whether
        // a relocated code pointer is also observed as ordinary data on the false path.
        if matches!(
            bundle.cfg.node_weight(node),
            Some(Block::Body(body))
                if body.instructions.last().is_some_and(|instruction| {
                    matches!(instruction.op, Opcode::JUMPI)
                })
        ) && let Some(false_successor) = positions
            .get(&node)
            .and_then(|position| bundle.layout_order().get(position + 1))
            .copied()
        {
            successors.push(false_successor);
        }
        for jump in &transfer.jumps {
            if let AbstractValue::CodePointer { targets, .. } = &jump.value {
                successors.extend(targets.iter().copied());
            }
        }
        successors.sort_by_key(|target| positions.get(target).copied().unwrap_or(usize::MAX));
        successors.dedup();

        for successor in successors {
            let contexts = states.entry(successor).or_default();
            if contexts.insert(transfer.output.clone()) {
                worklist.push_back((successor, transfer.output.clone()));
                state_count += 1;
            }
            if state_count > MAX_ABSTRACT_CONTEXTS {
                tracing::debug!("code-pointer analysis exceeded its context limit");
                analysis_sound = false;
                worklist.clear();
                break;
            }
        }
    }

    if !analysis_sound {
        return DynamicControlAnalysis {
            constructor_materialized_control,
            ..DynamicControlAnalysis::default()
        };
    }

    // Re-evaluate every reachable abstract context. A source is considered resolved only when
    // every context reaching its jump carries a finite set of literal code pointers.
    let mut resolved_sources = HashSet::new();
    let mut sources_with_jumps = HashSet::new();
    let mut unresolved_sources = HashSet::new();
    let mut links = Vec::new();
    let mut used_origins = BTreeSet::new();
    let mut origins_to_targets = HashMap::new();

    let mut final_nodes: Vec<_> = states.into_iter().collect();
    final_nodes.sort_by_key(|(node, _)| positions.get(node).copied().unwrap_or(usize::MAX));
    for (node, contexts) in final_nodes {
        for input in contexts {
            let Some(transfer) = transfer_block(bundle, node, input) else {
                continue;
            };
            if !transfer.jumps.is_empty() {
                sources_with_jumps.insert(node);
            }
            for jump in transfer.jumps {
                if matches!(&jump.value, AbstractValue::ConstructorMaterialized { .. }) {
                    constructor_materialized_control.insert(node);
                    unresolved_sources.insert(node);
                    continue;
                }
                let AbstractValue::CodePointer { origins, targets } = jump.value else {
                    let (start_pc, tail) = match &bundle.cfg[node] {
                        Block::Body(body) => (
                            body.start_pc,
                            body.instructions
                                .iter()
                                .rev()
                                .take(8)
                                .map(|instruction| instruction.op.name())
                                .collect::<Vec<_>>(),
                        ),
                        _ => (0, Vec::new()),
                    };
                    tracing::debug!(
                        node = node.index(),
                        start_pc = format_args!("0x{start_pc:x}"),
                        value = ?jump.value,
                        tail = ?tail,
                        "code-pointer analysis could not resolve a reachable jump destination"
                    );
                    unresolved_sources.insert(node);
                    continue;
                };
                if origins.is_empty() || targets.is_empty() {
                    unresolved_sources.insert(node);
                    continue;
                }
                used_origins.extend(origins.iter().copied());
                for origin in origins {
                    if let Some(target) = code_pointer_target(bundle, origin.0, origin.1) {
                        origins_to_targets.insert(origin, target);
                    } else {
                        unresolved_sources.insert(node);
                    }
                }
                for target in targets {
                    links.push((node, target, jump.kind));
                }
            }
        }
    }
    resolved_sources.extend(sources_with_jumps.difference(&unresolved_sources).copied());

    links.sort_by_key(|(source, target, kind)| {
        (
            positions.get(source).copied().unwrap_or(usize::MAX),
            positions.get(target).copied().unwrap_or(usize::MAX),
            edge_rank(kind),
        )
    });
    links.dedup();

    let observed_code_pointer_data = observed_origins_by_node
        .into_iter()
        .filter_map(|(node, origins)| {
            origins
                .iter()
                .any(|origin| used_origins.contains(origin))
                .then_some(node)
        })
        .collect();

    let mut relocations: Vec<_> = used_origins
        .into_iter()
        .filter_map(|(source, instruction_index)| {
            origins_to_targets
                .get(&(source, instruction_index))
                .copied()
                .map(|target| CodePointerRelocation {
                    source,
                    instruction_index,
                    target,
                    encoding: match &bundle.cfg[source] {
                        Block::Body(body) if body.section == SectionKind::Runtime => {
                            JumpEncoding::RuntimeRelative
                        }
                        _ => JumpEncoding::Absolute,
                    },
                })
        })
        .collect();
    relocations.sort();
    relocations.dedup();

    DynamicControlAnalysis {
        resolved_sources,
        links,
        relocations,
        observed_code_pointer_data,
        constructor_materialized_control,
    }
}

fn transfer_block(
    bundle: &CfgIrBundle,
    node: NodeIndex,
    mut stack: Vec<AbstractValue>,
) -> Option<BlockTransfer> {
    const EVM_STACK_LIMIT: usize = 1_024;

    let Block::Body(body) = &bundle.cfg[node] else {
        return None;
    };
    if stack.len() > EVM_STACK_LIMIT {
        return None;
    }
    let mut jumps = Vec::new();
    let mut observed_code_pointer_origins = BTreeSet::new();

    for (instruction_index, instruction) in body.instructions.iter().enumerate() {
        match instruction.op {
            Opcode::PUSH(width) => {
                let value = instruction
                    .imm
                    .as_deref()
                    .and_then(|immediate| usize::from_str_radix(immediate, 16).ok());
                let value = if is_constructor_materialized_placeholder(bundle, body, instruction) {
                    AbstractValue::ConstructorMaterialized {
                        origins: BTreeSet::from([(node, instruction_index)]),
                    }
                } else {
                    value.map_or(AbstractValue::Unknown, |value| {
                        code_pointer_target_for_value(bundle, body.section, value).map_or(
                            AbstractValue::Unknown,
                            |target| AbstractValue::CodePointer {
                                origins: BTreeSet::from([(node, instruction_index)]),
                                targets: BTreeSet::from([target]),
                            },
                        )
                    })
                };
                let _ = width;
                if stack.len() == EVM_STACK_LIMIT {
                    return None;
                }
                stack.push(value);
                continue;
            }
            Opcode::PUSH0 => {
                if stack.len() == EVM_STACK_LIMIT {
                    return None;
                }
                stack.push(AbstractValue::Unknown);
                continue;
            }
            Opcode::DUP(depth) => {
                let depth = depth as usize;
                if depth == 0 || stack.len() < depth {
                    return None;
                }
                if stack.len() == EVM_STACK_LIMIT {
                    return None;
                }
                stack.push(stack[stack.len() - depth].clone());
                continue;
            }
            Opcode::SWAP(depth) => {
                let depth = depth as usize;
                if depth == 0 || stack.len() <= depth {
                    return None;
                }
                let top = stack.len() - 1;
                stack.swap(top, top - depth);
                continue;
            }
            Opcode::JUMP | Opcode::JUMPI => {
                let destination = stack.last().cloned().unwrap_or(AbstractValue::Unknown);
                jumps.push(JumpResolution {
                    kind: if matches!(instruction.op, Opcode::JUMPI) {
                        EdgeType::BranchTrue
                    } else {
                        EdgeType::Jump
                    },
                    value: destination,
                });
            }
            _ => {}
        }

        let info = instruction.op.info()?;
        if stack.len() < info.inputs as usize {
            return None;
        }
        let inputs = info.inputs as usize;
        let consumed = &stack[stack.len() - inputs..];
        let data_inputs = match instruction.op {
            // The stack top is the jump destination. JUMPI's remaining input is its condition and
            // therefore an ordinary data use if it carries a relocatable code pointer.
            Opcode::JUMP | Opcode::JUMPI => &consumed[..consumed.len().saturating_sub(1)],
            // Throwing away a duplicate address is not externally observable.
            Opcode::POP => &consumed[0..0],
            _ => consumed,
        };
        for value in data_inputs {
            if let AbstractValue::CodePointer { origins, .. } = value {
                observed_code_pointer_origins.extend(origins.iter().copied());
            }
        }
        let constructor_materialized_origins: BTreeSet<_> = consumed
            .iter()
            .filter_map(|value| match value {
                AbstractValue::ConstructorMaterialized { origins } => Some(origins),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        stack.truncate(stack.len() - inputs);
        if stack.len() + info.outputs as usize > EVM_STACK_LIMIT {
            return None;
        }
        let output = if constructor_materialized_origins.is_empty() {
            AbstractValue::Unknown
        } else {
            AbstractValue::ConstructorMaterialized {
                origins: constructor_materialized_origins,
            }
        };
        stack.extend((0..info.outputs).map(|_| output.clone()));
    }

    Some(BlockTransfer {
        output: stack,
        jumps,
        observed_code_pointer_origins,
    })
}

/// True for an unlinked Solidity immutable word in an init-bearing artifact.
///
/// A standalone deployed-runtime artifact may intentionally contain `PUSH32 0`; without init
/// code there is no constructor capable of replacing the immediate, so it remains an ordinary
/// literal. With init code, however, the exact all-zero PUSH32 shape is the compiler's immutable
/// placeholder contract and must retain constructor provenance through control-flow analysis.
fn is_constructor_materialized_placeholder(
    bundle: &CfgIrBundle,
    body: &super::BlockBody,
    instruction: &crate::decoder::Instruction,
) -> bool {
    body.section == SectionKind::Runtime
        && bundle
            .clean_report
            .removed
            .iter()
            .any(|removed| removed.kind == SectionKind::Init)
        && matches!(instruction.op, Opcode::PUSH(32))
        && instruction.imm.as_deref().is_some_and(|immediate| {
            immediate.len() == 64 && immediate.bytes().all(|byte| byte == b'0')
        })
}

/// Returns the external empty-stack entry of each executable section region.
///
/// Init and deployed runtime are separate EVM executions. Seeding only the graph's global Entry
/// successor leaves runtime unanalyzed when a caller builds a combined init/runtime CFG. We seed
/// the first block of each contiguous executable region, but never arbitrary blocks in the middle
/// of a region (which could incorrectly invent empty-stack paths into internal functions).
fn find_analysis_entries(bundle: &CfgIrBundle) -> Vec<NodeIndex> {
    let mut entries = Vec::new();
    let mut previous_section = None;
    for node in bundle.layout_order().iter().copied() {
        let Block::Body(body) = &bundle.cfg[node] else {
            continue;
        };
        let starts_region = previous_section != Some(body.section);
        if starts_region && matches!(body.section, SectionKind::Init | SectionKind::Runtime) {
            entries.push(node);
        }
        previous_section = Some(body.section);
    }
    entries
}

fn code_pointer_target(
    bundle: &CfgIrBundle,
    source: NodeIndex,
    instruction_index: usize,
) -> Option<NodeIndex> {
    let Block::Body(body) = &bundle.cfg[source] else {
        return None;
    };
    let instruction = body.instructions.get(instruction_index)?;
    let value = instruction
        .imm
        .as_deref()
        .and_then(|immediate| usize::from_str_radix(immediate, 16).ok())?;
    code_pointer_target_for_value(bundle, body.section, value)
}

fn code_pointer_target_for_value(
    bundle: &CfgIrBundle,
    source_section: SectionKind,
    value: usize,
) -> Option<NodeIndex> {
    let absolute = if source_section == SectionKind::Runtime {
        bundle
            .runtime_bounds
            .map(|(runtime_start, _)| runtime_start.saturating_add(value))
            .unwrap_or(value)
    } else {
        value
    };
    let node = *bundle.pc_to_block.get(&absolute)?;
    let Block::Body(target) = &bundle.cfg[node] else {
        return None;
    };
    target
        .instructions
        .first()
        .is_some_and(|instruction| matches!(instruction.op, Opcode::JUMPDEST))
        .then_some(node)
}

#[derive(Debug, Clone)]
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn find(&mut self, value: usize) -> usize {
        if self.parent[value] != value {
            self.parent[value] = self.find(self.parent[value]);
        }
        self.parent[value]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        match self.rank[left_root].cmp(&self.rank[right_root]) {
            std::cmp::Ordering::Less => self.parent[left_root] = right_root,
            std::cmp::Ordering::Greater => self.parent[right_root] = left_root,
            std::cmp::Ordering::Equal => {
                self.parent[right_root] = left_root;
                self.rank[left_root] += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_ir::build_cfg_ir;
    use crate::decoder::Instruction;
    use crate::detection::Section;
    use crate::strip::{CleanReport, RuntimeSpan};
    use revm::primitives::B256;

    fn instruction(pc: usize, op: Opcode, immediate: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: immediate.map(str::to_string),
        }
    }

    fn clean_report(len: usize) -> CleanReport {
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

    fn build(instructions: &[Instruction], sections: &[Section], code_len: usize) -> CfgIrBundle {
        build_cfg_ir(
            instructions,
            sections,
            clean_report(code_len),
            &vec![0; code_len],
        )
        .expect("test CFG builds")
    }

    #[test]
    fn fallthrough_to_end_is_an_explicit_exit_anchor() {
        let instructions = vec![
            instruction(0, Opcode::JUMPDEST, None),
            instruction(1, Opcode::PUSH(1), Some("04")),
            instruction(3, Opcode::JUMP, None),
            instruction(4, Opcode::JUMPDEST, None),
            instruction(5, Opcode::STOP, None),
            instruction(6, Opcode::JUMPDEST, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 7,
        }];
        let bundle = build(&instructions, &sections, 7);
        let order = bundle.layout_order();
        assert_eq!(
            bundle.relationships.exit_fallthrough_block,
            order.last().copied()
        );

        let invalid = vec![order[0], order[2], order[1]];
        let error = bundle
            .relationships
            .validate_layout(&invalid)
            .expect_err("moving the end-of-code fallthrough must fail closed");
        assert!(error.contains("must remain last"));
    }

    #[test]
    fn fallthrough_constraint_does_not_depend_on_cached_edges() {
        let instructions = vec![
            instruction(0, Opcode::PUSH0, None),
            instruction(1, Opcode::POP, None),
            instruction(2, Opcode::JUMPDEST, None),
            instruction(3, Opcode::STOP, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 4,
        }];
        let mut bundle = build(&instructions, &sections, 4);
        let source = bundle.layout_order()[0];
        let target = bundle.layout_order()[1];
        let edges: Vec<_> = bundle
            .cfg
            .edges_directed(source, Outgoing)
            .map(|edge| edge.id())
            .collect();
        for edge in edges {
            bundle.cfg.remove_edge(edge);
        }

        bundle
            .refresh_relationships()
            .expect("relationships rebuild");
        assert!(bundle.relationships.adjacency.contains(&(source, target)));
    }

    #[test]
    fn runtime_region_is_seeded_and_return_addresses_are_relocated() {
        // Init and runtime are separate executions. Runtime performs a legacy internal call:
        // PUSH return; PUSH callee; JUMP, with the callee dynamically jumping to the return block.
        let instructions = vec![
            instruction(0, Opcode::STOP, None),
            instruction(1, Opcode::PUSH(1), Some("05")),
            instruction(3, Opcode::PUSH(1), Some("08")),
            instruction(5, Opcode::JUMP, None),
            instruction(6, Opcode::JUMPDEST, None),
            instruction(7, Opcode::STOP, None),
            instruction(8, Opcode::STOP, None),
            instruction(9, Opcode::JUMPDEST, None),
            instruction(10, Opcode::JUMP, None),
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
                len: 10,
            },
        ];
        let mut bundle = build(&instructions, &sections, 11);
        let original = bundle.layout_order().to_vec();
        assert_eq!(original.len(), 5, "the section boundary must split blocks");
        assert_eq!(
            bundle.relationships.region_entry_blocks,
            vec![original[0], original[1]]
        );
        assert!(bundle.relationships.unresolved_control.is_empty());
        assert_eq!(bundle.relationships.code_pointer_relocations.len(), 2);

        // Both executable-region entries remain fixed. Move the return, filler, and callee
        // clusters so both literal code pointers require new immediates.
        let reordered = vec![
            original[0],
            original[1],
            original[3],
            original[4],
            original[2],
        ];
        bundle
            .set_layout_order(reordered)
            .expect("intra-runtime cluster order is valid");
        bundle.reindex_pcs().expect("typed relocation succeeds");

        let Block::Body(call_site) = &bundle.cfg[original[1]] else {
            panic!("runtime entry is a body block");
        };
        assert_eq!(call_site.instructions[0].imm.as_deref(), Some("08"));
        assert_eq!(call_site.instructions[1].imm.as_deref(), Some("06"));
    }

    #[test]
    fn executable_region_entry_cannot_move_within_its_section() {
        let instructions = vec![
            instruction(0, Opcode::STOP, None),
            instruction(1, Opcode::JUMPDEST, None),
            instruction(2, Opcode::STOP, None),
            instruction(3, Opcode::JUMPDEST, None),
            instruction(4, Opcode::STOP, None),
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
                len: 4,
            },
        ];
        let bundle = build(&instructions, &sections, 5);
        let order = bundle.layout_order();
        let invalid = vec![order[0], order[2], order[1]];
        let error = bundle
            .relationships
            .validate_layout(&invalid)
            .expect_err("runtime entry must remain first in its region");
        assert!(error.contains("section-region entry"));
    }

    #[test]
    fn resolved_true_jump_does_not_hide_unresolved_false_fallthrough() {
        let instructions = vec![
            instruction(0, Opcode::JUMPDEST, None),
            instruction(1, Opcode::PUSH(1), Some("01")),
            instruction(3, Opcode::PUSH(1), Some("00")),
            instruction(5, Opcode::JUMPI, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 6,
        }];
        let bundle = build(&instructions, &sections, 6);
        let source = bundle.layout_order()[0];

        assert_eq!(
            bundle.relationships.unresolved_control,
            vec![source],
            "resolving JUMPI's true destination must not clear its raw false path"
        );
        assert!(!bundle.relationships.is_relocatable());
    }

    #[test]
    fn resolved_stack_carried_jumpi_preserves_physical_false_successor() {
        // The SWAP keeps the destination stack-carried, so the local jump-pattern recognizer
        // leaves BlockControl as Unknown. The abstract analysis can still resolve the true target,
        // but JUMPI's false path must remain adjacent to the source block.
        let instructions = vec![
            instruction(0, Opcode::PUSH(1), Some("09")),
            instruction(2, Opcode::PUSH(1), Some("00")),
            instruction(4, Opcode::SWAP(1), None),
            instruction(5, Opcode::JUMPI, None),
            instruction(6, Opcode::PUSH0, None),
            instruction(7, Opcode::PUSH0, None),
            instruction(8, Opcode::RETURN, None),
            instruction(9, Opcode::JUMPDEST, None),
            instruction(10, Opcode::PUSH0, None),
            instruction(11, Opcode::PUSH0, None),
            instruction(12, Opcode::REVERT, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 13,
        }];
        let bundle = build(&instructions, &sections, 13);
        let order = bundle.layout_order();
        let source = order[0];
        let false_successor = order[1];

        assert!(
            matches!(bundle.cfg[source], Block::Body(ref body) if body.control == BlockControl::Unknown)
        );
        assert!(bundle.relationships.unresolved_control.is_empty());
        assert!(
            bundle
                .relationships
                .adjacency
                .contains(&(source, false_successor))
        );
        assert_eq!(
            bundle.relationships.blocks[&source].cluster,
            bundle.relationships.blocks[&false_successor].cluster
        );

        let invalid = vec![source, order[2], false_successor];
        let error = bundle
            .relationships
            .validate_layout(&invalid)
            .expect_err("dynamic JUMPI must remain next to its false successor");
        assert!(error.contains("required adjacency"));
    }

    #[test]
    fn stack_carried_jumpi_pointer_observed_on_false_path_is_position_sensitive() {
        // One copy is the resolved true destination; the other survives JUMPI and is returned as
        // data on the false path. Relocating the literal would therefore change observable output.
        let instructions = vec![
            instruction(0, Opcode::PUSH(1), Some("0c")),
            instruction(2, Opcode::DUP(1), None),
            instruction(3, Opcode::PUSH0, None),
            instruction(4, Opcode::SWAP(1), None),
            instruction(5, Opcode::JUMPI, None),
            instruction(6, Opcode::PUSH0, None),
            instruction(7, Opcode::MSTORE, None),
            instruction(8, Opcode::PUSH(1), Some("20")),
            instruction(10, Opcode::PUSH0, None),
            instruction(11, Opcode::RETURN, None),
            instruction(12, Opcode::JUMPDEST, None),
            instruction(13, Opcode::STOP, None),
            instruction(14, Opcode::JUMPDEST, None),
            instruction(15, Opcode::STOP, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 16,
        }];
        let bundle = build(&instructions, &sections, 16);
        let false_successor = bundle.layout_order()[1];

        assert!(bundle.relationships.unresolved_control.is_empty());
        assert_eq!(bundle.relationships.code_pointer_relocations.len(), 1);
        assert!(
            bundle
                .relationships
                .position_sensitive
                .contains(&false_successor)
        );
        assert!(!bundle.relationships.is_relocatable());
    }

    #[test]
    fn relocation_overflow_leaves_bundle_unmodified() {
        let mut instructions = vec![
            instruction(0, Opcode::PUSH(1), Some("05")),
            instruction(2, Opcode::PUSH(1), Some("07")),
            instruction(4, Opcode::JUMP, None),
            instruction(5, Opcode::JUMPDEST, None),
            instruction(6, Opcode::STOP, None),
            instruction(7, Opcode::JUMPDEST, None),
            instruction(8, Opcode::JUMP, None),
        ];
        // Moving this 251-byte terminal block before the two PUSH1 targets shifts the return
        // address from 0x05 to 0x100, which cannot be represented without changing code shape.
        for pc in 9..259 {
            instructions.push(instruction(pc, Opcode::PUSH0, None));
        }
        instructions.push(instruction(259, Opcode::STOP, None));
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 260,
        }];
        let mut bundle = build(&instructions, &sections, 260);
        let original = bundle.layout_order().to_vec();
        let reordered = vec![original[0], original[3], original[1], original[2]];
        bundle
            .set_layout_order(reordered)
            .expect("layout itself is relationship-safe");

        let before_layout = bundle.layout_order().to_vec();
        let before_bounds = bundle.runtime_bounds;
        let before_trace_len = bundle.trace.len();
        let before_instructions: Vec<_> = before_layout
            .iter()
            .map(|node| {
                let Block::Body(body) = &bundle.cfg[*node] else {
                    unreachable!();
                };
                (
                    *node,
                    body.start_pc,
                    body.instructions
                        .iter()
                        .map(|instruction| (instruction.pc, instruction.imm.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let error = bundle
            .reindex_pcs()
            .expect_err("PUSH1 relocation must fail instead of widening silently");
        assert!(matches!(error, crate::result::Error::InvalidImmediate(_)));
        assert_eq!(bundle.layout_order(), before_layout);
        assert_eq!(bundle.runtime_bounds, before_bounds);
        assert_eq!(bundle.trace.len(), before_trace_len);
        let after_instructions: Vec<_> = before_layout
            .iter()
            .map(|node| {
                let Block::Body(body) = &bundle.cfg[*node] else {
                    unreachable!();
                };
                (
                    *node,
                    body.start_pc,
                    body.instructions
                        .iter()
                        .map(|instruction| (instruction.pc, instruction.imm.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(after_instructions, before_instructions);
    }

    #[test]
    fn code_pointer_reused_as_data_is_position_sensitive() {
        // The return address is duplicated. The callee consumes one copy as a JUMP destination;
        // the return block stores the other copy in memory and returns it to the caller. Moving the
        // return block would necessarily change that observable value, so relocation must refuse.
        let instructions = vec![
            instruction(0, Opcode::PUSH(1), Some("07")),
            instruction(2, Opcode::DUP(1), None),
            instruction(3, Opcode::PUSH(1), Some("0e")),
            instruction(5, Opcode::JUMP, None),
            instruction(6, Opcode::STOP, None),
            instruction(7, Opcode::JUMPDEST, None),
            instruction(8, Opcode::PUSH0, None),
            instruction(9, Opcode::MSTORE, None),
            instruction(10, Opcode::PUSH(1), Some("20")),
            instruction(12, Opcode::PUSH0, None),
            instruction(13, Opcode::RETURN, None),
            instruction(14, Opcode::JUMPDEST, None),
            instruction(15, Opcode::JUMP, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 16,
        }];
        let bundle = build(&instructions, &sections, 16);
        let return_block = bundle.layout_order()[2];

        assert!(bundle.relationships.unresolved_control.is_empty());
        assert!(
            bundle
                .relationships
                .position_sensitive
                .contains(&return_block)
        );
        assert!(!bundle.relationships.is_relocatable());
    }

    #[test]
    fn coincidental_jumpdest_literal_used_only_as_data_is_not_relocated() {
        let instructions = vec![
            instruction(0, Opcode::PUSH(1), Some("05")),
            instruction(2, Opcode::PUSH0, None),
            instruction(3, Opcode::MSTORE, None),
            instruction(4, Opcode::STOP, None),
            instruction(5, Opcode::JUMPDEST, None),
            instruction(6, Opcode::STOP, None),
        ];
        let sections = [Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: 7,
        }];
        let bundle = build(&instructions, &sections, 7);

        assert!(bundle.relationships.code_pointer_relocations.is_empty());
        assert!(bundle.relationships.position_sensitive.is_empty());
        assert!(bundle.relationships.is_relocatable());
    }
}
