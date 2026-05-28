//! Control-flow graph over a list of `AsmItem`s.
//!
//! Unlike the existing `cfg_ir` module (which builds blocks from decoded
//! instructions and tracks them by program counter), this CFG keys blocks by
//! their **tag id** — the symbolic label that solc emits in `legacyAssembly`.
//! Items are the source of truth; the CFG is a view over them.
//!
//! Round-trip property: `flatten(build_asm_cfg(items)) == items` for any
//! valid solc-emitted item list. Mutating the CFG's blocks and flattening
//! produces a new item list that solc can re-assemble.

use super::item::AsmItem;
use std::collections::HashMap;

/// A basic-block identifier — the `value` of a solc `tag` item.
pub type AsmBlockId = u64;

/// A basic block in the asm-item CFG.
///
/// Items are stored in source order, including the leading `tag` and
/// `JUMPDEST` items for non-entry blocks. The entry block (items before the
/// first `tag` in the list) has `id = None`.
#[derive(Debug, Clone)]
pub struct AsmBlock {
    /// Tag id, or `None` for the entry block (items before the first `tag`).
    pub id: Option<AsmBlockId>,
    /// Items in this block, in source order.
    pub items: Vec<AsmItem>,
}

impl AsmBlock {
    /// Returns the block's terminator item (the first control-transfer or
    /// halt opcode), if any. Blocks without a terminator implicitly
    /// fall through to the next block.
    pub fn terminator(&self) -> Option<&AsmItem> {
        self.items.iter().find(|i| i.is_terminator())
    }

    /// Returns the index within `items` of the terminator, if any.
    pub fn terminator_index(&self) -> Option<usize> {
        self.items.iter().position(|i| i.is_terminator())
    }

    /// Returns true if this block ends in an unconditional halt (no outgoing
    /// edges, not even fall-through).
    pub fn is_halt(&self) -> bool {
        matches!(
            self.terminator().map(|i| i.name.as_str()),
            Some("STOP" | "RETURN" | "REVERT" | "INVALID" | "SELFDESTRUCT" | "RETF" | "RETURNCONTRACT"),
        )
    }
}

/// Edge kind in the asm-item CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsmEdgeKind {
    /// Unconditional jump (`JUMP`).
    Jump,
    /// Conditional branch (`JUMPI`) — the taken edge.
    BranchTaken,
    /// Fall-through into the lexically next block (after `JUMPI` or after
    /// a block without a terminator).
    Fallthrough,
}

/// Where an edge points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsmEdgeTarget {
    /// Resolved to a block via `PUSH [tag]` immediately before the jump, or
    /// by fall-through to the lexically next block.
    Block(AsmBlockId),
    /// Unresolved: the jump's target was computed (no static `PUSH [tag]`),
    /// or fall-through reached the end of the item list with no next block.
    Unresolved,
}

/// A directed edge from one block to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsmEdge {
    /// Edge classification.
    pub kind: AsmEdgeKind,
    /// Target block (resolved or unresolved).
    pub target: AsmEdgeTarget,
}

/// CFG over a list of `AsmItem`s.
#[derive(Debug, Clone)]
pub struct AsmCfg {
    /// Blocks in source order. The entry block (if any) is `blocks[0]`.
    pub blocks: Vec<AsmBlock>,
    /// Index into `blocks` keyed by tag id. The entry block is not keyed.
    pub block_by_id: HashMap<AsmBlockId, usize>,
}

impl AsmCfg {
    /// Total number of basic blocks (including the entry block).
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Lookup a block by tag id.
    pub fn block(&self, id: AsmBlockId) -> Option<&AsmBlock> {
        self.block_by_id.get(&id).map(|&i| &self.blocks[i])
    }

    /// Mutable lookup by tag id.
    pub fn block_mut(&mut self, id: AsmBlockId) -> Option<&mut AsmBlock> {
        let idx = *self.block_by_id.get(&id)?;
        Some(&mut self.blocks[idx])
    }

    /// Outgoing edges from a block, computed from its items.
    ///
    /// `next_block_id` is the tag id of the lexically next block (used to
    /// resolve fall-through targets). Pass `None` if this block is last.
    pub fn outgoing_edges(
        &self,
        block_idx: usize,
    ) -> Vec<AsmEdge> {
        let block = &self.blocks[block_idx];
        let next_block_id: Option<AsmBlockId> = self
            .blocks
            .get(block_idx + 1)
            .and_then(|b| b.id);

        let Some(term_idx) = block.terminator_index() else {
            // No terminator → implicit fall-through.
            return match next_block_id {
                Some(id) => vec![AsmEdge {
                    kind: AsmEdgeKind::Fallthrough,
                    target: AsmEdgeTarget::Block(id),
                }],
                None => vec![],
            };
        };

        let term = &block.items[term_idx];
        let resolved_target = preceding_push_tag(&block.items, term_idx);

        match term.name.as_str() {
            "JUMP" => vec![AsmEdge {
                kind: AsmEdgeKind::Jump,
                target: resolved_target
                    .map(AsmEdgeTarget::Block)
                    .unwrap_or(AsmEdgeTarget::Unresolved),
            }],
            "JUMPI" => {
                let mut edges = vec![AsmEdge {
                    kind: AsmEdgeKind::BranchTaken,
                    target: resolved_target
                        .map(AsmEdgeTarget::Block)
                        .unwrap_or(AsmEdgeTarget::Unresolved),
                }];
                // Fall-through edge.
                if let Some(id) = next_block_id {
                    edges.push(AsmEdge {
                        kind: AsmEdgeKind::Fallthrough,
                        target: AsmEdgeTarget::Block(id),
                    });
                } else {
                    edges.push(AsmEdge {
                        kind: AsmEdgeKind::Fallthrough,
                        target: AsmEdgeTarget::Unresolved,
                    });
                }
                edges
            }
            // Halts have no outgoing edges.
            _ => vec![],
        }
    }

    /// Flatten the CFG back into a single item list, preserving source order.
    /// Round-trip property: `flatten(build_asm_cfg(items)) == items` for any
    /// valid item list.
    pub fn flatten(&self) -> Vec<AsmItem> {
        self.blocks
            .iter()
            .flat_map(|b| b.items.iter().cloned())
            .collect()
    }
}

/// Find the most recent `PUSH [tag]` immediately preceding the terminator at
/// `term_idx`, ignoring intervening source-map noise. Returns the resolved
/// tag id or `None` if the previous item isn't a `PUSH [tag]`.
fn preceding_push_tag(items: &[AsmItem], term_idx: usize) -> Option<AsmBlockId> {
    if term_idx == 0 {
        return None;
    }
    let prev = &items[term_idx - 1];
    if prev.is_push_tag() {
        prev.tag_id()
    } else {
        None
    }
}

/// Build a CFG over a list of asm items.
///
/// Splits the list into basic blocks: items before the first `tag` form the
/// (id-less) entry block; each subsequent block runs from a `tag` to just
/// before the next `tag`.
///
/// Edges are not stored on blocks — they're derived on demand from items via
/// [`AsmCfg::outgoing_edges`], because items are the source of truth and
/// transforms manipulate items directly.
pub fn build_asm_cfg(items: &[AsmItem]) -> AsmCfg {
    let mut blocks: Vec<AsmBlock> = Vec::new();
    let mut block_by_id: HashMap<AsmBlockId, usize> = HashMap::new();

    let mut current_id: Option<AsmBlockId> = None;
    let mut current_items: Vec<AsmItem> = Vec::new();

    for item in items {
        if item.is_tag() {
            // Flush the current block (if non-empty) before starting a new one.
            if !current_items.is_empty() || current_id.is_some() {
                let idx = blocks.len();
                if let Some(id) = current_id {
                    block_by_id.insert(id, idx);
                }
                blocks.push(AsmBlock {
                    id: current_id,
                    items: std::mem::take(&mut current_items),
                });
            }
            current_id = item.tag_id();
            current_items.push(item.clone());
        } else {
            current_items.push(item.clone());
        }
    }

    // Flush the final block.
    if !current_items.is_empty() || current_id.is_some() {
        let idx = blocks.len();
        if let Some(id) = current_id {
            block_by_id.insert(id, idx);
        }
        blocks.push(AsmBlock {
            id: current_id,
            items: current_items,
        });
    }

    AsmCfg {
        blocks,
        block_by_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm_ir::item::AsmItem;

    fn it(name: &str) -> AsmItem {
        AsmItem::op(name)
    }
    fn it_v(name: &str, value: &str) -> AsmItem {
        AsmItem::op_with_value(name, value)
    }

    #[test]
    fn empty_input_produces_empty_cfg() {
        let cfg = build_asm_cfg(&[]);
        assert_eq!(cfg.block_count(), 0);
        assert_eq!(cfg.flatten().len(), 0);
    }

    #[test]
    fn entry_block_only() {
        // No tags → entire item list is the entry block.
        let items = vec![it("PUSH"), it("MSTORE"), it("STOP")];
        let cfg = build_asm_cfg(&items);
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.blocks[0].id, None);
        assert_eq!(cfg.blocks[0].items.len(), 3);
        assert!(cfg.block_by_id.is_empty());
        // Halt → no outgoing edges.
        assert!(cfg.outgoing_edges(0).is_empty());
    }

    #[test]
    fn splits_on_tags() {
        let items = vec![
            it("PUSH"),                        // entry block: prologue
            it_v("tag", "1"),                   // start of block 1
            it("JUMPDEST"),
            it("ADD"),
            it("STOP"),
            it_v("tag", "2"),                   // start of block 2
            it("JUMPDEST"),
            it("RETURN"),
        ];
        let cfg = build_asm_cfg(&items);
        assert_eq!(cfg.block_count(), 3);
        assert_eq!(cfg.blocks[0].id, None);     // entry
        assert_eq!(cfg.blocks[0].items.len(), 1);
        assert_eq!(cfg.blocks[1].id, Some(1));
        assert_eq!(cfg.blocks[1].items.len(), 4);
        assert_eq!(cfg.blocks[2].id, Some(2));
        assert_eq!(cfg.blocks[2].items.len(), 3);
        assert_eq!(cfg.block_by_id.len(), 2);
        assert_eq!(cfg.block(1).unwrap().items.len(), 4);
        assert_eq!(cfg.block(2).unwrap().items.len(), 3);
    }

    #[test]
    fn jump_edge_resolves_via_preceding_push_tag() {
        // tag 1: PUSH [tag] 2 ; JUMP   →  edge to block 2
        let items = vec![
            it_v("tag", "1"),
            it("JUMPDEST"),
            it_v("PUSH [tag]", "2"),
            it("JUMP"),
            it_v("tag", "2"),
            it("JUMPDEST"),
            it("STOP"),
        ];
        let cfg = build_asm_cfg(&items);
        let edges = cfg.outgoing_edges(0);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, AsmEdgeKind::Jump);
        assert_eq!(edges[0].target, AsmEdgeTarget::Block(2));
    }

    #[test]
    fn jumpi_produces_taken_and_fallthrough_edges() {
        // tag 1: ... PUSH [tag] 3 ; JUMPI   then tag 2 (fall-through), then tag 3
        let items = vec![
            it_v("tag", "1"),
            it("JUMPDEST"),
            it_v("PUSH [tag]", "3"),
            it("JUMPI"),
            it_v("tag", "2"),
            it("JUMPDEST"),
            it("STOP"),
            it_v("tag", "3"),
            it("JUMPDEST"),
            it("RETURN"),
        ];
        let cfg = build_asm_cfg(&items);
        let edges = cfg.outgoing_edges(0);
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].kind, AsmEdgeKind::BranchTaken);
        assert_eq!(edges[0].target, AsmEdgeTarget::Block(3));
        assert_eq!(edges[1].kind, AsmEdgeKind::Fallthrough);
        assert_eq!(edges[1].target, AsmEdgeTarget::Block(2));
    }

    #[test]
    fn jump_without_preceding_push_tag_is_unresolved() {
        // Computed jump: target on the stack but not from a static PUSH [tag].
        let items = vec![
            it_v("tag", "1"),
            it("JUMPDEST"),
            it("CALLDATALOAD"),
            it("JUMP"),
        ];
        let cfg = build_asm_cfg(&items);
        let edges = cfg.outgoing_edges(0);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, AsmEdgeKind::Jump);
        assert_eq!(edges[0].target, AsmEdgeTarget::Unresolved);
    }

    #[test]
    fn flatten_round_trips() {
        let items = vec![
            it("PUSH"),
            it_v("tag", "1"),
            it("JUMPDEST"),
            it("ADD"),
            it_v("PUSH [tag]", "2"),
            it("JUMP"),
            it_v("tag", "2"),
            it("JUMPDEST"),
            it("STOP"),
        ];
        let cfg = build_asm_cfg(&items);
        let flat = cfg.flatten();
        assert_eq!(flat.len(), items.len());
        for (a, b) in flat.iter().zip(items.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.value, b.value);
        }
    }
}
