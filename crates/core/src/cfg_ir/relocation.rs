//! Relocation recovery and lowering for CFG/IR jump targets.
//!
//! EVM bytecode stores control-flow targets as ordinary `PUSH` immediates.
//! That is convenient for the VM, but dangerous for a transformation pipeline:
//! once a transform changes instruction sizes or block order, a numeric PC
//! literal can silently stop naming the `JUMPDEST` it used to name. Adjacent
//! patching after layout is not enough because many real Solidity targets are
//! not adjacent to the jump that eventually consumes them.
//!
//! The relocation pass turns PC-sensitive immediates into typed metadata before
//! final layout. A transform may still edit instructions, but no literal that
//! may flow into `JUMP` or `JUMPI` should survive as an untyped number: it is
//! either a symbolic block target, a relocation, explicitly observed as
//! non-control data, or an unresolved dynamic jump that blocks unsafe
//! PC-shifting transforms.
//!
//! There are three related but different sets to keep separate:
//!
//! * **Valid `JUMPDEST` PCs** are exact. They are the decoded instruction PCs
//!   whose opcode is `JUMPDEST`; bytes inside `PUSH` immediates are never
//!   scanned as opcodes.
//! * **Statically recoverable jump targets** are literals or expressions whose
//!   value can be mapped to a valid `JUMPDEST`, such as direct jumps,
//!   PC-relative branches, and split `ADD` expressions.
//! * **Stack-carried Solidity return addresses** are valid `JUMPDEST` PCs that
//!   Solidity pushes before an internal call and consumes later with a bare
//!   `JUMP` in the callee.
//! * **Truly dynamic jump targets** are runtime values, such as
//!   `CALLDATALOAD; JUMP`, that are not decidable by this local recovery pass.
//!
//! Solidity internal functions are the major failure mode for post-hoc
//! patching. A caller commonly pushes the return address, pushes the internal
//! function entry, and jumps. The callee eventually returns with a bare `JUMP`
//! that consumes the return address which has been carried on the stack:
//!
//! ```text
//! PUSH2 return_pc
//! PUSH2 internal_func
//! JUMP
//! ...
//! internal_func:
//!   ...
//!   JUMP
//! ```
//!
//! A local `PUSH target; JUMP` patcher can update `internal_func`, but it will
//! miss `return_pc`. If any earlier transform grows or moves code, that return
//! address becomes stale and can produce `InvalidJump` only on the affected
//! runtime path.
//!
//! ```text
//! Old model:
//!   1. Transform bytecode/CFG.
//!   2. Recompute PCs.
//!   3. Patch direct `PUSH target; JUMP` cases.
//!   4. Heuristically scan for orphan PUSHes that look like old PCs.
//!
//! Failure:
//!   Stack-carried return addresses and calculated targets may not be adjacent to
//!   the consuming jump. If a transform changes byte lengths, those literals become
//!   stale and validation may not catch every reachable path.
//!
//! New model:
//!   1. Recover every PC-sensitive immediate before layout changes.
//!   2. Store it as a relocation or symbolic target expression.
//!   3. Apply transforms while preserving relocation metadata.
//!   4. Lower relocations after final layout.
//!   5. Reject unsafe unknown dynamic jumps.
//! ```
//!
//! The supported recovery examples are intentionally small and compiler-like:
//!
//! Direct jump:
//!
//! ```text
//! PUSH2 0x0042
//! JUMP
//! ```
//!
//! The old model patched this only if the `PUSH` stayed adjacent to the final
//! `JUMP`. The new model records an `AbsolutePc` or `RuntimeRelativePc`
//! relocation to a block and writes the block's final PC after layout.
//!
//! Conditional jump:
//!
//! ```text
//! PUSH2 0x0100
//! DUP1
//! JUMPI
//! ```
//!
//! `JUMPI` pops the target first and the condition second. Recovery tracks the
//! stack position so the target copy is relocatable while a condition literal in
//! a sequence such as `PUSH1 0x01; PUSH2 target; JUMPI` is not mistaken for a
//! control-flow target.
//!
//! PC-relative jump:
//!
//! ```text
//! PUSH2 delta
//! PC
//! ADD
//! JUMPI
//! ```
//!
//! The `delta` is relative to the final PC of the `PC` instruction itself. If
//! either the source or target block moves, the delta must be recomputed from
//! the final layout.
//!
//! Split-add jump:
//!
//! ```text
//! PUSH2 a
//! PUSH2 b
//! ADD
//! JUMP
//! ```
//!
//! Neither `a` nor `b` is a PC by itself. The expression `a + b` is the target,
//! so lowering rewrites the two pushes while preserving their combined value.
//!
//! False-positive literal:
//!
//! ```text
//! PUSH2 0x0123
//! SLOAD
//! ```
//!
//! If `0x0123` also happens to be a `JUMPDEST`, it still must not be remapped:
//! the value is consumed as a storage slot, not as control flow.
//!
//! Unknown dynamic jump:
//!
//! ```text
//! CALLDATALOAD
//! JUMP
//! ```
//!
//! Arbitrary dynamic targets are not statically recoverable here. A transform
//! that changes byte length or block layout must treat them as a safety barrier
//! unless another analysis proves a relocatable target set.

use super::{
    Block, CfgIrBundle, JumpEncoding, apply_immediate, apply_split_add_immediate,
    push_reaches_jump, snapshot_block_body,
};
use crate::Opcode;
use crate::decoder::Instruction;
use crate::result::Error;
use petgraph::graph::NodeIndex;
use std::collections::{HashMap, HashSet};

/// A stable reference to an instruction that owns a relocatable immediate.
///
/// The `block` and `instr_idx` identify the instruction in the CFG, while
/// `pc` records the instruction's old PC at recovery time. The old PC is used
/// for diagnostics and for remapping PC-relative helper instructions after
/// `reindex_pcs` has assigned final PCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelocInstrRef {
    /// CFG body block containing the instruction.
    pub block: NodeIndex,
    /// Index within `BlockBody::instructions`.
    pub instr_idx: usize,
    /// Instruction PC before final layout.
    pub pc: usize,
}

/// A table of every bytecode immediate that represents, or may represent,
/// a control-flow target and therefore must be rewritten after block layout
/// changes.
///
/// This table is the source of truth for PC-sensitive immediates. A transform
/// that changes instruction sizes or block order must preserve and later apply
/// these entries rather than trying to rediscover stale numeric PCs in the final
/// bytecode.
#[derive(Debug, Clone, Default)]
pub struct RelocationTable {
    /// Relocations that can be lowered safely once final PCs are known.
    pub entries: Vec<Relocation>,
    /// Jump sites whose target cannot be resolved by this conservative pass.
    pub unresolved_dynamic_jumps: Vec<JumpSite>,
    /// PUSH literals that equal a valid `JUMPDEST` but were not rewritten.
    pub suspicious_pc_literals: Vec<SuspiciousPcLiteral>,
}

impl RelocationTable {
    /// Returns `true` when this table contains dynamic jump sites that cannot
    /// be safely relocated by the current recovery pass.
    #[must_use]
    pub fn has_unresolved_dynamic_jumps(&self) -> bool {
        !self.unresolved_dynamic_jumps.is_empty()
    }

    /// Counts relocations by pattern so trace logs and tests can tell which
    /// recovery paths were exercised.
    #[must_use]
    pub fn stats(&self) -> RelocationStats {
        let mut stats = RelocationStats {
            suspicious_pc_literals: self.suspicious_pc_literals.len(),
            unresolved_dynamic_jumps: self.unresolved_dynamic_jumps.len(),
            ..RelocationStats::default()
        };

        for entry in &self.entries {
            match entry.kind {
                RelocKind::AbsolutePc | RelocKind::RuntimeRelativePc => match entry.site_kind {
                    Some(JumpSiteKind::Jumpi) => stats.branch += 1,
                    _ => stats.direct += 1,
                },
                RelocKind::PcRelativeDelta => stats.pc_relative += 1,
                RelocKind::SplitAdd => stats.split_add += 1,
                RelocKind::ReturnAddress => stats.return_address += 1,
                RelocKind::TargetSet => stats.target_set += 1,
            }
        }

        stats
    }
}

/// Human-readable relocation counters emitted during recovery and lowering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelocationStats {
    /// Direct `JUMP` target relocations.
    pub direct: usize,
    /// Direct `JUMPI` target relocations.
    pub branch: usize,
    /// `PUSH delta; PC; ADD; JUMPI` relocations.
    pub pc_relative: usize,
    /// `PUSH a; PUSH b; ADD; JUMP/JUMPI` relocations.
    pub split_add: usize,
    /// Solidity-style stack-carried return address relocations.
    pub return_address: usize,
    /// Explicit target-set entries, reserved for future jump-table recovery.
    pub target_set: usize,
    /// PUSH literals that matched a `JUMPDEST` but were not relocated.
    pub suspicious_pc_literals: usize,
    /// Dynamic jumps that this pass could not resolve.
    pub unresolved_dynamic_jumps: usize,
}

/// One relocatable bytecode immediate or immediate expression.
///
/// The primary `instr` is the PUSH instruction that should be rewritten. For
/// split-add patterns, `companion_instr` is the second PUSH in the expression.
/// `encoding` records whether the stored value is an absolute creation-code PC,
/// a runtime-relative PC, or a PC-relative delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// The primary instruction whose immediate is rewritten.
    pub instr: RelocInstrRef,
    /// Optional second PUSH for expression relocations such as split-add.
    pub companion_instr: Option<RelocInstrRef>,
    /// The bytecode pattern represented by this relocation.
    pub kind: RelocKind,
    /// The symbolic target to lower after final layout.
    pub target: TargetExpr,
    /// Coordinate system used by the PUSH immediate.
    pub encoding: JumpEncoding,
    /// Whether the relocation came from `JUMP` or `JUMPI`, when applicable.
    pub site_kind: Option<JumpSiteKind>,
}

/// Classification of a relocatable control-flow immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocKind {
    /// A direct absolute jump target such as:
    ///
    /// ```text
    /// PUSH2 0x1234
    /// JUMP
    /// ```
    ///
    /// The pushed value is replaced with the final absolute PC of the target
    /// block after layout is complete.
    AbsolutePc,
    /// A direct runtime-relative jump target. Solidity runtime bytecode uses
    /// PCs relative to the deployed runtime's start even when the decoded
    /// creation bytecode PCs are absolute.
    ///
    /// Lowering writes `target_final_pc - runtime_start_final`.
    RuntimeRelativePc,
    /// A `PUSH delta; PC; ADD; JUMPI` expression.
    ///
    /// The stored delta is recomputed from the final PC of the `PC`
    /// instruction to the final PC of the target block.
    PcRelativeDelta,
    /// A split arithmetic target such as:
    ///
    /// ```text
    /// PUSH2 a
    /// PUSH2 b
    /// ADD
    /// JUMP
    /// ```
    ///
    /// Lowering rewrites both pushes so their sum is the final encoded target.
    SplitAdd,
    /// A Solidity internal-function return address.
    ///
    /// Solidity commonly compiles an internal call by pushing the return
    /// address, then jumping to the internal function. The callee later
    /// performs a bare `JUMP` using that stack-carried address:
    ///
    /// ```text
    /// PUSH2 return_pc
    /// PUSH2 internal_func
    /// JUMP
    ///
    /// internal_func:
    ///   ...
    ///   JUMP   // consumes return_pc
    /// ```
    ///
    /// Local `PUSH; JUMP` scanning does not see this relationship. This
    /// relocation records the return address so it can be remapped after PC
    /// changes.
    ReturnAddress,
    /// An explicit finite set of possible targets.
    ///
    /// This is reserved for future jump-table recovery. It is safe only when
    /// the table representation is explicit enough to rewrite every entry.
    TargetSet,
}

/// Symbolic expression describing where a recovered target points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetExpr {
    /// A target that resolves to a CFG body block.
    Block(NodeIndex),
    /// A raw old PC plus its original encoding. Lowering remaps the old PC
    /// through the old-to-new PC map and stores it in the requested coordinate
    /// system.
    RawPc { pc: usize, encoding: JumpEncoding },
    /// A PC-relative expression. `base_instr_pc` is the old PC of the `PC`
    /// opcode and `target` is the block reached by `base + delta`.
    PcRelative {
        base_instr_pc: usize,
        target: NodeIndex,
    },
    /// A split-add expression whose two PUSH values sum to the encoded target
    /// block PC.
    SplitAdd { target: NodeIndex },
    /// A stack-carried internal-function return address.
    ReturnAddress(NodeIndex),
    /// A finite dynamic target set. Lowering support is intentionally
    /// conservative and currently errors unless a future table representation
    /// makes every entry explicit.
    TargetSet(Vec<NodeIndex>),
    /// A target that this recovery pass cannot statically resolve.
    Unknown,
}

/// A resolved or unresolved `JUMP`/`JUMPI` instruction site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpSite {
    /// CFG block containing the jump instruction.
    pub block: NodeIndex,
    /// Instruction index of the jump.
    pub instr_idx: usize,
    /// Old PC of the jump.
    pub pc: usize,
    /// Whether this site is `JUMP` or `JUMPI`.
    pub kind: JumpSiteKind,
    /// Recovered target expression, or `Unknown` for dynamic sites.
    pub target: TargetExpr,
}

/// The kind of EVM jump instruction being analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JumpSiteKind {
    /// Unconditional `JUMP`, which pops only the target PC.
    Jump,
    /// Conditional `JUMPI`, which pops the target first and condition second.
    Jumpi,
}

/// A PUSH literal that numerically equals a valid `JUMPDEST` but is not a
/// relocation.
///
/// Suspicious literals are diagnostic, not automatic errors. They capture the
/// cases that future analyses may want to inspect, such as a value consumed by
/// `SLOAD` or a `JUMPI` condition that happens to equal a destination PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousPcLiteral {
    /// CFG block containing the literal.
    pub block: NodeIndex,
    /// Instruction index of the literal.
    pub instr_idx: usize,
    /// Immediate value before any runtime-relative adjustment.
    pub old_value: usize,
    /// Why the literal was not converted into a relocation.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StackValue {
    Unknown,
    External,
    Literal {
        instr_idx: usize,
        pc: usize,
        value: usize,
    },
    Pc {
        instr_idx: usize,
        pc: usize,
    },
    Add(Box<StackValue>, Box<StackValue>),
}

#[derive(Debug, Clone, Copy)]
struct ResolvedTarget {
    node: NodeIndex,
    encoding: JumpEncoding,
    old_abs_pc: usize,
}

impl CfgIrBundle {
    /// Recovers PC-sensitive immediates from the current CFG.
    ///
    /// `old_runtime_bounds` should describe the layout whose PCs are currently
    /// encoded in instruction immediates, usually `self.runtime_bounds` before
    /// `reindex_pcs` runs. The pass builds the exact set of decoded
    /// `JUMPDEST` PCs, tracks simple stack expressions at `JUMP`/`JUMPI`, and
    /// scans for Solidity-style return addresses that may be consumed in later
    /// blocks.
    ///
    /// This pass is intentionally conservative. It recovers direct jump
    /// targets, PC-relative jump targets, split arithmetic jump targets, and
    /// Solidity-style stack-carried return addresses. It does not claim to
    /// solve arbitrary dynamic EVM control flow.
    ///
    /// Any jump target that cannot be resolved is recorded in
    /// `RelocationTable::unresolved_dynamic_jumps`. Callers that intend to
    /// apply byte-length-changing transforms must treat those unresolved jumps
    /// as a safety barrier unless another analysis proves them safe.
    pub fn recover_relocations(
        &self,
        old_runtime_bounds: Option<(usize, usize)>,
    ) -> Result<RelocationTable, Error> {
        let mut table = RelocationTable::default();
        let jumpdest_to_block = self.jumpdest_to_block_by_old_pc();
        let old_jumpdest_pcs: HashSet<_> = jumpdest_to_block.keys().copied().collect();
        let mut covered_pushes: HashSet<(NodeIndex, usize)> = HashSet::new();
        let mut pending_unknown_jumps = Vec::new();

        for node in self.cfg.node_indices() {
            let Some(Block::Body(body)) = self.cfg.node_weight(node) else {
                continue;
            };

            let in_runtime = block_in_runtime_by_instruction(body, old_runtime_bounds);
            let sites =
                recover_jump_sites_for_block(node, body, old_runtime_bounds, &jumpdest_to_block)?;

            for (site, relocation, external_target) in sites {
                match relocation {
                    Some(relocation) => {
                        covered_pushes.insert((relocation.instr.block, relocation.instr.instr_idx));
                        if let Some(companion) = relocation.companion_instr {
                            covered_pushes.insert((companion.block, companion.instr_idx));
                        }
                        table.entries.push(relocation);
                    }
                    None if matches!(site.target, TargetExpr::Unknown) => {
                        pending_unknown_jumps.push((site, external_target));
                    }
                    None => {}
                }
            }

            for (idx, instr) in body.instructions.iter().enumerate() {
                if covered_pushes.contains(&(node, idx)) {
                    continue;
                }
                let Some(value) = parse_push_immediate(instr) else {
                    continue;
                };
                let Some(resolved) =
                    resolve_old_pc_value(value, in_runtime, old_runtime_bounds, &jumpdest_to_block)
                else {
                    continue;
                };

                if push_reaches_jump(&body.instructions, idx) {
                    table.entries.push(Relocation {
                        instr: RelocInstrRef {
                            block: node,
                            instr_idx: idx,
                            pc: instr.pc,
                        },
                        companion_instr: None,
                        kind: RelocKind::ReturnAddress,
                        target: TargetExpr::ReturnAddress(resolved.node),
                        encoding: resolved.encoding,
                        site_kind: None,
                    });
                    covered_pushes.insert((node, idx));
                } else {
                    table.suspicious_pc_literals.push(SuspiciousPcLiteral {
                        block: node,
                        instr_idx: idx,
                        old_value: value,
                        reason: format!(
                            "literal resolves to JUMPDEST 0x{:x} but is consumed as non-control data",
                            resolved.old_abs_pc
                        ),
                    });
                }
            }
        }

        let return_targets: Vec<_> = table
            .entries
            .iter()
            .filter_map(|entry| match entry.target {
                TargetExpr::ReturnAddress(node) => Some(node),
                _ => None,
            })
            .collect();

        if return_targets.is_empty() {
            table.unresolved_dynamic_jumps = pending_unknown_jumps
                .into_iter()
                .map(|(site, _)| site)
                .collect();
        } else {
            let target_set = TargetExpr::TargetSet(return_targets);
            for (mut site, external_target) in pending_unknown_jumps {
                if external_target && matches!(site.kind, JumpSiteKind::Jump) {
                    site.target = target_set.clone();
                    tracing::debug!(
                        block = site.block.index(),
                        instr_idx = site.instr_idx,
                        pc = format_args!("0x{:x}", site.pc),
                        "recover_relocations: treating bare JUMP as covered by recovered return-address target set"
                    );
                } else {
                    table.unresolved_dynamic_jumps.push(site);
                }
            }
        }

        let stats = table.stats();
        tracing::debug!(
            direct = stats.direct,
            branch = stats.branch,
            pc_relative = stats.pc_relative,
            split_add = stats.split_add,
            return_address = stats.return_address,
            suspicious_pc_literals = stats.suspicious_pc_literals,
            unresolved_dynamic_jumps = stats.unresolved_dynamic_jumps,
            "recover_relocations: recovered relocation table"
        );

        let _ = old_jumpdest_pcs;
        Ok(table)
    }

    /// Returns whether the current CFG contains dynamic jumps that cannot be
    /// relocated safely by the conservative recovery pass.
    ///
    /// This helper is intended for byte-length-changing or block-layout
    /// transforms. Those transforms should skip or fail clearly when this
    /// returns `true`, unless they have a stronger analysis proving the dynamic
    /// target set is safe.
    #[must_use]
    pub fn has_unresolved_dynamic_jumps(&self) -> bool {
        self.recover_relocations(self.runtime_bounds)
            .map(|table| table.has_unresolved_dynamic_jumps())
            .unwrap_or(true)
    }

    /// Applies recovered relocations after final PCs have been assigned.
    ///
    /// `pc_mapping` maps old instruction PCs to final PCs. Direct and return
    /// relocations write the final target PC in the appropriate absolute or
    /// runtime-relative coordinate system. PC-relative relocations recompute
    /// the delta from the final `PC` instruction. Split-add relocations rewrite
    /// both PUSH operands so their sum is the final encoded target.
    ///
    /// The function deliberately does not guess for `TargetSet` or `Unknown`;
    /// callers must reject unsafe dynamic jumps before relying on layout
    /// changes.
    pub fn apply_relocations(
        &mut self,
        table: &RelocationTable,
        pc_mapping: &HashMap<usize, usize>,
        _old_runtime_bounds: Option<(usize, usize)>,
    ) -> Result<(), Error> {
        let mut modified_blocks = HashSet::new();

        for relocation in &table.entries {
            match relocation.kind {
                RelocKind::AbsolutePc | RelocKind::RuntimeRelativePc | RelocKind::ReturnAddress => {
                    let value = self.lower_target_value(
                        &relocation.target,
                        relocation.encoding,
                        pc_mapping,
                    )?;
                    self.write_relocation_immediate(relocation.instr, value)?;
                    modified_blocks.insert(relocation.instr.block);
                }
                RelocKind::PcRelativeDelta => {
                    let TargetExpr::PcRelative {
                        base_instr_pc,
                        target,
                    } = relocation.target
                    else {
                        return Err(Error::InvalidBlockStructure(
                            "PC-relative relocation missing PcRelative target".into(),
                        ));
                    };
                    let base_new_pc = pc_mapping.get(&base_instr_pc).copied().ok_or_else(|| {
                        Error::InvalidBlockStructure(format!(
                            "missing PC mapping for PC-relative base 0x{base_instr_pc:x}"
                        ))
                    })?;
                    let target_pc = self.block_start_pc(target)?;
                    if target_pc < base_new_pc {
                        return Err(Error::InvalidImmediate(format!(
                            "PC-relative target 0x{target_pc:x} precedes base 0x{base_new_pc:x}"
                        )));
                    }
                    self.write_relocation_immediate(relocation.instr, target_pc - base_new_pc)?;
                    modified_blocks.insert(relocation.instr.block);
                }
                RelocKind::SplitAdd => {
                    let TargetExpr::SplitAdd { target } = relocation.target else {
                        return Err(Error::InvalidBlockStructure(
                            "split-add relocation missing SplitAdd target".into(),
                        ));
                    };
                    let encoded =
                        self.encode_target_pc(self.block_start_pc(target)?, relocation.encoding)?;
                    let companion = relocation.companion_instr.ok_or_else(|| {
                        Error::InvalidBlockStructure(
                            "split-add relocation missing companion PUSH".into(),
                        )
                    })?;
                    self.write_split_relocation(relocation.instr, companion, encoded)?;
                    modified_blocks.insert(relocation.instr.block);
                }
                RelocKind::TargetSet => {
                    return Err(Error::InvalidBlockStructure(
                        "target-set relocation lowering is not yet supported".into(),
                    ));
                }
            }
        }

        self.validate_relocation_invariants(table, pc_mapping)?;

        let stats = table.stats();
        tracing::debug!(
            direct = stats.direct,
            branch = stats.branch,
            pc_relative = stats.pc_relative,
            split_add = stats.split_add,
            return_address = stats.return_address,
            suspicious_pc_literals = stats.suspicious_pc_literals,
            unresolved_dynamic_jumps = stats.unresolved_dynamic_jumps,
            modified_blocks = modified_blocks.len(),
            "apply_relocations: lowered relocation table"
        );

        Ok(())
    }

    /// Checks that lowered relocations still encode their expected final target.
    ///
    /// This is a local assembler invariant, not a proof of all possible runtime
    /// control flow. It verifies the immediates we rewrote and deliberately
    /// leaves arbitrary dynamic jumps to REVM/fuzz tests and higher-level
    /// analysis.
    pub fn validate_relocation_invariants(
        &self,
        table: &RelocationTable,
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<(), Error> {
        for relocation in &table.entries {
            match relocation.kind {
                RelocKind::AbsolutePc | RelocKind::RuntimeRelativePc | RelocKind::ReturnAddress => {
                    let expected = self.lower_target_value(
                        &relocation.target,
                        relocation.encoding,
                        pc_mapping,
                    )?;
                    let actual = self.read_relocation_immediate(relocation.instr)?;
                    if actual != expected {
                        return Err(Error::InvalidImmediate(format!(
                            "relocation at pc 0x{:x} encoded 0x{:x}, expected 0x{:x}",
                            relocation.instr.pc, actual, expected
                        )));
                    }
                }
                RelocKind::PcRelativeDelta => {
                    let TargetExpr::PcRelative {
                        base_instr_pc,
                        target,
                    } = relocation.target
                    else {
                        continue;
                    };
                    let base_new_pc = pc_mapping.get(&base_instr_pc).copied().ok_or_else(|| {
                        Error::InvalidBlockStructure(format!(
                            "missing PC mapping for PC-relative base 0x{base_instr_pc:x}"
                        ))
                    })?;
                    let target_pc = self.block_start_pc(target)?;
                    let expected = target_pc.saturating_sub(base_new_pc);
                    let actual = self.read_relocation_immediate(relocation.instr)?;
                    if actual != expected {
                        return Err(Error::InvalidImmediate(format!(
                            "PC-relative relocation at pc 0x{:x} encoded 0x{:x}, expected 0x{:x}",
                            relocation.instr.pc, actual, expected
                        )));
                    }
                }
                RelocKind::SplitAdd => {
                    let TargetExpr::SplitAdd { target } = relocation.target else {
                        continue;
                    };
                    let companion = relocation.companion_instr.ok_or_else(|| {
                        Error::InvalidBlockStructure(
                            "split-add relocation missing companion PUSH".into(),
                        )
                    })?;
                    let expected =
                        self.encode_target_pc(self.block_start_pc(target)?, relocation.encoding)?;
                    let actual = self
                        .read_relocation_immediate(relocation.instr)?
                        .checked_add(self.read_relocation_immediate(companion)?)
                        .ok_or_else(|| {
                            Error::InvalidImmediate(
                                "split-add relocation immediate overflowed".into(),
                            )
                        })?;
                    if actual != expected {
                        return Err(Error::InvalidImmediate(format!(
                            "split-add relocation at pc 0x{:x} encoded sum 0x{:x}, expected 0x{:x}",
                            relocation.instr.pc, actual, expected
                        )));
                    }
                }
                RelocKind::TargetSet => {}
            }
        }
        Ok(())
    }

    fn jumpdest_to_block_by_old_pc(&self) -> HashMap<usize, NodeIndex> {
        let mut out = HashMap::new();
        for node in self.cfg.node_indices() {
            let Some(Block::Body(body)) = self.cfg.node_weight(node) else {
                continue;
            };
            if let Some(first) = body.instructions.first() {
                out.entry(first.pc).or_insert(node);
            }
            for instr in &body.instructions {
                if matches!(instr.op, Opcode::JUMPDEST) {
                    out.insert(instr.pc, node);
                }
            }
        }
        out
    }

    fn block_start_pc(&self, node: NodeIndex) -> Result<usize, Error> {
        match self.cfg.node_weight(node) {
            Some(Block::Body(body)) => Ok(body.start_pc),
            _ => Err(Error::InvalidBlockStructure(format!(
                "relocation target node {} is not a body block",
                node.index()
            ))),
        }
    }

    fn encode_target_pc(&self, target_pc: usize, encoding: JumpEncoding) -> Result<usize, Error> {
        match encoding {
            JumpEncoding::Absolute => Ok(target_pc),
            JumpEncoding::RuntimeRelative => self
                .runtime_bounds
                .map(|(start, _)| target_pc.saturating_sub(start))
                .ok_or_else(|| {
                    Error::InvalidBlockStructure(
                        "runtime-relative relocation without runtime bounds".into(),
                    )
                }),
            JumpEncoding::PcRelative => Err(Error::InvalidBlockStructure(
                "PcRelative target must be lowered by PcRelativeDelta".into(),
            )),
        }
    }

    fn lower_target_value(
        &self,
        target: &TargetExpr,
        encoding: JumpEncoding,
        pc_mapping: &HashMap<usize, usize>,
    ) -> Result<usize, Error> {
        match target {
            TargetExpr::Block(node) | TargetExpr::ReturnAddress(node) => {
                self.encode_target_pc(self.block_start_pc(*node)?, encoding)
            }
            TargetExpr::RawPc { pc, encoding } => {
                let mapped = pc_mapping.get(pc).copied().ok_or_else(|| {
                    Error::InvalidBlockStructure(format!(
                        "missing PC mapping for raw relocation target 0x{pc:x}"
                    ))
                })?;
                self.encode_target_pc(mapped, *encoding)
            }
            TargetExpr::PcRelative { .. } | TargetExpr::SplitAdd { .. } => Err(
                Error::InvalidBlockStructure("expression target lowered by relocation kind".into()),
            ),
            TargetExpr::TargetSet(_) => Err(Error::InvalidBlockStructure(
                "target-set relocation lowering is not yet supported".into(),
            )),
            TargetExpr::Unknown => Err(Error::InvalidBlockStructure(
                "cannot lower unknown relocation target".into(),
            )),
        }
    }

    fn write_relocation_immediate(
        &mut self,
        instr_ref: RelocInstrRef,
        value: usize,
    ) -> Result<(), Error> {
        let before = snapshot_block_body(self, instr_ref.block);
        let Some(Block::Body(body)) = self.cfg.node_weight_mut(instr_ref.block) else {
            return Err(Error::InvalidBlockStructure(format!(
                "relocation block {} is not a body block",
                instr_ref.block.index()
            )));
        };
        let instr = body
            .instructions
            .get_mut(instr_ref.instr_idx)
            .ok_or_else(|| {
                Error::InvalidBlockStructure(format!(
                    "relocation instruction {} missing from block {}",
                    instr_ref.instr_idx,
                    instr_ref.block.index()
                ))
            })?;
        apply_immediate(instr, value)?;
        let _ = before;
        Ok(())
    }

    fn write_split_relocation(
        &mut self,
        first: RelocInstrRef,
        second: RelocInstrRef,
        total: usize,
    ) -> Result<(), Error> {
        if first.block != second.block {
            return Err(Error::InvalidBlockStructure(
                "split-add relocation spans multiple blocks".into(),
            ));
        }
        let Some(Block::Body(body)) = self.cfg.node_weight_mut(first.block) else {
            return Err(Error::InvalidBlockStructure(format!(
                "relocation block {} is not a body block",
                first.block.index()
            )));
        };
        apply_split_add_immediate(
            &mut body.instructions,
            first.instr_idx,
            second.instr_idx,
            total,
        )
    }

    fn read_relocation_immediate(&self, instr_ref: RelocInstrRef) -> Result<usize, Error> {
        let Some(Block::Body(body)) = self.cfg.node_weight(instr_ref.block) else {
            return Err(Error::InvalidBlockStructure(format!(
                "relocation block {} is not a body block",
                instr_ref.block.index()
            )));
        };
        let instr = body.instructions.get(instr_ref.instr_idx).ok_or_else(|| {
            Error::InvalidBlockStructure(format!(
                "relocation instruction {} missing from block {}",
                instr_ref.instr_idx,
                instr_ref.block.index()
            ))
        })?;
        parse_push_immediate(instr).ok_or_else(|| {
            Error::InvalidImmediate(format!(
                "relocation instruction at pc 0x{:x} is not a PUSH immediate",
                instr.pc
            ))
        })
    }
}

fn recover_jump_sites_for_block(
    node: NodeIndex,
    body: &super::BlockBody,
    old_runtime_bounds: Option<(usize, usize)>,
    jumpdest_to_block: &HashMap<usize, NodeIndex>,
) -> Result<Vec<(JumpSite, Option<Relocation>, bool)>, Error> {
    // Body blocks start with an unknown caller/callee stack. Seeding a small
    // abstract prefix lets us distinguish stack-carried external values (the
    // Solidity return-address case) from values computed dynamically inside the
    // current block, such as CALLDATALOAD; JUMP.
    let mut stack = vec![StackValue::External; 16];
    let mut out = Vec::new();
    let in_runtime = block_in_runtime_by_instruction(body, old_runtime_bounds);

    for (idx, instr) in body.instructions.iter().enumerate() {
        match instr.op {
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                let value = parse_push_immediate(instr).unwrap_or(0);
                stack.push(StackValue::Literal {
                    instr_idx: idx,
                    pc: instr.pc,
                    value,
                });
            }
            Opcode::PC => {
                stack.push(StackValue::Pc {
                    instr_idx: idx,
                    pc: instr.pc,
                });
            }
            Opcode::ADD => {
                let rhs = stack.pop().unwrap_or(StackValue::Unknown);
                let lhs = stack.pop().unwrap_or(StackValue::Unknown);
                stack.push(StackValue::Add(Box::new(lhs), Box::new(rhs)));
            }
            Opcode::DUP(n) => {
                let depth = n as usize;
                if depth == 0 || depth > stack.len() {
                    stack.push(StackValue::Unknown);
                } else {
                    stack.push(stack[stack.len() - depth].clone());
                }
            }
            Opcode::SWAP(n) => {
                let depth = n as usize;
                if depth < stack.len() {
                    let top = stack.len() - 1;
                    let other = top - depth;
                    stack.swap(top, other);
                } else {
                    stack.clear();
                }
            }
            Opcode::JUMP | Opcode::JUMPI => {
                // EVM `JUMPI` pops the target first and the condition second.
                // The condition can be a literal that equals a JUMPDEST, but it
                // is not a relocatable control-flow target.
                let target_value = stack.pop().unwrap_or(StackValue::External);
                let site_kind = if matches!(instr.op, Opcode::JUMPI) {
                    let _condition = stack.pop();
                    JumpSiteKind::Jumpi
                } else {
                    JumpSiteKind::Jump
                };
                let (target, relocation, external_target) = relocation_from_stack_value(
                    node,
                    site_kind,
                    target_value,
                    in_runtime,
                    old_runtime_bounds,
                    jumpdest_to_block,
                )?;
                out.push((
                    JumpSite {
                        block: node,
                        instr_idx: idx,
                        pc: instr.pc,
                        kind: site_kind,
                        target,
                    },
                    relocation,
                    external_target,
                ));
            }
            Opcode::JUMPDEST => {}
            _ => apply_stack_effect(&mut stack, instr.op),
        }
    }

    Ok(out)
}

fn relocation_from_stack_value(
    node: NodeIndex,
    site_kind: JumpSiteKind,
    value: StackValue,
    in_runtime: bool,
    old_runtime_bounds: Option<(usize, usize)>,
    jumpdest_to_block: &HashMap<usize, NodeIndex>,
) -> Result<(TargetExpr, Option<Relocation>, bool), Error> {
    match value {
        StackValue::Literal {
            instr_idx,
            pc,
            value,
        } => {
            let Some(resolved) =
                resolve_old_pc_value(value, in_runtime, old_runtime_bounds, jumpdest_to_block)
            else {
                return Ok((TargetExpr::Unknown, None, false));
            };
            let kind = match resolved.encoding {
                JumpEncoding::Absolute => RelocKind::AbsolutePc,
                JumpEncoding::RuntimeRelative => RelocKind::RuntimeRelativePc,
                JumpEncoding::PcRelative => unreachable!(),
            };
            Ok((
                TargetExpr::Block(resolved.node),
                Some(Relocation {
                    instr: RelocInstrRef {
                        block: node,
                        instr_idx,
                        pc,
                    },
                    companion_instr: None,
                    kind,
                    target: TargetExpr::Block(resolved.node),
                    encoding: resolved.encoding,
                    site_kind: Some(site_kind),
                }),
                false,
            ))
        }
        StackValue::Add(lhs, rhs) => {
            if let Some((literal, pc_instr)) = literal_plus_pc(&lhs, &rhs) {
                let Some(target_abs) = pc_instr.pc.checked_add(literal.value) else {
                    return Ok((TargetExpr::Unknown, None, false));
                };
                let Some(&target_node) = jumpdest_to_block.get(&target_abs) else {
                    return Ok((TargetExpr::Unknown, None, false));
                };
                return Ok((
                    TargetExpr::PcRelative {
                        base_instr_pc: pc_instr.pc,
                        target: target_node,
                    },
                    Some(Relocation {
                        instr: RelocInstrRef {
                            block: node,
                            instr_idx: literal.instr_idx,
                            pc: literal.pc,
                        },
                        companion_instr: None,
                        kind: RelocKind::PcRelativeDelta,
                        target: TargetExpr::PcRelative {
                            base_instr_pc: pc_instr.pc,
                            target: target_node,
                        },
                        encoding: JumpEncoding::PcRelative,
                        site_kind: Some(site_kind),
                    }),
                    false,
                ));
            }

            if let Some((a, b)) = literal_plus_literal(&lhs, &rhs) {
                let Some(total) = a.value.checked_add(b.value) else {
                    return Ok((TargetExpr::Unknown, None, false));
                };
                let Some(resolved) =
                    resolve_old_pc_value(total, in_runtime, old_runtime_bounds, jumpdest_to_block)
                else {
                    return Ok((TargetExpr::Unknown, None, false));
                };
                return Ok((
                    TargetExpr::SplitAdd {
                        target: resolved.node,
                    },
                    Some(Relocation {
                        instr: RelocInstrRef {
                            block: node,
                            instr_idx: a.instr_idx,
                            pc: a.pc,
                        },
                        companion_instr: Some(RelocInstrRef {
                            block: node,
                            instr_idx: b.instr_idx,
                            pc: b.pc,
                        }),
                        kind: RelocKind::SplitAdd,
                        target: TargetExpr::SplitAdd {
                            target: resolved.node,
                        },
                        encoding: resolved.encoding,
                        site_kind: Some(site_kind),
                    }),
                    false,
                ));
            }

            Ok((TargetExpr::Unknown, None, false))
        }
        StackValue::External => Ok((TargetExpr::Unknown, None, true)),
        StackValue::Pc { .. } | StackValue::Unknown => Ok((TargetExpr::Unknown, None, false)),
    }
}

#[derive(Debug, Clone, Copy)]
struct LiteralSource {
    instr_idx: usize,
    pc: usize,
    value: usize,
}

#[derive(Debug, Clone, Copy)]
struct PcSource {
    pc: usize,
}

fn literal_plus_pc(lhs: &StackValue, rhs: &StackValue) -> Option<(LiteralSource, PcSource)> {
    match (lhs, rhs) {
        (
            StackValue::Literal {
                instr_idx,
                pc,
                value,
            },
            StackValue::Pc { pc: pc_pc, .. },
        )
        | (
            StackValue::Pc { pc: pc_pc, .. },
            StackValue::Literal {
                instr_idx,
                pc,
                value,
            },
        ) => Some((
            LiteralSource {
                instr_idx: *instr_idx,
                pc: *pc,
                value: *value,
            },
            PcSource { pc: *pc_pc },
        )),
        _ => None,
    }
}

fn literal_plus_literal(
    lhs: &StackValue,
    rhs: &StackValue,
) -> Option<(LiteralSource, LiteralSource)> {
    match (lhs, rhs) {
        (
            StackValue::Literal {
                instr_idx: a_idx,
                pc: a_pc,
                value: a_value,
            },
            StackValue::Literal {
                instr_idx: b_idx,
                pc: b_pc,
                value: b_value,
            },
        ) => Some((
            LiteralSource {
                instr_idx: *a_idx,
                pc: *a_pc,
                value: *a_value,
            },
            LiteralSource {
                instr_idx: *b_idx,
                pc: *b_pc,
                value: *b_value,
            },
        )),
        _ => None,
    }
}

fn resolve_old_pc_value(
    value: usize,
    in_runtime: bool,
    old_runtime_bounds: Option<(usize, usize)>,
    jumpdest_to_block: &HashMap<usize, NodeIndex>,
) -> Option<ResolvedTarget> {
    if in_runtime
        && let Some((old_start, _)) = old_runtime_bounds
        && let Some(old_abs_pc) = old_start.checked_add(value)
        && let Some(&node) = jumpdest_to_block.get(&old_abs_pc)
    {
        return Some(ResolvedTarget {
            node,
            encoding: JumpEncoding::RuntimeRelative,
            old_abs_pc,
        });
    }

    jumpdest_to_block
        .get(&value)
        .copied()
        .map(|node| ResolvedTarget {
            node,
            encoding: JumpEncoding::Absolute,
            old_abs_pc: value,
        })
}

fn block_in_runtime_by_instruction(
    body: &super::BlockBody,
    old_runtime_bounds: Option<(usize, usize)>,
) -> bool {
    let Some((start, end)) = old_runtime_bounds else {
        return false;
    };
    body.instructions
        .first()
        .is_some_and(|instr| instr.pc >= start && instr.pc < end)
}

fn parse_push_immediate(instr: &Instruction) -> Option<usize> {
    match instr.op {
        Opcode::PUSH0 => Some(0),
        Opcode::PUSH(_) => instr
            .imm
            .as_deref()
            .and_then(|imm| usize::from_str_radix(imm, 16).ok()),
        _ => None,
    }
}

fn apply_stack_effect(stack: &mut Vec<StackValue>, opcode: Opcode) {
    let (pops, pushes) = stack_effect(opcode);
    if pops > stack.len() {
        stack.clear();
    } else {
        for _ in 0..pops {
            let _ = stack.pop();
        }
    }
    for _ in 0..pushes {
        stack.push(StackValue::Unknown);
    }
}

fn stack_effect(opcode: Opcode) -> (usize, usize) {
    match opcode {
        Opcode::STOP | Opcode::JUMPDEST | Opcode::INVALID => (0, 0),
        Opcode::POP => (1, 0),
        Opcode::MLOAD
        | Opcode::SLOAD
        | Opcode::ISZERO
        | Opcode::NOT
        | Opcode::BALANCE
        | Opcode::CALLDATALOAD
        | Opcode::EXTCODESIZE
        | Opcode::BLOCKHASH
        | Opcode::EXTCODEHASH => (1, 1),
        Opcode::ADD
        | Opcode::SUB
        | Opcode::MUL
        | Opcode::DIV
        | Opcode::SDIV
        | Opcode::MOD
        | Opcode::SMOD
        | Opcode::EXP
        | Opcode::SIGNEXTEND
        | Opcode::LT
        | Opcode::GT
        | Opcode::SLT
        | Opcode::SGT
        | Opcode::EQ
        | Opcode::AND
        | Opcode::OR
        | Opcode::XOR
        | Opcode::BYTE
        | Opcode::SHL
        | Opcode::SHR
        | Opcode::SAR
        | Opcode::KECCAK256 => (2, 1),
        Opcode::ADDMOD | Opcode::MULMOD => (3, 1),
        Opcode::MSTORE | Opcode::MSTORE8 | Opcode::SSTORE => (2, 0),
        Opcode::CODECOPY | Opcode::CALLDATACOPY | Opcode::EXTCODECOPY | Opcode::RETURNDATACOPY => {
            (3, 0)
        }
        Opcode::LOG0 => (2, 0),
        Opcode::LOG1 => (3, 0),
        Opcode::LOG2 => (4, 0),
        Opcode::LOG3 => (5, 0),
        Opcode::LOG4 => (6, 0),
        Opcode::CREATE => (3, 1),
        Opcode::CREATE2 => (4, 1),
        Opcode::CALL | Opcode::CALLCODE => (7, 1),
        Opcode::DELEGATECALL | Opcode::STATICCALL => (6, 1),
        Opcode::RETURN | Opcode::REVERT | Opcode::SELFDESTRUCT => (usize::MAX, 0),
        Opcode::ADDRESS
        | Opcode::ORIGIN
        | Opcode::CALLER
        | Opcode::CALLVALUE
        | Opcode::CALLDATASIZE
        | Opcode::CODESIZE
        | Opcode::GASPRICE
        | Opcode::COINBASE
        | Opcode::TIMESTAMP
        | Opcode::NUMBER
        | Opcode::DIFFICULTY
        | Opcode::GASLIMIT
        | Opcode::CHAINID
        | Opcode::SELFBALANCE
        | Opcode::BASEFEE
        | Opcode::GAS
        | Opcode::RETURNDATASIZE
        | Opcode::MSIZE => (0, 1),
        _ => (usize::MAX, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_ir::build_cfg_ir;
    use crate::detection::{Section, SectionKind};
    use crate::strip::{CleanReport, RuntimeSpan};
    use revm::primitives::B256;

    fn ins(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
        Instruction {
            pc,
            op,
            imm: imm.map(str::to_string),
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

    fn bundle(instructions: Vec<Instruction>) -> CfgIrBundle {
        let len = instructions
            .iter()
            .map(|instr| instr.pc + instr.byte_size())
            .max()
            .unwrap_or(0);
        let sections = vec![Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len,
        }];
        let bytecode = vec![0; len];
        build_cfg_ir(&instructions, &sections, clean_report(len), &bytecode)
            .expect("synthetic CFG builds")
    }

    fn sorted_instructions(cfg: &CfgIrBundle) -> Vec<Instruction> {
        let mut instructions = Vec::new();
        for node in cfg.cfg.node_indices() {
            if let Block::Body(body) = &cfg.cfg[node] {
                instructions.extend(body.instructions.clone());
            }
        }
        instructions.sort_by_key(|instr| instr.pc);
        instructions
    }

    fn insert_instruction(
        cfg: &mut CfgIrBundle,
        block_old_start_pc: usize,
        instr_idx: usize,
        instr: Instruction,
    ) {
        let node = cfg
            .cfg
            .node_indices()
            .find(|&idx| match &cfg.cfg[idx] {
                Block::Body(body) => body
                    .instructions
                    .first()
                    .is_some_and(|first| first.pc == block_old_start_pc),
                _ => false,
            })
            .expect("block exists");
        if let Some(Block::Body(body)) = cfg.cfg.node_weight_mut(node) {
            body.instructions.insert(instr_idx, instr);
        }
    }

    #[test]
    fn direct_relocation_updates_after_growth() {
        // Direct target immediates are recovered before reindexing and lowered
        // to the final JUMPDEST PC after the source block grows.
        let mut cfg = bundle(vec![
            ins(0, Opcode::JUMPDEST, None),
            ins(1, Opcode::PUSH(1), Some("04")),
            ins(3, Opcode::JUMP, None),
            ins(4, Opcode::JUMPDEST, None),
            ins(5, Opcode::STOP, None),
        ]);
        insert_instruction(&mut cfg, 0, 1, ins(0x80, Opcode::PUSH0, None));

        let table = cfg
            .recover_relocations(cfg.runtime_bounds)
            .expect("relocations recover");
        assert_eq!(table.stats().direct, 1);

        cfg.reindex_pcs().expect("reindex succeeds");
        let push = sorted_instructions(&cfg)
            .into_iter()
            .find(|instr| matches!(instr.op, Opcode::PUSH(1)))
            .expect("push present");
        assert_eq!(push.imm.as_deref(), Some("05"));
    }

    #[test]
    fn return_address_relocation_updates_after_growth() {
        // Solidity-style return addresses are not adjacent to the bare return
        // JUMP, so relocation recovery must catch them as stack-carried values.
        let mut cfg = bundle(vec![
            ins(0, Opcode::PUSH(1), Some("05")),
            ins(2, Opcode::PUSH(1), Some("07")),
            ins(4, Opcode::JUMP, None),
            ins(5, Opcode::JUMPDEST, None),
            ins(6, Opcode::STOP, None),
            ins(7, Opcode::JUMPDEST, None),
            ins(8, Opcode::JUMP, None),
        ]);
        insert_instruction(&mut cfg, 0, 0, ins(0x80, Opcode::PUSH0, None));

        let table = cfg
            .recover_relocations(cfg.runtime_bounds)
            .expect("relocations recover");
        assert_eq!(table.stats().return_address, 1);
        assert!(!table.has_unresolved_dynamic_jumps());

        cfg.reindex_pcs().expect("reindex succeeds");
        let return_push = sorted_instructions(&cfg)
            .into_iter()
            .find(|instr| matches!(instr.op, Opcode::PUSH(1)) && instr.pc == 1)
            .expect("return push present");
        assert_eq!(return_push.imm.as_deref(), Some("06"));
    }

    #[test]
    fn data_literal_equal_to_jumpdest_is_only_suspicious() {
        // A literal consumed by SLOAD is a storage slot even if its numeric
        // value happens to equal a valid JUMPDEST.
        let cfg = bundle(vec![
            ins(0, Opcode::PUSH(2), Some("0100")),
            ins(3, Opcode::SLOAD, None),
            ins(4, Opcode::STOP, None),
            ins(0x100, Opcode::JUMPDEST, None),
            ins(0x101, Opcode::STOP, None),
        ]);

        let table = cfg
            .recover_relocations(cfg.runtime_bounds)
            .expect("relocations recover");
        assert!(table.entries.is_empty());
        assert_eq!(table.suspicious_pc_literals.len(), 1);
    }

    #[test]
    fn dynamic_jump_is_unresolved() {
        // CALLDATALOAD; JUMP is genuinely dynamic and must block unsafe
        // PC-shifting transforms unless another pass proves a target set.
        let cfg = bundle(vec![
            ins(0, Opcode::CALLDATALOAD, None),
            ins(1, Opcode::JUMP, None),
            ins(2, Opcode::JUMPDEST, None),
            ins(3, Opcode::STOP, None),
        ]);

        let table = cfg
            .recover_relocations(cfg.runtime_bounds)
            .expect("relocations recover");
        assert!(table.has_unresolved_dynamic_jumps());
        assert!(cfg.has_unresolved_dynamic_jumps());
    }
}
