use azoth_core::cfg_ir::{
    build_cfg_ir, push_reaches_jump, Block, CfgIrBundle, CfgIrDiff, OperationKind, RelocKind,
};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{self, Section, SectionKind};
use azoth_core::seed::Seed;
use azoth_core::strip::RuntimeSpan;
use azoth_core::Opcode;
use azoth_core::{decoder, encoder, strip, validator};
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;
use petgraph::visit::EdgeRef;
use revm::primitives::B256;
use std::collections::HashSet;

const STORAGE_BYTECODE: &str = include_str!("../../bytecode/storage.hex");

async fn build_storage_cfg() -> CfgIrBundle {
    let (instructions, _info, _asm, bytes) = decoder::decode_bytecode(STORAGE_BYTECODE, false)
        .await
        .expect("failed to decode storage bytecode");
    let sections = detection::locate_sections(&bytes, &instructions, &[])
        .expect("failed to locate sections for storage bytecode");
    let (_clean_runtime, report) =
        strip::strip_bytecode(&bytes, &sections).expect("failed to strip storage bytecode");

    build_cfg_ir(&instructions, &sections, report, &bytes)
        .expect("failed to build CFG for storage bytecode")
}

fn synthetic_clean_report(len: usize) -> strip::CleanReport {
    strip::CleanReport {
        runtime_layout: vec![RuntimeSpan { offset: 0, len }],
        removed: Vec::new(),
        swarm_hash: None,
        bytes_saved: 0,
        clean_len: len,
        clean_keccak: B256::ZERO,
        program_counter_mapping: Vec::new(),
    }
}

fn synthetic_cfg(instructions: Vec<Instruction>) -> CfgIrBundle {
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
    build_cfg_ir(
        &instructions,
        &sections,
        synthetic_clean_report(len),
        &bytecode,
    )
    .expect("synthetic CFG builds")
}

fn cfg_instructions(cfg_ir: &CfgIrBundle) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    for node in cfg_ir.cfg.node_indices() {
        if let Block::Body(body) = &cfg_ir.cfg[node] {
            instructions.extend(body.instructions.clone());
        }
    }
    instructions.sort_by_key(|instr| instr.pc);
    instructions
}

fn insert_instruction(
    cfg_ir: &mut CfgIrBundle,
    block_old_start_pc: usize,
    instr_idx: usize,
    instr: Instruction,
) {
    let node = cfg_ir
        .cfg
        .node_indices()
        .find(|&idx| match &cfg_ir.cfg[idx] {
            Block::Body(body) => body
                .instructions
                .first()
                .is_some_and(|first| first.pc == block_old_start_pc),
            _ => false,
        })
        .expect("block exists");
    if let Block::Body(body) = cfg_ir.cfg.node_weight_mut(node).expect("node present") {
        body.instructions.insert(instr_idx, instr);
    }
}

fn instr(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
    Instruction {
        pc,
        op,
        imm: imm.map(|s| s.to_string()),
    }
}

#[tokio::test]
async fn test_storage_cfg_runtime_bounds_detected() {
    let cfg_ir = build_storage_cfg().await;
    let bounds = cfg_ir
        .runtime_bounds
        .expect("storage bytecode should expose runtime bounds");

    let expected_bounds = cfg_ir
        .sections
        .iter()
        .find(|section| section.kind == SectionKind::Runtime)
        .map(|section| (section.offset, section.offset + section.len))
        .expect("storage bytecode should expose a runtime section");
    assert_eq!(bounds, expected_bounds);

    let build_event = cfg_ir
        .trace
        .first()
        .expect("build_cfg_ir should seed a trace event");
    assert!(matches!(build_event.kind, OperationKind::Build { .. }));
    let snapshot = match &build_event.diff {
        CfgIrDiff::FullSnapshot(snapshot) => snapshot.as_ref(),
        other => panic!("expected full snapshot diff, got {other:?}"),
    };
    assert_eq!(snapshot.runtime_bounds, cfg_ir.runtime_bounds);
}

#[tokio::test]
async fn test_storage_cfg_graph_shape() {
    let cfg_ir = build_storage_cfg().await;

    let build_event = cfg_ir
        .trace
        .first()
        .expect("build_cfg_ir should seed a trace event");
    let (expected_body_blocks, expected_section_count) = match &build_event.kind {
        OperationKind::Build {
            body_blocks,
            sections,
        } => (*body_blocks, *sections),
        _ => panic!("expected build event to record body blocks"),
    };
    let snapshot = match &build_event.diff {
        CfgIrDiff::FullSnapshot(snapshot) => snapshot.as_ref(),
        other => panic!("expected full snapshot diff, got {other:?}"),
    };
    assert_eq!(snapshot.blocks.len(), cfg_ir.cfg.node_count());
    assert_eq!(snapshot.edges.len(), cfg_ir.cfg.edge_count());
    let body_block_count = cfg_ir
        .cfg
        .node_indices()
        .filter(|idx| matches!(cfg_ir.cfg[*idx], Block::Body(_)))
        .count();
    assert_eq!(body_block_count, expected_body_blocks);
    assert_eq!(cfg_ir.sections.len(), expected_section_count);
    assert!(
        cfg_ir.trace.get(1).is_none(),
        "build should be the only recorded operation"
    );

    let entry = cfg_ir
        .cfg
        .node_indices()
        .find(|idx| matches!(cfg_ir.cfg[*idx], Block::Entry))
        .expect("CFG must contain an entry node");
    let entry_targets: Vec<_> = cfg_ir.cfg.edges(entry).map(|edge| edge.target()).collect();
    assert!(
        !entry_targets.is_empty(),
        "entry node should connect to at least one successor"
    );
    let first_body = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|idx| match &cfg_ir.cfg[idx] {
            Block::Body(body) => Some((idx, body.start_pc)),
            _ => None,
        })
        .min_by_key(|(_, pc)| *pc)
        .map(|(idx, _)| idx)
        .expect("CFG must contain a body block");
    assert!(
        entry_targets.contains(&first_body),
        "entry should connect to the first body block"
    );
}

#[tokio::test]
async fn test_storage_cfg_trace_progression() {
    let mut cfg_ir = build_storage_cfg().await;
    let initial_len = cfg_ir.trace.len();
    assert!(
        !cfg_ir.trace.is_empty(),
        "build should seed at least one trace entry"
    );
    let initial_build_events = cfg_ir
        .trace
        .iter()
        .filter(|event| matches!(event.kind, OperationKind::Build { .. }))
        .count();
    assert_eq!(
        initial_len, initial_build_events,
        "initial trace should only contain build events"
    );

    let initial_instruction_pcs: HashSet<usize> = {
        let mut pcs = HashSet::new();
        for node in cfg_ir.cfg.node_indices() {
            if let Block::Body(body) = &cfg_ir.cfg[node] {
                pcs.extend(body.instructions.iter().map(|instr| instr.pc));
            }
        }
        pcs
    };

    let (mapping, old_runtime_bounds) = cfg_ir
        .reindex_pcs()
        .expect("reindexing PCs for storage bytecode should succeed");
    dbg!(&cfg_ir.trace);
    assert_eq!(
        mapping.len(),
        initial_instruction_pcs.len(),
        "mapping should cover every instruction PC"
    );
    assert!(
        mapping
            .keys()
            .all(|pc| initial_instruction_pcs.contains(pc)),
        "mapping should only remap known instruction PCs"
    );
    assert!(cfg_ir.trace.len() > initial_len);
    let reindex_event = cfg_ir
        .trace
        .iter()
        .rev()
        .find(|event| matches!(event.kind, OperationKind::ReindexPcs))
        .expect("trace should contain a ReindexPcs event");
    assert_eq!(reindex_event.remapped_pcs.as_ref(), Some(&mapping));
    assert!(matches!(reindex_event.diff, CfgIrDiff::PcsRemapped { .. }));

    cfg_ir
        .patch_jump_immediates(&mapping, old_runtime_bounds)
        .expect("patching jump immediates should succeed");

    assert!(cfg_ir.trace.len() > initial_len);
    let patch_event = cfg_ir
        .trace
        .iter()
        .rev()
        .find(|event| matches!(event.kind, OperationKind::PatchJumpImmediates))
        .expect("trace should contain a PatchJumpImmediates event");
    assert_eq!(patch_event.remapped_pcs.as_ref(), Some(&mapping));
    assert!(matches!(
        patch_event.diff,
        CfgIrDiff::BlockChanges(_) | CfgIrDiff::None
    ));

    let wrote_symbolic = cfg_ir
        .trace
        .iter()
        .any(|event| matches!(event.kind, OperationKind::WriteSymbolicImmediates { .. }));
    let mapping_changed = mapping.iter().any(|(old_pc, new_pc)| old_pc != new_pc);
    if mapping_changed {
        assert!(
            wrote_symbolic,
            "non-identity PC remap should trigger symbolic immediate writes"
        );
    }
}

// -----------------------------------------------------------------------
// push_reaches_jump unit tests
//
// `push_reaches_jump` gates `remap_orphan_jump_pushes`'s extended scan so
// only PUSH literals whose value is *plausibly* a branch target get
// remapped after a PC-shifting transform. The critical invariants these
// tests pin down are:
//
//   * direct JUMP/JUMPI targets -> true
//   * values consumed by non-jump ops (arithmetic, MSTORE/SSTORE,
//     SLOAD as the slot operand, …) -> false
//   * JUMPI condition (pos == 1 at the JUMPI) -> false, even though
//     the value happens to be a boolean
//   * stack-carried values (Solidity internal-function-call pattern
//     where the return address sits beneath the JUMP's target) ->
//     true, which is the reason the entire extended scan exists
//
// Together these ensure the post-reindex remap cannot silently corrupt
// a PUSH2 whose 16-bit literal numerically coincides with a JUMPDEST
// PC but semantically is not a branch target.
// -----------------------------------------------------------------------

fn prj_instr(pc: usize, op: Opcode, imm: Option<&str>) -> Instruction {
    Instruction {
        pc,
        op,
        imm: imm.map(|s| s.to_string()),
    }
}

#[test]
fn push_reaches_jump_direct_jump_target() {
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::JUMP, None),
    ];
    assert!(push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_direct_jumpi_target() {
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(1), Some("01")),   // cond
        prj_instr(2, Opcode::PUSH(2), Some("0100")), // target
        prj_instr(5, Opcode::JUMPI, None),
    ];
    assert!(push_reaches_jump(&instrs, 1));
}

#[test]
fn push_reaches_jump_jumpi_condition_is_rejected() {
    // `PUSH 0x0100; PUSH <target>; JUMPI` -> at JUMPI the first PUSH
    // (0x0100) is at pos 1, which is the JUMPI condition, not the
    // branch target.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")), // value matches a JUMPDEST PC
        prj_instr(3, Opcode::PUSH(2), Some("0200")), // target
        prj_instr(6, Opcode::JUMPI, None),
    ];
    assert!(!push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_consumed_by_add_is_rejected() {
    // `PUSH 0x0100; PUSH 0x05; ADD` -> ADD pops top two, producing
    // `0x0105`. Our tracked PUSH at idx 0 is one of the two consumed
    // positions -> false.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::PUSH(1), Some("05")),
        prj_instr(5, Opcode::ADD, None),
    ];
    assert!(!push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_consumed_by_sstore_as_slot_is_rejected() {
    // `PUSH <value>; PUSH <slot>; SSTORE` -> SSTORE pops top 2. The
    // first PUSH ends up at pos 1 when SSTORE runs and is consumed as
    // the value operand -> false.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("00ff")),
        prj_instr(3, Opcode::PUSH(1), Some("07")),
        prj_instr(5, Opcode::SSTORE, None),
    ];
    assert!(!push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_consumed_by_sload_as_slot_is_rejected() {
    // `PUSH 0x0100; SLOAD` -> SLOAD pops top (our value, used as the
    // slot). The matching PC might numerically equal a JUMPDEST but
    // semantically it's a storage slot literal, not a branch target.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::SLOAD, None),
    ];
    assert!(!push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_stack_carried_past_internal_call() {
    // Solidity internal-function-call convention:
    //
    //     PUSH ret_addr    ; return address (our tracked PUSH)
    //     DUP2             ; copy deeper stack arg
    //     DUP4             ; copy another deeper stack arg
    //     PUSH func_entry  ; function to call
    //     JUMP             ; transfer control — `func_entry` is the
    //                        JUMP target, `ret_addr` is stack-carried
    //                        and will be consumed by a JUMP inside
    //                        the callee after it finishes.
    //
    // The tracked PUSH must reach this JUMP with pos != 0 and the
    // function must still return `true` — otherwise the extended scan
    // would fail to remap return addresses after a PC-shifting
    // transform grew the callee, recreating the `collect() HALT
    // InvalidJump` regression from the push_split fix.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0326")), // ret_addr
        prj_instr(3, Opcode::DUP(2), None),
        prj_instr(4, Opcode::DUP(4), None),
        prj_instr(5, Opcode::PUSH(2), Some("0a72")), // func entry
        prj_instr(8, Opcode::JUMP, None),
    ];
    assert!(push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_stack_carried_to_block_end() {
    // No JUMP in this slice. The tracked PUSH survives to the end
    // and is assumed to flow into the next block via the stack.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::DUP(2), None),
        prj_instr(4, Opcode::SWAP(1), None),
    ];
    assert!(push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_consumed_after_sstore_sequence() {
    // Mirrors the Solidity pattern where storage slot initializers run
    // between a return-address PUSH and the callee's JUMP. The
    // tracked PUSH at idx 0 should survive both SSTOREs and reach
    // the final JUMP.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("05c2")),
        prj_instr(3, Opcode::DUP(3), None),
        prj_instr(4, Opcode::PUSH(1), Some("ff")),
        prj_instr(6, Opcode::SWAP(4), None),
        prj_instr(7, Opcode::PUSH0, None),
        prj_instr(8, Opcode::SSTORE, None),
        prj_instr(9, Opcode::PUSH(1), Some("02")),
        prj_instr(11, Opcode::SSTORE, None),
        prj_instr(12, Opcode::JUMP, None),
    ];
    assert!(push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_terminal_without_jump_is_rejected() {
    // `PUSH 0x0100; STOP` — the block terminates in STOP without the
    // tracked value ever being consumed by a JUMP. Even though the
    // value numerically matches a JUMPDEST PC, it's not a branch
    // target because execution never branches on it.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::STOP, None),
    ];
    assert!(!push_reaches_jump(&instrs, 0));
}

#[test]
fn push_reaches_jump_dup_of_tracked_slot_is_conservative() {
    // DUP1 with our value at pos 0 duplicates us: one copy sits at
    // pos 0 (new top) and the original shifts to pos 1. Either copy
    // could reach a downstream JUMP; returning `true` is the
    // conservative (no false negative) behavior.
    let instrs = vec![
        prj_instr(0, Opcode::PUSH(2), Some("0100")),
        prj_instr(3, Opcode::DUP(1), None),
        prj_instr(4, Opcode::POP, None), // consume one copy
        prj_instr(5, Opcode::JUMP, None),
    ];
    assert!(push_reaches_jump(&instrs, 0));
}

#[tokio::test]
async fn direct_jump_relocation_survives_block_growth() {
    // Regression for adjacent direct jump targets. The source block grows
    // before reindexing, so the old PUSH immediate must be relocated to the
    // target block's final PC rather than left as the stale old PC.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::JUMPDEST, None),
        instr(1, Opcode::PUSH(1), Some("04")),
        instr(3, Opcode::JUMP, None),
        instr(4, Opcode::JUMPDEST, None),
        instr(5, Opcode::STOP, None),
    ]);

    insert_instruction(&mut cfg_ir, 0, 1, instr(0x80, Opcode::PUSH0, None));
    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().direct, 1);

    cfg_ir.reindex_pcs().expect("reindex succeeds");
    let instructions = cfg_instructions(&cfg_ir);
    let jump_push = instructions
        .iter()
        .find(|instr| matches!(instr.op, Opcode::PUSH(1)) && instr.pc == 2)
        .expect("jump target push present");
    assert_eq!(jump_push.imm.as_deref(), Some("05"));

    let bytes = encoder::encode(&instructions, &[]).expect("encoded bytecode");
    validator::validate_jump_targets(&bytes)
        .await
        .expect("statically resolvable jumps validate");
}

#[tokio::test]
async fn direct_jumpi_relocation_survives_block_growth() {
    // `JUMPI` consumes the target from the top of stack and condition from the
    // next slot. Growing the block must rewrite only the target PUSH.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("01")),
        instr(2, Opcode::PUSH(1), Some("06")),
        instr(4, Opcode::JUMPI, None),
        instr(5, Opcode::STOP, None),
        instr(6, Opcode::JUMPDEST, None),
        instr(7, Opcode::STOP, None),
    ]);

    insert_instruction(&mut cfg_ir, 0, 1, instr(0x80, Opcode::PUSH0, None));
    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().branch, 1);

    cfg_ir.reindex_pcs().expect("reindex succeeds");
    let instructions = cfg_instructions(&cfg_ir);
    let immediates: Vec<_> = instructions
        .iter()
        .filter_map(|instr| matches!(instr.op, Opcode::PUSH(1)).then_some(instr.imm.as_deref()))
        .collect();
    assert!(
        immediates.contains(&Some("01")),
        "condition stays unchanged"
    );
    assert!(immediates.contains(&Some("07")), "target is relocated");

    let bytes = encoder::encode(&instructions, &[]).expect("encoded bytecode");
    validator::validate_jump_targets(&bytes)
        .await
        .expect("statically resolvable jumps validate");
}

#[tokio::test]
async fn pc_relative_delta_recomputes_after_intervening_block_growth() {
    // PC-relative branches encode `target - pc_instruction`. Growing a block
    // between the source and target changes only the target side, so the delta
    // must be recomputed from the final `PC` instruction address.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("04")),
        instr(2, Opcode::PC, None),
        instr(3, Opcode::ADD, None),
        instr(4, Opcode::JUMPI, None),
        instr(5, Opcode::STOP, None),
        instr(6, Opcode::JUMPDEST, None),
        instr(7, Opcode::STOP, None),
    ]);

    insert_instruction(&mut cfg_ir, 5, 0, instr(0x80, Opcode::PUSH0, None));
    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().pc_relative, 1);

    cfg_ir.reindex_pcs().expect("reindex succeeds");
    let instructions = cfg_instructions(&cfg_ir);
    let delta_push = instructions
        .iter()
        .find(|instr| matches!(instr.op, Opcode::PUSH(1)))
        .expect("delta push present");
    assert_eq!(delta_push.imm.as_deref(), Some("05"));

    let bytes = encoder::encode(&instructions, &[]).expect("encoded bytecode");
    validator::validate_jump_targets(&bytes)
        .await
        .expect("PC-relative branch validates");
}

#[test]
fn split_add_relocation_recomputes_parts_after_block_growth() {
    // Split-add jump encodings hide the target in `a + b`; neither PUSH alone
    // is a PC. Relocation rewrites both parts so the sum names the final block.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("02")),
        instr(2, Opcode::PUSH(1), Some("04")),
        instr(4, Opcode::ADD, None),
        instr(5, Opcode::JUMP, None),
        instr(6, Opcode::JUMPDEST, None),
        instr(7, Opcode::STOP, None),
    ]);

    insert_instruction(&mut cfg_ir, 0, 0, instr(0x80, Opcode::PUSH0, None));
    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().split_add, 1);

    cfg_ir.reindex_pcs().expect("reindex succeeds");
    let parts: Vec<_> = cfg_instructions(&cfg_ir)
        .iter()
        .filter(|instr| matches!(instr.op, Opcode::PUSH(1)))
        .map(|instr| usize::from_str_radix(instr.imm.as_deref().unwrap(), 16).unwrap())
        .collect();
    assert_eq!(parts.iter().sum::<usize>(), 7);
}

#[tokio::test]
async fn return_address_relocation_survives_block_growth() {
    // Regression test for Solidity-style internal calls. The return address is
    // pushed before jumping to the internal function and is consumed by a later
    // bare JUMP, so adjacent PUSH/JUMP patching cannot find it.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("05")),
        instr(2, Opcode::PUSH(1), Some("07")),
        instr(4, Opcode::JUMP, None),
        instr(5, Opcode::JUMPDEST, None),
        instr(6, Opcode::STOP, None),
        instr(7, Opcode::JUMPDEST, None),
        instr(8, Opcode::JUMP, None),
    ]);

    insert_instruction(&mut cfg_ir, 0, 0, instr(0x80, Opcode::PUSH0, None));
    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().return_address, 1);
    assert!(
        !table.has_unresolved_dynamic_jumps(),
        "bare internal-function return JUMP is covered by recovered return targets"
    );

    cfg_ir.reindex_pcs().expect("reindex succeeds");
    let instructions = cfg_instructions(&cfg_ir);
    let return_push = instructions
        .iter()
        .find(|instr| matches!(instr.op, Opcode::PUSH(1)) && instr.pc == 1)
        .expect("return-address push present");
    assert_eq!(return_push.imm.as_deref(), Some("06"));

    let bytes = encoder::encode(&instructions, &[]).expect("encoded bytecode");
    validator::validate_jump_targets(&bytes)
        .await
        .expect("direct internal-call jump validates");
}

#[test]
fn sload_literal_equal_to_jumpdest_is_not_relocated() {
    // False-positive guard: a PUSH that numerically equals a JUMPDEST but is
    // consumed by SLOAD is a storage slot, not a control-flow relocation.
    let cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(2), Some("0100")),
        instr(3, Opcode::SLOAD, None),
        instr(4, Opcode::STOP, None),
        instr(0x100, Opcode::JUMPDEST, None),
        instr(0x101, Opcode::STOP, None),
    ]);

    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().return_address, 0);
    assert_eq!(table.suspicious_pc_literals.len(), 1);
}

#[test]
fn sstore_literal_equal_to_jumpdest_is_not_relocated() {
    // False-positive guard: SSTORE consumes both slot and value operands, so a
    // matching PC literal in that operand pair must be treated as data.
    let cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(2), Some("0100")),
        instr(3, Opcode::PUSH(1), Some("00")),
        instr(5, Opcode::SSTORE, None),
        instr(6, Opcode::STOP, None),
        instr(0x100, Opcode::JUMPDEST, None),
        instr(0x101, Opcode::STOP, None),
    ]);

    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().return_address, 0);
    assert_eq!(table.suspicious_pc_literals.len(), 1);
}

#[test]
fn jumpi_condition_literal_equal_to_jumpdest_is_not_relocated() {
    // `JUMPI` target and condition have different stack positions. The first
    // PUSH is the condition here and must not be relocated, even though it
    // equals the target JUMPDEST.
    let cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("05")),
        instr(2, Opcode::PUSH(1), Some("05")),
        instr(4, Opcode::JUMPI, None),
        instr(5, Opcode::JUMPDEST, None),
        instr(6, Opcode::STOP, None),
    ]);

    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().branch, 1);
    assert_eq!(table.stats().return_address, 0);
    assert_eq!(table.suspicious_pc_literals.len(), 1);
}

#[test]
fn terminal_block_literal_equal_to_jumpdest_is_not_relocated() {
    // A block ending in STOP never branches on the pushed value, so a matching
    // JUMPDEST literal is reported but not remapped.
    let cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("03")),
        instr(2, Opcode::STOP, None),
        instr(3, Opcode::JUMPDEST, None),
        instr(4, Opcode::STOP, None),
    ]);

    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert!(table.entries.is_empty());
    assert_eq!(table.suspicious_pc_literals.len(), 1);
}

#[test]
fn unresolved_dynamic_jump_blocks_layout_transform() {
    // Arbitrary runtime-computed targets such as CALLDATALOAD; JUMP are not
    // relocatable by this pass, so a layout-changing transform must skip.
    let mut cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::CALLDATALOAD, None),
        instr(1, Opcode::JUMP, None),
        instr(2, Opcode::JUMPDEST, None),
        instr(3, Opcode::STOP, None),
    ]);

    assert!(cfg_ir.has_unresolved_dynamic_jumps());
    let seed = Seed::from_bytes([7u8; 32]);
    let mut rng = seed.create_deterministic_rng();
    let changed = Shuffle
        .apply(&mut cfg_ir, &mut rng)
        .expect("shuffle handles safety gate");
    assert!(!changed);
}

#[test]
fn relocation_recovery_classifies_dup_jumpi_target() {
    // Conditional jump example from the relocation docs: DUP copies the target
    // to the top of stack, and the copied target, not the condition slot, is
    // what JUMPI consumes first.
    let cfg_ir = synthetic_cfg(vec![
        instr(0, Opcode::PUSH(1), Some("04")),
        instr(2, Opcode::DUP(1), None),
        instr(3, Opcode::JUMPI, None),
        instr(4, Opcode::JUMPDEST, None),
        instr(5, Opcode::STOP, None),
    ]);

    let table = cfg_ir
        .recover_relocations(cfg_ir.runtime_bounds)
        .expect("relocations recover");
    assert_eq!(table.stats().branch, 1);
    assert!(matches!(
        table.entries[0].kind,
        RelocKind::RuntimeRelativePc
    ));
}
