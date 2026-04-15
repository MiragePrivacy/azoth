use azoth_core::cfg_ir::{
    build_cfg_ir, push_reaches_jump, Block, CfgIrBundle, CfgIrDiff, OperationKind,
};
use azoth_core::decoder::Instruction;
use azoth_core::detection::{self, SectionKind};
use azoth_core::Opcode;
use azoth_core::{decoder, strip};
use petgraph::visit::EdgeRef;
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
