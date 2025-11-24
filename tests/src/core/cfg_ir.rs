use azoth_core::cfg_ir::{build_cfg_ir, Block, CfgIrBundle, CfgIrDiff, OperationKind};
use azoth_core::detection::{self, SectionKind};
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
        cfg_ir.trace.iter().skip(1).next().is_none(),
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
        entry_targets.iter().any(|target| *target == first_body),
        "entry should connect to the first body block"
    );
}

#[tokio::test]
async fn test_storage_cfg_trace_progression() {
    let mut cfg_ir = build_storage_cfg().await;
    let initial_len = cfg_ir.trace.len();
    assert!(
        cfg_ir.trace.first().is_some(),
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
