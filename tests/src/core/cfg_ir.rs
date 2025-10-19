use azoth_core::cfg_ir::build_cfg_ir;
use azoth_core::{decoder, detection, strip};

#[tokio::test]
async fn test_build_cfg_ir_simple() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

    let cfg_ir =
        build_cfg_ir(&instructions, &sections, report, &bytes).expect("CFG builder failed");
    assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
    assert_eq!(cfg_ir.pc_to_block.len(), 2); // Two body blocks mapped
}

#[tokio::test]
async fn test_build_cfg_ir_straight_line() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x600050"; // PUSH1 0x00, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

    let cfg_ir =
        build_cfg_ir(&instructions, &sections, report, &bytes).expect("CFG builder failed");
    assert_eq!(cfg_ir.cfg.node_count(), 3); // Entry, single block, Exit
    assert_eq!(cfg_ir.cfg.edge_count(), 2); // Entry->block, block->Exit
}

#[tokio::test]
async fn test_build_cfg_ir_diamond() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

    let cfg_ir =
        build_cfg_ir(&instructions, &sections, report, &bytes).expect("CFG builder failed");
    assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
    assert_eq!(cfg_ir.cfg.edge_count(), 2); // Entry->block1, BranchFalse
}

#[tokio::test]
async fn test_build_cfg_ir_loop() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x60005b6000"; // PUSH1 0x00, JUMPDEST, PUSH1 0x00
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

    let cfg_ir =
        build_cfg_ir(&instructions, &sections, report, &bytes).expect("CFG builder failed");
    assert_eq!(cfg_ir.cfg.node_count(), 4); // Entry, two blocks, Exit
    assert_eq!(cfg_ir.cfg.edge_count(), 3); // Entry->block0, block0->block2, block2->Exit
}

#[tokio::test]
async fn test_build_cfg_ir_malformed() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let bytecode = "0x6001"; // PUSH1 0x01, no terminal
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();

    let cfg_ir =
        build_cfg_ir(&instructions, &sections, report, &bytes).expect("CFG builder succeeded");
    assert_eq!(cfg_ir.cfg.node_count(), 3); // Entry, lone block, Exit
}
