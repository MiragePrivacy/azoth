use azoth_analysis::{
    collect_metrics, compare,
    metrics::{dom_overlap, dominator_pairs},
};
use azoth_core::{cfg_ir, decoder, detection, result::Error, strip};
use petgraph::graph::NodeIndex;

/// Tests metrics computation for a simple bytecode with linear control flow.
#[tokio::test]
async fn test_collect_metrics_simple() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let bytecode = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();

    let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
    assert_eq!(metrics.byte_len, 6, "Byte length mismatch");
    assert_eq!(metrics.block_cnt, 2, "Block count mismatch");
    assert!(
        metrics.max_stack_peak > 0,
        "Max stack peak should be positive"
    );
    assert!(metrics.potency > 0.0, "Potency score should be positive");
    assert!(
        metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
        "Invalid overlap"
    );
}

/// Tests metrics computation for a single-block bytecode.
#[tokio::test]
async fn test_collect_metrics_single_block() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let bytecode = "0x600050"; // PUSH1 0x00, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();

    let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
    assert_eq!(metrics.byte_len, 3, "Byte length mismatch");
    assert_eq!(metrics.block_cnt, 1, "Block count mismatch");
    assert_eq!(metrics.edge_cnt, 2, "Edge count mismatch");
    assert_eq!(metrics.max_stack_peak, 1, "Max stack peak mismatch");
    assert!(
        metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
        "Invalid overlap"
    );
}

/// Tests metrics computation for a bytecode with conditional branching.
#[tokio::test]
async fn test_collect_metrics_branching() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let bytecode = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();

    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();

    let metrics = collect_metrics(&cfg_ir, &report).expect("Metrics computation failed");
    assert_eq!(metrics.byte_len, 8, "Byte length mismatch");
    assert_eq!(metrics.block_cnt, 2, "Block count mismatch");
    assert_eq!(metrics.edge_cnt, 2, "Edge count mismatch");
    assert!(
        metrics.max_stack_peak >= 1,
        "Max stack peak should be positive"
    );
    assert!(
        metrics.dom_overlap >= 0.0 && metrics.dom_overlap <= 1.0,
        "Invalid overlap"
    );
}

/// Tests that decoding an empty bytecode fails with a parse error.
#[tokio::test]
async fn test_collect_metrics_empty_input() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let err = decoder::decode_bytecode("0x", false)
        .await
        .expect_err("empty blob must fail to decode");
    assert!(matches!(err, Error::ParseError { .. }));
}

/// Tests metrics computation for a CFG with no body blocks.
#[tokio::test]
async fn test_collect_metrics_no_body_blocks() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let bytecode = "0x00"; // STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, false).await.unwrap();

    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();

    let m = collect_metrics(&cfg_ir, &report).expect("single STOP is still code");
    assert_eq!(m.block_cnt, 1, "Single STOP should form one body block");
}

/// Tests the compare function for metrics.
#[tokio::test]
async fn test_compare_metrics() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let bytecode_before = "0x600050"; // PUSH1 0x00, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode_before, false)
        .await
        .unwrap();

    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();
    let metrics_before = collect_metrics(&cfg_ir, &report).unwrap();

    let bytecode_after = "0x600160015601"; // PUSH1 0x01, PUSH1 0x01, ADD
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode_after, false)
        .await
        .unwrap();

    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();
    let metrics_after = collect_metrics(&cfg_ir, &report).unwrap();

    let score = compare(&metrics_before, &metrics_after);
    assert!(score > 0.0, "Transform should increase potency");
}

/// Tests invariant: potency score increases with more edges.
#[tokio::test]
async fn test_potency_edge_increase() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let bytecode_simple = "0x600050"; // PUSH1 0x00, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode_simple, false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();
    let metrics_simple = collect_metrics(&cfg_ir, &report).unwrap();

    let bytecode_complex = "0x6000600157600256"; // PUSH1 0x00, JUMPI, JUMPDEST, STOP
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode_complex, false)
        .await
        .unwrap();
    let sections = detection::locate_sections(&bytes, &instructions).unwrap();
    let (_clean_runtime, report) = strip::strip_bytecode(&bytes, &sections).unwrap();
    let cfg_ir = cfg_ir::build_cfg_ir(&instructions, &sections, report.clone(), &bytes).unwrap();
    let metrics_complex = collect_metrics(&cfg_ir, &report).unwrap();

    assert!(
        metrics_complex.potency > metrics_simple.potency,
        "More edges should increase potency"
    );
}

/// Tests dominator and post-dominator computation for a branching CFG.
#[tokio::test]
async fn test_dominator_computation() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let bytecode = "0x6000600157600256"; // PUSH1 0x00, PUSH1 0x01, JUMPI, PUSH1 0x02, JUMP
    let (cfg_ir, _, _, _) = azoth_core::process_bytecode_to_cfg(bytecode, false)
        .await
        .unwrap();

    let (dominators, post_dominators) = dominator_pairs(&cfg_ir.cfg);
    let overlap = dom_overlap(&dominators, &post_dominators);

    // Verify dominators
    let entry = NodeIndex::<u32>::new(0);
    let first_body = NodeIndex::<u32>::new(2); // First body block is at index 2
    assert!(
        dominators.contains_key(&first_body),
        "First body block should have a dominator"
    );
    assert_eq!(
        dominators.get(&first_body).copied(),
        Some(entry),
        "First body block's dominator should be Entry"
    );

    // Verify post-dominators
    let _exit = NodeIndex::<u32>::new(1); // Exit is at index 1
    let second_body = NodeIndex::<u32>::new(3); // Second body block is at index 3
    assert!(
        post_dominators.contains_key(&first_body),
        "First body block should have a post-dominator"
    );
    assert!(
        !post_dominators.contains_key(&second_body),
        "Second body block should have no post-dominator due to potential loop"
    );
    assert_eq!(
        post_dominators.get(&first_body).copied(),
        Some(second_body),
        "In this graph every path from first body block goes through second body block, not Exit"
    );

    // Verify overlap bounds
    assert!(
        (0.0..=1.0).contains(&overlap),
        "Dominator overlap should be between 0 and 1"
    );

    // Verify metrics integration
    let metrics = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    assert_eq!(
        metrics.dom_overlap, overlap,
        "Metrics overlap should match computed overlap"
    );
}
