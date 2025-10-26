use azoth_analysis::collect_metrics;
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::Transform;

#[tokio::test]
async fn test_opaque_predicate_adds_blocks() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let bytecode = "0x6001600260016003"; // PUSH1 0x01, PUSH1 0x02, PUSH1 0x01, PUSH1 0x03
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false).await.unwrap();

    let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();
    let transform = OpaquePredicate::new();
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    assert!(changed, "OpaquePredicate should insert predicates");
    let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    assert!(
        after.block_cnt > before.block_cnt,
        "Block count should increase"
    );
}
