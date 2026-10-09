use azoth_analysis::collect_metrics;
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::Transform;

#[tokio::test]
async fn legacy_opaque_predicate_fails_closed_on_invalid_layout() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .without_time()
        .try_init();
    let bytecode = "0x6001600260016003"; // PUSH1 0x01, PUSH1 0x02, PUSH1 0x01, PUSH1 0x03
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();
    let transform = OpaquePredicate::new();
    let error = transform
        .apply(&mut cfg_ir, &mut rng)
        .expect_err("the relationship validator must reject an invalid legacy layout");
    assert!(
        error.to_string().contains("invalid block structure")
            && error.to_string().contains("gap or overlap"),
        "unexpected fail-closed error: {error}"
    );
    assert_eq!(before.block_cnt, 1);
}
