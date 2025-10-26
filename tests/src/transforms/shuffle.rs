use azoth_analysis::collect_metrics;
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;

#[tokio::test]
async fn test_shuffle_reorders_blocks() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();
    let bytecode = "0x6004565b60016000555b60026000555b6003600055";
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false).await.unwrap();

    let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();
    let transform = Shuffle;
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    let after = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    assert!(changed, "Shuffle should reorder blocks");
    assert_eq!(
        before.byte_len, after.byte_len,
        "Byte length should not change"
    );
}
