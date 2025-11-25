use azoth_analysis::collect_metrics;
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;

#[tokio::test]
async fn test_shuffle_reorders_blocks() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();
    let bytecode = "0x6004565b60016000555b60026000555b6003600055";
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    let before = collect_metrics(&cfg_ir, &cfg_ir.clean_report).unwrap();
    let seed = Seed::generate();
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

#[tokio::test]
async fn test_shuffle_storage_bytecode() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    let bytecode = include_str!("../../bytecode/storage.hex").trim();
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    // Collect block start PCs before shuffle
    let before_pcs: Vec<usize> = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|n| {
            if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[n] {
                Some(body.start_pc)
            } else {
                None
            }
        })
        .collect();

    println!("Block PCs before shuffle: {:?}", before_pcs);

    let seed = Seed::generate();
    let mut rng = seed.create_deterministic_rng();
    let transform = Shuffle;
    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();

    // Collect block start PCs after shuffle
    let after_pcs: Vec<usize> = cfg_ir
        .cfg
        .node_indices()
        .filter_map(|n| {
            if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[n] {
                Some(body.start_pc)
            } else {
                None
            }
        })
        .collect();

    println!("Block PCs after shuffle: {:?}", after_pcs);
    println!("Shuffle changed: {}", changed);

    // Verify block count didn't change
    assert_eq!(
        before_pcs.len(),
        after_pcs.len(),
        "Block count should remain the same"
    );
}
