use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;

#[tokio::test]
async fn legacy_shuffle_fails_closed_instead_of_using_temporary_overlapping_pcs() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();
    let bytecode = "0x6004565b60016000555b60026000555b6003600055";
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    let seed = Seed::from_bytes([0x51; 32]);
    let mut rng = seed.create_deterministic_rng();
    let transform = Shuffle;
    let error = transform
        .apply(&mut cfg_ir, &mut rng)
        .expect_err("temporary block PCs must fail structural validation");
    assert!(
        error.to_string().contains("invalid block structure")
            && error.to_string().contains("gap or overlap"),
        "unexpected fail-closed error: {error}"
    );
}

#[tokio::test]
async fn legacy_shuffle_storage_fixture_fails_closed() {
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

    let seed = Seed::from_bytes([0x52; 32]);
    let mut rng = seed.create_deterministic_rng();
    let transform = Shuffle;
    let error = transform
        .apply(&mut cfg_ir, &mut rng)
        .expect_err("temporary block PCs must fail structural validation");
    assert!(
        error.to_string().contains("invalid block structure")
            && error.to_string().contains("gap or overlap"),
        "unexpected fail-closed error: {error}"
    );
}
