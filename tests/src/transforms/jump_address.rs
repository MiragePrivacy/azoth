use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::Transform;

#[tokio::test]
async fn legacy_jump_address_transformer_fails_closed_on_invalid_layout() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .without_time()
        .try_init();

    // Simple bytecode with a conditional jump
    let bytecode = "0x60085760015b00"; // PUSH1 0x08, JUMPI, PUSH1 0x01, JUMPDEST, STOP
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    let transform = JumpAddressTransformer::new();

    let error = transform
        .apply(&mut cfg_ir, &mut rng)
        .expect_err("the legacy pass must not emit overlapping instruction spans");
    assert!(
        error.to_string().contains("invalid block structure")
            && error.to_string().contains("gap or overlap"),
        "unexpected fail-closed error: {error}"
    );
}

#[test]
fn test_split_jump_target() {
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();
    let transformer = JumpAddressTransformer::new();

    let target = 0x100;
    let (part1, part2) = transformer.split_jump_target(target, &mut rng);

    assert_eq!(
        part1 + part2,
        target,
        "Split parts should sum to original target"
    );
    assert!(part1 < target, "First part should be less than target");
    assert!(part1 > 0, "First part should be greater than 0");
}
