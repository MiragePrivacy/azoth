use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::Transform;

#[tokio::test]
async fn test_jump_address_transformer() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    // Simple bytecode with a conditional jump
    let bytecode = "0x60085760015b00"; // PUSH1 0x08, JUMPI, PUSH1 0x01, JUMPDEST, STOP
    let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
        .await
        .unwrap();

    // Count instructions before transformation
    let mut instruction_count_before = 0;
    for node_idx in cfg_ir.cfg.node_indices() {
        if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[node_idx] {
            instruction_count_before += body.instructions.len();
        }
    }

    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng = seed.create_deterministic_rng();

    let transform = JumpAddressTransformer::new();

    let changed = transform.apply(&mut cfg_ir, &mut rng).unwrap();
    assert!(changed, "JumpAddressTransformer should modify bytecode");

    // Count instructions after transformation
    let mut instruction_count_after = 0;
    for node_idx in cfg_ir.cfg.node_indices() {
        if let azoth_core::cfg_ir::Block::Body(body) = &cfg_ir.cfg[node_idx] {
            instruction_count_after += body.instructions.len();
        }
    }

    // Should have more instructions after transformation
    assert!(
        instruction_count_after > instruction_count_before,
        "Instruction count should increase: before={}, after={}",
        instruction_count_before,
        instruction_count_after
    );

    // Verify we added exactly 2 more instructions (1 PUSH was replaced with 2 PUSH + 1 ADD = net +2)
    assert_eq!(
        instruction_count_after,
        instruction_count_before + 2,
        "Should add exactly 2 instructions"
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
