use azoth_core::decoder;
use azoth_core::detection;
use azoth_core::detection::FunctionSelector;
use azoth_core::seed::Seed;
use azoth_transform::function_dispatcher::FunctionDispatcher;
use azoth_transform::obfuscator::obfuscate_bytecode;
use azoth_transform::obfuscator::ObfuscationConfig;
use azoth_transform::PassConfig;

#[tokio::test]
async fn test_token_dispatcher_obfuscation() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let bytecode =
        "0x60003560e01c80637ff36ab514601e578063a9059cbb14602357600080fd5b600080fd5b600080fd";

    println!("Input bytecode: {}", bytecode);

    // Analyze original bytecode
    let (instructions, _, _, _) = decoder::decode_bytecode(bytecode, false).await.unwrap();

    println!("\nOriginal dispatcher structure:");
    for (i, instr) in instructions.iter().enumerate() {
        println!(
            "  [{}] {} {}",
            i,
            instr.op,
            instr.imm.as_deref().unwrap_or("")
        );
    }

    // Detect original selectors
    let original_selectors =
        if let Some(dispatcher_info) = detection::detect_function_dispatcher(&instructions) {
            println!("\nDetected selectors:");
            for selector in &dispatcher_info.selectors {
                println!(
                    "  0x{:08x} -> jump target 0x{:x}",
                    selector.selector, selector.target_address
                );
            }
            dispatcher_info
                .selectors
                .iter()
                .map(|s| s.selector)
                .collect::<Vec<_>>()
        } else {
            panic!("No dispatcher detected in test bytecode");
        };

    // Apply obfuscation with deterministic seed to prevent flakiness
    let config = ObfuscationConfig::with_seed(
        Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap(),
    );

    let result = obfuscate_bytecode(bytecode, config).await.unwrap();

    println!("\nTransformation result:");
    println!("  Original: {} bytes", result.original_size);
    println!("  Obfuscated: {} bytes", result.obfuscated_size);
    println!(
        "  Size: {} → {} bytes ({:+.1}%)",
        result.original_size, result.obfuscated_size, result.size_increase_percentage
    );
    println!("  Raw bytecode: {}", result.obfuscated_bytecode);

    // Verify transformation was applied
    assert!(
        result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher transform should be applied"
    );
    assert_ne!(
        result.obfuscated_bytecode, bytecode,
        "Bytecode should be modified"
    );

    // Decode obfuscated bytecode
    let (obfuscated_instructions, _, _, _) =
        decoder::decode_bytecode(&result.obfuscated_bytecode, false)
            .await
            .unwrap();

    println!("\nObfuscated dispatcher structure:");
    for (i, instr) in obfuscated_instructions.iter().enumerate() {
        println!(
            "  [{}] {} {}",
            i,
            instr.op,
            instr.imm.as_deref().unwrap_or("")
        );
    }

    // Verify original selectors are completely removed
    let original_selector_found = obfuscated_instructions.iter().any(|instr| {
        if let Some(imm) = &instr.imm {
            original_selectors.iter().any(|&selector| {
                format!("{:08x}", selector) == *imm || format!("{:x}", selector) == *imm
            })
        } else {
            false
        }
    });
    assert!(
        !original_selector_found,
        "Original selectors still present in obfuscated bytecode"
    );

    assert!(
        result.size_increase_percentage < 100.0,
        "Size increase should be reasonable (< 100%)"
    );
}

#[test]
fn test_token_generation_deterministic() {
    let config = PassConfig::default();
    let transform = FunctionDispatcher::new(config);

    // Use fixed seed for deterministic testing
    let seed = Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .unwrap();
    let mut rng1 = seed.create_deterministic_rng();
    let mut rng2 = seed.create_deterministic_rng();

    let selectors = vec![
        FunctionSelector {
            selector: 0xa9059cbb, // transfer(address,uint256)
            target_address: 0x1234,
            instruction_index: 0,
        },
        FunctionSelector {
            selector: 0x095ea7b3, // approve(address,uint256)
            target_address: 0x5678,
            instruction_index: 10,
        },
    ];

    // Generate mappings with same seed
    let mapping1 = transform.generate_mapping(&selectors, &mut rng1).unwrap();
    let mapping2 = transform.generate_mapping(&selectors, &mut rng2).unwrap();

    // Should be identical (deterministic)
    assert_eq!(
        mapping1, mapping2,
        "Token generation should be deterministic with same seed"
    );

    // Should have all selectors
    assert_eq!(mapping1.len(), 2);
    assert!(mapping1.contains_key(&0xa9059cbb));
    assert!(mapping1.contains_key(&0x095ea7b3));

    // Tokens should be different from each other
    let token1 = &mapping1[&0xa9059cbb];
    let token2 = &mapping1[&0x095ea7b3];
    assert_ne!(
        token1, token2,
        "Different selectors should get different tokens"
    );

    // Verify tokens are in expected 1-8 byte range
    assert!(
        (1..=8).contains(&token1.len()),
        "Token1 should be 1-8 bytes, got {}",
        token1.len()
    );
    assert!(
        (1..=8).contains(&token2.len()),
        "Token2 should be 1-8 bytes, got {}",
        token2.len()
    );

    println!("✓ Token generation is deterministic and collision-free");
    println!(
        "  0x{:08x} → {:02x?} ({} bytes)",
        0xa9059cbbu32 as i32,
        token1,
        token1.len()
    );
    println!(
        "  0x{:08x} → {:02x?} ({} bytes)",
        0x095ea7b3u32 as i32,
        token2,
        token2.len()
    );
}
