use azoth_core::decoder;
use azoth_core::detection;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::obfuscate_bytecode;
use azoth_transform::obfuscator::ObfuscationConfig;

const BYTECODE: &str =
    "0x60003560e01c80637ff36ab514601e578063a9059cbb14602357600080fd5b600080fd5b600080fd";

#[tokio::test]
async fn test_dispatcher_transformation_and_determinism() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    println!("Input bytecode: {}", BYTECODE);

    // Analyze original bytecode
    let (instructions, _, _, _) = decoder::decode_bytecode(BYTECODE, false).await.unwrap();

    println!("\nOriginal dispatcher structure:");
    for (i, instruction) in instructions.iter().enumerate() {
        println!(
            "  [{}] {} {}",
            i,
            instruction.op,
            instruction.imm.as_deref().unwrap_or("")
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

    // Obfuscation with deterministic seed
    let seed = Seed::generate();
    let config1 = ObfuscationConfig::with_seed(seed.clone());
    let config2 = ObfuscationConfig::with_seed(seed.clone());

    let result1 = obfuscate_bytecode(BYTECODE, config1).await.unwrap();
    let result2 = obfuscate_bytecode(BYTECODE, config2).await.unwrap();

    println!("\nTransformation result:");
    println!("  Original: {} bytes", result1.original_size);
    println!("  Obfuscated: {} bytes", result1.obfuscated_size);
    println!(
        "  Size: {} → {} bytes ({:+.1}%)",
        result1.original_size, result1.obfuscated_size, result1.size_increase_percentage
    );

    // Verify transformation was applied
    assert!(
        result1
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher transform should be applied"
    );
    assert_ne!(
        result1.obfuscated_bytecode, BYTECODE,
        "Bytecode should be modified"
    );

    assert_eq!(
        result1.obfuscated_bytecode, result2.obfuscated_bytecode,
        "Same seed should produce identical obfuscated bytecode"
    );
    assert_eq!(
        result1.selector_mapping, result2.selector_mapping,
        "Same seed should produce identical selector mappings"
    );
    println!("✓ Deterministic obfuscation verified");

    println!("\nObfuscated bytecode hex: {}", result1.obfuscated_bytecode);

    // Decode obfuscated bytecode
    let (obfuscated_instructions, _, _, _) =
        decoder::decode_bytecode(&result1.obfuscated_bytecode, false)
            .await
            .unwrap();

    println!("\nObfuscated dispatcher structure:");
    for (i, instruction) in obfuscated_instructions.iter().enumerate() {
        println!(
            "  [{}] {} {}",
            i,
            instruction.op,
            instruction.imm.as_deref().unwrap_or("")
        );
    }

    // Original selectors are completely removed
    let original_selector_found = obfuscated_instructions.iter().any(|instruction| {
        if let Some(immediate) = &instruction.imm {
            original_selectors.iter().any(|&selector| {
                format!("{:08x}", selector) == *immediate || format!("{:x}", selector) == *immediate
            })
        } else {
            false
        }
    });
    assert!(
        !original_selector_found,
        "Original selectors still present in obfuscated bytecode"
    );
    println!("✓ Original selectors completely removed");

    let mapping = result1.selector_mapping.as_ref().unwrap();
    assert_eq!(mapping.len(), 2, "Should have 2 selector mappings");

    let tokens: Vec<_> = mapping.values().collect();
    assert_ne!(tokens[0], tokens[1], "Tokens should be unique");

    for token in tokens {
        assert!(
            (1..=8).contains(&token.len()),
            "Token should be 1-8 bytes, got {}",
            token.len()
        );
    }
    println!("✓ Token generation is collision-free");

    assert!(
        result1.size_increase_percentage < 100.0,
        "Size increase should be reasonable (< 100%)"
    );

    println!("✓ Transformation applied correctly");
    println!("✓ Determinism verified");
    println!("✓ Original selectors removed");
    println!("✓ Tokens are unique and valid");
}
