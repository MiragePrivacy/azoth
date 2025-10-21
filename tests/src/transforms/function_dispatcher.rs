use azoth_core::decoder;
use azoth_core::detection;
use azoth_core::detection::SectionKind;
use azoth_core::normalize_hex_string;
use azoth_core::process_bytecode_to_cfg;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::obfuscate_bytecode;
use azoth_transform::obfuscator::ObfuscationConfig;

const SIMPLE_BYTECODE: &str =
    "0x60003560e01c80637ff36ab514601e578063a9059cbb14602357600080fd5b600080fd5b600080fd";

const COUNTER_BYTECODE: &str =
    "0x6080604052348015600e575f5ffd5b506101d98061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806306661abd1461004e578063371303c01461006c5780636d4ce63c14610076578063b3bcfa8214610094575b5f5ffd5b61005661009e565b60405161006391906100f7565b60405180910390f35b6100746100a3565b005b61007e6100bd565b60405161008b91906100f7565b60405180910390f35b61009c6100c5565b005b5f5481565b60015f5f8282546100b4919061013d565b92505081905550565b5f5f54905090565b60015f5f8282546100d69190610170565b92505081905550565b5f819050919050565b6100f1816100df565b82525050565b5f60208201905061010a5f8301846100e8565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610147826100df565b9150610152836100df565b925082820190508082111561016a57610169610110565b5b92915050565b5f61017a826100df565b9150610185836100df565b925082820390508181111561019d5761019c610110565b5b9291505056fea264697066735822122078c44612ebfc52f8c09e96e351b62f1c6feebaa2694fa7d29431ccb4ae9ed15064736f6c634300081c0033";

#[tokio::test]
async fn test_dispatcher_transformation_and_determinism() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    println!("Input bytecode: {}", SIMPLE_BYTECODE);

    // Analyze original bytecode
    let (instructions, _, _, _) = decoder::decode_bytecode(SIMPLE_BYTECODE, false)
        .await
        .unwrap();

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

    let result1 = obfuscate_bytecode(SIMPLE_BYTECODE, config1).await.unwrap();
    let result2 = obfuscate_bytecode(SIMPLE_BYTECODE, config2).await.unwrap();

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
        result1.obfuscated_bytecode, SIMPLE_BYTECODE,
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

#[tokio::test]
async fn test_counter_dispatcher_detection() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    let (_, instructions, sections, _) = process_bytecode_to_cfg(COUNTER_BYTECODE, false)
        .await
        .unwrap();

    let runtime_section = sections
        .iter()
        .find(|section| section.kind == SectionKind::Runtime)
        .expect("runtime section is detected");

    let runtime_instructions: Vec<_> = instructions
        .iter()
        .filter(|instruction| {
            instruction.pc >= runtime_section.offset
                && instruction.pc < runtime_section.offset + runtime_section.len
        })
        .cloned()
        .collect();

    let dispatcher_info = detection::detect_function_dispatcher(&runtime_instructions)
        .expect("Function dispatcher should be detected for the Counter runtime");
    assert_eq!(
        dispatcher_info.selectors.len(),
        4,
        "Expected four selectors in Counter dispatcher"
    );

    let result = obfuscate_bytecode(COUNTER_BYTECODE, ObfuscationConfig::default())
        .await
        .expect("obfuscator should succeed");

    assert!(
        result
            .metadata
            .transforms_applied
            .iter()
            .any(|name| name == "FunctionDispatcher"),
        "Function dispatcher transform should be applied when detection succeeds"
    );
    println!(
        "Applied transforms: {:?}",
        result.metadata.transforms_applied
    );

    let normalized_input = normalize_hex_string(COUNTER_BYTECODE).expect("valid hex input");
    let sanitized_output = result
        .obfuscated_bytecode
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    assert_ne!(
        sanitized_output, normalized_input,
        "Obfuscated bytecode should differ once dispatcher transform runs"
    );

    let mapping = result
        .selector_mapping
        .as_ref()
        .expect("Selector mapping should be emitted for dispatcher transform");
    println!(
        "Selector mapping entries: {} -> {:?}",
        mapping.len(),
        mapping.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        mapping.len(),
        dispatcher_info.selectors.len(),
        "Selector mapping should cover all dispatcher selectors"
    );
}
