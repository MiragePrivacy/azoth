use super::{
    deploy_contract, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, ESCROW_CONTRACT_RUNTIME_BYTECODE,
};
use azoth_core::seed::Seed;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::primitives::Address;

/// Deploy bytecode and verify it executes without reverting
fn deploy_and_verify_contract_revm(bytecode_hex: &str, name: &str) -> Result<(Address, u64)> {
    let outcome = deploy_contract(bytecode_hex)
        .map_err(|e| eyre!("deployment failed for {}: {}", name, e))?;

    println!(
        "✓ {} deployed at {} ({} bytes runtime, {} gas)",
        name,
        outcome.address,
        outcome.runtime.len(),
        outcome.gas_used
    );

    Ok((outcome.address, outcome.gas_used))
}

fn create_config_with_transforms(
    transforms: Vec<Box<dyn Transform>>,
    seed: Seed,
) -> ObfuscationConfig {
    ObfuscationConfig {
        seed,
        transforms,
        preserve_unknown_opcodes: true,
    }
}

#[tokio::test]
async fn test_function_dispatch_only() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing FunctionDispatcher only (no additional transforms)");

    let config = create_config_with_transforms(vec![], seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with function dispatcher: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));

    let (address, _) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "FunctionDispatcher")?;

    println!(
        "✓ FunctionDispatcher test passed - Deployed at: {}",
        address
    );

    Ok(())
}

#[tokio::test]
#[ignore = "Shuffle reorders dispatcher controller/decoy blocks, breaking their stored jump metadata."]
async fn test_shuffle_transform() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle transform");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with shuffle: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));

    let (address, _) = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle")?;
    println!("✓ Shuffle test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_jump_address_transform() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    let seed = Seed::generate();

    println!("Testing JumpAddressTransformer");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(JumpAddressTransformer::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with jump address transformer: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));

    let (address, _) = deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "JumpAddress")?;
    println!("✓ JumpAddress test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_opaque_predicate_transform() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    let seed = Seed::generate();

    println!("Testing OpaquePredicate");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(OpaquePredicate::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with opaque predicate: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let (address, _) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "OpaquePredicate")?;
    println!("✓ OpaquePredicate test passed - Deployed at: {}", address);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_shuffle_and_jump_address() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle + JumpAddressTransformer combination");

    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(Shuffle), Box::new(JumpAddressTransformer::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with shuffle + jump address: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));

    let (address, _) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle+JumpAddress")?;
    println!(
        "✓ Shuffle + JumpAddress test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_shuffle_and_opaque_predicate() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle + OpaquePredicate combination");
    let transforms: Vec<Box<dyn Transform>> =
        vec![Box::new(Shuffle), Box::new(OpaquePredicate::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with shuffle + opaque predicate: {}", e))?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let (address, _) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Shuffle+OpaquePredicate")?;
    println!(
        "✓ Shuffle + OpaquePredicate test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_jump_address_and_opaque_predicate() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing JumpAddressTransformer + OpaquePredicate combination");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(JumpAddressTransformer::new()),
        Box::new(OpaquePredicate::new()),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| {
        eyre!(
            "Failed to obfuscate with jump address + opaque predicate: {}",
            e
        )
    })?;

    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let (address, _) = deploy_and_verify_contract_revm(
        &result.obfuscated_bytecode,
        "JumpAddress+OpaquePredicate",
    )?;
    println!(
        "✓ JumpAddress + OpaquePredicate test passed - Deployed at: {}",
        address
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_all_transforms_enabled() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing all transforms enabled");

    let transforms: Vec<Box<dyn Transform>> = vec![
        Box::new(Shuffle),
        Box::new(JumpAddressTransformer::new()),
        Box::new(OpaquePredicate::new()),
    ];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
    .await
    .map_err(|e| eyre!("Failed to obfuscate with all transforms: {}", e))?;

    // Verify all transforms were applied
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"FunctionDispatcher".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"Shuffle".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"JumpAddressTransformer".to_string()));
    assert!(result
        .metadata
        .transforms_applied
        .contains(&"OpaquePredicate".to_string()));

    let size_increase = result.size_increase_percentage;
    println!(
        "Size increase with all transforms: {:.1}% ({} -> {} bytes)",
        size_increase, result.original_size, result.obfuscated_size
    );

    let (address, _) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "AllTransforms")?;
    println!("✓ All transforms test passed - Deployed at: {}", address);
    println!(
        "  Final size: {} bytes ({:+.1}% vs original)",
        result.obfuscated_size, size_increase
    );
    Ok(())
}
