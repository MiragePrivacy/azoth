use super::{
    mock_token_bytecode, prepare_bytecode, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, MOCK_TOKEN_ADDR,
};
use azoth_core::seed::Seed;
use azoth_transform::jump_address_transformer::JumpAddressTransformer;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::opaque_predicate::OpaquePredicate;
use azoth_transform::shuffle::Shuffle;
use azoth_transform::Transform;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

/// Deploy bytecode and verify it executes without reverting
fn deploy_and_verify_contract_revm(bytecode_hex: &str, name: &str) -> Result<(Address, u64)> {
    // Prepare bytecode with constructor arguments
    let bytecode_bytes = prepare_bytecode(bytecode_hex)?;

    println!(
        "Testing {} contract deployment ({} bytes)",
        name,
        bytecode_bytes.len()
    );

    // Setup EVM with mock token
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        MOCK_TOKEN_ADDR,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(mock_token_bytecode())),
        },
    );

    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let deployer = Address::from([0x42u8; 20]);

    let tx_env = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: Bytes::from(bytecode_bytes),
        value: U256::ZERO,
        ..Default::default()
    };

    let result = evm
        .transact(tx_env)
        .map_err(|e| eyre!("REVM execution failed for {}: {:?}", name, e))?;

    match result.result {
        ExecutionResult::Success {
            output, gas_used, ..
        } => match output {
            Output::Create(bytes, Some(address)) => {
                println!(
                    "✓ {} deployed at {} ({} bytes runtime, {} gas)",
                    name,
                    address,
                    bytes.len(),
                    gas_used
                );
                Ok((address, gas_used))
            }
            Output::Create(_, None) => Err(eyre!(
                "Contract deployment failed - no address returned for {}",
                name
            )),
            _ => Err(eyre!(
                "Unexpected output type for contract deployment: {}",
                name
            )),
        },
        ExecutionResult::Revert { output, .. } => {
            Err(eyre!("Deployment reverted for {}: {:?}", name, output))
        }
        ExecutionResult::Halt { reason, .. } => Err(eyre!(
            "Deployment halted for {} with reason: {:?}",
            name,
            reason
        )),
    }
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
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
async fn test_shuffle_transform() -> Result<()> {
    let seed = Seed::generate();

    println!("Testing Shuffle transform");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
        .try_init();

    let seed = Seed::generate();

    println!("Testing JumpAddressTransformer");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(JumpAddressTransformer::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
        .try_init();

    let seed = Seed::generate();

    println!("Testing OpaquePredicate");

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(OpaquePredicate::new())];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
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

#[tokio::test]
async fn test_gas_consumption_analysis() -> Result<()> {
    let seed = Seed::generate();
    println!("Testing gas consumption analysis");

    let (_, original_gas) =
        deploy_and_verify_contract_revm(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, "Original")?;

    let transforms: Vec<Box<dyn Transform>> = vec![Box::new(Shuffle)];
    let config = create_config_with_transforms(transforms, seed);
    let result = obfuscate_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate: {}", e))?;

    let (_, obfuscated_gas) =
        deploy_and_verify_contract_revm(&result.obfuscated_bytecode, "Obfuscated")?;

    let gas_increase =
        ((obfuscated_gas as f64 - original_gas as f64) / original_gas as f64) * 100.0;

    println!("Gas Analysis:");
    println!("  Original: {} gas", original_gas);
    println!("  Obfuscated: {} gas", obfuscated_gas);
    println!(
        "  Increase: {:.1}% ({:+} gas)",
        gas_increase,
        obfuscated_gas as i64 - original_gas as i64
    );

    Ok(())
}
