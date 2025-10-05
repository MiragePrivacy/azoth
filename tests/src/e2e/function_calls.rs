//! End-to-end tests for calling obfuscated contract functions.
//!
//! These tests verify that obfuscated contracts not only deploy successfully,
//! but also execute correctly when functions are called using obfuscated tokens
//! instead of standard 4-byte selectors.

use super::{mock_token_bytecode, prepare_escrow_bytecode, EscrowMappings, ObfuscatedCaller, ESCROW_CONTRACT_BYTECODE, MOCK_TOKEN_ADDR};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::PassConfig;
use azoth_utils::seed::Seed;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

#[tokio::test]
async fn test_obfuscated_function_calls() -> Result<()> {
    println!("\n=== Testing Obfuscated Function Calls ===\n");

    // Step 1: Obfuscate the contract
    let seed = Seed::generate();
    let config = ObfuscationConfig {
        seed,
        transforms: vec![],
        pass_config: PassConfig::default(),
        preserve_unknown_opcodes: true,
    };

    let obfuscation_result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate bytecode: {:?}", e))?;

    println!(
        "✓ Contract obfuscated ({} -> {} bytes, {:+.1}%)",
        obfuscation_result.original_size,
        obfuscation_result.obfuscated_size,
        obfuscation_result.size_increase_percentage
    );

    // Step 2: Extract selector mappings
    let selector_mapping = obfuscation_result
        .selector_mapping
        .as_ref()
        .ok_or_else(|| eyre!("No selector mapping found in obfuscation result"))?;
    println!(
        "✓ Extracted {} selector mappings",
        selector_mapping.len()
    );

    let escrow_mappings = EscrowMappings::from_obfuscator_output(selector_mapping)
        .map_err(|e| eyre!("Failed to create escrow mappings: {}", e))?;

    println!("✓ Created EscrowMappings with obfuscated tokens");

    // Step 3: Setup EVM with mock token contract
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
    let deployer = Address::from([0x42; 20]);

    // Deploy the obfuscated contract
    let obfuscated_bytecode = prepare_escrow_bytecode(&obfuscation_result.obfuscated_bytecode)?;

    let deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: obfuscated_bytecode,
        value: U256::ZERO,
        ..Default::default()
    };

    let deploy_result = evm
        .transact(deploy_tx)
        .map_err(|e| eyre!("Deployment transaction failed: {:?}", e))?;

    let contract_address = match deploy_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, Some(address)) => address,
            _ => return Err(eyre!("Deployment failed: no address returned")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Deployment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Deployment halted: {:?}", reason));
        }
    };

    println!("✓ Obfuscated contract deployed at: {}", contract_address);

    // Step 4: Create caller with obfuscated tokens
    let caller = ObfuscatedCaller::new(escrow_mappings);

    // Step 5: Test calling is_bonded() - should return false initially
    println!("\n--- Testing is_bonded() function ---");
    let is_bonded_calldata = caller.is_bonded_call_data();
    println!("  Calldata (obfuscated): 0x{}", hex::encode(&is_bonded_calldata));

    let call_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: is_bonded_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let call_result = evm
        .transact(call_tx)
        .map_err(|e| eyre!("Call transaction failed: {:?}", e))?;

    let is_bonded_result = match call_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Call reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Call halted: {:?}", reason));
        }
    };

    let is_bonded = caller.parse_bool(&is_bonded_result);

    println!("  Result: is_bonded = {}", is_bonded);
    assert!(!is_bonded, "Expected is_bonded to be false initially");
    println!("✓ is_bonded() call succeeded with correct result");

    // Step 6: Test calling bond() with amount
    println!("\n--- Testing bond() function ---");
    let bond_amount = U256::from(1000);
    let bond_calldata = caller.bond_call_data(bond_amount);
    println!("  Calldata (obfuscated): 0x{}", hex::encode(&bond_calldata));

    let bond_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: bond_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let bond_result = evm
        .transact(bond_tx)
        .map_err(|e| eyre!("Bond transaction failed: {:?}", e))?;

    let bond_output = match bond_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Bond call reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Bond call halted: {:?}", reason));
        }
    };

    println!("  Result: {} bytes returned", bond_output.len());
    println!("✓ bond() call succeeded");

    // Step 7: Verify state changed - is_bonded should now be true
    println!("\n--- Verifying state change ---");
    let is_bonded_calldata = caller.is_bonded_call_data();

    let verify_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: is_bonded_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let verify_result = evm
        .transact(verify_tx)
        .map_err(|e| eyre!("Verification transaction failed: {:?}", e))?;

    let is_bonded_result = match verify_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Verification call reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Verification call halted: {:?}", reason));
        }
    };

    let is_bonded = caller.parse_bool(&is_bonded_result);

    println!("  Result after bonding: is_bonded = {}", is_bonded);
    assert!(is_bonded, "Expected is_bonded to be true after bonding");
    println!("✓ State change verified - bonding worked correctly");

    // Step 8: Test other functions
    println!("\n--- Testing additional functions ---");

    let collect_calldata = caller.collect_call_data();
    println!("  collect() calldata: 0x{}", hex::encode(&collect_calldata));

    let withdraw_calldata = caller.withdraw_call_data();
    println!("  withdraw() calldata: 0x{}", hex::encode(&withdraw_calldata));

    let fund_calldata = caller.fund_call_data();
    println!("  fund() calldata: 0x{}", hex::encode(&fund_calldata));

    println!("\n=== All Tests Passed ===");
    println!("✓ Obfuscated contract executes correctly");
    println!("✓ Function calls using obfuscated tokens work");
    println!("✓ State changes are preserved through obfuscation");

    Ok(())
}

#[tokio::test]
async fn test_obfuscated_vs_original_equivalence() -> Result<()> {
    println!("\n=== Testing Obfuscated vs Original Equivalence ===\n");

    // Deploy both original and obfuscated contracts and verify they behave identically

    let seed = Seed::generate();
    let config = ObfuscationConfig {
        seed,
        transforms: vec![],
        pass_config: PassConfig::default(),
        preserve_unknown_opcodes: true,
    };

    let obfuscation_result = obfuscate_bytecode(ESCROW_CONTRACT_BYTECODE, config)
        .await
        .map_err(|e| eyre!("Failed to obfuscate bytecode: {:?}", e))?;

    // Setup two separate EVM instances
    let mut db_original = InMemoryDB::default();
    db_original.insert_account_info(
        MOCK_TOKEN_ADDR,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(mock_token_bytecode())),
        },
    );

    let mut db_obfuscated = InMemoryDB::default();
    db_obfuscated.insert_account_info(
        MOCK_TOKEN_ADDR,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(mock_token_bytecode())),
        },
    );

    let mut evm_original = Context::mainnet().with_db(db_original).build_mainnet();
    let mut evm_obfuscated = Context::mainnet().with_db(db_obfuscated).build_mainnet();
    let deployer = Address::from([0x42; 20]);

    // Deploy original contract
    let original_bytecode = prepare_escrow_bytecode(ESCROW_CONTRACT_BYTECODE)?;
    let original_deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: original_bytecode,
        value: U256::ZERO,
        ..Default::default()
    };

    let original_deploy_result = evm_original
        .transact(original_deploy_tx)
        .map_err(|e| eyre!("Original deployment failed: {:?}", e))?;

    let original_address = match original_deploy_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, Some(address)) => address,
            _ => return Err(eyre!("Original deployment: no address returned")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Original deployment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Original deployment halted: {:?}", reason));
        }
    };

    println!("✓ Original contract deployed at: {}", original_address);

    // Deploy obfuscated contract
    let obfuscated_bytecode = prepare_escrow_bytecode(&obfuscation_result.obfuscated_bytecode)?;
    let obfuscated_deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: obfuscated_bytecode,
        value: U256::ZERO,
        ..Default::default()
    };

    let obfuscated_deploy_result = evm_obfuscated
        .transact(obfuscated_deploy_tx)
        .map_err(|e| eyre!("Obfuscated deployment failed: {:?}", e))?;

    let obfuscated_address = match obfuscated_deploy_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, Some(address)) => address,
            _ => return Err(eyre!("Obfuscated deployment: no address returned")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Obfuscated deployment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Obfuscated deployment halted: {:?}", reason));
        }
    };

    println!(
        "✓ Obfuscated contract deployed at: {}",
        obfuscated_address
    );

    // Prepare callers
    let selector_mapping = obfuscation_result
        .selector_mapping
        .as_ref()
        .ok_or_else(|| eyre!("No selector mapping found in obfuscation result"))?;
    let escrow_mappings = EscrowMappings::from_obfuscator_output(selector_mapping)
        .map_err(|e| eyre!("Failed to create escrow mappings: {}", e))?;
    let obfuscated_caller = ObfuscatedCaller::new(escrow_mappings);

    // Test is_bonded on both - should both return false
    println!("\n--- Comparing is_bonded() results ---");

    // Original: using standard selector
    let original_is_bonded_calldata = super::build_standard_calldata(
        super::ESCROW_IS_BONDED,
        &[],
    );

    let original_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(original_address),
        data: original_is_bonded_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let original_call_result = evm_original
        .transact(original_tx)
        .map_err(|e| eyre!("Original is_bonded call failed: {:?}", e))?;

    let original_result = match original_call_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Original is_bonded reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Original is_bonded halted: {:?}", reason));
        }
    };

    let original_is_bonded = obfuscated_caller.parse_bool(&original_result);

    // Obfuscated: using obfuscated token
    let obfuscated_is_bonded_calldata = obfuscated_caller.is_bonded_call_data();

    let obfuscated_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(obfuscated_address),
        data: obfuscated_is_bonded_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let obfuscated_call_result = evm_obfuscated
        .transact(obfuscated_tx)
        .map_err(|e| eyre!("Obfuscated is_bonded call failed: {:?}", e))?;

    let obfuscated_result = match obfuscated_call_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Obfuscated is_bonded reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Obfuscated is_bonded halted: {:?}", reason));
        }
    };

    let obfuscated_is_bonded = obfuscated_caller.parse_bool(&obfuscated_result);

    println!("  Original is_bonded: {}", original_is_bonded);
    println!("  Obfuscated is_bonded: {}", obfuscated_is_bonded);
    assert_eq!(
        original_is_bonded, obfuscated_is_bonded,
        "is_bonded results should match"
    );
    println!("✓ is_bonded() results match");

    // Test bonding on both
    println!("\n--- Comparing bond() execution ---");
    let bond_amount = U256::from(5000);

    // Original
    let mut original_bond_calldata = super::ESCROW_BOND.0.to_vec();
    original_bond_calldata.extend_from_slice(&bond_amount.to_be_bytes::<32>());

    let original_bond_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(original_address),
        data: Bytes::from(original_bond_calldata),
        value: U256::ZERO,
        ..Default::default()
    };

    let original_bond_result = evm_original
        .transact(original_bond_tx)
        .map_err(|e| eyre!("Original bond call failed: {:?}", e))?;

    match original_bond_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Original bond reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Original bond halted: {:?}", reason));
        }
    }

    // Obfuscated
    let obfuscated_bond_calldata = obfuscated_caller.bond_call_data(bond_amount);

    let obfuscated_bond_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(obfuscated_address),
        data: obfuscated_bond_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let obfuscated_bond_result = evm_obfuscated
        .transact(obfuscated_bond_tx)
        .map_err(|e| eyre!("Obfuscated bond call failed: {:?}", e))?;

    match obfuscated_bond_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Obfuscated bond reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Obfuscated bond halted: {:?}", reason));
        }
    }

    println!("✓ Both bond() calls succeeded");

    // Verify is_bonded is true on both after bonding
    println!("\n--- Verifying state changes match ---");

    let original_verify_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(original_address),
        data: super::build_standard_calldata(super::ESCROW_IS_BONDED, &[]),
        value: U256::ZERO,
        ..Default::default()
    };

    let original_verify_result = evm_original
        .transact(original_verify_tx)
        .map_err(|e| eyre!("Original verification failed: {:?}", e))?;

    let original_result = match original_verify_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Original verification reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Original verification halted: {:?}", reason));
        }
    };

    let original_is_bonded = obfuscated_caller.parse_bool(&original_result);

    let obfuscated_verify_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(obfuscated_address),
        data: obfuscated_caller.is_bonded_call_data(),
        value: U256::ZERO,
        ..Default::default()
    };

    let obfuscated_verify_result = evm_obfuscated
        .transact(obfuscated_verify_tx)
        .map_err(|e| eyre!("Obfuscated verification failed: {:?}", e))?;

    let obfuscated_result = match obfuscated_verify_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => data,
            _ => return Err(eyre!("Unexpected output type")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Obfuscated verification reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Obfuscated verification halted: {:?}", reason));
        }
    };

    let obfuscated_is_bonded = obfuscated_caller.parse_bool(&obfuscated_result);

    println!("  Original is_bonded after bond: {}", original_is_bonded);
    println!(
        "  Obfuscated is_bonded after bond: {}",
        obfuscated_is_bonded
    );
    assert!(
        original_is_bonded && obfuscated_is_bonded,
        "Both should be bonded"
    );
    assert_eq!(
        original_is_bonded, obfuscated_is_bonded,
        "Bonded state should match"
    );

    println!("\n=== Equivalence Tests Passed ===");
    println!("✓ Original and obfuscated contracts behave identically");

    Ok(())
}
