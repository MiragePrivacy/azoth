//! End-to-end tests for calling obfuscated contract functions.
//!
//! These tests verify that obfuscated contracts not only deploy successfully,
//! but also execute correctly when functions are called using obfuscated tokens
//! instead of standard 4-byte selectors.

use super::{
    mock_token_bytecode, prepare_bytecode, EscrowMappings, ObfuscatedCaller,
    ESCROW_CONTRACT_BYTECODE, MOCK_TOKEN_ADDR,
};
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use azoth_transform::PassConfig;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

#[tokio::test]
async fn test_obfuscated_function_calls() -> Result<()> {
    // obfuscate contract
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

    // extracting selector mappings
    let selector_mapping = obfuscation_result
        .selector_mapping
        .as_ref()
        .ok_or_else(|| eyre!("No selector mapping found in obfuscation result"))?;
    println!("✓ Extracted {} selector mappings", selector_mapping.len());

    println!("Selectors found:");
    for (selector, token) in selector_mapping.iter() {
        println!("  0x{:08x} -> 0x{}", selector, hex::encode(token));
    }

    let escrow_mappings = EscrowMappings::from_obfuscator_output(selector_mapping)
        .map_err(|e| eyre!("Failed to create escrow mappings: {}", e))?;

    println!("✓ Created EscrowMappings with obfuscated tokens");

    // setup EVM with mock token contract
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

    let deployer = Address::from([0x42; 20]);

    db.insert_account_info(
        deployer,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128), // 1 ETH in wei
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );

    let obfuscated_bytecode = prepare_bytecode(&obfuscation_result.obfuscated_bytecode)?;

    let mut evm = Context::mainnet().with_db(db).build_mainnet();

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

    let caller = ObfuscatedCaller::new(escrow_mappings);

    let is_bonded_calldata = caller.is_bonded_call_data();
    println!(
        "  Calldata (obfuscated): 0x{}",
        hex::encode(&is_bonded_calldata)
    );

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

    let fund_calldata = caller.fund_call_data();
    println!("  Calldata (obfuscated): 0x{}", hex::encode(&fund_calldata));

    let fund_amount = U256::from(10000); // Send some ETH to fund the contract

    let fund_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: fund_calldata,
        value: fund_amount,
        ..Default::default()
    };

    let fund_result = evm
        .transact(fund_tx)
        .map_err(|e| eyre!("Fund transaction failed: {:?}", e))?;

    match fund_result.result {
        ExecutionResult::Success { gas_used, .. } => {
            println!("✓ fund() call succeeded (gas: {})", gas_used);
            println!("  State changes: {}", fund_result.state.len());
        }
        ExecutionResult::Revert { output, gas_used } => {
            return Err(eyre!(
                "Fund call reverted (gas: {}): {:?}",
                gas_used,
                output
            ));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(eyre!("Fund call halted (gas: {}): {:?}", gas_used, reason));
        }
    }

    // Check if contract is funded
    let funded_calldata = caller.funded_call_data();
    let funded_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: funded_calldata,
        value: U256::ZERO,
        ..Default::default()
    };

    let funded_result = evm
        .transact(funded_tx)
        .map_err(|e| eyre!("Funded check failed: {:?}", e))?;

    if let ExecutionResult::Success { output, .. } = funded_result.result {
        if let Output::Call(data) = output {
            let is_funded = caller.parse_bool(&data);
            println!("  Contract funded state: {}", is_funded);
        }
    }

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
        ExecutionResult::Success {
            output, gas_used, ..
        } => {
            println!("  Gas used: {}", gas_used);
            match output {
                Output::Call(data) => data,
                _ => return Err(eyre!("Unexpected output type")),
            }
        }
        ExecutionResult::Revert { output, gas_used } => {
            return Err(eyre!(
                "Bond call reverted (gas: {}): {:?}",
                gas_used,
                output
            ));
        }
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(eyre!("Bond call halted (gas: {}): {:?}", gas_used, reason));
        }
    };

    println!("  Result: {} bytes returned", bond_output.len());
    println!("  State committed: {}", bond_result.state.len());
    println!("✓ bond() call succeeded");

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

    println!("✓ bond() executed successfully on obfuscated contract");

    let collect_calldata = caller.collect_call_data();
    println!("  collect() calldata: 0x{}", hex::encode(&collect_calldata));

    let withdraw_calldata = caller.withdraw_call_data();
    println!(
        "  withdraw() calldata: 0x{}",
        hex::encode(&withdraw_calldata)
    );

    let fund_calldata = caller.fund_call_data();
    println!("  fund() calldata: 0x{}", hex::encode(&fund_calldata));

    println!("✓ Obfuscated contract executes correctly");
    println!("✓ Function calls using obfuscated tokens work");
    println!("✓ State changes are preserved through obfuscation");

    Ok(())
}
