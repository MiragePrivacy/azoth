use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use hex::encode as hex_encode;
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::ContextTr;
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};
use std::collections::HashMap;

const COUNTER_DEPLOYMENT_BYTECODE: &str =
    include_str!("../../bytecode/counter/counter_deployment.hex");

#[allow(dead_code)]
const COUNTER_RUNTIME_BYTECODE: &str = include_str!("../../bytecode/counter/counter_runtime.hex");

const SELECTOR_SET_NUMBER: u32 = 0x3fb5c1cb;
const SELECTOR_NUMBER: u32 = 0x8381f58a;
const SELECTOR_INCREMENT: u32 = 0xd09de08a;

fn selector_token(mapping: &HashMap<u32, Vec<u8>>, selector: u32) -> Result<Bytes> {
    let token = mapping
        .get(&selector)
        .ok_or_else(|| eyre!("Missing token mapping for selector 0x{selector:08x}"))?;

    if token.is_empty() || token.len() > 32 {
        return Err(eyre!(
            "Invalid token length {} for selector 0x{selector:08x}",
            token.len()
        ));
    }

    // The dispatcher uses CALLDATALOAD(0) which loads 32 bytes starting at offset 0,
    // then shifts right by 0xe0 (224 bits) to extract the leftmost 4 bytes.
    // So we need to left-pad the token to 32 bytes.
    let mut padded = vec![0u8; 32];
    padded[..token.len()].copy_from_slice(token);
    Ok(Bytes::from(padded))
}

fn parse_u256(data: &[u8]) -> U256 {
    if data.len() >= 32 {
        U256::from_be_slice(&data[..32])
    } else {
        U256::ZERO
    }
}

#[tokio::test]
async fn test_obfuscated_counter_deploys_and_counts() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let obfuscation_result =
        obfuscate_bytecode(COUNTER_DEPLOYMENT_BYTECODE, ObfuscationConfig::default())
            .await
            .map_err(|e| eyre!("Bytecode transformation failed: {}", e))?;

    assert!(
        obfuscation_result
            .metadata
            .transforms_applied
            .contains(&"FunctionDispatcher".to_string()),
        "FunctionDispatcher transform must be applied"
    );

    let selector_mapping = obfuscation_result
        .selector_mapping
        .as_ref()
        .ok_or_else(|| eyre!("Selector mapping missing from obfuscation result"))?;

    let set_number_token = selector_token(selector_mapping, SELECTOR_SET_NUMBER)?;
    let number_token = selector_token(selector_mapping, SELECTOR_NUMBER)?;
    let increment_token = selector_token(selector_mapping, SELECTOR_INCREMENT)?;

    println!(
        "Selector tokens (first 4 bytes):\n  setNumber: {}\n  number:    {}\n  increment: {}",
        hex_encode(&set_number_token[..4.min(set_number_token.len())]),
        hex_encode(&number_token[..4.min(number_token.len())]),
        hex_encode(&increment_token[..4.min(increment_token.len())])
    );
    println!(
        "Token lengths: setNumber={}, number={}, increment={}",
        set_number_token.len(),
        number_token.len(),
        increment_token.len()
    );

    let mut db = InMemoryDB::default();
    let deployer = Address::from([0x45; 20]);
    db.insert_account_info(
        deployer,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );

    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let obfuscated_bytes = hex::decode(
        obfuscation_result
            .obfuscated_bytecode
            .trim_start_matches("0x"),
    )
    .map_err(|e| eyre!("Failed to decode obfuscated bytecode: {}", e))?;

    println!(
        "Deploying {} bytes, init code (first 28 bytes, hex): {}",
        obfuscated_bytes.len(),
        hex_encode(&obfuscated_bytes[..28.min(obfuscated_bytes.len())])
    );

    let deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 20_000_000,
        kind: TxKind::Create,
        data: Bytes::from(obfuscated_bytes),
        value: U256::ZERO,
        nonce: 0,
        ..Default::default()
    };

    let deploy_result = evm
        .transact(deploy_tx)
        .map_err(|e| eyre!("Deployment failed: {:?}", e))?;

    evm.db_mut().commit(deploy_result.state.clone());

    let contract_address = match deploy_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, Some(address)) => address,
            _ => return Err(eyre!("Deployment failed: missing contract address")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Deployment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Deployment halted: {:?}", reason));
        }
    };

    let deployed_code = evm
        .db()
        .cache
        .accounts
        .get(&contract_address)
        .and_then(|acc| acc.info.code.as_ref())
        .ok_or_else(|| eyre!("Missing deployed code"))?;

    let runtime_len = match deployed_code {
        Bytecode::LegacyAnalyzed(analyzed) => {
            let bytes = analyzed.bytecode();
            println!(
                "Deployed runtime (first 200 bytes): {}",
                hex_encode(&bytes[..bytes.len().min(200)])
            );
            bytes.len()
        }
        _ => return Err(eyre!("Unexpected deployed bytecode format")),
    };
    println!(
        "✓ Counter deployed at {} with {} bytes runtime",
        contract_address, runtime_len
    );

    let mut nonce: u64 = 1;

    let read_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: number_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let read_before = evm
        .transact(read_tx)
        .map_err(|e| eyre!("Initial number() failed: {:?}", e))?;
    evm.db_mut().commit(read_before.state.clone());

    let initial_value = match read_before.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("number() raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for number() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Initial number() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Initial number() halted: {:?}", reason));
        }
    };
    println!("Counter initial value: {}", initial_value);

    // Call increment()
    let inc_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: increment_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let inc_result = evm
        .transact(inc_tx)
        .map_err(|e| eyre!("increment() call failed: {:?}", e))?;

    evm.db_mut().commit(inc_result.state.clone());

    match inc_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("increment() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("increment() halted: {:?}", reason));
        }
    }

    // Read value after increment
    let read_after_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: number_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let read_after = evm
        .transact(read_after_tx)
        .map_err(|e| eyre!("number() after increment failed: {:?}", e))?;
    evm.db_mut().commit(read_after.state.clone());

    let after_value = match read_after.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("number() after increment raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for number() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("number() after increment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("number() after increment halted: {:?}", reason));
        }
    };
    println!("Counter value after increment: {}", after_value);
    assert_eq!(after_value, initial_value.saturating_add(U256::from(1u64)));

    // Call setNumber(42)
    let new_value = U256::from(42u64);
    let mut calldata = vec![0u8; 36];
    calldata[..4].copy_from_slice(&set_number_token[..4]);
    calldata[4..36].copy_from_slice(&new_value.to_be_bytes::<32>());

    let set_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: Bytes::from(calldata),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let set_result = evm
        .transact(set_tx)
        .map_err(|e| eyre!("setNumber() call failed: {:?}", e))?;

    evm.db_mut().commit(set_result.state.clone());

    match set_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("setNumber() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("setNumber() halted: {:?}", reason));
        }
    }

    // Read final value
    let read_final_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: number_token,
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };

    let read_final = evm
        .transact(read_final_tx)
        .map_err(|e| eyre!("Final number() failed: {:?}", e))?;
    evm.db_mut().commit(read_final.state.clone());

    let final_value = match read_final.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("number() after setNumber raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for final number() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Final number() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Final number() halted: {:?}", reason));
        }
    };

    println!("Counter value after setNumber(42): {}", final_value);
    assert_eq!(final_value, new_value);

    Ok(())
}
