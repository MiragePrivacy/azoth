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

const COUNTER_BYTECODE: &str = "0x6080604052348015600e575f5ffd5b506101d98061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806306661abd1461004e578063371303c01461006c5780636d4ce63c14610076578063b3bcfa8214610094575b5f5ffd5b61005661009e565b60405161006391906100f7565b60405180910390f35b6100746100a3565b005b61007e6100bd565b60405161008b91906100f7565b60405180910390f35b61009c6100c5565b005b5f5481565b60015f5f8282546100b4919061013d565b92505081905550565b5f5f54905090565b60015f5f8282546100d69190610170565b92505081905550565b5f819050919050565b6100f1816100df565b82525050565b5f60208201905061010a5f8301846100e8565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610147826100df565b9150610152836100df565b925082820190508082111561016a57610169610110565b5b92915050565b5f61017a826100df565b9150610185836100df565b925082820390508181111561019d5761019c610110565b5b9291505056fea264697066735822122078c44612ebfc52f8c09e96e351b62f1c6feebaa2694fa7d29431ccb4ae9ed15064736f6c634300081c0033";

const SELECTOR_COUNT: u32 = 0x06661abd;
const SELECTOR_INC: u32 = 0x371303c0;
const SELECTOR_GET: u32 = 0x6d4ce63c;
const SELECTOR_DEC: u32 = 0xb3bcfa82;

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

    let obfuscation_result = obfuscate_bytecode(COUNTER_BYTECODE, ObfuscationConfig::default())
        .await
        .map_err(|e| eyre!("Failed to obfuscate counter bytecode: {}", e))?;

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

    let count_token = selector_token(selector_mapping, SELECTOR_COUNT)?;
    let get_token = selector_token(selector_mapping, SELECTOR_GET)?;
    let inc_token = selector_token(selector_mapping, SELECTOR_INC)?;
    let dec_token = selector_token(selector_mapping, SELECTOR_DEC)?;

    println!(
        "Selector tokens (first 4 bytes):\n  count: {}\n  get:   {}\n  inc:   {}\n  dec:   {}",
        hex_encode(&count_token[..4.min(count_token.len())]),
        hex_encode(&get_token[..4.min(get_token.len())]),
        hex_encode(&inc_token[..4.min(inc_token.len())]),
        hex_encode(&dec_token[..4.min(dec_token.len())])
    );
    println!(
        "Token lengths: count={}, get={}, inc={}, dec={}",
        count_token.len(),
        get_token.len(),
        inc_token.len(),
        dec_token.len()
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
        data: get_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let read_before = evm
        .transact(read_tx)
        .map_err(|e| eyre!("Initial get() failed: {:?}", e))?;
    evm.db_mut().commit(read_before.state.clone());

    let initial_value = match read_before.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("get() raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for get() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Initial get() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Initial get() halted: {:?}", reason));
        }
    };
    println!("Counter value before increment (get): {}", initial_value);

    let count_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: count_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let count_before = evm
        .transact(count_tx)
        .map_err(|e| eyre!("count() call failed: {:?}", e))?;
    evm.db_mut().commit(count_before.state.clone());

    let count_value_before = match count_before.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("count() raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for count() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("count() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("count() halted: {:?}", reason));
        }
    };
    println!(
        "Counter value before increment (count): {}",
        count_value_before
    );
    assert_eq!(initial_value, count_value_before);

    let inc_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: inc_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let inc_result = evm
        .transact(inc_tx)
        .map_err(|e| eyre!("inc() call failed: {:?}", e))?;

    evm.db_mut().commit(inc_result.state.clone());

    match inc_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("inc() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("inc() halted: {:?}", reason));
        }
    }

    let read_after_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: get_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let read_after = evm
        .transact(read_after_tx)
        .map_err(|e| eyre!("Second get() failed: {:?}", e))?;
    evm.db_mut().commit(read_after.state.clone());

    let after_value = match read_after.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("get() after inc raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for second get() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Second get() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Second get() halted: {:?}", reason));
        }
    };
    println!("Counter value after increment: {}", after_value);
    assert_eq!(after_value, initial_value.saturating_add(U256::from(1u64)));

    let dec_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: dec_token.clone(),
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };
    nonce += 1;

    let dec_result = evm
        .transact(dec_tx)
        .map_err(|e| eyre!("dec() call failed: {:?}", e))?;

    evm.db_mut().commit(dec_result.state.clone());

    match dec_result.result {
        ExecutionResult::Success { .. } => {}
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("dec() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("dec() halted: {:?}", reason));
        }
    }

    let read_final_tx = TxEnv {
        caller: deployer,
        gas_limit: 5_000_000,
        kind: TxKind::Call(contract_address),
        data: get_token,
        value: U256::ZERO,
        nonce,
        ..Default::default()
    };

    let read_final = evm
        .transact(read_final_tx)
        .map_err(|e| eyre!("Final get() failed: {:?}", e))?;
    evm.db_mut().commit(read_final.state.clone());

    let restored_value = match read_final.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(data) => {
                println!("get() after dec raw output: {}", hex_encode(&data));
                parse_u256(&data)
            }
            _ => return Err(eyre!("Unexpected output for final get() call")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Final get() reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Final get() halted: {:?}", reason));
        }
    };

    println!("Counter value after decrement: {}", restored_value);
    assert_eq!(restored_value, initial_value);

    Ok(())
}
