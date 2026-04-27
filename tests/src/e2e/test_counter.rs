use super::{
    call_tx, create_tx, expect_success, funded_account_info, init_tracing, parse_call_output,
    parse_create_result, parse_u256_word, selector_token_word,
};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use hex::encode as hex_encode;
use revm::context::ContextTr;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, U256};
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};

const COUNTER_DEPLOYMENT_BYTECODE: &str =
    include_str!("../../bytecode/counter/counter_deployment.hex");
const COUNTER_RUNTIME_BYTECODE: &str = include_str!("../../bytecode/counter/counter_runtime.hex");

const SELECTOR_SET_NUMBER: u32 = 0x3fb5c1cb;
const SELECTOR_NUMBER: u32 = 0x8381f58a;
const SELECTOR_INCREMENT: u32 = 0xd09de08a;

#[tokio::test]
async fn test_obfuscated_counter_deploys_and_counts() -> Result<()> {
    init_tracing();

    let obfuscation_result = obfuscate_bytecode(
        COUNTER_DEPLOYMENT_BYTECODE,
        COUNTER_RUNTIME_BYTECODE,
        ObfuscationConfig::default(),
    )
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

    let set_number_token = selector_token_word(selector_mapping, SELECTOR_SET_NUMBER)?;
    let number_token = selector_token_word(selector_mapping, SELECTOR_NUMBER)?;
    let increment_token = selector_token_word(selector_mapping, SELECTOR_INCREMENT)?;

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
    db.insert_account_info(deployer, funded_account_info(0));

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

    let deploy_result = evm
        .transact(create_tx(
            deployer,
            Bytes::from(obfuscated_bytes),
            20_000_000,
            0,
        ))
        .map_err(|e| eyre!("Deployment failed: {:?}", e))?;

    evm.db_mut().commit(deploy_result.state.clone());

    let deployment = parse_create_result(deploy_result.result, "Deployment")?;
    let contract_address = deployment.address;
    println!(
        "Deployed runtime (first 200 bytes): {}",
        hex_encode(&deployment.runtime[..deployment.runtime.len().min(200)])
    );
    println!(
        "✓ Counter deployed at {} with {} bytes runtime",
        contract_address,
        deployment.runtime.len()
    );

    let mut nonce: u64 = 1;

    let read_tx = call_tx(
        deployer,
        contract_address,
        number_token.clone(),
        5_000_000,
        nonce,
    );
    nonce += 1;

    let read_before = evm
        .transact(read_tx)
        .map_err(|e| eyre!("Initial number() failed: {:?}", e))?;
    evm.db_mut().commit(read_before.state.clone());

    let output = parse_call_output(read_before.result, "Initial number()")?;
    println!("number() raw output: {}", hex_encode(&output));
    let initial_value = parse_u256_word(&output);
    println!("Counter initial value: {}", initial_value);

    let inc_tx = call_tx(
        deployer,
        contract_address,
        increment_token.clone(),
        5_000_000,
        nonce,
    );
    nonce += 1;

    let inc_result = evm
        .transact(inc_tx)
        .map_err(|e| eyre!("increment() call failed: {:?}", e))?;

    evm.db_mut().commit(inc_result.state.clone());
    expect_success(inc_result.result, "increment()")?;

    let read_after_tx = call_tx(
        deployer,
        contract_address,
        number_token.clone(),
        5_000_000,
        nonce,
    );
    nonce += 1;

    let read_after = evm
        .transact(read_after_tx)
        .map_err(|e| eyre!("number() after increment failed: {:?}", e))?;
    evm.db_mut().commit(read_after.state.clone());

    let output = parse_call_output(read_after.result, "number() after increment")?;
    println!(
        "number() after increment raw output: {}",
        hex_encode(&output)
    );
    let after_value = parse_u256_word(&output);
    println!("Counter value after increment: {}", after_value);
    assert_eq!(after_value, initial_value.saturating_add(U256::from(1u64)));

    // Call setNumber(42)
    let new_value = U256::from(42u64);
    let mut calldata = vec![0u8; 36];
    calldata[..4].copy_from_slice(&set_number_token[..4]);
    calldata[4..36].copy_from_slice(&new_value.to_be_bytes::<32>());

    let set_tx = call_tx(
        deployer,
        contract_address,
        Bytes::from(calldata),
        5_000_000,
        nonce,
    );
    nonce += 1;

    let set_result = evm
        .transact(set_tx)
        .map_err(|e| eyre!("setNumber() call failed: {:?}", e))?;

    evm.db_mut().commit(set_result.state.clone());
    expect_success(set_result.result, "setNumber()")?;

    let read_final_tx = call_tx(deployer, contract_address, number_token, 5_000_000, nonce);

    let read_final = evm
        .transact(read_final_tx)
        .map_err(|e| eyre!("Final number() failed: {:?}", e))?;
    evm.db_mut().commit(read_final.state.clone());

    let output = parse_call_output(read_final.result, "Final number()")?;
    println!(
        "number() after setNumber raw output: {}",
        hex_encode(&output)
    );
    let final_value = parse_u256_word(&output);

    println!("Counter value after setNumber(42): {}", final_value);
    assert_eq!(final_value, new_value);

    Ok(())
}
