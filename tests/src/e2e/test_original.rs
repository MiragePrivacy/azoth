//! Test original unobfuscated contract to verify baseline functionality

use super::{mock_token_bytecode, prepare_bytecode, ESCROW_CONTRACT_BYTECODE, MOCK_TOKEN_ADDR};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::ContextTr;
use revm::context::TxEnv;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};

#[tokio::test]
async fn test_original_is_bonded() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    // Use ORIGINAL unobfuscated bytecode
    let original_bytecode_hex = azoth_core::normalize_hex_string(ESCROW_CONTRACT_BYTECODE)
        .map_err(|e| eyre!("Failed to normalize bytecode: {}", e))?;
    let original_bytecode = prepare_bytecode(&original_bytecode_hex)?;

    println!("Testing ORIGINAL (unobfuscated) contract...");

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
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );

    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: original_bytecode,
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
            _ => return Err(eyre!("Deployment failed: no address returned")),
        },
        ExecutionResult::Revert { output, .. } => {
            return Err(eyre!("Deployment reverted: {:?}", output));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Deployment halted: {:?}", reason));
        }
    };

    println!("✓ Original contract deployed at: {}", contract_address);

    // Call is_bonded() using standard 4-byte selector: 0xcb766a56
    let is_bonded_selector = hex::decode("cb766a56").unwrap();
    let call_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: Bytes::from(is_bonded_selector),
        value: U256::ZERO,
        nonce: 1,
        ..Default::default()
    };

    println!("Calling is_bonded() with selector 0xcb766a56...");
    let call_result = evm.transact(call_tx);
    println!("Call result: {:?}", call_result);

    let call_result = call_result.map_err(|e| eyre!("Call failed: {:?}", e))?;

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

    // Parse boolean result
    let is_bonded = is_bonded_result.len() >= 32 && is_bonded_result[31] != 0;
    println!("✓ is_bonded() returned: {}", is_bonded);
    assert!(!is_bonded, "Expected is_bonded to be false initially");

    println!("\n✓ Original (unobfuscated) contract works correctly");
    Ok(())
}
