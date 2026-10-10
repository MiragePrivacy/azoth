use azoth_core::seed::Seed;
use azoth_transform::cluster_shuffle::ClusterShuffle;
use azoth_transform::jump_trampoline::JumpTrampoline;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::{eyre, Result};
use revm::bytecode::Bytecode;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{ContextTr, TxEnv};
use revm::database::InMemoryDB;
use revm::primitives::{keccak256, Address, Bytes, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};

const SEED: [u8; 32] = [0x42; 32];
const COLLISION_DEPLOYMENT: &str =
    "0x6017600a5f3960175ff361000c6100105600000000005b0000005b5f5260205ff3";
const COLLISION_RUNTIME: &str = "0x61000c6100105600000000005b0000005b5f5260205ff3";
const DYNAMIC_JUMP_DEPLOYMENT: &str = "0x6010600a5f3960105ff35f35565b005b005b602a5f5260205ff3";
const DYNAMIC_JUMP_RUNTIME: &str = "0x5f35565b005b005b602a5f5260205ff3";
const TAIL_DEPLOYMENT: &str = "0x600b600a5f39600b5ff3610008565bfe5bfe5b6002";
const TAIL_RUNTIME: &str = "0x610008565bfe5bfe5b6002";
const UNRESOLVED_JUMPI_DEPLOYMENT: &str =
    "0x6011600a5f3960115ff36000600f805057602a5f5260205ff35bfe";
const UNRESOLVED_JUMPI_RUNTIME: &str = "0x6000600f805057602a5f5260205ff35bfe";
const INIT_DATA_COLLISION_DEPLOYMENT: &str =
    "0x601260105f395f600c015f5560125ff35f600857600c56fe5b6010565b6010565b00";
const INIT_DATA_COLLISION_RUNTIME: &str = "0x5f600857600c56fe5b6010565b6010565b00";
const UNPROVEN_IMMUTABLE_BASE_DEPLOYMENT: &str = "0x604b60315f397f5b602a5f5260205ff30000000000000000000000000000000000000000000000602260090152604b5ff336600757602b565b7f000000000000000000000000000000000000000000000000000000000000000050005b00000000000000000000000000000000000000000000000000000000000000";
const UNPROVEN_IMMUTABLE_BASE_RUNTIME: &str = "0x36600757602b565b7f000000000000000000000000000000000000000000000000000000000000000050005b00000000000000000000000000000000000000000000000000000000000000";

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    hex::decode(value.trim_start_matches("0x")).map_err(Into::into)
}

fn execute_runtime(runtime: &[u8], calldata: &[u8]) -> Result<Bytes> {
    let caller = Address::new([0x45; 20]);
    let contract = Address::new([0x24; 20]);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    db.insert_account_info(
        contract,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: keccak256(runtime),
            code: Some(Bytecode::new_raw(Bytes::copy_from_slice(runtime))),
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let result = evm
        .transact(TxEnv {
            caller,
            gas_limit: 5_000_000,
            kind: TxKind::Call(contract),
            data: Bytes::copy_from_slice(calldata),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|error| eyre!("runtime execution failed: {error:?}"))?;

    match result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Call(bytes) => Ok(bytes),
            Output::Create(..) => Err(eyre!("runtime call returned create output")),
        },
        ExecutionResult::Revert { output, .. } => {
            Err(eyre!("runtime reverted with 0x{}", hex::encode(output)))
        }
        ExecutionResult::Halt { reason, .. } => Err(eyre!("runtime halted: {reason:?}")),
    }
}

fn deploy_storage_slot_zero(creation: &[u8]) -> Result<U256> {
    let caller = Address::new([0x45; 20]);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    let mut evm = Context::mainnet().with_db(db).build_mainnet();
    let deployment = evm
        .transact(TxEnv {
            caller,
            gas_limit: 5_000_000,
            kind: TxKind::Create,
            data: Bytes::copy_from_slice(creation),
            value: U256::ZERO,
            nonce: 0,
            ..Default::default()
        })
        .map_err(|error| eyre!("deployment execution failed: {error:?}"))?;
    let address = match &deployment.result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(address)),
            ..
        } => *address,
        other => return Err(eyre!("deployment failed: {other:?}")),
    };
    evm.db_mut().commit(deployment.state);
    let account = evm
        .db()
        .cache
        .accounts
        .get(&address)
        .ok_or_else(|| eyre!("deployed account is missing"))?;
    Ok(account
        .storage
        .get(&U256::ZERO)
        .copied()
        .unwrap_or_default())
}

#[tokio::test]
async fn stack_carried_data_equal_to_jumpdest_is_not_relocated() -> Result<()> {
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes(SEED));
    config.transforms = vec![Box::new(ClusterShuffle::new())];
    let transformed = obfuscate_bytecode(COLLISION_DEPLOYMENT, COLLISION_RUNTIME, config).await?;
    let original_output = execute_runtime(&decode_hex(COLLISION_RUNTIME)?, &[])?;
    let transformed_runtime = decode_hex(&transformed.obfuscated_runtime)?;
    let transformed_output = execute_runtime(&transformed_runtime, &[])?;

    let mut expected = [0u8; 32];
    expected[31] = 0x0c;
    assert_eq!(original_output.as_ref(), expected);
    assert_eq!(transformed_output, original_output);
    Ok(())
}

#[tokio::test]
async fn immutable_like_write_with_unproven_runtime_base_fails_closed() -> Result<()> {
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ]));
    config.transforms = vec![Box::new(ClusterShuffle::new())];
    let error = obfuscate_bytecode(
        UNPROVEN_IMMUTABLE_BASE_DEPLOYMENT,
        UNPROVEN_IMMUTABLE_BASE_RUNTIME,
        config,
    )
    .await
    .expect_err("an unrelated ADD base must not be patched as a Solidity immutable write");
    assert!(
        error
            .to_string()
            .contains("does not reuse the proven CODECOPY base and length"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn unresolved_dynamic_jump_fails_closed() {
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes(SEED));
    config.transforms = vec![Box::new(ClusterShuffle::new())];
    let error = obfuscate_bytecode(DYNAMIC_JUMP_DEPLOYMENT, DYNAMIC_JUMP_RUNTIME, config)
        .await
        .expect_err("calldata-derived jump target must not be guessed");
    assert!(error.message.contains("unresolved dynamic JUMP/JUMPI"));
}

#[tokio::test]
async fn eof_falloff_is_preserved_by_each_layout_pass() -> Result<()> {
    let original_output = execute_runtime(&decode_hex(TAIL_RUNTIME)?, &[])?;
    for transforms in [
        vec![Box::new(ClusterShuffle::new()) as Box<dyn azoth_transform::Transform>],
        vec![Box::new(JumpTrampoline::new()) as Box<dyn azoth_transform::Transform>],
    ] {
        let mut config = ObfuscationConfig::with_seed(Seed::from_bytes(SEED));
        config.transforms = transforms;
        let transformed = obfuscate_bytecode(TAIL_DEPLOYMENT, TAIL_RUNTIME, config).await?;
        let output = execute_runtime(&decode_hex(&transformed.obfuscated_runtime)?, &[])?;
        assert_eq!(output, original_output);
    }
    Ok(())
}

#[tokio::test]
async fn unresolved_jumpi_false_fallthrough_stays_adjacent() -> Result<()> {
    let mut config = ObfuscationConfig::with_seed(Seed::from_bytes(SEED));
    config.transforms = vec![Box::new(ClusterShuffle::new())];
    let transformed = obfuscate_bytecode(
        UNRESOLVED_JUMPI_DEPLOYMENT,
        UNRESOLVED_JUMPI_RUNTIME,
        config,
    )
    .await?;
    let original_output = execute_runtime(&decode_hex(UNRESOLVED_JUMPI_RUNTIME)?, &[])?;
    let output = execute_runtime(&decode_hex(&transformed.obfuscated_runtime)?, &[])?;
    assert_eq!(output, original_output);
    assert_eq!(output.len(), 32);
    assert_eq!(output[31], 0x2a);
    Ok(())
}

#[tokio::test]
async fn init_arithmetic_literal_equal_to_runtime_pc_is_not_relocated() -> Result<()> {
    let mut config = ObfuscationConfig::with_seed(
        Seed::from_hex("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("fixed seed"),
    );
    config.transforms = vec![Box::new(ClusterShuffle::new())];
    let transformed = obfuscate_bytecode(
        INIT_DATA_COLLISION_DEPLOYMENT,
        INIT_DATA_COLLISION_RUNTIME,
        config,
    )
    .await?;

    let original_slot = deploy_storage_slot_zero(&decode_hex(INIT_DATA_COLLISION_DEPLOYMENT)?)?;
    let transformed_slot =
        deploy_storage_slot_zero(&decode_hex(&transformed.obfuscated_bytecode)?)?;
    assert_eq!(original_slot, U256::from(0x0c));
    assert_eq!(transformed_slot, original_slot);
    Ok(())
}
