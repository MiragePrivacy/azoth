//! Test original unobfuscated contract to verify baseline functionality

use super::{mock_token_bytecode, prepare_bytecode, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, MOCK_TOKEN_ADDR};
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
    let original_bytecode_hex = azoth_core::normalize_hex_string(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE)
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

    // Validate all PUSH+JUMP pairs in deployed bytecode
    println!("\n=== Validating Original Deployed Bytecode ===");
    let deployed_code = evm
        .db()
        .cache
        .accounts
        .get(&contract_address)
        .and_then(|acc| acc.info.code.as_ref())
        .ok_or_else(|| eyre!("Failed to get deployed code"))?;

    let deployed_bytes = match deployed_code {
        Bytecode::LegacyAnalyzed(analyzed) => analyzed.bytecode(),
        _ => return Err(eyre!("Unexpected bytecode format")),
    };

    // Decode and validate
    let (deployed_instructions, _, _, _) =
        azoth_core::decoder::decode_bytecode(&hex::encode(deployed_bytes), false)
            .await
            .map_err(|e| eyre!("Failed to decode deployed bytecode: {:?}", e))?;

    // Find all JUMPDESTs
    let jumpdests: std::collections::HashSet<usize> = deployed_instructions
        .iter()
        .filter(|i| matches!(i.op, azoth_core::Opcode::JUMPDEST))
        .map(|i| i.pc)
        .collect();

    println!(
        "Original deployed bytecode has {} JUMPDESTs",
        jumpdests.len()
    );

    // Check all PUSH+JUMP/JUMPI pairs
    let mut valid_jumps = 0;
    let mut invalid_jumps = Vec::new();
    for i in 0..deployed_instructions.len().saturating_sub(1) {
        let curr = &deployed_instructions[i];
        let next = &deployed_instructions[i + 1];

        if matches!(curr.op, azoth_core::Opcode::PUSH(_))
            && matches!(
                next.op,
                azoth_core::Opcode::JUMP | azoth_core::Opcode::JUMPI
            )
        {
            if let Some(target_hex) = &curr.imm {
                if let Ok(target) = usize::from_str_radix(target_hex, 16) {
                    let has_jumpdest = jumpdests.contains(&target);
                    if has_jumpdest {
                        valid_jumps += 1;
                    } else {
                        invalid_jumps.push((curr.pc, target, next.op));
                    }
                }
            }
        }
    }

    println!("Original bytecode jump statistics:");
    println!("  Total jumps: {}", valid_jumps + invalid_jumps.len());
    println!("  Valid jumps: {}", valid_jumps);
    println!("  Invalid jumps: {}", invalid_jumps.len());

    if !invalid_jumps.is_empty() {
        println!("  Found {} invalid jump targets in deployed bytecode! First invalid: PUSH at 0x{:x} -> 0x{:x}",
        invalid_jumps.len(),
        invalid_jumps[0].0,
        invalid_jumps[0].1);
    }

    println!("✓ Validation complete\n");

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
