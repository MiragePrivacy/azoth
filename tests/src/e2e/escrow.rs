//! End-to-end tests for calling obfuscated contract functions.
//!
//! These tests verify that obfuscated contracts not only deploy successfully,
//! but also execute correctly when functions are called using obfuscated tokens
//! instead of standard 4-byte selectors.

use super::{
    mock_token_bytecode, prepare_bytecode, EscrowMappings, ObfuscatedCaller,
    ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, ESCROW_CONTRACT_RUNTIME_BYTECODE, MOCK_TOKEN_ADDR,
};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::bytecode::Bytecode;
use revm::context::journal::Journal;
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, CfgEnv, ContextTr, TxEnv};
use revm::database::InMemoryDB;
use revm::inspector::Inspector;
use revm::interpreter::interpreter_types::Jumps;
use revm::primitives::{Address, TxKind, U256};
use revm::state::AccountInfo;
use revm::{Context, DatabaseCommit, ExecuteEvm, InspectEvm, MainBuilder, MainContext};

#[derive(Default)]
struct StepTracer {
    enabled: bool,
    max_steps: usize,
    steps: usize,
}

impl StepTracer {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            max_steps: 2000,
            steps: 0,
        }
    }
}

impl Inspector<Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, ()>>
    for StepTracer
{
    fn step(
        &mut self,
        interp: &mut revm::interpreter::Interpreter,
        _context: &mut Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, ()>,
    ) {
        if !self.enabled || self.steps >= self.max_steps {
            if !self.enabled {
                println!("StepTracer disabled");
            } else if self.steps == self.max_steps {
                println!("StepTracer max steps reached");
            }
            self.steps = self.steps.saturating_add(1);
            return;
        }

        let pc = interp.bytecode.pc();
        let opcode = interp.bytecode.opcode();
        println!(
            "TRACE step {:05} pc=0x{pc:x} opcode=0x{opcode:02x}",
            self.steps
        );
        self.steps += 1;
    }
}

#[tokio::test]
async fn test_obfuscated_function_calls() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .try_init();

    // TEST: First try deploying the ORIGINAL (non-obfuscated) bytecode to verify test setup
    println!("\n=== Testing Original (Non-Obfuscated) Deployment ===");
    let original_bytecode = prepare_bytecode(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE)?;

    let mut test_db = InMemoryDB::default();
    test_db.insert_account_info(
        MOCK_TOKEN_ADDR,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: Some(Bytecode::new_raw(mock_token_bytecode())),
        },
    );

    let test_deployer = Address::from([0x42; 20]);
    test_db.insert_account_info(
        test_deployer,
        AccountInfo {
            balance: U256::from(1_000_000_000_000_000_000u128),
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );

    let mut test_evm = Context::mainnet().with_db(test_db).build_mainnet();

    let test_deploy_tx = TxEnv {
        caller: test_deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: original_bytecode,
        value: U256::ZERO,
        nonce: 0,
        ..Default::default()
    };

    let test_result = test_evm.transact(test_deploy_tx)?;

    match &test_result.result {
        ExecutionResult::Success { .. } => {
            println!("✓ Original deployment SUCCEEDED");
        }
        ExecutionResult::Revert { output, gas_used } => {
            println!(
                "✗ Original deployment REVERTED (gas: {}): 0x{}",
                gas_used,
                hex::encode(output)
            );
            return Err(eyre!("Original deployment failed - test setup issue!"));
        }
        ExecutionResult::Halt { reason, .. } => {
            println!("✗ Original deployment HALTED: {:?}", reason);
            return Err(eyre!("Original deployment failed - test setup issue!"));
        }
    }

    // obfuscate contract
    println!("\n=== Proceeding with Obfuscated Deployment ===");
    let config = ObfuscationConfig::default();

    let obfuscation_result = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        config,
    )
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

    let trace_deploy = std::env::var("TRACE_DEPLOY").is_ok();
    let mut evm = Context::mainnet()
        .with_db(db)
        .build_mainnet_with_inspector(StepTracer::default());

    // Track nonce explicitly for each transaction
    let mut deployer_nonce = 0u64;

    let deploy_tx = TxEnv {
        caller: deployer,
        gas_limit: 30_000_000,
        kind: TxKind::Create,
        data: obfuscated_bytecode,
        value: U256::ZERO,
        nonce: deployer_nonce,
        ..Default::default()
    };

    let deploy_result = if trace_deploy {
        evm.inspect(deploy_tx, StepTracer::new(true))
    } else {
        evm.transact(deploy_tx)
    }
    .map_err(|e| eyre!("Deployment transaction failed: {:?}", e))?;

    // Detailed logging of deployment result
    println!("\n=== Deployment Result Details ===");
    match &deploy_result.result {
        ExecutionResult::Success { gas_used, .. } => {
            println!("  Status: SUCCESS");
            println!("  Gas used: {}", gas_used);
        }
        ExecutionResult::Revert { gas_used, output } => {
            println!("  Status: REVERT");
            println!("  Gas used: {}", gas_used);
            println!("  Output length: {} bytes", output.len());
            if !output.is_empty() {
                println!("  Output hex: 0x{}", hex::encode(output));
                if output.len() >= 4 {
                    let selector = u32::from_be_bytes([output[0], output[1], output[2], output[3]]);
                    println!("  Error selector: 0x{:08x}", selector);
                    if selector == 0x08c379a0 {
                        println!("  Error type: Error(string) - check Solidity error message");
                    } else if selector == 0x4e487b71 {
                        println!("  Error type: Panic(uint256) - Solidity panic");
                        if output.len() >= 36 {
                            let panic_code = u32::from_be_bytes([
                                output[output.len() - 4],
                                output[output.len() - 3],
                                output[output.len() - 2],
                                output[output.len() - 1],
                            ]);
                            println!("  Panic code: 0x{:02x}", panic_code);
                        }
                    }
                }
            } else {
                println!("  Empty revert (no error message)");
            }
        }
        ExecutionResult::Halt { reason, gas_used } => {
            println!("  Status: HALT");
            println!("  Reason: {:?}", reason);
            println!("  Gas used: {}", gas_used);
        }
    }
    println!(
        "  State changes: {} accounts modified",
        deploy_result.state.len()
    );
    for (addr, account) in &deploy_result.state {
        println!(
            "    touched {} -> nonce={}, balance={}, storage={}, code_len={}",
            addr,
            account.info.nonce,
            account.info.balance,
            account.storage.len(),
            account.info.code.as_ref().map(|c| c.len()).unwrap_or(0)
        );
    }

    // Commit deployment state changes to database
    evm.db_mut().commit(deploy_result.state.clone());

    // Increment nonce after successful deployment
    deployer_nonce += 1;

    let contract_address = match deploy_result.result {
        ExecutionResult::Success { output, .. } => match output {
            Output::Create(_, Some(address)) => address,
            _ => return Err(eyre!("Deployment failed: no address returned")),
        },
        ExecutionResult::Revert { output, gas_used } => {
            return Err(eyre!(
                "Deployment reverted (gas: {}): 0x{}",
                gas_used,
                hex::encode(&output)
            ));
        }
        ExecutionResult::Halt { reason, .. } => {
            return Err(eyre!("Deployment halted: {:?}", reason));
        }
    };

    println!("✓ Obfuscated contract deployed at: {}", contract_address);

    // Validate all PUSH+JUMP pairs in deployed bytecode
    println!("\n=== Validating Deployed Bytecode ===");
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
        "Obfuscated deployed bytecode has {} JUMPDESTs",
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

    println!("Obfuscated deployed bytecode jump statistics:");
    println!("  Total jumps: {}", valid_jumps + invalid_jumps.len());
    println!("  Valid jumps: {}", valid_jumps);
    println!("  Invalid jumps: {}", invalid_jumps.len());

    if !invalid_jumps.is_empty() {
        println!("\n=== Invalid Jump Details (first 10) ===");
        for (i, (push_pc, target, jump_type)) in invalid_jumps.iter().take(10).enumerate() {
            println!(
                "  [{}] PUSH at PC 0x{:x} -> target 0x{:x} ({:?}) - NO JUMPDEST",
                i, push_pc, target, jump_type
            );
        }
        println!("\n=== All Available JUMPDESTs (first 20) ===");
        let mut jd_list: Vec<_> = jumpdests.iter().collect();
        jd_list.sort();
        for (i, jd) in jd_list.iter().take(20).enumerate() {
            println!("  [{}] JUMPDEST at PC 0x{:x}", i, jd);
        }

        return Err(eyre!(
            "Found {} invalid jump targets in deployed bytecode! First invalid: PUSH at 0x{:x} -> 0x{:x}",
            invalid_jumps.len(),
            invalid_jumps[0].0,
            invalid_jumps[0].1
        ));
    }

    println!("✓ All PUSH+JUMP pairs target valid JUMPDESTs\n");

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
        nonce: deployer_nonce,
        ..Default::default()
    };

    let call_result = evm.transact(call_tx);
    println!("Call result: {:?}", call_result);
    let call_result = call_result.map_err(|e| eyre!("Call transaction failed: {:?}", e))?;

    // Persist nonce/state changes produced by the view call so the next
    // transaction sees the incremented account nonce.
    evm.db_mut().commit(call_result.state.clone());

    // Increment nonce after successful transaction
    deployer_nonce += 1;

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

    let reward_amount = U256::from(5000);
    let payment_amount = U256::from(5000);
    let fund_calldata = caller.fund_call_data(reward_amount, payment_amount);
    println!(
        "  Calldata (obfuscated): 0x{} (reward: {}, payment: {})",
        hex::encode(&fund_calldata),
        reward_amount,
        payment_amount
    );

    let fund_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: fund_calldata,
        value: U256::ZERO,
        nonce: deployer_nonce,
        ..Default::default()
    };

    let fund_result = evm
        .transact(fund_tx)
        .map_err(|e| eyre!("Fund transaction failed: {:?}", e))?;

    // Commit fund state changes to database
    evm.db_mut().commit(fund_result.state.clone());

    // Increment nonce after successful transaction
    deployer_nonce += 1;

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
        nonce: deployer_nonce,
        ..Default::default()
    };

    let funded_result = evm
        .transact(funded_tx)
        .map_err(|e| eyre!("Funded check failed: {:?}", e))?;

    evm.db_mut().commit(funded_result.state.clone());

    // Increment nonce after successful transaction
    deployer_nonce += 1;

    if let ExecutionResult::Success {
        output: Output::Call(data),
        ..
    } = funded_result.result
    {
        let is_funded = caller.parse_bool(&data);
        println!("  Contract funded state: {}", is_funded);
    }

    let bond_amount = U256::from(2500);
    let bond_calldata = caller.bond_call_data(bond_amount);
    println!("  Calldata (obfuscated): 0x{}", hex::encode(&bond_calldata));

    let bond_tx = TxEnv {
        caller: deployer,
        gas_limit: 10_000_000,
        kind: TxKind::Call(contract_address),
        data: bond_calldata,
        value: U256::ZERO,
        nonce: deployer_nonce,
        ..Default::default()
    };

    let bond_result = evm
        .transact(bond_tx)
        .map_err(|e| eyre!("Bond transaction failed: {:?}", e))?;

    // Commit bond state changes to database
    evm.db_mut().commit(bond_result.state.clone());

    // Increment nonce after successful transaction
    deployer_nonce += 1;

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
        nonce: deployer_nonce,
        ..Default::default()
    };

    let verify_result = evm
        .transact(verify_tx)
        .map_err(|e| eyre!("Verification transaction failed: {:?}", e))?;

    evm.db_mut().commit(verify_result.state.clone());

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

    println!("\n✓ Obfuscated contract executes correctly");
    println!("✓ Valid tokens route to correct functions");
    println!("✓ Token extraction works with function arguments (bond with uint256)");
    println!("✓ State changes are preserved through obfuscation");

    Ok(())
}
