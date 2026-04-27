//! Test original unobfuscated contract to verify baseline functionality

use super::{
    call_tx, code_account_info, create_tx, funded_account_info, init_tracing, mock_token_bytecode,
    parse_bool_word, parse_call_output, parse_create_result, prepare_bytecode,
    ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, MOCK_TOKEN_ADDR,
};
use color_eyre::eyre::eyre;
use color_eyre::Result;
use revm::context::ContextTr;
use revm::database::InMemoryDB;
use revm::primitives::{Address, Bytes};
use revm::{Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext};

#[tokio::test]
async fn test_original_is_bonded() -> Result<()> {
    init_tracing();

    let original_bytecode_hex =
        azoth_core::normalize_hex_string(ESCROW_CONTRACT_DEPLOYMENT_BYTECODE)
            .map_err(|e| eyre!("Failed to normalize bytecode: {}", e))?;
    let original_bytecode = prepare_bytecode(&original_bytecode_hex)?;

    println!("Testing ORIGINAL (unobfuscated) contract...");

    // setup EVM with mock token contract
    let mut db = InMemoryDB::default();
    db.insert_account_info(MOCK_TOKEN_ADDR, code_account_info(mock_token_bytecode(), 1));

    let deployer = Address::from([0x42; 20]);
    db.insert_account_info(deployer, funded_account_info(0));

    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    let deploy_result = evm
        .transact(create_tx(deployer, original_bytecode, 30_000_000, 0))
        .map_err(|e| eyre!("Deployment failed: {:?}", e))?;

    evm.db_mut().commit(deploy_result.state.clone());

    let deployment = parse_create_result(deploy_result.result, "Deployment")?;
    let contract_address = deployment.address;

    println!("✓ Original contract deployed at: {}", contract_address);

    // Validate all PUSH+JUMP pairs in deployed bytecode
    println!("\n=== Validating Original Deployed Bytecode ===");
    let deployed_bytes = deployment.runtime;

    // Decode and validate
    let (deployed_instructions, _, _, _) =
        azoth_core::decoder::decode_bytecode(&hex::encode(deployed_bytes.as_ref()), false)
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
    let call_env = call_tx(
        deployer,
        contract_address,
        Bytes::from(is_bonded_selector),
        10_000_000,
        1,
    );

    println!("Calling is_bonded() with selector 0xcb766a56...");
    let call_result = evm.transact(call_env);
    println!("Call result: {:?}", call_result);

    let call_result = call_result.map_err(|e| eyre!("Call failed: {:?}", e))?;

    let is_bonded_result = parse_call_output(call_result.result, "is_bonded()")?;

    // Parse boolean result
    let is_bonded = parse_bool_word(&is_bonded_result);
    println!("✓ is_bonded() returned: {}", is_bonded);
    assert!(!is_bonded, "Expected is_bonded to be false initially");

    println!("\n✓ Original (unobfuscated) contract works correctly");
    Ok(())
}
