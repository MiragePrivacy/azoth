use super::{
    deploy_contract, ESCROW_CONTRACT_DEPLOYMENT_BYTECODE, ESCROW_CONTRACT_RUNTIME_BYTECODE,
};
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use color_eyre::Result;

const FIXED_SEED: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn runtime_preview_hex(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(16);
    format!("0x{}", hex::encode(&bytes[..preview_len]))
}

#[tokio::test]
async fn test_same_seed_produces_same_deployed_runtime() -> Result<()> {
    let seed = Seed::from_hex(FIXED_SEED).unwrap();

    let result_a = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        ObfuscationConfig::with_seed(seed.clone()),
    )
    .await?;
    let result_b = obfuscate_bytecode(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
        ObfuscationConfig::with_seed(seed),
    )
    .await?;

    let deployed_a = deploy_contract(&result_a.obfuscated_bytecode)?;
    let deployed_b = deploy_contract(&result_b.obfuscated_bytecode)?;

    println!(
        "run A deployed runtime: {} bytes, prefix {}",
        deployed_a.runtime.len(),
        runtime_preview_hex(&deployed_a.runtime)
    );
    println!(
        "run B deployed runtime: {} bytes, prefix {}",
        deployed_b.runtime.len(),
        runtime_preview_hex(&deployed_b.runtime)
    );

    assert_eq!(
        result_a.obfuscated_bytecode, result_b.obfuscated_bytecode,
        "same seed should produce identical obfuscated deployment bytecode"
    );
    assert_eq!(
        result_a.obfuscated_runtime, result_b.obfuscated_runtime,
        "same seed should produce identical obfuscated runtime template"
    );
    assert_eq!(
        deployed_a.runtime, deployed_b.runtime,
        "same seed and same constructor args should produce identical deployed runtime"
    );

    Ok(())
}
