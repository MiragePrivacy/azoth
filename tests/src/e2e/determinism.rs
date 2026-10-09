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
        ObfuscationConfig::with_seed(seed.clone()),
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
        result_a.integrity, result_b.integrity,
        "same inputs must produce an identical integrity manifest"
    );
    assert_eq!(
        result_a.private_interaction_manifest(),
        result_b.private_interaction_manifest(),
        "same inputs must produce an identical private interaction guide"
    );
    assert_eq!(
        serde_json::to_string(&result_a)?,
        serde_json::to_string(&result_b)?,
        "the complete serialized result, including its diagnostic trace, must replay exactly"
    );
    assert_eq!(
        deployed_a.runtime, deployed_b.runtime,
        "same seed and same constructor args should produce identical deployed runtime"
    );

    let input_deployment = hex::decode(azoth_core::normalize_hex_string(
        ESCROW_CONTRACT_DEPLOYMENT_BYTECODE,
    )?)?;
    let input_runtime = hex::decode(azoth_core::normalize_hex_string(
        ESCROW_CONTRACT_RUNTIME_BYTECODE,
    )?)?;
    result_a
        .verify_integrity(&input_deployment, &input_runtime, &seed)
        .map_err(color_eyre::eyre::Error::msg)?;
    let output_deployment = hex::decode(result_a.obfuscated_bytecode.trim_start_matches("0x"))?;
    let output_runtime = hex::decode(result_a.obfuscated_runtime.trim_start_matches("0x"))?;
    let guide = result_a.private_interaction_manifest();
    let serialized_guide = serde_json::to_vec(&guide)?;
    let decoded_guide: azoth_transform::obfuscator::PrivateInteractionManifest =
        serde_json::from_slice(&serialized_guide)?;
    decoded_guide
        .verify_integrity(
            &input_deployment,
            &input_runtime,
            &output_deployment,
            &output_runtime,
            &seed,
        )
        .map_err(color_eyre::eyre::Error::msg)?;

    let wrong_seed = Seed::from_bytes([0xa5; 32]);
    assert!(
        result_a
            .verify_integrity(&input_deployment, &input_runtime, &wrong_seed)
            .is_err(),
        "a party without the correct seed must not authenticate the manifest"
    );
    let mut tampered = result_a.clone();
    tampered.obfuscated_bytecode.push_str("00");
    assert!(
        tampered
            .verify_integrity(&input_deployment, &input_runtime, &seed)
            .is_err(),
        "artifact tampering must invalidate the manifest"
    );
    let mut tampered_configuration = result_a.clone();
    tampered_configuration
        .integrity
        .pipeline_configuration
        .requested_transforms
        .push(azoth_transform::obfuscator::TransformRecipeManifest {
            name: "unrequested-pass".to_string(),
            configuration_id: "unrequested-pass@parameterless-v1".to_string(),
        });
    assert!(
        tampered_configuration
            .verify_integrity(&input_deployment, &input_runtime, &seed)
            .is_err(),
        "pipeline-configuration tampering must invalidate the authenticated manifest"
    );
    let mut tampered_guide = decoded_guide;
    tampered_guide.calldata_rule = "send unrelated calldata".to_string();
    assert!(
        tampered_guide
            .verify_integrity(
                &input_deployment,
                &input_runtime,
                &output_deployment,
                &output_runtime,
                &seed,
            )
            .is_err(),
        "a standalone guide with a modified interaction rule must fail authentication"
    );

    Ok(())
}
