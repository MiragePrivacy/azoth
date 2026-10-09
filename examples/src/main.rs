//! Mirage Privacy Protocol - safe-foundation replay workflow.
//!
//! This example demonstrates deterministic transformation and authenticated replay. It does not
//! claim semantic equivalence, indistinguishability, anonymity, or production readiness.

#![recursion_limit = "256"]

use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig, ObfuscationResult};
use serde_json::json;
use std::fs;

const MIRAGE_ESCROW_DEPLOYMENT_PATH: &str = "escrow-bytecode/artifacts/erc20_deployment.hex";
const MIRAGE_ESCROW_RUNTIME_PATH: &str = "escrow-bytecode/artifacts/erc20_runtime.hex";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Mirage Privacy Protocol - Safe Foundation Replay Workflow");
    println!("=================================================");

    // Load contract bytecode (both deployment and runtime)
    let (original_bytecode, runtime_bytecode) = load_mirage_contract()?;
    let seed_k2 =
        Seed::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?;

    println!(
        "Loaded Escrow bytecode: {} bytes (deployment), {} bytes (runtime)",
        original_bytecode.len(),
        runtime_bytecode.len()
    );

    // SENDER: Run the currently admitted foundation profile O(S, K2).
    println!("\nSENDER: Applying the safe foundation profile...");
    let obfuscation_result =
        apply_mirage_obfuscation(&original_bytecode, &runtime_bytecode, &seed_k2).await?;
    let obfuscated_bytecode = hex::decode(
        obfuscation_result
            .obfuscated_bytecode
            .trim_start_matches("0x"),
    )?;

    let size_delta = calculate_percentage_delta(original_bytecode.len(), obfuscated_bytecode.len());
    println!("   Original:   {} bytes", original_bytecode.len());
    println!(
        "   Output:     {} bytes ({:+.1}%)",
        obfuscated_bytecode.len(),
        size_delta
    );

    // Print transform information
    println!(
        "   Transforms applied: {:?}",
        obfuscation_result.metadata.transforms_applied
    );
    if obfuscation_result.unknown_opcodes_count > 0 {
        println!(
            "   Unknown opcodes preserved: {}",
            obfuscation_result.unknown_opcodes_count
        );
    }

    // VERIFIER: Replay the exact inputs and authenticate the resulting artifact manifest.
    println!("\nVERIFIER: Checking deterministic replay with K2...");
    let recompilation_result =
        apply_mirage_obfuscation(&original_bytecode, &runtime_bytecode, &seed_k2).await?;
    let recompiled_bytecode = hex::decode(
        recompilation_result
            .obfuscated_bytecode
            .trim_start_matches("0x"),
    )?;

    let deterministic_replay_verified = obfuscated_bytecode == recompiled_bytecode
        && obfuscation_result.obfuscated_runtime == recompilation_result.obfuscated_runtime
        && obfuscation_result.integrity == recompilation_result.integrity
        && obfuscation_result.private_interaction_manifest()
            == recompilation_result.private_interaction_manifest();
    if !deterministic_replay_verified {
        return Err("Deterministic replay failed - identical private inputs diverged".into());
    }
    println!("   Deterministic replay VERIFIED");

    obfuscation_result
        .verify_integrity(&original_bytecode, &runtime_bytecode, &seed_k2)
        .map_err(|error| format!("Integrity-manifest verification failed: {error}"))?;
    let integrity_manifest_verified = true;
    println!("   Authenticated artifact integrity VERIFIED");

    let bytecode_changed = original_bytecode != obfuscated_bytecode;
    println!(
        "   Variation outcome: {}",
        if bytecode_changed {
            "changed artifact"
        } else {
            "exact identity (a conservative fallback, not a variation success)"
        }
    );
    println!("   Semantic equivalence: NOT VERIFIED (formal verifier unavailable)");
    println!("   Indistinguishability/anonymity: NOT EVALUATED");

    // Gas analysis
    println!("\nCREATION INPUT INTRINSIC GAS ESTIMATE (not total deployment gas):");
    let gas_analysis = analyze_gas_costs(&original_bytecode, &obfuscated_bytecode);
    println!("   Original payload:    {} gas", gas_analysis.original_gas);
    println!(
        "   Transformed payload: {} gas",
        gas_analysis.obfuscated_gas
    );
    println!("   Gas delta: {:+.2}%", gas_analysis.delta_percentage);

    println!("\nDETERMINISTIC REPLAY TEST:");
    let alternate_seed_changed =
        verify_deterministic_replay_test(&original_bytecode, &runtime_bytecode, &seed_k2).await?;

    // Generate comprehensive report
    let report = generate_workflow_report(
        &original_bytecode,
        &obfuscated_bytecode,
        &gas_analysis,
        &obfuscation_result,
        deterministic_replay_verified,
        integrity_manifest_verified,
        bytecode_changed,
        alternate_seed_changed,
    );

    save_report(&report, "mirage_report.json")?;

    println!("\nFOUNDATION REPLAY WORKFLOW COMPLETED");
    println!("   Deterministic replay: VERIFIED");
    println!("   Artifact integrity: VERIFIED");
    println!(
        "   Variation outcome: {}",
        if bytecode_changed {
            "CHANGED"
        } else {
            "IDENTITY"
        }
    );
    println!("   Semantic equivalence: NOT VERIFIED");
    println!("   Indistinguishability/anonymity: NOT EVALUATED");
    println!("   Input-gas delta: {:+.2}%", gas_analysis.delta_percentage);
    println!("   Size delta: {size_delta:+.1}%");
    println!("   Report saved: mirage_report.json");

    Ok(())
}

/// Load Escrow contract bytecode from submodule artifact (both deployment and runtime)
fn load_mirage_contract() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let deployment_content = fs::read_to_string(MIRAGE_ESCROW_DEPLOYMENT_PATH).map_err(|_| {
        format!("Failed to load deployment bytecode from {MIRAGE_ESCROW_DEPLOYMENT_PATH}")
    })?;
    let runtime_content = fs::read_to_string(MIRAGE_ESCROW_RUNTIME_PATH).map_err(|_| {
        format!("Failed to load runtime bytecode from {MIRAGE_ESCROW_RUNTIME_PATH}")
    })?;

    let clean_deployment = deployment_content
        .trim()
        .strip_prefix("0x")
        .unwrap_or(deployment_content.trim());
    let clean_runtime = runtime_content
        .trim()
        .strip_prefix("0x")
        .unwrap_or(runtime_content.trim());

    if clean_deployment.is_empty() || clean_deployment.len() < 20 {
        return Err("Invalid or empty deployment bytecode in artifact".into());
    }
    if clean_runtime.is_empty() || clean_runtime.len() < 20 {
        return Err("Invalid or empty runtime bytecode in artifact".into());
    }

    let deployment =
        hex::decode(clean_deployment).map_err(|e| format!("Deployment hex decode error: {e}"))?;
    let runtime =
        hex::decode(clean_runtime).map_err(|e| format!("Runtime hex decode error: {e}"))?;

    Ok((deployment, runtime))
}

/// Apply the currently admitted safe foundation profile using the unified pipeline.
async fn apply_mirage_obfuscation(
    bytecode: &[u8],
    runtime_bytecode: &[u8],
    seed_k2: &Seed,
) -> Result<ObfuscationResult, Box<dyn std::error::Error + Send + Sync>> {
    let hex_input = format!("0x{}", hex::encode(bytecode));
    let runtime_hex = format!("0x{}", hex::encode(runtime_bytecode));

    let config = create_safe_foundation_config(seed_k2);

    // Use the unified obfuscation pipeline
    obfuscate_bytecode(&hex_input, &runtime_hex, config)
        .await
        .map_err(|e| e.into())
}

/// Build the conservative foundation configuration exposed by default.
fn create_safe_foundation_config(seed_k2: &Seed) -> ObfuscationConfig {
    ObfuscationConfig::with_seed(seed_k2.clone())
}

/// Gas analysis results
#[derive(Debug, Clone)]
struct GasAnalysis {
    original_gas: u64,
    obfuscated_gas: u64,
    delta_percentage: f64,
}

/// Estimate only the intrinsic transaction-data component for the creation payload.
///
/// This deliberately excludes init-code execution, memory expansion, EIP-3860 metering, and
/// code-deposit gas, so it must not be presented as total deployment gas.
fn analyze_gas_costs(original: &[u8], obfuscated: &[u8]) -> GasAnalysis {
    let original_gas = calculate_intrinsic_input_gas(original);
    let obfuscated_gas = calculate_intrinsic_input_gas(obfuscated);
    let delta_percentage = calculate_gas_percentage_delta(original_gas, obfuscated_gas);

    GasAnalysis {
        original_gas,
        obfuscated_gas,
        delta_percentage,
    }
}

/// Calculate the base transaction plus zero/non-zero calldata byte cost.
fn calculate_intrinsic_input_gas(bytecode: &[u8]) -> u64 {
    let zero_bytes = bytecode.iter().filter(|&&b| b == 0).count() as u64;
    let non_zero_bytes = (bytecode.len() as u64) - zero_bytes;
    21_000 + (zero_bytes * 4) + (non_zero_bytes * 16)
}

/// Calculate percentage increase between two values
fn calculate_percentage_delta(original: usize, new: usize) -> f64 {
    let orig = original as f64;
    let new_val = new as f64;
    ((new_val / orig) - 1.0) * 100.0
}

/// Calculate percentage increase for gas values
fn calculate_gas_percentage_delta(original: u64, new: u64) -> f64 {
    let orig = original as f64;
    let new_val = new as f64;
    ((new_val / orig) - 1.0) * 100.0
}

/// Verify exact same-seed replay and report, without requiring, cross-seed diversity.
///
/// Different seeds may legitimately produce the same artifact when a pass has no movable units or
/// a safety gate returns the unchanged input. Cross-seed equality is therefore an outcome, not a
/// determinism failure.
async fn verify_deterministic_replay_test(
    bytecode: &[u8],
    runtime_bytecode: &[u8],
    seed: &Seed,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let result1 = apply_mirage_obfuscation(bytecode, runtime_bytecode, seed).await?;
    let result2 = apply_mirage_obfuscation(bytecode, runtime_bytecode, seed).await?;

    if result1.obfuscated_bytecode != result2.obfuscated_bytecode {
        return Err("Same seed produced different bytecode - replay is not deterministic".into());
    }
    println!("   Same seed produces identical bytecode: VERIFIED");

    let different_seed = Seed::from_bytes([0xa5; 32]);
    let diff_result = apply_mirage_obfuscation(bytecode, runtime_bytecode, &different_seed).await?;
    let alternate_seed_changed = result1.obfuscated_bytecode != diff_result.obfuscated_bytecode;
    println!(
        "   Fixed alternate seed outcome: {}",
        if alternate_seed_changed {
            "different artifact"
        } else {
            "same artifact (permitted for a no-op/identity fallback)"
        }
    );

    Ok(alternate_seed_changed)
}

/// Generate comprehensive workflow report
#[allow(clippy::too_many_arguments)]
fn generate_workflow_report(
    original: &[u8],
    obfuscated: &[u8],
    gas_analysis: &GasAnalysis,
    obfuscation_result: &ObfuscationResult,
    deterministic_replay_verified: bool,
    integrity_manifest_verified: bool,
    bytecode_changed: bool,
    alternate_seed_changed: bool,
) -> serde_json::Value {
    json!({
        "mirage_obfuscation_workflow": {
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "bytecode_analysis": {
                "original_bytes": original.len(),
                "obfuscated_bytes": obfuscated.len(),
                "size_delta_bytes": obfuscated.len() as i64 - original.len() as i64,
                "size_delta_percentage": calculate_percentage_delta(original.len(), obfuscated.len()),
                "variation_outcome": if bytecode_changed { "changed" } else { "exact_identity" },
                "unknown_opcodes_preserved": obfuscation_result.unknown_opcodes_count,
                "blocks_created": obfuscation_result.blocks_created,
                "instructions_added": obfuscation_result.instructions_added
            },
            "gas_analysis": {
                "scope": "base transaction plus creation-payload calldata bytes only; not total deployment gas",
                "original_intrinsic_input_gas_estimate": gas_analysis.original_gas,
                "transformed_intrinsic_input_gas_estimate": gas_analysis.obfuscated_gas,
                "gas_delta": (gas_analysis.obfuscated_gas as i64 - gas_analysis.original_gas as i64),
                "gas_delta_percentage": gas_analysis.delta_percentage
            },
            "verification_results": {
                "deterministic_replay_verified": deterministic_replay_verified,
                "integrity_manifest_verified": integrity_manifest_verified,
                "alternate_seed_changed_artifact": alternate_seed_changed,
                "semantic_equivalence_status": "not_verified",
                "formal_verification_status": "unavailable_fail_closed",
                "release_gate_passed": false
            },
            "security_assessment": {
                "statistical_indistinguishability": "not_evaluated",
                "anonymity_set_membership": "not_demonstrated",
                "clustering_resistance": "not_demonstrated",
                "transforms_applied": obfuscation_result.metadata.transforms_applied,
                "warning": "a changed artifact is not evidence of stealth or semantic equivalence"
            },
            "mirage_protocol": {
                "authorized_replay": if deterministic_replay_verified { "artifact reproduced from bytecode and K2" } else { "replay failed" },
                "integrity": if integrity_manifest_verified { "seed-bound artifact hashes authenticated" } else { "integrity check failed" },
                "interface": "safe profile preserves original selectors; no private selector mapping is needed",
                "production_readiness": "no_go"
            },
            "obfuscation_details": {
                "size_limit_exceeded": obfuscation_result.metadata.size_limit_exceeded,
                "unknown_opcodes_preserved": obfuscation_result.metadata.unknown_opcodes_preserved,
                "total_instructions_processed": obfuscation_result.total_instructions
            },
            "recommendations": {
                "immediate": [
                    "Treat deterministic replay and integrity authentication as narrower properties than equivalence",
                    "Count exact-identity results separately from changed outputs",
                    "Use the safe profile only for development and evaluation"
                ],
                "before_production": [
                    "Implement and independently validate complete semantic-equivalence obligations",
                    "Run differential behavior tests over calls, state, logs, reverts, external calls, and fork contexts",
                    "Evaluate genuinely changed outputs against a representative Ethereum negative corpus",
                    "Complete independent security review"
                ]
            }
        }
    })
}

/// Save report to file
fn save_report(
    report: &serde_json::Value,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fs::write(filename, serde_json::to_string_pretty(report)?)?;
    Ok(())
}
