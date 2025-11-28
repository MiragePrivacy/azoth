//! Module for the `obfuscate` subcommand, which applies obfuscation transforms to EVM
//! bytecode.
//!
//! This module processes input bytecode and uses the unified obfuscation pipeline
//! from `azoth-transform` to apply transforms and output obfuscated bytecode.

use crate::commands::ObfuscateError;
use async_trait::async_trait;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{
    create_gas_report, obfuscate_bytecode, print_obfuscation_analysis, ObfuscationConfig,
};
use azoth_transform::Transform;
use clap::Args;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Arguments for the `obfuscate` subcommand.
#[derive(Args)]
pub struct ObfuscateArgs {
    /// Input deployment bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
    pub input: String,
    /// Input runtime bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
    #[arg(long)]
    pub runtime: String,
    /// Cryptographic seed for deterministic obfuscation
    #[arg(long)]
    seed: Option<String>,
    /// Comma-separated list of OPTIONAL transforms (default: shuffle,jump_transform,opaque_pred).
    /// Note: function_dispatcher is ALWAYS applied and doesn't need to be specified.
    #[arg(long, default_value = "shuffle")]
    passes: String,
    /// Path to emit gas/size report as JSON (optional).
    #[arg(long)]
    emit: Option<String>,
    /// Path to emit a detailed CFG trace debug report as JSON.
    #[arg(long, value_name = "PATH")]
    emit_debug: Option<String>,
}

/// Executes the `obfuscate` subcommand using the unified obfuscation pipeline.
#[async_trait]
impl super::Command for ObfuscateArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let ObfuscateArgs {
            input,
            runtime,
            seed,
            passes,
            emit,
            emit_debug,
        } = self;

        // Step 1: Read and normalize input
        let input_bytecode = read_input(&input)?;
        let runtime_bytecode = read_input(&runtime)?;

        // Step 2: Build transforms from CLI args
        let transforms = build_passes(&passes)?;

        // Step 3: Configure obfuscation
        let mut config = if let Some(seed_hex) = seed {
            // Use provided seed
            let seed = Seed::from_hex(&seed_hex).map_err(|e| format!("Invalid seed hex: {e}"))?;
            ObfuscationConfig::with_seed(seed)
        } else {
            // Use random seed
            ObfuscationConfig::default()
        };

        config.transforms = transforms;
        config.preserve_unknown_opcodes = true;

        // Step 4: Run obfuscation pipeline
        let result = match obfuscate_bytecode(&input_bytecode, &runtime_bytecode, config).await {
            Ok(result) => result,
            Err(e) => return Err(format!("{e}").into()),
        };

        // Step 5: Print analysis and results
        print_obfuscation_analysis(&result);

        // Step 6: Check size limits
        // Step 7: Write report if requested
        if let Some(path) = emit.as_ref() {
            let report = create_gas_report(&result);
            fs::write(path, serde_json::to_string_pretty(&report)?)?;
            println!("📊 Wrote gas/size report to {}", path);
        }

        if let Some(path) = emit_debug.as_ref() {
            let debug_payload = serde_json::to_string_pretty(&serde_json::json!({
                "metadata": &result.metadata,
                "trace": &result.trace,
            }))?;
            fs::write(path, debug_payload)?;
            println!("Wrote CFG trace debug report to {}", path);
        }

        // Step 8: Output final bytecode
        println!("{}", result.obfuscated_bytecode);

        Ok(())
    }
}

/// Reads input from hex string, .hex file, or binary file
pub(crate) fn read_input(input: &str) -> Result<String, Box<dyn Error>> {
    if input.trim_start().starts_with("0x") {
        // Direct hex string input
        Ok(input.to_string())
    } else if Path::new(input).extension().and_then(|s| s.to_str()) == Some("hex") {
        // .hex file
        let content = fs::read_to_string(input)?;
        let normalized = normalise_hex(&content)?;
        Ok(format!("0x{normalized}"))
    } else {
        // Binary file
        let bytes = fs::read(input)?;
        Ok(format!("0x{}", hex::encode(bytes)))
    }
}

/// Normalizes a hex string by removing prefixes and underscores.
pub(crate) fn normalise_hex(s: &str) -> Result<String, ObfuscateError> {
    let stripped = s.trim().trim_start_matches("0x").replace('_', "");
    if !stripped.len().is_multiple_of(2) {
        return Err(ObfuscateError::OddLength(stripped.len()));
    }
    Ok(stripped)
}

/// Builds a list of transform passes from a comma-separated string.
pub(crate) fn build_passes(list: &str) -> Result<Vec<Box<dyn Transform>>, Box<dyn Error>> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(|name| match name.trim() {
            "shuffle" => Ok(Box::new(azoth_transform::shuffle::Shuffle) as Box<dyn Transform>),
            "opaque_pred" | "opaque_predicate" => Ok(Box::new(
                azoth_transform::opaque_predicate::OpaquePredicate::new(),
            ) as Box<dyn Transform>),
            "jump_transform" | "jump_addr" => Ok(Box::new(
                azoth_transform::jump_address_transformer::JumpAddressTransformer::new(),
            ) as Box<dyn Transform>),
            "arithmetic_chain" => Ok(Box::new(
                azoth_transform::arithmetic_chain::ArithmeticChain::new(),
            ) as Box<dyn Transform>),
            "push_split" => {
                Ok(Box::new(azoth_transform::push_split::PushSplit::new()) as Box<dyn Transform>)
            }
            "storage_gates" => Ok(
                Box::new(azoth_transform::storage_gates::StorageGates::new()) as Box<dyn Transform>,
            ),
            "slot_shuffle" => {
                Ok(Box::new(azoth_transform::slot_shuffle::SlotShuffle::new())
                    as Box<dyn Transform>)
            }
            "cluster_shuffle" => Ok(
                Box::new(azoth_transform::cluster_shuffle::ClusterShuffle::new())
                    as Box<dyn Transform>,
            ),
            "splice" => Ok(Box::new(azoth_transform::splice::Splice::new()) as Box<dyn Transform>),
            _ => Err(ObfuscateError::InvalidPass(name.to_string()).into()),
        })
        .collect()
}
