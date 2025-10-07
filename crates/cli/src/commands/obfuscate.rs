use crate::commands::ObfuscateError;
/// Module for the `obfuscate` subcommand, which applies obfuscation transforms to EVM
/// bytecode.
///
/// This module processes input bytecode and uses the unified obfuscation pipeline
/// from azoth-transform to apply transforms and output obfuscated bytecode.
use async_trait::async_trait;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{
    create_gas_report, obfuscate_bytecode, print_obfuscation_analysis, ObfuscationConfig,
};
use azoth_transform::{PassConfig, Transform};
use clap::Args;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Arguments for the `obfuscate` subcommand.
#[derive(Args)]
pub struct ObfuscateArgs {
    /// Input bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
    pub input: String,
    /// Cryptographic seed for deterministic obfuscation
    #[arg(long)]
    seed: Option<String>,
    /// Comma-separated list of OPTIONAL transforms (default: shuffle,jump_transform,opaque_pred).
    /// Note: function_dispatcher is ALWAYS applied and doesn't need to be specified.
    #[arg(long, default_value = "shuffle,jump_transform,opaque_pred")]
    passes: String,
    /// Minimum quality threshold for accepting transforms (default: 0.0).
    #[arg(long, default_value_t = 0.0)]
    accept_threshold: f64,
    /// Maximum allowable size increase as a fraction (default: 0.1).
    #[arg(long, default_value_t = 0.1)]
    max_size_delta: f32,
    /// Path to emit gas/size report as JSON (optional).
    #[arg(long)]
    emit: Option<String>,
}

/// Executes the `obfuscate` subcommand using the unified obfuscation pipeline.
#[async_trait]
impl super::Command for ObfuscateArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        // Step 1: Read and normalize input
        let input_bytecode = read_input(&self.input)?;

        // Step 2: Build transforms from CLI args
        let transforms = build_passes(&self.passes)?;

        // Step 3: Configure obfuscation
        let mut config = if let Some(seed_hex) = self.seed {
            // Use provided seed
            let seed = Seed::from_hex(&seed_hex).map_err(|e| format!("Invalid seed hex: {e}"))?;
            ObfuscationConfig::with_seed(seed)
        } else {
            // Use random seed
            ObfuscationConfig::default()
        };

        config.transforms = transforms;
        config.pass_config = PassConfig {
            accept_threshold: self.accept_threshold,
            aggressive: true,
            max_size_delta: self.max_size_delta,
            max_opaque_ratio: 0.5,
        };
        config.preserve_unknown_opcodes = true;

        // Step 4: Run obfuscation pipeline
        let result = match obfuscate_bytecode(&input_bytecode, config).await {
            Ok(result) => result,
            Err(e) => return Err(format!("{e}").into()),
        };

        // Step 5: Print analysis and results
        print_obfuscation_analysis(&result);

        // Step 6: Check size limits
        if result.metadata.size_limit_exceeded {
            return Err(format!(
                "Obfuscated bytecode grew {:.1}%, exceeds --max-size-delta {:.1}%",
                result.size_increase_percentage,
                self.max_size_delta * 100.0
            )
            .into());
        }

        // Step 7: Write report if requested
        if let Some(path) = self.emit {
            let report = create_gas_report(&result);
            fs::write(&path, serde_json::to_string_pretty(&report)?)?;
            println!("📊 Wrote gas/size report to {}", &path);
        }

        // Step 8: Output final bytecode
        println!("{}", result.obfuscated_bytecode);

        Ok(())
    }
}

/// Reads input from hex string, .hex file, or binary file
fn read_input(input: &str) -> Result<String, Box<dyn Error>> {
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
fn normalise_hex(s: &str) -> Result<String, ObfuscateError> {
    let stripped = s.trim().trim_start_matches("0x").replace('_', "");
    if !stripped.len().is_multiple_of(2) {
        return Err(ObfuscateError::OddLength(stripped.len()));
    }
    Ok(stripped)
}

/// Builds a list of transform passes from a comma-separated string.
fn build_passes(list: &str) -> Result<Vec<Box<dyn Transform>>, Box<dyn Error>> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(|name| match name.trim() {
            "shuffle" => Ok(Box::new(azoth_transform::shuffle::Shuffle) as Box<dyn Transform>),
            "opaque_pred" | "opaque_predicate" => Ok(Box::new(
                azoth_transform::opaque_predicate::OpaquePredicate::new(PassConfig {
                    max_opaque_ratio: 0.5,
                    ..Default::default()
                }),
            ) as Box<dyn Transform>),
            "jump_transform" | "jump_addr" => Ok(Box::new(
                azoth_transform::jump_address_transformer::JumpAddressTransformer::new(
                    PassConfig::default(),
                ),
            ) as Box<dyn Transform>),
            _ => Err(ObfuscateError::InvalidPass(name.to_string()).into()),
        })
        .collect()
}
