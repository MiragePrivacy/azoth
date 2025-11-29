//! Decompile diff command for comparing decompiled bytecode before and after obfuscation.
//!
//! This module provides a CLI interface to the decompile diff analysis functionality,
//! which runs obfuscation on input bytecode, then uses Heimdall's decompiler to generate
//! human-readable Solidity-like output and computes a unified diff between the original
//! and obfuscated versions.

use async_trait::async_trait;
use azoth_analysis::decompile_diff;
use azoth_core::seed::Seed;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use clap::Args;
use std::error::Error;

use super::obfuscate::{build_passes, read_input};

/// Arguments for the `decompile-diff` subcommand.
///
/// This command obfuscates input bytecode and compares decompiled output of the
/// original vs obfuscated versions to visualize differences introduced by the transforms.
#[derive(Args)]
pub struct DecompileDiffArgs {
    /// Input deployment bytecode as a hex string (0x...), .hex file, or binary file.
    pub input: String,

    /// Input runtime bytecode as a hex string (0x...), .hex file, or binary file.
    #[arg(long)]
    pub runtime: String,

    /// Cryptographic seed for deterministic obfuscation.
    #[arg(long)]
    pub seed: Option<String>,

    /// Comma-separated list of transforms (default: shuffle).
    #[arg(long, default_value = "shuffle")]
    pub passes: String,

    /// Only print the decompiled output of the obfuscated bytecode (no diff).
    #[arg(long)]
    pub after: bool,
}

/// Executes the `decompile-diff` subcommand.
#[async_trait]
impl super::Command for DecompileDiffArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let input_bytecode = read_input(&self.input)?;
        let runtime_bytecode = read_input(&self.runtime)?;

        let transforms = build_passes(&self.passes)?;

        let mut config = if let Some(seed_hex) = &self.seed {
            let seed = Seed::from_hex(seed_hex).map_err(|e| format!("Invalid seed hex: {e}"))?;
            ObfuscationConfig::with_seed(seed)
        } else {
            ObfuscationConfig::default()
        };

        config.transforms = transforms;
        config.preserve_unknown_opcodes = true;

        let result = obfuscate_bytecode(&input_bytecode, &runtime_bytecode, config)
            .await
            .map_err(|e| format!("{e}"))?;

        let post_bytes = hex::decode(result.obfuscated_runtime.trim_start_matches("0x"))?;

        if self.after {
            let source = decompile_diff::decompile(post_bytes.into()).await?;
            println!("{source}");
        } else {
            let pre_bytes = hex::decode(runtime_bytecode.trim_start_matches("0x"))?;
            decompile_diff::compare(pre_bytes.into(), post_bytes.into()).await?;
        }

        Ok(())
    }
}
