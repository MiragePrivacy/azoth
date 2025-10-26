//! This module processes input bytecode, removes non-runtime sections (e.g., init code,
//! auxdata), and outputs either the cleaned runtime bytecode as a hex string or a JSON report
//! detailing the stripping process.

use async_trait::async_trait;
use azoth_core::decoder::decode_bytecode;
use azoth_core::detection::locate_sections;
use azoth_core::strip::strip_bytecode;
use clap::Args;
use serde_json;
use std::error::Error;
use std::path::Path;

/// Arguments for the `strip` subcommand.
#[derive(Args)]
pub struct StripArgs {
    /// Input bytecode as a hex string (0x...) or file path containing EVM bytecode.
    pub input: String,
    /// Output raw cleaned runtime hex instead of JSON report
    #[arg(long)]
    raw: bool,
}

/// Executes the `strip` subcommand to extract runtime bytecode.
#[async_trait]
impl super::Command for StripArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let is_file = !self.input.starts_with("0x") && Path::new(&self.input).is_file();
        let (instructions, _, _, bytes) = decode_bytecode(&self.input, is_file).await?;
        let sections = locate_sections(&bytes, &instructions)?;
        let (clean_runtime, report) = strip_bytecode(&bytes, &sections)?;

        if self.raw {
            println!("0x{}", hex::encode(&clean_runtime));
        } else {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{json}");
        }
        Ok(())
    }
}
