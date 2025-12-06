use async_trait::async_trait;
use clap::Subcommand;
use std::error::Error;

pub mod analyze;
pub mod cfg;
pub mod decode;
pub mod decompile_diff;
pub mod obfuscate;
pub mod strip;
pub mod tui;

use thiserror::Error;

/// Errors that can occur during obfuscation.
#[derive(Debug, Error)]
pub enum ObfuscateError {
    /// The hex string has an odd length, making it invalid.
    #[error("hex string has odd length: {0}")]
    OddLength(usize),
    /// Failed to decode hex string to bytes.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// File read/write error.
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    /// Transform application failed.
    #[error("transform error: {0}")]
    Transform(String),
    /// Invalid transform pass specified.
    #[error("invalid pass: {0}")]
    InvalidPass(String),
    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// CLI subcommands for Azoth.
#[derive(Subcommand)]
pub enum Cmd {
    /// Decode bytecode to annotated assembly.
    Decode(decode::DecodeArgs),
    /// Strip init/auxdata, dump runtime hex.
    Strip(strip::StripArgs),
    /// Write runtime CFG to stdout or a file.
    Cfg(cfg::CfgArgs),
    /// Obfuscate bytecode with specified transforms.
    Obfuscate(obfuscate::ObfuscateArgs),
    /// Run obfuscation analysis across multiple seeds.
    Analyze(analyze::AnalyzeArgs),
    /// Compare decompiled output before and after obfuscation.
    DecompileDiff(decompile_diff::DecompileDiffArgs),
    /// View obfuscation debug traces in a TUI.
    Tui(tui::TuiArgs),
}

/// Trait for executing CLI subcommands.
///
/// Implementors define the logic for processing input bytecode and producing output (e.g.,
/// assembly, stripped bytecode, CFG, or obfuscated bytecode).
#[async_trait]
pub trait Command {
    /// Executes the subcommand.
    ///
    /// # Returns
    /// A `Result` indicating success or an error if execution fails.
    async fn execute(self) -> Result<(), Box<dyn Error>>;
}

#[async_trait]
impl Command for Cmd {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        match self {
            Cmd::Decode(args) => args.execute().await,
            Cmd::Strip(args) => args.execute().await,
            Cmd::Cfg(args) => args.execute().await,
            Cmd::Obfuscate(args) => args.execute().await,
            Cmd::Analyze(args) => args.execute().await,
            Cmd::DecompileDiff(args) => args.execute().await,
            Cmd::Tui(args) => args.execute().await,
        }
    }
}
