use azoth_cli::commands::{Cmd, Command};
use clap::Parser;

/// Azoth CLI
///
/// Azoth is an EVM bytecode obfuscator that supports decoding bytecode to assembly,
/// stripping non-runtime sections, generating control flow graphs, and applying obfuscation
/// transforms
#[derive(Parser)]
#[command(name = "azoth")]
#[command(about = "Azoth: EVM bytecode obfuscator")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

/// Runs the Azoth CLI with the provided arguments.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .without_time()
        .init();

    let cli = Cli::parse();
    cli.command.execute().await
}
