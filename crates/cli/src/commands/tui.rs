//! TUI subcommand for viewing debug traces.

use std::path::PathBuf;

use async_trait::async_trait;
use clap::Args;

use super::Command;

/// View obfuscation debug traces in a TUI.
#[derive(Args)]
pub struct TuiArgs {
    /// Path to the debug JSON file.
    #[arg(default_value = "debug.json")]
    pub file: PathBuf,
}

#[async_trait]
impl Command for TuiArgs {
    async fn execute(self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.file.display().to_string();
        let debug = azoth_tui::load_debug_file(&self.file)?;
        azoth_tui::run(debug, Some(filename))
    }
}
