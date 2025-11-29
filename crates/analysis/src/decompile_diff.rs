//! Decompiled difference metrics.
//!
//! Uses Heimdall's decompilation on before and after bytecodes to quantify obfuscation level
//! by showing a colorized side-by-side diff of the decompiled Solidity-like output.

use alloy::primitives::Bytes;
use heimdall_decompiler::DecompilerArgsBuilder;
use imara_diff::{Diff, InternedInput, Interner, Token, UnifiedDiffPrinter};
use owo_colors::OwoColorize;
use std::fmt;

/// Errors that can occur during decompile diff analysis.
#[derive(thiserror::Error, Debug)]
pub enum DecompileDiffError {
    /// Error from the Heimdall decompiler.
    #[error("decompiler error: {0}")]
    Decompiler(#[from] heimdall_decompiler::Error),

    /// Decompilation produced no source output.
    #[error("decompilation produced no source output")]
    NoSource,
}

/// Colorized diff printer that shows removed lines in red, added lines in green,
/// and context/identical lines in the default color.
pub struct ColoredDiffPrinter<'a> {
    interner: &'a Interner<&'a str>,
}

impl<'a> ColoredDiffPrinter<'a> {
    /// Creates a new colored diff printer with the given string interner.
    pub fn new(interner: &'a Interner<&'a str>) -> Self {
        Self { interner }
    }
}

impl UnifiedDiffPrinter for ColoredDiffPrinter<'_> {
    fn display_header(
        &self,
        mut f: impl fmt::Write,
        start_before: u32,
        start_after: u32,
        len_before: u32,
        len_after: u32,
    ) -> fmt::Result {
        writeln!(
            f,
            "{}",
            format!(
                "@@ -{},{} +{},{} @@",
                start_before + 1,
                len_before,
                start_after + 1,
                len_after
            )
            .cyan()
        )
    }

    fn display_context_token(&self, mut f: impl fmt::Write, token: Token) -> fmt::Result {
        let line = self.interner[token];
        write!(f, " {}", line.dimmed())?;
        if !line.ends_with('\n') {
            writeln!(f)?;
        }
        Ok(())
    }

    fn display_hunk(
        &self,
        mut f: impl fmt::Write,
        before: &[Token],
        after: &[Token],
    ) -> fmt::Result {
        for &token in before {
            let line = self.interner[token];
            write!(f, "{}", format!("-{line}").red())?;
            if !line.ends_with('\n') {
                writeln!(f)?;
            }
        }
        for &token in after {
            let line = self.interner[token];
            write!(f, "{}", format!("+{line}").green())?;
            if !line.ends_with('\n') {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// Configuration for the full diff output that shows all lines including identical sections.
pub struct FullDiffConfig {
    /// Number of context lines to show around changes (0 means show all).
    pub context_len: u32,
}

impl Default for FullDiffConfig {
    fn default() -> Self {
        Self { context_len: 0 }
    }
}

/// Compares two bytecodes by decompiling them and showing a colorized diff.
///
/// This function decompiles both bytecode inputs using Heimdall, then computes
/// and displays a unified diff with:
/// - Removed lines shown in red with `-` prefix
/// - Added lines shown in green with `+` prefix
/// - Identical/context lines shown dimmed with ` ` prefix
/// - Hunk headers shown in cyan
///
/// The diff shows all lines, not just changes, to provide full context of
/// how the obfuscation affected the decompiled output.
pub async fn compare(pre: Bytes, post: Bytes) -> Result<(), DecompileDiffError> {
    let pre_source = decompile(pre).await?;
    let post_source = decompile(post).await?;

    println!(
        "{}\n",
        "═══ Decompiled Diff (original → obfuscated) ═══"
            .bold()
            .cyan()
    );

    let input = InternedInput::new(pre_source.as_str(), post_source.as_str());
    let mut diff = Diff::compute(imara_diff::Algorithm::Histogram, &input);
    diff.postprocess_lines(&input);

    let printer = ColoredDiffPrinter::new(&input.interner);

    // Print full diff with all context (use line count to show everything)
    let mut config = imara_diff::UnifiedDiffConfig::default();
    config.context_len(input.before.len().max(input.after.len()) as u32);

    let unified = diff.unified_diff(&printer, config, &input);
    println!("{unified}");

    // Print summary statistics
    let hunks: Vec<_> = diff.hunks().collect();
    let total_removed: usize = hunks.iter().map(|h| h.before.len()).sum();
    let total_added: usize = hunks.iter().map(|h| h.after.len()).sum();
    let total_original = input.before.len();
    let unchanged = total_original.saturating_sub(total_removed);

    println!();
    println!(
        "{}",
        format!(
            "Summary: {} hunks, {} lines removed, {} lines added, {} lines unchanged",
            hunks.len(),
            total_removed,
            total_added,
            unchanged
        )
        .bold()
    );

    Ok(())
}

/// Decompiles bytecode and returns the Solidity-like source.
///
/// This function uses Heimdall to decompile EVM bytecode into human-readable
/// Solidity-like output without requiring network access.
pub async fn decompile(target: Bytes) -> Result<String, DecompileDiffError> {
    let args = DecompilerArgsBuilder::new()
        .target(target.to_string())
        .output("print".into())
        .include_solidity(true)
        .build()
        .unwrap();
    let result = heimdall_decompiler::decompile(args).await?;
    result.source.ok_or(DecompileDiffError::NoSource)
}
