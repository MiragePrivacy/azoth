//! Decompiled difference metrics.
//!
//! Uses Heimdall's decompilation on before and after bytecodes to quantify obfuscation level
//! by computing structured diff results that can be aggregated across multiple obfuscation runs.

use alloy::primitives::Bytes;
use heimdall_decompiler::DecompilerArgsBuilder;
use imara_diff::{Diff, InternedInput, Interner, Token, UnifiedDiffPrinter};
use owo_colors::OwoColorize;
use std::collections::HashMap;
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

/// A single replacement hunk representing lines removed and added.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Replacement {
    /// Lines that were removed (from original).
    pub before: Vec<String>,
    /// Lines that were added (in obfuscated).
    pub after: Vec<String>,
}

/// Statistics from a single diff comparison.
#[derive(Debug, Clone)]
pub struct DiffStats {
    /// Number of diff hunks.
    pub hunk_count: usize,
    /// Number of lines removed from original.
    pub lines_removed: usize,
    /// Number of lines added in obfuscated.
    pub lines_added: usize,
    /// Number of lines unchanged.
    pub lines_unchanged: usize,
    /// Total lines in original.
    pub total_original_lines: usize,
}

/// Result of a decompile diff comparison containing both the formatted diff
/// output and structured statistics for aggregation.
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// The unified diff output as a formatted string (without color codes).
    pub unified_diff: String,
    /// The unified diff output with ANSI color codes for terminal display.
    pub colored_diff: String,
    /// Statistics about the diff.
    pub stats: DiffStats,
    /// Individual replacements for pattern analysis.
    pub replacements: Vec<Replacement>,
}

/// Aggregated statistics across multiple diff runs.
#[derive(Debug, Clone)]
pub struct AggregatedStats {
    /// Minimum values observed.
    pub min: DiffStats,
    /// Maximum values observed.
    pub max: DiffStats,
    /// Average values (as floats for precision).
    pub avg: AvgDiffStats,
    /// Number of samples aggregated.
    pub sample_count: usize,
    /// Replacement patterns with their occurrence counts.
    replacement_counts: HashMap<Replacement, usize>,
}

/// Average statistics with floating-point precision.
#[derive(Debug, Clone)]
pub struct AvgDiffStats {
    /// Average number of diff hunks.
    pub hunk_count: f64,
    /// Average number of lines removed.
    pub lines_removed: f64,
    /// Average number of lines added.
    pub lines_added: f64,
    /// Average number of lines unchanged.
    pub lines_unchanged: f64,
}

impl AggregatedStats {
    /// Creates a new aggregated stats collector from an initial diff result.
    pub fn new(first: &DiffResult) -> Self {
        let mut replacement_counts = HashMap::new();
        for r in &first.replacements {
            *replacement_counts.entry(r.clone()).or_insert(0usize) += 1;
        }

        Self {
            min: first.stats.clone(),
            max: first.stats.clone(),
            avg: AvgDiffStats {
                hunk_count: first.stats.hunk_count as f64,
                lines_removed: first.stats.lines_removed as f64,
                lines_added: first.stats.lines_added as f64,
                lines_unchanged: first.stats.lines_unchanged as f64,
            },
            sample_count: 1,
            replacement_counts,
        }
    }

    /// Adds another diff result to the aggregation.
    pub fn add(&mut self, result: &DiffResult) {
        let stats = &result.stats;

        // Update min
        self.min.hunk_count = self.min.hunk_count.min(stats.hunk_count);
        self.min.lines_removed = self.min.lines_removed.min(stats.lines_removed);
        self.min.lines_added = self.min.lines_added.min(stats.lines_added);
        self.min.lines_unchanged = self.min.lines_unchanged.min(stats.lines_unchanged);

        // Update max
        self.max.hunk_count = self.max.hunk_count.max(stats.hunk_count);
        self.max.lines_removed = self.max.lines_removed.max(stats.lines_removed);
        self.max.lines_added = self.max.lines_added.max(stats.lines_added);
        self.max.lines_unchanged = self.max.lines_unchanged.max(stats.lines_unchanged);

        // Update running average
        let n = self.sample_count as f64;
        let n1 = (self.sample_count + 1) as f64;
        self.avg.hunk_count = (self.avg.hunk_count * n + stats.hunk_count as f64) / n1;
        self.avg.lines_removed = (self.avg.lines_removed * n + stats.lines_removed as f64) / n1;
        self.avg.lines_added = (self.avg.lines_added * n + stats.lines_added as f64) / n1;
        self.avg.lines_unchanged =
            (self.avg.lines_unchanged * n + stats.lines_unchanged as f64) / n1;

        // Accumulate replacement counts
        for r in &result.replacements {
            *self.replacement_counts.entry(r.clone()).or_insert(0) += 1;
        }

        self.sample_count += 1;
    }

    /// Returns the top N most common replacements sorted by frequency.
    pub fn top_replacements(&self, n: usize) -> Vec<(&Replacement, usize)> {
        let mut sorted: Vec<_> = self
            .replacement_counts
            .iter()
            .map(|(k, &v)| (k, v))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }
}

/// Colorized diff printer that shows removed lines in red, added lines in green,
/// and context/identical lines in the default color.
struct ColoredDiffPrinter<'a> {
    interner: &'a Interner<&'a str>,
}

impl<'a> ColoredDiffPrinter<'a> {
    fn new(interner: &'a Interner<&'a str>) -> Self {
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

/// Plain diff printer without color codes for file output.
struct PlainDiffPrinter<'a> {
    interner: &'a Interner<&'a str>,
}

impl<'a> PlainDiffPrinter<'a> {
    fn new(interner: &'a Interner<&'a str>) -> Self {
        Self { interner }
    }
}

impl UnifiedDiffPrinter for PlainDiffPrinter<'_> {
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
            "@@ -{},{} +{},{} @@",
            start_before + 1,
            len_before,
            start_after + 1,
            len_after
        )
    }

    fn display_context_token(&self, mut f: impl fmt::Write, token: Token) -> fmt::Result {
        let line = self.interner[token];
        write!(f, " {line}")?;
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
            write!(f, "-{line}")?;
            if !line.ends_with('\n') {
                writeln!(f)?;
            }
        }
        for &token in after {
            let line = self.interner[token];
            write!(f, "+{line}")?;
            if !line.ends_with('\n') {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

/// Compares two decompiled sources and returns structured diff results.
///
/// This function computes a unified diff between the pre and post decompiled sources,
/// returning both formatted diff output and structured statistics that can be aggregated
/// across multiple runs for statistical analysis.
///
/// # Parameters
///
/// * `pre_source` - The decompiled source of the original bytecode.
/// * `post_source` - The decompiled source of the obfuscated bytecode.
///
/// # Returns
///
/// Returns a `DiffResult` containing the unified diff output (both plain and colored),
/// statistics about lines added/removed/unchanged, and individual replacement hunks
/// for pattern analysis.
pub fn compare_sources(pre_source: &str, post_source: &str) -> DiffResult {
    let input = InternedInput::new(pre_source, post_source);
    let mut diff = Diff::compute(imara_diff::Algorithm::Histogram, &input);
    diff.postprocess_lines(&input);

    // Generate both plain and colored diff output
    let mut config = imara_diff::UnifiedDiffConfig::default();
    config.context_len(input.before.len().max(input.after.len()) as u32);

    let plain_printer = PlainDiffPrinter::new(&input.interner);
    let unified_diff = diff
        .unified_diff(&plain_printer, config.clone(), &input)
        .to_string();

    let colored_printer = ColoredDiffPrinter::new(&input.interner);
    let colored_diff = diff
        .unified_diff(&colored_printer, config, &input)
        .to_string();

    // Compute statistics
    let hunks: Vec<_> = diff.hunks().collect();
    let total_removed: usize = hunks.iter().map(|h| h.before.len()).sum();
    let total_added: usize = hunks.iter().map(|h| h.after.len()).sum();
    let total_original = input.before.len();
    let unchanged = total_original.saturating_sub(total_removed);

    // Extract replacements for pattern analysis
    let replacements: Vec<Replacement> = hunks
        .iter()
        .map(|h| Replacement {
            before: h
                .before
                .clone()
                .map(|idx| input.interner[input.before[idx as usize]].to_string())
                .collect(),
            after: h
                .after
                .clone()
                .map(|idx| input.interner[input.after[idx as usize]].to_string())
                .collect(),
        })
        .collect();

    DiffResult {
        unified_diff,
        colored_diff,
        stats: DiffStats {
            hunk_count: hunks.len(),
            lines_removed: total_removed,
            lines_added: total_added,
            lines_unchanged: unchanged,
            total_original_lines: total_original,
        },
        replacements,
    }
}

/// Compares two bytecodes by decompiling them and returning structured diff results.
///
/// This function decompiles both bytecode inputs using Heimdall, then computes
/// a unified diff and returns structured results containing statistics and
/// replacement patterns suitable for aggregation across multiple runs.
///
/// # Parameters
///
/// * `pre` - The original bytecode before obfuscation.
/// * `post` - The obfuscated bytecode.
///
/// # Returns
///
/// Returns a `DiffResult` containing diff output and statistics, or an error
/// if decompilation fails.
pub async fn compare(pre: Bytes, post: Bytes) -> Result<DiffResult, DecompileDiffError> {
    let pre_source = decompile(pre).await?;
    let post_source = decompile(post).await?;
    Ok(compare_sources(&pre_source, &post_source))
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
