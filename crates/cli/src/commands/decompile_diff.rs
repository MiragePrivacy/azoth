//! Decompile diff command for comparing decompiled bytecode before and after obfuscation.
//!
//! This module provides a CLI interface to the decompile diff analysis functionality,
//! which runs obfuscation on input bytecode, then uses Heimdall's decompiler to generate
//! human-readable Solidity-like output and computes structured diffs between the original
//! and obfuscated versions.
//!
//! The structured diff uses the selector mapping from obfuscation to pair functions,
//! enabling semantic comparison even when selectors are remapped. Supports running multiple
//! iterations with different seeds to generate statistical analysis.

use async_trait::async_trait;
use azoth_analysis::decompile_diff::{self, DiffStats, StructureKind, StructuredDiffResult};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use clap::Args;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinSet;

use super::obfuscate::{build_passes, read_input};

/// Arguments for the `decompile-diff` subcommand.
///
/// This command obfuscates input bytecode and compares decompiled output of the
/// original vs obfuscated versions using structured diff that pairs functions
/// by their selector mapping.
#[derive(Args)]
pub struct DecompileDiffArgs {
    /// Input deployment bytecode as a hex string (0x...), .hex file, or binary file.
    #[arg(short = 'D', long = "deployment")]
    pub deployment_bytecode: String,

    /// Input runtime bytecode as a hex string (0x...), .hex file, or binary file.
    #[arg(short = 'R', long = "runtime")]
    pub runtime_bytecode: String,

    /// Comma-separated list of transforms (default: shuffle).
    #[arg(long, default_value = "shuffle")]
    pub passes: String,

    /// Number of iterations to run with different seeds for statistical analysis.
    #[arg(long, short = 'n', default_value = "10")]
    pub iterations: usize,

    /// Output file path for writing the diff from the first iteration.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Only show items that have changes.
    #[arg(long)]
    pub changed_only: bool,
}

/// Aggregated statistics across multiple structured diff runs.
#[derive(Debug, Clone)]
struct AggregatedStructuredStats {
    min: DiffStats,
    max: DiffStats,
    sum: DiffStats,
    sample_count: usize,
}

impl AggregatedStructuredStats {
    fn new(first: &DiffStats) -> Self {
        Self {
            min: first.clone(),
            max: first.clone(),
            sum: first.clone(),
            sample_count: 1,
        }
    }

    fn add(&mut self, stats: &DiffStats) {
        self.min.hunk_count = self.min.hunk_count.min(stats.hunk_count);
        self.min.lines_removed = self.min.lines_removed.min(stats.lines_removed);
        self.min.lines_added = self.min.lines_added.min(stats.lines_added);
        self.min.lines_unchanged = self.min.lines_unchanged.min(stats.lines_unchanged);

        self.max.hunk_count = self.max.hunk_count.max(stats.hunk_count);
        self.max.lines_removed = self.max.lines_removed.max(stats.lines_removed);
        self.max.lines_added = self.max.lines_added.max(stats.lines_added);
        self.max.lines_unchanged = self.max.lines_unchanged.max(stats.lines_unchanged);

        self.sum.hunk_count += stats.hunk_count;
        self.sum.lines_removed += stats.lines_removed;
        self.sum.lines_added += stats.lines_added;
        self.sum.lines_unchanged += stats.lines_unchanged;

        self.sample_count += 1;
    }

    fn avg_hunks(&self) -> f64 {
        self.sum.hunk_count as f64 / self.sample_count as f64
    }

    fn avg_removed(&self) -> f64 {
        self.sum.lines_removed as f64 / self.sample_count as f64
    }

    fn avg_added(&self) -> f64 {
        self.sum.lines_added as f64 / self.sample_count as f64
    }

    fn avg_unchanged(&self) -> f64 {
        self.sum.lines_unchanged as f64 / self.sample_count as f64
    }
}

/// Executes the `decompile-diff` subcommand.
#[async_trait]
impl super::Command for DecompileDiffArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let input_bytecode = read_input(&self.deployment_bytecode)?;
        let runtime_bytecode = read_input(&self.runtime_bytecode)?;
        let pre_bytes = hex::decode(runtime_bytecode.trim_start_matches("0x"))?;

        // Run iterations in parallel with bounded concurrency
        let max_concurrency = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

        let input_bytecode = Arc::new(input_bytecode);
        let runtime_bytecode = Arc::new(runtime_bytecode);
        let pre_bytes = Arc::new(pre_bytes);
        let passes = Arc::new(self.passes.clone());

        let mut join_set: JoinSet<Result<StructuredDiffResult, String>> = JoinSet::new();

        for _ in 0..self.iterations {
            let input_bytecode = Arc::clone(&input_bytecode);
            let runtime_bytecode = Arc::clone(&runtime_bytecode);
            let pre_bytes = Arc::clone(&pre_bytes);
            let passes = Arc::clone(&passes);
            let semaphore = Arc::clone(&semaphore);

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let transforms = build_passes(&passes).map_err(|e| format!("build_passes: {e}"))?;

                // Each iteration uses a fresh random seed
                let config = ObfuscationConfig {
                    transforms,
                    preserve_unknown_opcodes: true,
                    ..Default::default()
                };

                let obf_result = obfuscate_bytecode(&input_bytecode, &runtime_bytecode, config)
                    .await
                    .map_err(|e| format!("obfuscate: {e}"))?;

                let post_bytes =
                    hex::decode(obf_result.obfuscated_runtime.trim_start_matches("0x"))
                        .map_err(|e| format!("hex decode: {e}"))?;

                let selector_mapping: HashMap<u32, Vec<u8>> =
                    obf_result.selector_mapping.unwrap_or_default();

                let diff_result = decompile_diff::compare_structured(
                    pre_bytes.as_ref().clone().into(),
                    post_bytes.into(),
                    selector_mapping,
                )
                .await
                .map_err(|e| format!("decompile: {e}"))?;

                Ok(diff_result)
            });
        }

        // Collect results
        let mut results = Vec::with_capacity(self.iterations);
        while let Some(result) = join_set.join_next().await {
            results.push(result.map_err(|e| format!("join error: {e}"))?);
        }

        // Aggregate statistics
        let mut aggregated: Option<AggregatedStructuredStats> = None;
        let mut first_result: Option<StructuredDiffResult> = None;

        for (i, result) in results.into_iter().enumerate() {
            let diff_result = result?;
            let stats = diff_result.aggregate_stats();

            if i == 0 {
                first_result = Some(diff_result);
            }

            match &mut aggregated {
                None => aggregated = Some(AggregatedStructuredStats::new(&stats)),
                Some(agg) => agg.add(&stats),
            }
        }

        let aggregated = aggregated.expect("at least one iteration");
        let first_result = first_result.expect("at least one iteration");

        // Write diff to file if requested, otherwise print to terminal
        if let Some(output_path) = &self.output {
            let output = self.format_diff_output(&first_result);
            fs::write(output_path, output)?;
        } else {
            self.print_structured_diff(&first_result);
        }

        // Always print summary and statistics
        self.print_statistics(&aggregated, &first_result);

        Ok(())
    }
}

impl DecompileDiffArgs {
    /// Formats the diff only (no stats) as plain text for file output.
    fn format_diff_output(&self, result: &StructuredDiffResult) -> String {
        let mut output = String::new();

        for item in &result.items {
            if self.changed_only && !item.has_changes() {
                continue;
            }

            output.push_str(&format!("─── {} ───\n", item.kind));

            if item.has_changes() {
                output.push_str(&item.diff.unified_diff);
            } else {
                output.push_str("(no changes)\n");
            }
            output.push('\n');
        }

        output
    }

    /// Prints the structured diff to stdout with colors (no summary, just diffs).
    fn print_structured_diff(&self, result: &StructuredDiffResult) {
        // Each item
        for item in &result.items {
            if self.changed_only && !item.has_changes() {
                continue;
            }

            // Section header
            let header = match &item.kind {
                StructureKind::Header => "Header".to_string(),
                StructureKind::Storage => "Storage".to_string(),
                StructureKind::Function {
                    original_selector,
                    obfuscated_selector,
                    name,
                } => {
                    format!(
                        "Function {} ({} → {})",
                        name.bold(),
                        format!("0x{:08x}", original_selector).dimmed(),
                        format!("0x{:08x}", obfuscated_selector).cyan()
                    )
                }
                StructureKind::UnmatchedOriginal { selector, name } => {
                    format!(
                        "{} {} ({})",
                        "Removed:".red(),
                        name,
                        format!("0x{:08x}", selector).dimmed()
                    )
                }
                StructureKind::UnmatchedObfuscated { selector, name } => {
                    format!(
                        "{} {} ({})",
                        "Added:".green(),
                        name,
                        format!("0x{:08x}", selector).cyan()
                    )
                }
            };

            println!("─── {} ───", header);

            if item.has_changes() {
                let stats = &item.diff.stats;
                println!(
                    "    {} hunks, {} {}, {} {}",
                    stats.hunk_count,
                    format!("-{}", stats.lines_removed).red(),
                    "removed".dimmed(),
                    format!("+{}", stats.lines_added).green(),
                    "added".dimmed()
                );
                println!();
                print!("{}", item.diff.colored_diff);
            } else {
                println!("    {}", "(no changes)".dimmed());
            }
            println!();
        }
    }

    /// Prints summary and aggregated statistics to stdout as valid markdown.
    fn print_statistics(&self, stats: &AggregatedStructuredStats, result: &StructuredDiffResult) {
        println!(
            "## Statistics ({} iteration{})\n",
            stats.sample_count,
            if stats.sample_count == 1 { "" } else { "s" }
        );

        // Summary from first result
        let diff_stats = result.aggregate_stats();
        let changed_count = result.items.iter().filter(|i| i.has_changes()).count();

        println!(
            "- **Total:** {} hunks, -{} removed, +{} added",
            diff_stats.hunk_count, diff_stats.lines_removed, diff_stats.lines_added
        );
        println!(
            "- **Items:** {} total, {} with changes",
            result.items.len(),
            changed_count
        );

        if !result.selector_mapping.is_empty() {
            println!(
                "- **Selectors:** {} remapped",
                result.selector_mapping.len()
            );
        }
        println!();

        // Markdown table with padding for readability
        println!(
            "| {:<15} | {:>10} | {:>10} | {:>10} |",
            "Metric", "Min", "Avg", "Max"
        );
        println!("|-{:-<15}-|-{:->10}:|-{:->10}:|-{:->10}:|", "", "", "", "");
        println!(
            "| {:<15} | {:>10} | {:>10.1} | {:>10} |",
            "Hunks",
            stats.min.hunk_count,
            stats.avg_hunks(),
            stats.max.hunk_count
        );
        println!(
            "| {:<15} | {:>10} | {:>10.1} | {:>10} |",
            "Lines removed",
            stats.min.lines_removed,
            stats.avg_removed(),
            stats.max.lines_removed
        );
        println!(
            "| {:<15} | {:>10} | {:>10.1} | {:>10} |",
            "Lines added",
            stats.min.lines_added,
            stats.avg_added(),
            stats.max.lines_added
        );
        println!(
            "| {:<15} | {:>10} | {:>10.1} | {:>10} |",
            "Lines unchanged",
            stats.min.lines_unchanged,
            stats.avg_unchanged(),
            stats.max.lines_unchanged
        );
    }
}
