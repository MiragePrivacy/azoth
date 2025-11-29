//! Decompile diff command for comparing decompiled bytecode before and after obfuscation.
//!
//! This module provides a CLI interface to the decompile diff analysis functionality,
//! which runs obfuscation on input bytecode, then uses Heimdall's decompiler to generate
//! human-readable Solidity-like output and computes a unified diff between the original
//! and obfuscated versions. Supports running multiple iterations with different seeds
//! to generate statistical analysis of obfuscation effectiveness.

use async_trait::async_trait;
use azoth_analysis::decompile_diff::{self, AggregatedStats, DiffResult};
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use clap::Args;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinSet;

use super::obfuscate::{build_passes, read_input};

/// Arguments for the `decompile-diff` subcommand.
///
/// This command obfuscates input bytecode and compares decompiled output of the
/// original vs obfuscated versions to visualize differences introduced by the transforms.
/// When running multiple iterations, it aggregates statistics across all runs.
#[derive(Args)]
pub struct DecompileDiffArgs {
    /// Input deployment bytecode as a hex string (0x...), .hex file, or binary file.
    pub input: String,

    /// Input runtime bytecode as a hex string (0x...), .hex file, or binary file.
    #[arg(long)]
    pub runtime: String,

    /// Comma-separated list of transforms (default: shuffle).
    #[arg(long, default_value = "shuffle")]
    pub passes: String,

    /// Number of iterations to run with different seeds for statistical analysis.
    #[arg(long, short = 'n', default_value = "10")]
    pub iterations: usize,

    /// Number of top common replacements to show in statistics.
    #[arg(long, default_value = "3")]
    pub top_replacements: usize,

    /// Output file path for writing the diff from the first iteration.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

/// Executes the `decompile-diff` subcommand.
#[async_trait]
impl super::Command for DecompileDiffArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let input_bytecode = read_input(&self.input)?;
        let runtime_bytecode = read_input(&self.runtime)?;
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

        let mut join_set: JoinSet<Result<DiffResult, String>> = JoinSet::new();

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

                let diff_result =
                    decompile_diff::compare(pre_bytes.as_ref().clone().into(), post_bytes.into())
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

        // Aggregate results
        let mut aggregated: Option<AggregatedStats> = None;
        let mut first_result: Option<DiffResult> = None;

        for (i, result) in results.into_iter().enumerate() {
            let diff_result = result?;

            if i == 0 {
                first_result = Some(diff_result.clone());
            }

            match &mut aggregated {
                None => aggregated = Some(AggregatedStats::new(&diff_result)),
                Some(agg) => agg.add(&diff_result),
            }
        }

        let aggregated = aggregated.expect("at least one iteration");
        let first_result = first_result.expect("at least one iteration");

        // Write diff to file if requested
        if let Some(output_path) = &self.output {
            fs::write(output_path, &first_result.unified_diff)?;
            println!("Diff written to: {}", output_path.display());
            println!();
        }

        // Print statistics
        self.print_statistics(&aggregated, &first_result);

        Ok(())
    }
}

impl DecompileDiffArgs {
    /// Prints aggregated statistics to stdout.
    fn print_statistics(&self, stats: &AggregatedStats, first_result: &DiffResult) {
        // Print diff for single iteration when no output file specified
        if self.iterations == 1 && self.output.is_none() {
            println!("═══ Decompiled Diff (original → obfuscated) ═══\n");
            println!("{}", first_result.colored_diff);
        }

        // Print statistics header
        println!(
            "═══ Statistics ({} iteration{}) ═══",
            stats.sample_count,
            if stats.sample_count == 1 { "" } else { "s" }
        );
        println!();

        // Table header
        println!("{:20} {:>10} {:>10} {:>10}", "Metric", "Min", "Avg", "Max");
        println!("{}", "─".repeat(52));

        // Statistics rows
        println!(
            "{:20} {:>10} {:>10.1} {:>10}",
            "Hunks", stats.min.hunk_count, stats.avg.hunk_count, stats.max.hunk_count
        );
        println!(
            "{:20} {:>10} {:>10.1} {:>10}",
            "Lines removed",
            stats.min.lines_removed,
            stats.avg.lines_removed,
            stats.max.lines_removed
        );
        println!(
            "{:20} {:>10} {:>10.1} {:>10}",
            "Lines added", stats.min.lines_added, stats.avg.lines_added, stats.max.lines_added
        );
        println!(
            "{:20} {:>10} {:>10.1} {:>10}",
            "Lines unchanged",
            stats.min.lines_unchanged,
            stats.avg.lines_unchanged,
            stats.max.lines_unchanged
        );

        // Top replacements
        let top = stats.top_replacements(self.top_replacements);
        if !top.is_empty() {
            println!();
            println!("═══ Top {} Common Replacements ═══", top.len());
            println!();

            for (i, (replacement, count)) in top.iter().enumerate() {
                println!(
                    "{}. {} occurrence{}",
                    i + 1,
                    count,
                    if *count == 1 { "" } else { "s" }
                );

                // Show before lines
                if replacement.before.is_empty() {
                    println!("   (no lines removed)");
                } else {
                    for line in &replacement.before {
                        let trimmed = line.trim_end();
                        println!("   -{trimmed}");
                    }
                }

                // Show after lines
                if replacement.after.is_empty() {
                    println!("   (no lines added)");
                } else {
                    for line in &replacement.after {
                        let trimmed = line.trim_end();
                        println!("   +{trimmed}");
                    }
                }
                println!();
            }
        }
    }
}
