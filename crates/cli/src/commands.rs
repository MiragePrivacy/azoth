use async_trait::async_trait;
use clap::Subcommand;
use std::error::Error;

use thiserror::Error;

pub const DEFAULT_PASSES: &str = "cluster_shuffle";

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
    /// A legacy pass is available to library developers but is not admitted to the production
    /// profile because its semantic or detectability obligations are not yet proven.
    #[error("pass is disabled in the production profile: {0}")]
    UnsafePass(String),
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
    /// Fuzz test the obfuscation pipeline.
    Fuzz(fuzz::FuzzArgs),
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
            Cmd::Fuzz(args) => args.execute().await,
        }
    }
}

pub mod analyze {
    use crate::commands::{obfuscate::read_input, ObfuscateError};
    use async_trait::async_trait;
    use azoth_analysis::obfuscation::{analyze_obfuscation, AnalysisConfig, AnalysisError};
    use azoth_core::seed::Seed;
    use clap::Args;
    use std::{error::Error, path::PathBuf};
    const DEFAULT_DEPLOYMENT_PATH: &str = "examples/escrow-bytecode/artifacts/erc20_deployment.hex";
    const DEFAULT_RUNTIME_PATH: &str = "examples/escrow-bytecode/artifacts/erc20_runtime.hex";

    /// Analyze how much bytecode survives obfuscation across multiple seeds.
    #[derive(Args)]
    pub struct AnalyzeArgs {
        /// Number of obfuscated samples to generate.
        pub iterations: usize,
        /// Input deployment bytecode as hex, .hex file, or binary file.
        #[arg(short = 'D', long = "deployment", value_name = "BYTECODE", default_value = DEFAULT_DEPLOYMENT_PATH)]
        pub deployment_bytecode: String,
        /// Input runtime bytecode as hex, .hex file, or binary file.
        #[arg(short = 'R', long = "runtime", value_name = "RUNTIME", default_value = DEFAULT_RUNTIME_PATH)]
        pub runtime_bytecode: String,
        /// Where to write the markdown report (default: ./obfuscation_analysis_report.md).
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Maximum attempts per iteration when an obfuscation fails.
        #[arg(long, default_value_t = 5)]
        max_attempts: usize,
        /// Private 256-bit root seed used to derive the reproducible analysis corpus.
        #[arg(long)]
        seed: String,
    }

    #[async_trait]
    impl super::Command for AnalyzeArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            let AnalyzeArgs {
                iterations,
                deployment_bytecode,
                runtime_bytecode,
                output,
                max_attempts,
                seed,
            } = self;

            let input_hex = read_input(&deployment_bytecode)?;
            let runtime_hex = read_input(&runtime_bytecode)?;

            let root_seed =
                Seed::from_hex(&seed).map_err(|error| format!("invalid seed hex: {error}"))?;
            let mut config = AnalysisConfig::new(&input_hex, &runtime_hex, iterations, root_seed);
            config.max_attempts = max_attempts;
            if let Some(path) = output {
                config.report_path = path;
            }

            let report = match analyze_obfuscation(config).await {
                Ok(report) => report,
                Err(AnalysisError::UnknownOpcodes { count }) => {
                    println!(
                        "Analysis aborted: obfuscation preserved {count} unknown opcode(s).\nStrip or normalize the bytecode before running analysis."
                    );
                    return Ok(());
                }
                Err(err) => return Err(map_analysis_error(err)),
            };

            println!("============================================================");
            println!("SUMMARY");
            println!("============================================================");
            println!(
                "Average longest sequence:  {:.2} bytes ({:.2}% of original)",
                report.summary.average_length, report.summary.preservation_ratio
            );
            println!(
                "Median longest sequence:   {:.2} bytes",
                report.summary.median_length
            );
            println!(
                "Standard deviation:        {:.2} bytes",
                report.summary.std_dev
            );
            println!(
                "Range:                     {}-{} bytes",
                report.summary.min_length, report.summary.max_length
            );
            println!(
                "25th percentile:           {:.2} bytes",
                report.summary.percentile_25
            );
            println!(
                "75th percentile:           {:.2} bytes",
                report.summary.percentile_75
            );
            println!(
                "95th percentile:           {:.2} bytes",
                report.summary.percentile_95
            );
            println!(
                "Seeds generated:           {} (unique: {})",
                report.seed_commitments.len(),
                report.unique_seed_count
            );
            println!("Transforms observed:       {}", report.transform_summary());
            println!();
            for (n, value) in &report.ngram_diversity {
                println!("{:>2}-byte n-gram diversity: {:>6.2}%", n, value);
            }
            println!("============================================================");
            println!(
                "Analysis complete! Report saved to: {}",
                report.markdown_path.display()
            );

            Ok(())
        }
    }

    fn map_analysis_error(err: AnalysisError) -> Box<dyn Error> {
        match err {
            AnalysisError::Decode(err) => Box::new(err),
            AnalysisError::UnknownOpcodes { count } => Box::new(std::io::Error::other(format!(
                "analysis aborted due to {count} unknown opcode(s)"
            ))),
            AnalysisError::InvalidPass(name) => Box::new(ObfuscateError::InvalidPass(name)),
            AnalysisError::ObfuscationFailure { source, .. } => source,
            AnalysisError::Io(err) => Box::new(err),
            AnalysisError::Fmt(err) => Box::new(err),
            AnalysisError::EmptyIterations => Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "iterations must be positive",
            )),
            AnalysisError::EmptyAttempts => Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "max attempts must be positive",
            )),
        }
    }
}

pub mod cfg {
    //! This module processes input bytecode, constructs a CFG using the `cfg_ir` module, and
    //! generates a Graphviz .dot file representing the CFG. The output can be written to a file or
    //! printed to stdout.

    use async_trait::async_trait;
    use azoth_core::cfg_ir::{Block, CfgIrBundle, EdgeType};
    use azoth_core::process_bytecode_to_cfg;
    use clap::Args;
    use std::error::Error;
    use std::fs;
    use std::path::Path;

    /// Arguments for the `cfg` subcommand.
    #[derive(Args)]
    pub struct CfgArgs {
        /// Input deployment bytecode as a hex string (0x...) or file path containing EVM bytecode.
        #[arg(short = 'D', long = "deployment")]
        pub deployment_bytecode: String,
        /// Input runtime bytecode as a hex string (0x...) or file path containing EVM bytecode.
        #[arg(short = 'R', long = "runtime")]
        pub runtime_bytecode: String,
        /// Output file for Graphviz .dot (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    }

    /// Executes the `cfg` subcommand to generate a CFG visualization.
    #[async_trait]
    impl super::Command for CfgArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            let is_file = !self.deployment_bytecode.starts_with("0x")
                && Path::new(&self.deployment_bytecode).is_file();
            let runtime_is_file = !self.runtime_bytecode.starts_with("0x")
                && Path::new(&self.runtime_bytecode).is_file();
            let (cfg_ir, _, _, _) = process_bytecode_to_cfg(
                &self.deployment_bytecode,
                is_file,
                &self.runtime_bytecode,
                runtime_is_file,
            )
            .await
            .map_err(|error| -> Box<dyn Error> { error })?;

            let dot = generate_dot(&cfg_ir);
            if let Some(out_path) = self.output {
                fs::write(out_path, &dot)?;
            } else {
                println!("{dot}");
            }
            Ok(())
        }
    }

    /// Generates a Graphviz .dot representation of the CFG.
    ///
    /// # Arguments
    /// * `cfg_ir` - The `CfgIrBundle` containing the CFG to visualize.
    ///
    /// # Returns
    /// A `String` containing the .dot file content.
    fn generate_dot(cfg_ir: &CfgIrBundle) -> String {
        let mut dot = String::from("digraph CFG {\n");

        // Add nodes
        for node in cfg_ir.cfg.node_indices() {
            let block = cfg_ir.cfg.node_weight(node).unwrap();
            let label = match block {
                Block::Entry => "Entry".to_string(),
                Block::Exit => "Exit".to_string(),
                Block::Body(body) => {
                    let instrs: Vec<String> =
                        body.instructions.iter().map(|i| i.to_string()).collect();
                    format!("Block_{}\\n{}", body.start_pc, instrs.join("\\n"))
                }
            };
            dot.push_str(&format!("    {} [label=\"{}\"];\n", node.index(), label));
        }

        // Add edges
        for edge in cfg_ir.cfg.edge_indices() {
            let (src, dst) = cfg_ir.cfg.edge_endpoints(edge).unwrap();
            let edge_type = cfg_ir.cfg.edge_weight(edge).unwrap();
            let label = match edge_type {
                EdgeType::Fallthrough => "Fallthrough",
                EdgeType::Jump => "Jump",
                EdgeType::BranchTrue => "BranchTrue",
                EdgeType::BranchFalse => "BranchFalse",
            };
            dot.push_str(&format!(
                "    {} -> {} [label=\"{}\"];\n",
                src.index(),
                dst.index(),
                label
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

pub mod decode {
    //! This module processes input bytecode and outputs Azoth's native assembly format.

    use async_trait::async_trait;
    use azoth_core::decoder::decode_input;
    use clap::Args;
    use std::error::Error;
    use std::path::Path;

    /// Arguments for the `decode` subcommand.
    #[derive(Args)]
    pub struct DecodeArgs {
        /// Input bytecode as a hex string (0x...) or file path containing EVM bytecode.
        #[arg(short = 'D', long = "deployment")]
        pub deployment_bytecode: String,
    }

    /// Executes the `decode` subcommand to decode bytecode.
    #[async_trait]
    impl super::Command for DecodeArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            let is_file = !self.deployment_bytecode.starts_with("0x")
                && Path::new(&self.deployment_bytecode).is_file();
            let decoded = decode_input(&self.deployment_bytecode, is_file)?;
            print!("{}", decoded.format_assembly());
            Ok(())
        }
    }
}

pub mod decompile_diff {
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
    use azoth_core::seed::Seed;
    use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
    use clap::Args;
    use owo_colors::OwoColorize;
    use std::collections::HashMap;
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::task::JoinSet;

    use crate::commands::DEFAULT_PASSES;

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

        /// Comma-separated list of production-admitted transforms (default: cluster shuffle).
        #[arg(long, default_value = DEFAULT_PASSES)]
        pub passes: String,

        /// Number of iterations to run with different seeds for statistical analysis.
        #[arg(long, short = 'n', default_value = "10")]
        pub iterations: usize,

        /// Private 256-bit root seed. Each iteration uses a deterministic domain-separated child.
        #[arg(long)]
        pub seed: String,

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
            if self.iterations == 0 {
                return Err("iterations must be at least one".into());
            }
            let input_bytecode = read_input(&self.deployment_bytecode)?;
            let runtime_bytecode = read_input(&self.runtime_bytecode)?;
            let pre_bytes = hex::decode(runtime_bytecode.trim_start_matches("0x"))?;
            let root_seed = Arc::new(
                Seed::from_hex(&self.seed).map_err(|error| format!("invalid seed hex: {error}"))?,
            );

            // Run iterations in parallel with bounded concurrency
            let max_concurrency = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4);
            let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

            let input_bytecode = Arc::new(input_bytecode);
            let runtime_bytecode = Arc::new(runtime_bytecode);
            let pre_bytes = Arc::new(pre_bytes);
            let passes = Arc::new(self.passes.clone());

            let mut join_set: JoinSet<Result<(usize, StructuredDiffResult), String>> =
                JoinSet::new();

            for iteration in 0..self.iterations {
                let input_bytecode = Arc::clone(&input_bytecode);
                let runtime_bytecode = Arc::clone(&runtime_bytecode);
                let pre_bytes = Arc::clone(&pre_bytes);
                let passes = Arc::clone(&passes);
                let semaphore = Arc::clone(&semaphore);
                let root_seed = Arc::clone(&root_seed);

                join_set.spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    let transforms =
                        build_passes(&passes).map_err(|e| format!("build_passes: {e}"))?;

                    let mut config =
                        ObfuscationConfig::with_seed(derive_iteration_seed(&root_seed, iteration));
                    config.transforms = transforms;

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

                    Ok((iteration, diff_result))
                });
            }

            // Collect results
            let mut results = Vec::with_capacity(self.iterations);
            while let Some(result) = join_set.join_next().await {
                results.push(
                    result
                        .map_err(|error| format!("join error: {error}"))?
                        .map_err(|error| format!("analysis iteration failed: {error}"))?,
                );
            }
            results.sort_by_key(|(iteration, _)| *iteration);

            // Aggregate statistics
            let mut aggregated: Option<AggregatedStructuredStats> = None;
            let mut first_result: Option<StructuredDiffResult> = None;

            for (i, (_, diff_result)) in results.into_iter().enumerate() {
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

    fn derive_iteration_seed(root: &Seed, iteration: usize) -> Seed {
        let mut domain = b"azoth-decompile-diff-iteration-v1".to_vec();
        domain.extend_from_slice(&(iteration as u64).to_be_bytes());
        root.derive_seed(&domain)
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
        fn print_statistics(
            &self,
            stats: &AggregatedStructuredStats,
            result: &StructuredDiffResult,
        ) {
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

    #[cfg(test)]
    mod tests {
        use super::derive_iteration_seed;
        use azoth_core::seed::Seed;

        #[test]
        fn iteration_seed_corpus_is_deterministic_and_domain_separated() {
            let root = Seed::from_bytes([0xa5; 32]);
            assert_eq!(
                derive_iteration_seed(&root, 7).as_bytes(),
                derive_iteration_seed(&root, 7).as_bytes()
            );
            assert_ne!(
                derive_iteration_seed(&root, 7).as_bytes(),
                derive_iteration_seed(&root, 8).as_bytes()
            );
        }
    }
}

pub mod fuzz {
    //! Fuzz testing subcommand for the Azoth CLI.
    //!
    //! Runs parallel fuzz testing against the obfuscation pipeline, saving
    //! reproducible crash inputs with debug traces for TUI visualization.

    use std::collections::HashSet;
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use async_trait::async_trait;
    use azoth_core::cfg_ir::TraceEvent;
    use azoth_core::seed::{DeterministicRng, Seed};
    use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
    use clap::{Args, Subcommand};
    use parking_lot::Mutex;
    use rand::{RngCore, SeedableRng};
    use revm::bytecode::Bytecode;
    use revm::context::result::{ExecutionResult, Output};
    use revm::context::TxEnv;
    use revm::database::InMemoryDB;
    use revm::primitives::{Address, Bytes, TxKind, U256};
    use revm::state::AccountInfo;
    use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
    use serde::{Deserialize, Serialize};
    use sha3::{Digest, Sha3_256};
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::obfuscate::build_passes;
    use crate::commands::DEFAULT_PASSES;

    const FUZZ_CRASH_SCHEMA_VERSION: u32 = 2;
    const EXPECTED_PIPELINE_PROFILE: &str = "azoth-foundation-v4";

    fn num_cpus() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }

    /// A writer that captures log output to a buffer.
    /// Uses Arc<Mutex> because tracing's `with_default` requires Send + Sync.
    /// parking_lot::Mutex is just a single atomic op for uncontended locks.
    #[derive(Clone)]
    struct LogCapture {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl LogCapture {
        fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn clear(&self) {
            self.buffer.lock().clear();
        }

        fn extract_lines(&self) -> Vec<String> {
            String::from_utf8_lossy(&self.buffer.lock())
                .lines()
                .map(|s| s.to_string())
                .collect()
        }
    }

    impl Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buffer.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // Contract bytecodes
    const ESCROW_DEPLOYMENT: &str =
        include_str!("../../../examples/escrow-bytecode/artifacts/erc20_deployment.hex");
    const ESCROW_RUNTIME: &str =
        include_str!("../../../examples/escrow-bytecode/artifacts/erc20_runtime.hex");
    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

    /// Fuzz testing for the obfuscation pipeline.
    #[derive(Args)]
    pub struct FuzzArgs {
        #[command(subcommand)]
        command: Option<FuzzCommand>,

        /// Number of parallel fuzzing tasks (defaults to number of CPU cores)
        #[arg(short = 'j', long, default_value_t = num_cpus())]
        jobs: usize,

        /// Maximum iterations (0 = infinite)
        #[arg(short, long, default_value = "0")]
        iterations: u64,

        /// Duration in seconds (0 = infinite)
        #[arg(short, long, default_value = "0")]
        duration: u64,

        /// Directory to save crash inputs
        #[arg(long, default_value = "crashes")]
        crash_dir: PathBuf,

        /// Check that obfuscated bytecode deploys successfully
        #[arg(long, default_value = "false")]
        check_deploy: bool,
    }

    #[derive(Subcommand)]
    enum FuzzCommand {
        /// Replay a saved crash file
        Replay {
            /// Path to crash JSON file
            crash_file: PathBuf,
        },
        /// List all saved crashes
        List,
    }

    /// Contract to fuzz test.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    enum Contract {
        Escrow,
        Counter,
    }

    impl Contract {
        const ALL: [Self; 2] = [Self::Escrow, Self::Counter];

        fn name(self) -> &'static str {
            match self {
                Self::Escrow => "escrow",
                Self::Counter => "counter",
            }
        }

        fn deployment_hex(self) -> &'static str {
            match self {
                Self::Escrow => ESCROW_DEPLOYMENT,
                Self::Counter => COUNTER_DEPLOYMENT,
            }
        }

        fn runtime_hex(self) -> &'static str {
            match self {
                Self::Escrow => ESCROW_RUNTIME,
                Self::Counter => COUNTER_RUNTIME,
            }
        }
    }

    /// Number of comma-separated passes in `DEFAULT_PASSES`.
    fn default_pass_count() -> u32 {
        DEFAULT_PASSES.split(',').count() as u32
    }

    /// Exclusive upper bound on the pass-selection bitmask, covering every default pass.
    fn pass_mask_limit() -> u32 {
        1u32 << default_pass_count()
    }

    /// Generate a random comma-separated pass string from bits.
    fn passes_from_bits(bits: u32) -> String {
        DEFAULT_PASSES
            .split(",")
            .enumerate()
            .filter(|(i, _)| bits & (1 << i) != 0)
            .map(|(_, name)| name)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Reproducible fuzz input containing all parameters needed to replay a test case.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct FuzzInput {
        contract: Contract,
        seed: String,
        passes: String,
    }

    impl FuzzInput {
        fn new(contract: Contract, seed_bytes: [u8; 32], passes: String) -> Self {
            Self {
                contract,
                seed: hex::encode(seed_bytes),
                passes,
            }
        }

        fn seed_bytes(&self) -> Result<[u8; 32], String> {
            let mut bytes = [0u8; 32];
            let decoded =
                hex::decode(&self.seed).map_err(|error| format!("invalid seed hex: {error}"))?;
            if decoded.len() != 32 {
                return Err(format!(
                    "invalid seed length: expected 32 bytes, received {}",
                    decoded.len()
                ));
            }
            bytes.copy_from_slice(&decoded);
            Ok(bytes)
        }
    }

    /// Error categories for crash classification.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    enum ErrorKind {
        Obfuscation,
        Validation,
        DeploymentMismatch { original: usize, obfuscated: usize },
    }

    impl fmt::Display for ErrorKind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Obfuscation => write!(f, "obfuscation failed"),
                Self::Validation => write!(f, "validation failed"),
                Self::DeploymentMismatch {
                    original,
                    obfuscated,
                } => {
                    write!(
                        f,
                        "deployment mismatch (orig={original}b, obf={obfuscated}b)"
                    )
                }
            }
        }
    }

    /// Crash report saved to disk for reproduction and debugging.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct CrashReport {
        #[serde(default)]
        schema_version: u32,
        #[serde(default)]
        pipeline_profile: String,
        id: String,
        timestamp: String,
        input: FuzzInput,
        check_deploy: bool,
        error_kind: ErrorKind,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        obfuscated_bytecode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        trace_file: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        logs: Vec<String>,
    }

    /// Statistics tracked during fuzzing
    struct FuzzStats {
        iterations: AtomicU64,
        successes: AtomicU64,
        errors: AtomicU64,
        deployment_mismatches: AtomicU64,
        unique_crashes: Mutex<HashSet<String>>,
        start_time: Instant,
    }

    impl FuzzStats {
        fn new() -> Self {
            Self {
                iterations: AtomicU64::new(0),
                successes: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                deployment_mismatches: AtomicU64::new(0),
                unique_crashes: Mutex::new(HashSet::new()),
                start_time: Instant::now(),
            }
        }

        fn print_summary(&self, check_deploy: bool) {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            let iters = self.iterations.load(Ordering::Relaxed);
            let rate = if elapsed > 0.0 {
                iters as f64 / elapsed
            } else {
                0.0
            };

            println!("\r\x1b[K=== Fuzzing Summary ===");
            println!("Duration: {:.1}s", elapsed);
            println!("Iterations: {}", iters);
            println!("Rate: {:.1} iter/sec", rate);
            println!("Successes: {}", self.successes.load(Ordering::Relaxed));
            println!("Errors: {}", self.errors.load(Ordering::Relaxed));
            if check_deploy {
                println!(
                    "Deployment-success regressions: {}",
                    self.deployment_mismatches.load(Ordering::Relaxed)
                );
            }
            println!(
                "Unique failing inputs saved: {}",
                self.unique_crashes.lock().len()
            );
        }
    }

    const MOCK_TOKEN_ADDR: Address = Address::new([0x11; 20]);

    fn prepare_escrow_bytecode(deployment_hex: &str, seed: [u8; 32]) -> Option<Vec<u8>> {
        let normalized = deployment_hex.trim().trim_start_matches("0x");
        let mut bytecode = hex::decode(normalized).ok()?;
        let mut rng = DeterministicRng::from_seed(seed);
        let mut recipient = [0u8; 20];
        let mut expected_amount = [0u8; 32];
        let mut payment_amount = [0u8; 32];
        rng.fill_bytes(&mut recipient);
        rng.fill_bytes(&mut expected_amount);
        rng.fill_bytes(&mut payment_amount);
        bytecode.extend_from_slice(&[0; 12]);
        bytecode.extend_from_slice(MOCK_TOKEN_ADDR.as_slice());
        bytecode.extend_from_slice(&[0; 12]);
        bytecode.extend_from_slice(&recipient);
        bytecode.extend_from_slice(&expected_amount);
        bytecode.extend_from_slice(&[0; 32]);
        bytecode.extend_from_slice(&payment_amount);
        Some(bytecode)
    }

    fn prepare_counter_bytecode(deployment_hex: &str) -> Option<Vec<u8>> {
        let normalized = deployment_hex.trim().trim_start_matches("0x");
        hex::decode(normalized).ok()
    }

    fn prepare_bytecode(
        contract: Contract,
        deployment_hex: &str,
        seed: [u8; 32],
    ) -> Option<Vec<u8>> {
        match contract {
            Contract::Escrow => prepare_escrow_bytecode(deployment_hex, seed),
            Contract::Counter => prepare_counter_bytecode(deployment_hex),
        }
    }

    fn deploy_to_revm(bytecode: &[u8], contract: Contract) -> Result<Address, String> {
        let mut db = InMemoryDB::default();
        let deployer = Address::from([0x42u8; 20]);

        db.insert_account_info(
            deployer,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128),
                nonce: 0,
                code_hash: revm::primitives::KECCAK_EMPTY,
                code: None,
            },
        );

        if contract == Contract::Escrow {
            db.insert_account_info(
                MOCK_TOKEN_ADDR,
                AccountInfo {
                    balance: U256::ZERO,
                    nonce: 1,
                    code_hash: revm::primitives::KECCAK_EMPTY,
                    code: Some(Bytecode::new_raw(Bytes::from_static(&[
                        0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
                    ]))),
                },
            );
        }

        let mut evm = Context::mainnet().with_db(db).build_mainnet();
        let tx = TxEnv {
            caller: deployer,
            gas_limit: 30_000_000,
            kind: TxKind::Create,
            data: bytecode.to_vec().into(),
            value: U256::ZERO,
            ..Default::default()
        };

        let result = evm
            .transact(tx)
            .map_err(|e| format!("EVM error: {:?}", e))?;

        match result.result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => Ok(addr),
            ExecutionResult::Success { .. } => Err("No address returned".into()),
            ExecutionResult::Revert { output, .. } => Err(format!("Reverted: {:?}", output)),
            ExecutionResult::Halt { reason, .. } => Err(format!("Halted: {:?}", reason)),
        }
    }

    fn hash_crash_field(hasher: &mut Sha3_256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    fn hash_error_kind(hasher: &mut Sha3_256, kind: &ErrorKind) {
        match kind {
            ErrorKind::Obfuscation => hasher.update([0]),
            ErrorKind::Validation => hasher.update([1]),
            ErrorKind::DeploymentMismatch {
                original,
                obfuscated,
            } => {
                hasher.update([2]);
                hasher.update((*original as u64).to_be_bytes());
                hasher.update((*obfuscated as u64).to_be_bytes());
            }
        }
    }

    fn crash_hash_parts(
        input: &FuzzInput,
        kind: &ErrorKind,
        message: &str,
        obfuscated_bytecode: Option<&str>,
        check_deploy: bool,
    ) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(b"AZOTH_FUZZ_CRASH_ID_V2");
        hasher.update(FUZZ_CRASH_SCHEMA_VERSION.to_be_bytes());
        hash_crash_field(&mut hasher, EXPECTED_PIPELINE_PROFILE.as_bytes());
        hasher.update([match input.contract {
            Contract::Escrow => 0,
            Contract::Counter => 1,
        }]);
        hash_crash_field(&mut hasher, input.seed.as_bytes());
        hash_crash_field(&mut hasher, input.passes.as_bytes());
        hasher.update([u8::from(check_deploy)]);
        hash_error_kind(&mut hasher, kind);
        hash_crash_field(&mut hasher, message.as_bytes());
        match obfuscated_bytecode {
            Some(bytecode) => {
                hasher.update([1]);
                hash_crash_field(&mut hasher, bytecode.as_bytes());
            }
            None => hasher.update([0]),
        }
        hex::encode(hasher.finalize())
    }

    fn crash_hash(input: &FuzzInput, failure: &FuzzFailure, check_deploy: bool) -> String {
        crash_hash_parts(
            input,
            &failure.kind,
            &failure.message,
            failure.obfuscated_bytecode.as_deref(),
            check_deploy,
        )
    }

    /// Failure from a fuzz run, containing error info and trace for debugging.
    struct FuzzFailure {
        kind: ErrorKind,
        message: String,
        trace: Vec<TraceEvent>,
        obfuscated_bytecode: Option<String>,
        logs: Vec<String>,
    }

    fn save_crash(
        crash_dir: &PathBuf,
        input: &FuzzInput,
        failure: &FuzzFailure,
        check_deploy: bool,
    ) -> std::io::Result<PathBuf> {
        fs::create_dir_all(crash_dir)?;

        let crash_id = crash_hash(input, failure, check_deploy);

        // Save trace file if we have trace events
        let trace_file = if !failure.trace.is_empty() {
            let filename = format!("trace_{crash_id}.json");
            let path = crash_dir.join(&filename);
            fs::write(&path, serde_json::to_string_pretty(&failure.trace)?)?;
            Some(filename)
        } else {
            None
        };

        let report = CrashReport {
            schema_version: FUZZ_CRASH_SCHEMA_VERSION,
            pipeline_profile: EXPECTED_PIPELINE_PROFILE.to_string(),
            id: crash_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            input: input.clone(),
            check_deploy,
            error_kind: failure.kind.clone(),
            message: failure.message.clone(),
            obfuscated_bytecode: failure.obfuscated_bytecode.clone(),
            trace_file,
            logs: failure.logs.clone(),
        };

        let path = crash_dir.join(format!("crash_{}.json", report.id));
        fs::write(&path, serde_json::to_string_pretty(&report)?)?;
        Ok(path)
    }

    async fn run_fuzz_input(input: &FuzzInput, check_deploy: bool) -> Result<(), FuzzFailure> {
        let deployment_hex = input.contract.deployment_hex();
        let runtime_hex = input.contract.runtime_hex();
        let seed_bytes = input.seed_bytes().map_err(|message| FuzzFailure {
            kind: ErrorKind::Obfuscation,
            message,
            trace: Vec::new(),
            obfuscated_bytecode: None,
            logs: Vec::new(),
        })?;
        let seed = Seed::from_bytes(seed_bytes);
        let original_bytes = prepare_bytecode(input.contract, deployment_hex, seed_bytes)
            .ok_or_else(|| FuzzFailure {
                kind: ErrorKind::Obfuscation,
                message: "failed to prepare original bytecode".into(),
                trace: Vec::new(),
                obfuscated_bytecode: None,
                logs: Vec::new(),
            })?;
        let full_deployment_hex = format!("0x{}", hex::encode(&original_bytes));

        let transforms = build_passes(&input.passes).map_err(|e| FuzzFailure {
            kind: ErrorKind::Obfuscation,
            message: format!("invalid passes: {e}"),
            trace: Vec::new(),
            obfuscated_bytecode: None,
            logs: Vec::new(),
        })?;

        let config = ObfuscationConfig {
            seed,
            transforms,
            preserve_unknown_opcodes: true,
            rewrite_function_selectors: false,
            obfuscate_constructor_arguments: false,
        };

        let result = obfuscate_bytecode(&full_deployment_hex, runtime_hex, config)
            .await
            .map_err(|e| {
                let kind = if e.message.contains("validation") || e.message.contains("invalid jump")
                {
                    ErrorKind::Validation
                } else {
                    ErrorKind::Obfuscation
                };
                FuzzFailure {
                    kind,
                    message: e.message,
                    trace: e.trace,
                    obfuscated_bytecode: None,
                    logs: Vec::new(),
                }
            })?;

        if result.integrity.pipeline_profile != EXPECTED_PIPELINE_PROFILE {
            return Err(FuzzFailure {
                kind: ErrorKind::Obfuscation,
                message: format!(
                    "fuzz harness expects pipeline profile {}, but Azoth emitted {}",
                    EXPECTED_PIPELINE_PROFILE, result.integrity.pipeline_profile
                ),
                trace: result.trace,
                obfuscated_bytecode: Some(result.obfuscated_bytecode),
                logs: Vec::new(),
            });
        }

        if !check_deploy {
            return Ok(());
        }

        deploy_to_revm(&original_bytes, input.contract).map_err(|error| FuzzFailure {
            kind: ErrorKind::Obfuscation,
            message: format!("invalid fuzz baseline: original deployment failed: {error}"),
            trace: result.trace.clone(),
            obfuscated_bytecode: Some(result.obfuscated_bytecode.clone()),
            logs: Vec::new(),
        })?;

        let prepared_obfuscated = hex::decode(result.obfuscated_bytecode.trim_start_matches("0x"))
            .map_err(|error| FuzzFailure {
                kind: ErrorKind::Obfuscation,
                message: format!("failed to decode obfuscated bytecode: {error}"),
                trace: result.trace.clone(),
                obfuscated_bytecode: Some(result.obfuscated_bytecode.clone()),
                logs: Vec::new(),
            })?;

        if let Err(error) = deploy_to_revm(&prepared_obfuscated, input.contract) {
            return Err(FuzzFailure {
                kind: ErrorKind::DeploymentMismatch {
                    original: original_bytes.len(),
                    obfuscated: prepared_obfuscated.len(),
                },
                message: format!(
                    "original deployed but obfuscated failed ({}b vs {}b): {error}",
                    original_bytes.len(),
                    prepared_obfuscated.len()
                ),
                trace: result.trace,
                obfuscated_bytecode: Some(result.obfuscated_bytecode),
                logs: Vec::new(),
            });
        }

        Ok(())
    }

    /// Runs a fuzz input using the provided log capture buffer.
    /// Clears the buffer before running and extracts logs on failure.
    async fn run_fuzz_input_capturing(
        input: &FuzzInput,
        log_capture: &LogCapture,
        check_deploy: bool,
    ) -> Result<(), FuzzFailure> {
        log_capture.clear();
        let result = run_fuzz_input(input, check_deploy).await;
        result.map_err(|mut failure| {
            failure.logs = log_capture.extract_lines();
            failure
        })
    }

    async fn replay_crash(crash_file: &PathBuf) -> Result<(), Box<dyn Error>> {
        let content = fs::read_to_string(crash_file)?;
        let report: CrashReport = serde_json::from_str(&content)?;
        if report.schema_version != FUZZ_CRASH_SCHEMA_VERSION
            || report.pipeline_profile != EXPECTED_PIPELINE_PROFILE
        {
            return Err(format!(
                "crash report targets schema/profile {}/{:?}, but this harness requires {}/{}",
                report.schema_version,
                report.pipeline_profile,
                FUZZ_CRASH_SCHEMA_VERSION,
                EXPECTED_PIPELINE_PROFILE
            )
            .into());
        }
        let expected_id = crash_hash_parts(
            &report.input,
            &report.error_kind,
            &report.message,
            report.obfuscated_bytecode.as_deref(),
            report.check_deploy,
        );
        if report.id != expected_id {
            return Err(format!(
                "crash report id mismatch: saved {}, recomputed {}",
                report.id, expected_id
            )
            .into());
        }

        println!("=== Replaying Crash ===");
        println!("ID: {}", report.id);
        println!("Timestamp: {}", report.timestamp);
        println!("Contract: {:?}", report.input.contract);
        println!("Seed: {}", report.input.seed);
        println!(
            "Passes: {}",
            if report.input.passes.is_empty() {
                "none"
            } else {
                &report.input.passes
            }
        );
        println!("Original error: {}", report.message);
        println!("Deployment check: {}", report.check_deploy);
        if let Some(ref trace) = report.trace_file {
            println!("Debug trace: {trace}");
        }
        if !report.logs.is_empty() {
            println!("Captured logs: {} lines", report.logs.len());
        }
        println!();

        if !report.logs.is_empty() {
            println!("=== Captured Logs ===");
            for line in &report.logs {
                println!("{line}");
            }
            println!();
        }

        println!("Running...");

        let log_capture = LogCapture::new();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(log_capture.clone())
                .with_ansi(false)
                .without_time(),
        );
        let dispatch = tracing::dispatcher::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let result =
            run_fuzz_input_capturing(&report.input, &log_capture, report.check_deploy).await;

        match result {
            Ok(()) => {
                println!("NOT REPRODUCED - the saved failure no longer occurs");
                Err("saved crash did not reproduce".into())
            }
            Err(failure) => {
                let exact = failure.kind == report.error_kind
                    && failure.message == report.message
                    && failure.obfuscated_bytecode == report.obfuscated_bytecode;
                println!(
                    "{}",
                    if exact {
                        "REPRODUCED EXACTLY"
                    } else {
                        "DIFFERENT FAILURE"
                    }
                );
                println!("Error: {}", failure.kind);
                println!("Message: {}", failure.message);
                if !failure.logs.is_empty() {
                    println!();
                    println!("=== New Logs ===");
                    for line in &failure.logs {
                        println!("{line}");
                    }
                }
                if exact {
                    return Err("saved crash reproduced exactly".into());
                }
                Err("saved crash produced a different failure".into())
            }
        }
    }

    fn list_crashes(crash_dir: &PathBuf) -> Result<(), Box<dyn Error>> {
        if !crash_dir.exists() {
            println!("No crashes directory found at {crash_dir:?}");
            return Ok(());
        }

        let mut crashes = Vec::new();
        for entry in fs::read_dir(crash_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("crash_"))
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(report) = serde_json::from_str::<CrashReport>(&content) {
                        crashes.push((path, report));
                    }
                }
            }
        }

        if crashes.is_empty() {
            println!("No crashes found in {crash_dir:?}");
            return Ok(());
        }

        println!("=== Saved Crashes ({}) ===\n", crashes.len());
        for (path, report) in crashes {
            println!("File: {}", path.display());
            println!("  ID: {}", report.id);
            println!("  Contract: {:?}", report.input.contract);
            println!(
                "  Passes: {}",
                if report.input.passes.is_empty() {
                    "none"
                } else {
                    &report.input.passes
                }
            );
            println!("  Error: {}", report.error_kind);
            if report.trace_file.is_some() {
                println!("  Trace: available");
            }
            if !report.logs.is_empty() {
                println!("  Logs: {} lines", report.logs.len());
            }
            println!();
        }

        Ok(())
    }

    async fn fuzzer_worker(
        _worker_id: usize,
        stats: Arc<FuzzStats>,
        args: Arc<FuzzArgs>,
        crash_dir: PathBuf,
    ) {
        let log_capture = LogCapture::new();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(log_capture.clone())
                .with_ansi(false)
                .without_time(),
        );
        let dispatch = tracing::dispatcher::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        loop {
            if args.duration > 0 && stats.start_time.elapsed().as_secs() >= args.duration {
                break;
            }
            let Some(iteration) = claim_iteration(&stats.iterations, args.iterations) else {
                break;
            };

            let input = fuzz_input_for_iteration(iteration);

            match run_fuzz_input_capturing(&input, &log_capture, args.check_deploy).await {
                Ok(()) => {
                    stats.successes.fetch_add(1, Ordering::Relaxed);
                }
                Err(failure) => {
                    let is_mismatch = matches!(failure.kind, ErrorKind::DeploymentMismatch { .. });

                    if is_mismatch {
                        stats.deployment_mismatches.fetch_add(1, Ordering::Relaxed);
                    }
                    stats.errors.fetch_add(1, Ordering::Relaxed);

                    let crash_id = crash_hash(&input, &failure, args.check_deploy);
                    let mut crashes = stats.unique_crashes.lock();
                    if !crashes.contains(&crash_id) {
                        match save_crash(&crash_dir, &input, &failure, args.check_deploy) {
                            Ok(path) => {
                                crashes.insert(crash_id);
                                let passes_display = if input.passes.is_empty() {
                                    "none"
                                } else {
                                    &input.passes
                                };
                                eprintln!("\n[CRASH] Saved: {}", path.display());
                                eprintln!(
                                    "  {:?} | {} | {}",
                                    input.contract, passes_display, failure.kind
                                );
                            }
                            Err(error) => {
                                eprintln!("\n[CRASH] Failed to save {crash_id}: {error}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// Atomically reserves and returns one fuzz-case index without allowing concurrent workers to
    /// overrun a finite iteration budget. A zero limit means unbounded execution.
    fn claim_iteration(counter: &AtomicU64, limit: u64) -> Option<u64> {
        if limit == 0 {
            return Some(counter.fetch_add(1, Ordering::Relaxed));
        }

        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < limit).then_some(current + 1)
            })
            .ok()
    }

    /// Derives a case solely from its global index. Fixed-iteration runs therefore exercise the same
    /// corpus regardless of worker count or scheduler timing.
    fn fuzz_input_for_iteration(iteration: u64) -> FuzzInput {
        let mut rng = DeterministicRng::seed_from_u64(iteration ^ 0xdead_beef_5eed_cafe);
        let contract = Contract::ALL[(rng.next_u32() as usize) % Contract::ALL.len()];
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        let passes = passes_from_bits(rng.next_u32() % pass_mask_limit());
        FuzzInput::new(contract, seed_bytes, passes)
    }

    fn status_printer(stats: Arc<FuzzStats>, stop: Arc<std::sync::atomic::AtomicBool>) {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let elapsed = stats.start_time.elapsed();
            let secs = elapsed.as_secs();
            let iters = stats.iterations.load(Ordering::Relaxed);
            let rate = if elapsed.as_secs_f64() > 0.0 {
                iters as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            let ok = stats.successes.load(Ordering::Relaxed);
            let mismatch = stats.deployment_mismatches.load(Ordering::Relaxed);
            let crashes = stats.unique_crashes.lock().len();
            print!(
                "\r\x1b[K[{:02}:{:02}] {:.1}/s iter={} ok={} mismatch={} failing_inputs={}",
                secs / 60,
                secs % 60,
                rate,
                iters,
                ok,
                mismatch,
                crashes
            );
            std::io::stdout().flush().ok();
        }
    }

    #[async_trait]
    impl super::Command for FuzzArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            match &self.command {
                Some(FuzzCommand::Replay { crash_file }) => {
                    return replay_crash(crash_file).await;
                }
                Some(FuzzCommand::List) => {
                    return list_crashes(&self.crash_dir);
                }
                None => {}
            }

            if self.jobs == 0 {
                return Err("jobs must be at least one".into());
            }

            println!("Azoth Fuzzer");
            println!("============");
            println!("Pipeline profile: {}", EXPECTED_PIPELINE_PROFILE);
            println!("Jobs: {}", self.jobs);
            println!(
                "Iterations: {}",
                if self.iterations == 0 {
                    "infinite".to_string()
                } else {
                    self.iterations.to_string()
                }
            );
            println!(
                "Duration: {}",
                if self.duration == 0 {
                    "infinite".to_string()
                } else {
                    format!("{}s", self.duration)
                }
            );
            println!("Crash dir: {}", self.crash_dir.display());
            println!(
                "Deployment check: creation success only; this is not a behavioral-equivalence proof"
            );
            let contracts: Vec<_> = Contract::ALL.iter().map(|c| c.name()).collect();
            println!("Contracts: {}", contracts.join(", "));
            println!("Transforms: none, {}", DEFAULT_PASSES);
            println!();

            let args = Arc::new(self);
            let stats = Arc::new(FuzzStats::new());
            let crash_dir = args.crash_dir.clone();

            // Spawn status printer on dedicated thread
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let status_thread = {
                let stats = stats.clone();
                let stop = stop.clone();
                std::thread::spawn(move || status_printer(stats, stop))
            };

            let mut handles = Vec::new();
            for worker_id in 0..args.jobs {
                let stats = stats.clone();
                let args = args.clone();
                let crash_dir = crash_dir.clone();

                handles.push(tokio::spawn(fuzzer_worker(
                    worker_id, stats, args, crash_dir,
                )));
            }

            let mut worker_error = None;
            for handle in handles {
                if let Err(error) = handle.await {
                    worker_error.get_or_insert(error);
                }
            }

            // Stop status printer and print summary
            stop.store(true, Ordering::Relaxed);
            let _ = status_thread.join();
            stats.print_summary(args.check_deploy);
            if let Some(error) = worker_error {
                return Err(format!("fuzzer worker terminated unexpectedly: {error}").into());
            }
            let iterations = stats.iterations.load(Ordering::Relaxed);
            let completed =
                stats.successes.load(Ordering::Relaxed) + stats.errors.load(Ordering::Relaxed);
            if completed != iterations {
                return Err(format!(
                    "fuzzer accounting mismatch: claimed {iterations} cases but recorded {completed} outcomes"
                )
                .into());
            }
            let errors = stats.errors.load(Ordering::Relaxed);
            if errors > 0 {
                return Err(format!("fuzz run recorded {errors} failing case(s)").into());
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fuzz_pass_selection_can_reach_every_default_pass() {
            let default_passes: Vec<&str> = DEFAULT_PASSES.split(',').map(str::trim).collect();

            for expected in &default_passes {
                let reachable = (0u32..pass_mask_limit()).any(|mask| {
                    passes_from_bits(mask)
                        .split(',')
                        .map(str::trim)
                        .any(|p| p == *expected)
                });
                assert!(
                    reachable,
                    "default pass {expected} is not reachable by fuzz pass selection"
                );
            }
        }

        #[test]
        fn pass_mask_limit_covers_all_default_passes() {
            assert_eq!(pass_mask_limit(), 1u32 << default_pass_count());
            assert!(default_pass_count() >= 1);
        }

        #[test]
        fn finite_iteration_claims_never_overshoot() {
            let counter = AtomicU64::new(0);
            assert_eq!(claim_iteration(&counter, 2), Some(0));
            assert_eq!(claim_iteration(&counter, 2), Some(1));
            assert_eq!(claim_iteration(&counter, 2), None);
            assert_eq!(counter.load(Ordering::Relaxed), 2);
        }

        #[test]
        fn fixed_iteration_corpus_is_reproducible() {
            let first = fuzz_input_for_iteration(17);
            let replay = fuzz_input_for_iteration(17);
            let next = fuzz_input_for_iteration(18);
            assert_eq!(first.contract, replay.contract);
            assert_eq!(first.seed, replay.seed);
            assert_eq!(first.passes, replay.passes);
            assert_ne!(first.seed, next.seed);
        }

        #[test]
        fn first_hundred_cases_cover_every_contract_and_pass_subset() {
            let cohorts: HashSet<_> = (0..100)
                .map(fuzz_input_for_iteration)
                .map(|input| (input.contract.name(), input.passes))
                .collect();
            let expected: HashSet<_> = Contract::ALL
                .iter()
                .flat_map(|contract| {
                    (0..pass_mask_limit()).map(|mask| (contract.name(), passes_from_bits(mask)))
                })
                .collect();
            assert_eq!(cohorts, expected);
        }

        #[test]
        fn malformed_replay_seed_is_rejected_instead_of_becoming_zero() {
            let input = FuzzInput {
                contract: Contract::Counter,
                seed: "not-hex".to_string(),
                passes: String::new(),
            };
            assert!(input.seed_bytes().is_err());
        }

        #[test]
        fn crash_id_binds_seed_deployment_mode_and_failure_details() {
            let input = FuzzInput::new(Contract::Counter, [1u8; 32], String::new());
            let changed_seed = FuzzInput::new(Contract::Counter, [2u8; 32], String::new());
            let failure = FuzzFailure {
                kind: ErrorKind::Validation,
                message: "first failure".to_string(),
                trace: Vec::new(),
                obfuscated_bytecode: None,
                logs: Vec::new(),
            };
            let changed_failure = FuzzFailure {
                kind: ErrorKind::Obfuscation,
                message: "second failure".to_string(),
                trace: Vec::new(),
                obfuscated_bytecode: None,
                logs: Vec::new(),
            };

            let baseline = crash_hash(&input, &failure, false);
            assert_eq!(baseline.len(), 64);
            assert_eq!(
                baseline,
                "ae10a34b737fc531872b91fe045801f1cdedc93c8398c814e645eed1905d95c0"
            );
            assert_ne!(baseline, crash_hash(&changed_seed, &failure, false));
            assert_ne!(baseline, crash_hash(&input, &failure, true));
            assert_ne!(baseline, crash_hash(&input, &changed_failure, false));

            let mut changed_output = FuzzFailure {
                kind: ErrorKind::Validation,
                message: "first failure".to_string(),
                trace: Vec::new(),
                obfuscated_bytecode: Some("0x00".to_string()),
                logs: Vec::new(),
            };
            assert_ne!(baseline, crash_hash(&input, &changed_output, false));
            changed_output.obfuscated_bytecode = Some("0x01".to_string());
            assert_ne!(
                crash_hash(
                    &input,
                    &FuzzFailure {
                        kind: ErrorKind::Validation,
                        message: "first failure".to_string(),
                        trace: Vec::new(),
                        obfuscated_bytecode: Some("0x00".to_string()),
                        logs: Vec::new(),
                    },
                    false
                ),
                crash_hash(&input, &changed_output, false)
            );
        }
    }
}

pub mod obfuscate {
    //! Module for the `obfuscate` subcommand, which applies obfuscation transforms to EVM
    //! bytecode.
    //!
    //! This module processes input bytecode and uses the unified obfuscation pipeline
    //! from `azoth-transform` to apply transforms and output obfuscated bytecode.

    use crate::commands::{ObfuscateError, DEFAULT_PASSES};
    use async_trait::async_trait;
    use azoth_core::seed::Seed;
    use azoth_transform::obfuscator::{
        create_gas_report, obfuscate_bytecode, print_obfuscation_analysis, ObfuscationConfig,
    };
    use azoth_transform::Transform;
    use clap::Args;
    use std::error::Error;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// Arguments for the `obfuscate` subcommand.
    #[derive(Args)]
    pub struct ObfuscateArgs {
        /// Input deployment bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
        #[arg(short = 'D', long = "deployment")]
        pub deployment_bytecode: String,
        /// Input runtime bytecode as a hex string, .hex file, or binary file containing EVM bytecode.
        #[arg(short = 'R', long = "runtime")]
        pub runtime_bytecode: String,
        /// ABI-encoded constructor argument suffix to append before obfuscation.
        /// May be omitted when the deployment input already contains the suffix.
        #[arg(long, value_name = "HEX")]
        constructor_args: Option<String>,
        /// Cryptographic seed for deterministic obfuscation. This value is visible in process argv;
        /// prefer --seed-stdin when the local execution environment is not fully trusted.
        #[arg(
            long,
            conflicts_with = "seed_stdin",
            required_unless_present = "seed_stdin"
        )]
        seed: Option<String>,
        /// Read the cryptographic seed from standard input instead of exposing it in process argv.
        #[arg(long, conflicts_with = "seed")]
        seed_stdin: bool,
        /// Comma-separated list of transforms to apply.
        /// The production CLI accepts only relationship-safe passes.
        #[arg(long, default_value = DEFAULT_PASSES)]
        passes: String,
        /// Path to emit gas/size report as JSON (optional).
        #[arg(long)]
        emit: Option<String>,
        /// Path to emit a detailed CFG trace debug report as JSON.
        #[arg(long, value_name = "PATH")]
        emit_debug: Option<String>,
        /// Path to emit the private selector/interaction manifest as JSON.
        /// Treat this file like the seed: do not publish it or store it on-chain.
        #[arg(long, value_name = "PATH")]
        emit_manifest: Option<String>,
        /// Launch TUI to view the debug trace after obfuscation.
        #[arg(long)]
        tui: bool,
    }

    /// Executes the `obfuscate` subcommand using the unified obfuscation pipeline.
    #[async_trait]
    impl super::Command for ObfuscateArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            let ObfuscateArgs {
                deployment_bytecode,
                runtime_bytecode,
                constructor_args,
                seed,
                seed_stdin,
                passes,
                emit,
                emit_debug,
                emit_manifest,
                tui,
            } = self;

            // Step 1: Read and normalize input
            let mut input_bytecode = read_input(&deployment_bytecode)?;
            let runtime_bytecode_hex = read_input(&runtime_bytecode)?;
            if let Some(constructor_args) = constructor_args {
                let deployment = normalise_hex(&input_bytecode)?;
                let args = normalise_hex(&constructor_args)?;
                input_bytecode = format!("0x{deployment}{args}");
            }

            // Step 2: Build transforms from CLI args
            let transforms = build_passes(&passes)?;

            // Step 3: Configure obfuscation
            // The seed is private protocol input, not hidden process state. Requiring it makes every
            // CLI result replayable and prevents an internally generated seed from being lost.
            let seed_hex = if seed_stdin {
                let mut value = String::new();
                io::stdin().read_to_string(&mut value)?;
                value.trim().to_string()
            } else {
                seed.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "either --seed or --seed-stdin is required",
                    )
                })?
            };
            let seed = Seed::from_hex(&seed_hex).map_err(|e| format!("Invalid seed hex: {e}"))?;
            let mut config = ObfuscationConfig::with_seed(seed);

            config.transforms = transforms;
            config.preserve_unknown_opcodes = true;

            // Step 4: Run obfuscation pipeline
            let result =
                match obfuscate_bytecode(&input_bytecode, &runtime_bytecode_hex, config).await {
                    Ok(result) => result,
                    Err(e) => return Err(format!("{e}").into()),
                };

            // Step 5: Print analysis and results
            print_obfuscation_analysis(&result);

            // Step 6: Check size limits
            // Step 7: Write report if requested
            if let Some(path) = emit.as_ref() {
                let report = create_gas_report(&result);
                fs::write(path, serde_json::to_string_pretty(&report)?)?;
                println!("📊 Wrote gas/size report to {}", path);
            }

            if let Some(path) = emit_debug.as_ref() {
                let debug_payload = serde_json::to_string_pretty(&serde_json::json!({
                    "metadata": &result.metadata,
                    "trace": &result.trace,
                }))?;
                // Experimental selector mappings can appear in CFG snapshots used by the TUI. Treat
                // a debug trace as private interaction material too: create it atomically with
                // owner-only permissions and never overwrite an existing file.
                write_private_manifest(Path::new(path), debug_payload.as_bytes())?;
                println!("Wrote CFG trace debug report to {}", path);
            }

            if let Some(path) = emit_manifest.as_ref() {
                let manifest = result.private_interaction_manifest();
                let payload = serde_json::to_vec_pretty(&manifest)?;
                write_private_manifest(Path::new(path), &payload)?;
                println!("Wrote private interaction manifest to {}", path);
            }

            // Step 8: Output final bytecode
            println!("{}", result.obfuscated_bytecode);

            // Step 9: Launch TUI if requested
            if tui {
                let debug = azoth_tui::DebugOutput {
                    metadata: azoth_tui::DebugMetadata {
                        transforms_applied: result.metadata.transforms_applied.clone(),
                        size_limit_exceeded: result.metadata.size_limit_exceeded,
                        unknown_opcodes_preserved: result.metadata.unknown_opcodes_preserved,
                    },
                    trace: result.trace,
                };
                azoth_tui::run(debug, Some(runtime_bytecode.clone()))?;
            }

            Ok(())
        }
    }

    /// Atomically publishes a private manifest and refuses to overwrite an existing path.
    ///
    /// The complete payload is written and synced to an owner-only temporary file in the target
    /// directory before the final filename becomes visible. `persist_noclobber` provides the
    /// create-new property without exposing a truncated destination after a crash. Selector mappings
    /// are equivalent to seed-authorized interaction material.
    fn write_private_manifest(path: &Path, payload: &[u8]) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut output = tempfile::Builder::new()
            .prefix(".azoth-private-")
            .tempfile_in(parent)?;

        #[cfg(unix)]
        fs::set_permissions(output.path(), std::fs::Permissions::from_mode(0o600))?;

        output.write_all(payload)?;
        output.as_file().sync_all()?;
        let persisted = output
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
        persisted.sync_all()?;

        // The file sync makes payload bytes durable; syncing the directory makes publication of the
        // final name durable on Unix filesystems that implement directory fsync.
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;

        Ok(())
    }

    /// Reads input from hex string, .hex file, or binary file
    pub(crate) fn read_input(input: &str) -> Result<String, Box<dyn Error>> {
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
    pub(crate) fn normalise_hex(s: &str) -> Result<String, ObfuscateError> {
        let stripped = s.trim().trim_start_matches("0x").replace('_', "");
        if !stripped.len().is_multiple_of(2) {
            return Err(ObfuscateError::OddLength(stripped.len()));
        }
        Ok(stripped)
    }

    /// Builds a list of transform passes from a comma-separated string.
    pub(crate) fn build_passes(list: &str) -> Result<Vec<Box<dyn Transform>>, Box<dyn Error>> {
        list.split(',')
            .filter(|s| !s.is_empty())
            .map(|name| match name.trim() {
                "cluster_shuffle" => Ok(Box::new(
                    azoth_transform::cluster_shuffle::ClusterShuffle::new(),
                ) as Box<dyn Transform>),
                "shuffle" | "opaque_pred" | "opaque_predicate" | "jump_transform" | "jump_addr"
                | "arithmetic_chain" | "push_split" | "storage_gates" | "slot_shuffle"
                | "string_obfuscate" | "string_obf" | "splice" => {
                    Err(ObfuscateError::UnsafePass(name.trim().to_string()).into())
                }
                _ => Err(ObfuscateError::InvalidPass(name.to_string()).into()),
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::{build_passes, write_private_manifest, ObfuscateArgs};
        use clap::Args as _;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn production_profile_accepts_only_relationship_safe_passes() {
            assert_eq!(build_passes("cluster_shuffle").unwrap().len(), 1);
            for legacy in [
                "shuffle",
                "opaque_predicate",
                "jump_addr",
                "arithmetic_chain",
                "push_split",
                "storage_gates",
                "slot_shuffle",
                "string_obfuscate",
                "splice",
            ] {
                let error = build_passes(legacy).err().expect("legacy pass must fail");
                assert!(
                    error
                        .to_string()
                        .contains("disabled in the production profile"),
                    "unexpected error for {legacy}: {error}"
                );
            }
        }

        #[test]
        fn exactly_one_seed_input_mechanism_is_required() {
            let command = || ObfuscateArgs::augment_args(clap::Command::new("obfuscate"));
            let base = ["obfuscate", "--deployment", "0x00", "--runtime", "0x00"];

            assert!(command().try_get_matches_from(base).is_err());
            assert!(command()
                .try_get_matches_from(base.into_iter().chain([
                    "--seed",
                    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ]))
                .is_ok());
            assert!(command()
                .try_get_matches_from(base.into_iter().chain(["--seed-stdin"]))
                .is_ok());
            assert!(command()
                .try_get_matches_from(base.into_iter().chain([
                    "--seed-stdin",
                    "--seed",
                    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ]))
                .is_err());
        }

        #[cfg(unix)]
        #[test]
        fn private_manifest_is_created_once_with_owner_only_permissions() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("interaction.json");

            write_private_manifest(&path, b"secret mapping").unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"secret mapping");

            let error = write_private_manifest(&path, b"replacement").unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            assert_eq!(std::fs::read(&path).unwrap(), b"secret mapping");
        }
    }
}

pub mod strip {
    //! This module processes input bytecode, removes non-runtime sections (e.g., init code,
    //! auxdata), and outputs either the cleaned runtime bytecode as a hex string or a JSON report
    //! detailing the stripping process.

    use async_trait::async_trait;
    use azoth_core::decoder::decode_input;
    use azoth_core::detection::locate_sections;
    use azoth_core::input_to_bytes;
    use azoth_core::strip::strip_bytecode;
    use clap::Args;
    use serde_json;
    use std::error::Error;
    use std::path::Path;

    /// Arguments for the `strip` subcommand.
    #[derive(Args)]
    pub struct StripArgs {
        /// Input deployment bytecode as a hex string (0x...) or file path containing EVM bytecode.
        #[arg(short = 'D', long = "deployment")]
        pub deployment_bytecode: String,
        /// Input runtime bytecode as a hex string (0x...) or file path containing EVM bytecode.
        #[arg(short = 'R', long = "runtime")]
        pub runtime_bytecode: String,
        /// Output raw cleaned runtime hex instead of JSON report
        #[arg(long)]
        raw: bool,
    }

    /// Executes the `strip` subcommand to extract runtime bytecode.
    #[async_trait]
    impl super::Command for StripArgs {
        async fn execute(self) -> Result<(), Box<dyn Error>> {
            let is_file = !self.deployment_bytecode.starts_with("0x")
                && Path::new(&self.deployment_bytecode).is_file();
            let runtime_is_file = !self.runtime_bytecode.starts_with("0x")
                && Path::new(&self.runtime_bytecode).is_file();
            let decoded = decode_input(&self.deployment_bytecode, is_file)?;
            let instructions = decoded.instructions;
            let bytes = decoded.bytes;
            let runtime_bytes = input_to_bytes(&self.runtime_bytecode, runtime_is_file)?;
            let sections = locate_sections(&bytes, &instructions, &runtime_bytes)?;
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
}

pub mod tui {
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
}
