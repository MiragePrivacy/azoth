use crate::commands::{obfuscate::read_input, ObfuscateError};
use async_trait::async_trait;
use azoth_analysis::obfuscation::{analyze_obfuscation, AnalysisConfig, AnalysisError};
use clap::Args;
use std::{error::Error, path::PathBuf};
const DEFAULT_BYTECODE_PATH: &str = "examples/escrow-bytecode/artifacts/deployment_bytecode.hex";

/// Analyze how much bytecode survives obfuscation across multiple seeds.
#[derive(Args)]
pub struct AnalyzeArgs {
    /// Number of obfuscated samples to generate.
    pub iterations: usize,
    /// Input bytecode as hex, .hex file, or binary file.
    #[arg(value_name = "BYTECODE", default_value = DEFAULT_BYTECODE_PATH)]
    pub input: String,
    /// Where to write the markdown report (default: ./obfuscation_analysis_report.md).
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Maximum attempts per iteration when an obfuscation fails.
    #[arg(long, default_value_t = 5)]
    max_attempts: usize,
}

#[async_trait]
impl super::Command for AnalyzeArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let AnalyzeArgs {
            iterations,
            input,
            output,
            max_attempts,
        } = self;

        let input_hex = read_input(&input)?;

        let mut config = AnalysisConfig::new(&input_hex, iterations);
        config.max_attempts = max_attempts;
        if let Some(path) = output {
            config.report_path = path;
        }

        let report = match analyze_obfuscation(config).await {
            Ok(report) => report,
            Err(AnalysisError::UnknownOpcodes { count }) => {
                println!("Analysis aborted: obfuscation preserved {count} unknown opcode(s).\nStrip or normalize the bytecode before running analysis.");
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
            report.seeds.len(),
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
        AnalysisError::UnknownOpcodes { count } => Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("analysis aborted due to {count} unknown opcode(s)"),
        )),
        AnalysisError::InvalidPass(name) => Box::new(ObfuscateError::InvalidPass(name)),
        AnalysisError::ObfuscationFailure { source, .. } => source,
        AnalysisError::Io(err) => Box::new(err),
        AnalysisError::Fmt(err) => Box::new(err),
        AnalysisError::EmptyIterations => Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "iterations must be positive",
        )),
    }
}
