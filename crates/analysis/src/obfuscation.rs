use azoth_core::seed::Seed;
use azoth_transform::{
    Transform,
    jump_address_transformer::JumpAddressTransformer,
    obfuscator::{ObfuscationConfig, obfuscate_bytecode},
    opaque_predicate::OpaquePredicate,
    shuffle::Shuffle,
};
use chrono::{DateTime, Utc};
use hex::FromHexError;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    path::{Path, PathBuf},
};
use thiserror::Error as ThisError;

/// Default passes applied to each obfuscation run.
pub const DEFAULT_PASSES: &str = "shuffle";

/// Configuration for running an obfuscation analysis experiment.
#[derive(Debug, Clone)]
pub struct AnalysisConfig<'a> {
    /// Number of obfuscated samples to generate.
    pub iterations: usize,
    /// Original bytecode (hex string with or without `0x` prefix).
    pub original_bytecode: &'a str,
    /// Path to write the markdown report.
    pub report_path: PathBuf,
    /// Maximum attempts per iteration before giving up on a seed.
    pub max_attempts: usize,
}

impl<'a> AnalysisConfig<'a> {
    /// Create config with sensible defaults.
    pub fn new(original_bytecode: &'a str, iterations: usize) -> Self {
        Self {
            iterations,
            original_bytecode,
            report_path: PathBuf::from("obfuscation_analysis_report.md"),
            max_attempts: 5,
        }
    }
}

/// Aggregated statistics from the obfuscation runs.
#[derive(Debug, Clone, Serialize)]
pub struct SummaryStats {
    pub average_length: f64,
    pub median_length: f64,
    pub std_dev: f64,
    pub min_length: usize,
    pub max_length: usize,
    pub percentile_25: f64,
    pub percentile_75: f64,
    pub percentile_95: f64,
    pub preservation_ratio: f64,
}

/// Histogram bucket used in the textual chart.
#[derive(Debug, Clone, Serialize)]
pub struct HistogramBucket {
    pub start: usize,
    pub end: usize,
    pub count: usize,
}

/// Top repeated sequence with frequency.
#[derive(Debug, Clone, Serialize)]
pub struct SequenceFrequency {
    pub length: usize,
    pub frequency: usize,
    pub sequence_hex: String,
}

/// Final report produced by the analysis.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub generated_at: DateTime<Utc>,
    pub iterations: usize,
    pub original_length: usize,
    pub transform_counts: BTreeMap<String, usize>,
    pub seeds: Vec<String>,
    pub unique_seed_count: usize,
    pub sequence_lengths: Vec<usize>,
    pub top_sequences: Vec<SequenceFrequency>,
    pub summary: SummaryStats,
    pub histogram: Vec<HistogramBucket>,
    pub ngram_diversity: BTreeMap<usize, f64>,
    pub markdown_path: PathBuf,
}

impl AnalysisReport {
    /// Convert report to markdown.
    pub fn to_markdown(&self) -> Result<String, AnalysisError> {
        let mut out = String::new();
        writeln!(out, "# Obfuscation Analysis Report")?;
        writeln!(out)?;
        writeln!(out, "**Generated:** {}  ", self.generated_at)?;
        writeln!(out, "**Iterations:** {}  ", self.iterations)?;
        writeln!(
            out,
            "**Original Bytecode Length:** {} bytes  ",
            self.original_length
        )?;
        writeln!(
            out,
            "**Transforms Observed:** {}  ",
            summarize_transforms(&self.transform_counts, self.iterations)
        )?;
        writeln!(out)?;
        writeln!(out, "## Summary Statistics")?;
        writeln!(out)?;
        writeln!(
            out,
            "Average longest common sequence length and related dispersion metrics across all obfuscated samples."
        )?;
        writeln!(out)?;
        writeln!(out, "### Sequence Length Metrics")?;
        writeln!(out)?;
        writeln!(
            out,
            "- **Average Length:** {:.2} bytes",
            self.summary.average_length
        )?;
        writeln!(
            out,
            "- **Median Length:** {:.2} bytes",
            self.summary.median_length
        )?;
        writeln!(
            out,
            "- **Standard Deviation:** {:.2} bytes",
            self.summary.std_dev
        )?;
        writeln!(
            out,
            "- **Minimum Length:** {} bytes",
            self.summary.min_length
        )?;
        writeln!(
            out,
            "- **Maximum Length:** {} bytes",
            self.summary.max_length
        )?;
        writeln!(out)?;
        writeln!(out, "### Distribution Percentiles")?;
        writeln!(out)?;
        writeln!(
            out,
            "- **25th Percentile:** {:.2} bytes",
            self.summary.percentile_25
        )?;
        writeln!(
            out,
            "- **75th Percentile:** {:.2} bytes",
            self.summary.percentile_75
        )?;
        writeln!(
            out,
            "- **95th Percentile:** {:.2} bytes",
            self.summary.percentile_95
        )?;
        writeln!(out)?;
        writeln!(out, "## Top 10 Most Repeated Sequences")?;
        writeln!(out)?;
        writeln!(
            out,
            "Most common longest preserved substrings (contiguous) observed across all obfuscations."
        )?;
        writeln!(out)?;
        if self.top_sequences.is_empty() {
            writeln!(out, "_No repeated sequences were observed._")?;
        } else {
            writeln!(
                out,
                "| Rank | Length (bytes) | Frequency | Sequence (hex) |"
            )?;
            writeln!(
                out,
                "|------|----------------|-----------|----------------|"
            )?;
            for (idx, seq) in self.top_sequences.iter().enumerate() {
                writeln!(
                    out,
                    "| {} | {} | {} | `{}` |",
                    idx + 1,
                    seq.length,
                    seq.frequency,
                    truncate_hex(&seq.sequence_hex, 40)
                )?;
            }
        }
        writeln!(out)?;
        writeln!(out, "## Seed Summary")?;
        writeln!(out)?;
        writeln!(out, "- **Total seeds generated:** {}", self.seeds.len())?;
        writeln!(out, "- **Unique seeds:** {}", self.unique_seed_count)?;
        if !self.seeds.is_empty() {
            let preview: Vec<_> = self.seeds.iter().take(5).cloned().collect();
            writeln!(out, "- **Sample seeds:** {}", preview.join(", "))?;
            if self.seeds.len() > 5 {
                writeln!(out, "- _...and {} more_", self.seeds.len() - preview.len())?;
            }
        }
        writeln!(out)?;
        writeln!(out, "## Transform Usage")?;
        writeln!(out)?;
        if self.transform_counts.is_empty() {
            writeln!(
                out,
                "_No additional transforms were applied beyond dispatcher detection._"
            )?;
        } else {
            writeln!(out, "| Transform | Iterations | Coverage |")?;
            writeln!(out, "|-----------|------------|----------|")?;
            for (name, count) in sorted_transform_entries(&self.transform_counts) {
                let coverage = count as f64 / self.iterations as f64 * 100.0;
                writeln!(out, "| {} | {} | {:.1}% |", name, count, coverage)?;
            }
        }
        writeln!(out)?;
        writeln!(out, "## N-gram Diversity Analysis")?;
        writeln!(out)?;
        writeln!(
            out,
            "Percentage of unique n-byte sequences across all obfuscated outputs."
        )?;
        writeln!(out)?;
        for (n, value) in &self.ngram_diversity {
            writeln!(out, "- **{}-byte sequences:** {:.2}% unique", n, value)?;
        }
        writeln!(out)?;
        writeln!(out, "## Distribution Histogram")?;
        writeln!(out)?;
        writeln!(
            out,
            "Textual histogram of longest common sequence lengths across iterations."
        )?;
        writeln!(out)?;
        if self.histogram.is_empty() {
            writeln!(out, "_No data available to build histogram._")?;
        } else {
            writeln!(out, "```")?;
            let max_count = self
                .histogram
                .iter()
                .map(|bucket| bucket.count)
                .max()
                .unwrap_or(1)
                .max(1);
            for bucket in &self.histogram {
                let normalized = ((bucket.count as f64 / max_count as f64) * 50.0).round() as usize;
                let bar = "#".repeat(normalized.max(1));
                writeln!(
                    out,
                    "{:4}-{:4} bytes | {} ({})",
                    bucket.start, bucket.end, bar, bucket.count
                )?;
            }
            writeln!(out, "```")?;
        }
        writeln!(out)?;
        writeln!(out, "## Interpretation")?;
        writeln!(out)?;
        writeln!(
            out,
            "Average longest common sequence covers **{:.2}%** of the original bytecode.",
            self.summary.preservation_ratio
        )?;
        if self.summary.preservation_ratio < 10.0 {
            writeln!(
                out,
                "This suggests strong obfuscation with minimal contiguous preservation."
            )?;
        } else if self.summary.preservation_ratio < 25.0 {
            writeln!(
                out,
                "This suggests moderate obfuscation with noticeable contiguous preservation."
            )?;
        } else {
            writeln!(
                out,
                "This suggests weaker obfuscation: significant contiguous blocks remain."
            )?;
        }
        writeln!(out)?;
        let diversity = self.ngram_diversity.get(&8).copied().unwrap_or(0.0);
        if diversity > 90.0 {
            writeln!(
                out,
                "High 8-byte diversity indicates obfuscation yields highly varied byte patterns."
            )?;
        } else if diversity > 70.0 {
            writeln!(
                out,
                "Moderate 8-byte diversity indicates reasonable variation across seeds."
            )?;
        } else {
            writeln!(
                out,
                "Low 8-byte diversity indicates many recurring patterns across outputs."
            )?;
        }
        writeln!(out)?;
        writeln!(out, "---")?;
        writeln!(
            out,
            "*Analysis generated by Azoth obfuscation analysis with {} iterations.*",
            self.iterations
        )?;

        Ok(out)
    }

    pub fn transform_summary(&self) -> String {
        summarize_transforms(&self.transform_counts, self.iterations)
    }
}

/// Errors thrown by the analysis pipeline.
#[derive(Debug, ThisError)]
pub enum AnalysisError {
    #[error("analysis requires at least one iteration")]
    EmptyIterations,
    #[error("bytecode decode error: {0}")]
    Decode(#[from] FromHexError),
    #[error("analysis aborted: obfuscation preserved {count} unknown opcode(s)")]
    UnknownOpcodes { count: usize },
    #[error("obfuscation failed after {attempts} attempts: {source}")]
    ObfuscationFailure {
        attempts: usize,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("invalid transform pass: {0}")]
    InvalidPass(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("format error: {0}")]
    Fmt(#[from] std::fmt::Error),
}

/// Run the obfuscation experiment and produce a report.
pub async fn analyze_obfuscation(
    config: AnalysisConfig<'_>,
) -> Result<AnalysisReport, AnalysisError> {
    if config.iterations == 0 {
        return Err(AnalysisError::EmptyIterations);
    }

    let passes = parse_passes(DEFAULT_PASSES)?;
    let original_bytes = hex_to_bytes(config.original_bytecode)?;
    let mut sequence_lengths = Vec::with_capacity(config.iterations);
    let mut sequence_counter: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut obfuscated_bytecodes: Vec<Vec<u8>> = Vec::with_capacity(config.iterations);
    let mut seeds = Vec::with_capacity(config.iterations);
    let mut transform_counts: BTreeMap<String, usize> = BTreeMap::new();
    transform_counts.insert("FunctionDispatcher".to_string(), 0);
    transform_counts.insert("Shuffle".to_string(), 0);

    for _ in 0..config.iterations {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let seed = Seed::generate();
            let seed_hex = seed.to_hex();
            let mut obfuscation_config = ObfuscationConfig::with_seed(seed.clone());
            obfuscation_config.preserve_unknown_opcodes = true;
            obfuscation_config.transforms = passes.iter().map(|p| p.build()).collect();

            match obfuscate_bytecode(config.original_bytecode, obfuscation_config).await {
                Ok(result) => {
                    let transforms_applied = result.metadata.transforms_applied.clone();
                    let obfuscated_bytes = hex_to_bytes(&result.obfuscated_bytecode)?;
                    let sequence = longest_common_substring(&original_bytes, &obfuscated_bytes);
                    if !sequence.is_empty() {
                        let entry = sequence_counter.entry(sequence.to_vec()).or_insert(0);
                        *entry += 1;
                    }
                    for name in transforms_applied {
                        *transform_counts.entry(name).or_insert(0) += 1;
                    }
                    sequence_lengths.push(sequence.len());
                    obfuscated_bytecodes.push(obfuscated_bytes);
                    seeds.push(seed_hex);
                    break;
                }
                Err(_err) if attempt < config.max_attempts => continue,
                Err(err) => {
                    return Err(AnalysisError::ObfuscationFailure {
                        attempts: config.max_attempts,
                        source: err,
                    });
                }
            }
        }
    }

    let summary = compute_summary_stats(&sequence_lengths, original_bytes.len());
    let histogram = build_histogram(&sequence_lengths);
    let top_sequences = compute_top_sequences(sequence_counter);
    let ngram_diversity = compute_ngram_diversity(&obfuscated_bytecodes, &[2, 4, 8]);

    let unique_seed_count = seeds.iter().collect::<HashSet<_>>().len();

    let report = AnalysisReport {
        generated_at: Utc::now(),
        iterations: config.iterations,
        original_length: original_bytes.len(),
        transform_counts,
        seeds,
        unique_seed_count,
        sequence_lengths,
        top_sequences,
        summary,
        histogram,
        ngram_diversity,
        markdown_path: config.report_path.clone(),
    };

    let markdown = report.to_markdown()?;
    write_report(&config.report_path, &markdown)?;

    Ok(report)
}

fn write_report(path: &Path, contents: &str) -> Result<(), AnalysisError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn hex_to_bytes(input: &str) -> Result<Vec<u8>, FromHexError> {
    let trimmed = input.trim();
    let without_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(without_prefix)
}

fn longest_common_substring<'a>(a: &'a [u8], b: &'a [u8]) -> &'a [u8] {
    let mut low = 0usize;
    let mut high = a.len().min(b.len());
    let mut best: &[u8] = &[];

    while low <= high {
        let mid = (low + high) / 2;
        if let Some(candidate) = has_common_of_length(a, b, mid) {
            if candidate.len() > best.len() {
                best = candidate;
            }
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best
}

fn has_common_of_length<'a>(a: &'a [u8], b: &[u8], len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if len > a.len() || len > b.len() {
        return None;
    }
    let mut set: HashSet<&[u8]> = HashSet::with_capacity(a.len().saturating_sub(len) + 1);
    for window in a.windows(len) {
        set.insert(window);
    }
    for window in b.windows(len) {
        if let Some(&candidate) = set.get(window) {
            return Some(candidate);
        }
    }
    None
}

fn compute_summary_stats(lengths: &[usize], original_len: usize) -> SummaryStats {
    let mut stats = SummaryStats {
        average_length: 0.0,
        median_length: 0.0,
        std_dev: 0.0,
        min_length: 0,
        max_length: 0,
        percentile_25: 0.0,
        percentile_75: 0.0,
        percentile_95: 0.0,
        preservation_ratio: 0.0,
    };

    if lengths.is_empty() {
        return stats;
    }

    let mut sorted = lengths.to_vec();
    sorted.sort_unstable();

    let len = lengths.len();
    let sum: usize = lengths.iter().sum();
    let mean = sum as f64 / len as f64;
    stats.average_length = mean;
    stats.median_length = if len.is_multiple_of(2) {
        (sorted[len / 2 - 1] as f64 + sorted[len / 2] as f64) / 2.0
    } else {
        sorted[len / 2] as f64
    };
    let variance = if len > 1 {
        let squared: f64 = lengths
            .iter()
            .map(|&value| {
                let diff = value as f64 - mean;
                diff * diff
            })
            .sum();
        squared / (len as f64 - 1.0)
    } else {
        0.0
    };
    stats.std_dev = variance.sqrt();
    stats.min_length = *sorted.first().unwrap();
    stats.max_length = *sorted.last().unwrap();
    stats.percentile_25 = percentile(&sorted, 25.0);
    stats.percentile_75 = percentile(&sorted, 75.0);
    stats.percentile_95 = percentile(&sorted, 95.0);
    stats.preservation_ratio = if original_len > 0 {
        mean / original_len as f64 * 100.0
    } else {
        0.0
    };
    stats
}

fn percentile(sorted: &[usize], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0] as f64;
    }

    let n = sorted.len() - 1;
    let position = (percentile / 100.0) * n as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        sorted[lower] as f64
    } else {
        let lower_value = sorted[lower] as f64;
        let upper_value = sorted[upper] as f64;
        lower_value + (position - lower as f64) * (upper_value - lower_value)
    }
}

fn build_histogram(lengths: &[usize]) -> Vec<HistogramBucket> {
    if lengths.is_empty() {
        return Vec::new();
    }
    let min = *lengths.iter().min().unwrap();
    let max = *lengths.iter().max().unwrap();
    let span = max.saturating_sub(min);
    let bucket_size = std::cmp::max(1, span / 10);
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for &len in lengths {
        let offset = len.saturating_sub(min);
        let bucket = min + bucket_size * (offset / bucket_size);
        *counts.entry(bucket).or_insert(0) += 1;
    }
    let mut buckets: Vec<_> = counts
        .into_iter()
        .map(|(start, count)| HistogramBucket {
            start,
            end: start + bucket_size.saturating_sub(1),
            count,
        })
        .collect();
    buckets.sort_by_key(|bucket| bucket.start);
    buckets
}

fn compute_top_sequences(counter: HashMap<Vec<u8>, usize>) -> Vec<SequenceFrequency> {
    let mut frequencies: Vec<_> = counter
        .into_iter()
        .map(|(sequence, frequency)| SequenceFrequency {
            length: sequence.len(),
            frequency,
            sequence_hex: hex::encode(sequence),
        })
        .collect();
    frequencies.sort_by(|a, b| b.frequency.cmp(&a.frequency));
    frequencies.truncate(10);
    frequencies
}

fn compute_ngram_diversity(bytecodes: &[Vec<u8>], ns: &[usize]) -> BTreeMap<usize, f64> {
    let mut map = BTreeMap::new();
    for &n in ns {
        if n == 0 {
            map.insert(n, 0.0);
            continue;
        }
        let mut total = 0usize;
        let mut unique: HashSet<Vec<u8>> = HashSet::new();
        for code in bytecodes {
            if code.len() < n {
                continue;
            }
            total += code.len() - n + 1;
            for window in code.windows(n) {
                unique.insert(window.to_vec());
            }
        }
        let diversity = if total == 0 {
            0.0
        } else {
            unique.len() as f64 / total as f64 * 100.0
        };
        map.insert(n, diversity);
    }
    map
}

fn sorted_transform_entries(counts: &BTreeMap<String, usize>) -> Vec<(String, usize)> {
    let mut entries: Vec<(String, usize)> = counts
        .iter()
        .map(|(name, count)| (name.clone(), *count))
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    entries
}

fn summarize_transforms(counts: &BTreeMap<String, usize>, iterations: usize) -> String {
    if counts.is_empty() {
        return "None detected (dispatcher skipped)".to_string();
    }
    let entries = sorted_transform_entries(counts);
    let mut parts = Vec::new();
    for (name, count) in entries {
        let pct = if iterations > 0 {
            (count as f64 / iterations as f64) * 100.0
        } else {
            0.0
        };
        parts.push(format!("{name} ({count}/{iterations}, {pct:.1}%)"));
    }
    parts.join(", ")
}

fn truncate_hex(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        input.to_string()
    } else if max_len > 3 {
        format!("{}...", &input[..max_len - 3])
    } else {
        input[..max_len].to_string()
    }
}

fn parse_passes(passes: &str) -> Result<Vec<TransformSpec>, AnalysisError> {
    let mut specs = Vec::new();
    if passes.trim().is_empty() {
        return Ok(specs);
    }
    for raw in passes.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let spec = match name {
            "shuffle" => TransformSpec::Shuffle,
            "opaque_pred" | "opaque_predicate" => TransformSpec::OpaquePredicate,
            "jump_transform" | "jump_addr" => TransformSpec::JumpTransform,
            other => return Err(AnalysisError::InvalidPass(other.to_string())),
        };
        specs.push(spec);
    }
    Ok(specs)
}

enum TransformSpec {
    Shuffle,
    OpaquePredicate,
    JumpTransform,
}

impl TransformSpec {
    fn build(&self) -> Box<dyn Transform> {
        match self {
            TransformSpec::Shuffle => Box::new(Shuffle),
            TransformSpec::OpaquePredicate => Box::new(OpaquePredicate::new()),
            TransformSpec::JumpTransform => Box::new(JumpAddressTransformer::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_common_substring_finds_match() {
        let a = b"abcdefg";
        let b = b"xyzabcuvw";
        let result = longest_common_substring(a, b);
        assert_eq!(result, b"abc");
    }

    #[test]
    fn percentile_handles_small_inputs() {
        let values = vec![10, 20, 30, 40];
        assert_eq!(percentile(&values, 25.0), 17.5);
        assert_eq!(percentile(&values, 75.0), 32.5);
    }
}
