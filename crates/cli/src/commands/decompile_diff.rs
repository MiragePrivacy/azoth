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
use azoth_core::cfg_ir::{CfgIrDiff, OperationKind, TraceEvent};
use azoth_core::decoder::Instruction;
use azoth_transform::obfuscator::{obfuscate_bytecode, ObfuscationConfig};
use clap::{ArgAction, Args};
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
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

    /// Comma-separated list of transforms (default: shuffle).
    #[arg(long, default_value = DEFAULT_PASSES)]
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

    /// Disable heuristic cause annotations in diff output.
    #[arg(long = "no-annotate-causes", action = ArgAction::SetFalse, default_value_t = true)]
    pub annotate_causes: bool,
}

/// Aggregated statistics across multiple structured diff runs.
#[derive(Debug, Clone)]
struct AggregatedStructuredStats {
    min: DiffStats,
    max: DiffStats,
    sum: DiffStats,
    sample_count: usize,
}

#[derive(Debug, Clone)]
struct DiffRun {
    diff: StructuredDiffResult,
    attribution: PcAttribution,
}

#[derive(Debug, Clone, Default)]
struct PcAttribution {
    pre: HashMap<usize, HashSet<DiffCause>>,
    post: HashMap<usize, HashSet<DiffCause>>,
    observed: HashSet<DiffCause>,
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

        let mut join_set: JoinSet<Result<DiffRun, String>> = JoinSet::new();

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

                let attribution = build_pc_attribution(&obf_result.trace);
                Ok(DiffRun {
                    diff: diff_result,
                    attribution,
                })
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
        let mut first_attribution: Option<PcAttribution> = None;

        for (i, result) in results.into_iter().enumerate() {
            let diff_run = result?;
            let stats = diff_run.diff.aggregate_stats();

            if i == 0 {
                first_result = Some(diff_run.diff);
                first_attribution = Some(diff_run.attribution);
            }

            match &mut aggregated {
                None => aggregated = Some(AggregatedStructuredStats::new(&stats)),
                Some(agg) => agg.add(&stats),
            }
        }

        let aggregated = aggregated.expect("at least one iteration");
        let first_result = first_result.expect("at least one iteration");
        let first_attribution = first_attribution.expect("at least one iteration");

        // Write diff to file if requested, otherwise print to terminal
        if let Some(output_path) = &self.output {
            let output = self.format_diff_output(&first_result, &first_attribution);
            fs::write(output_path, output)?;
        } else {
            self.print_structured_diff(&first_result, &first_attribution);
        }

        // Always print summary and statistics
        self.print_statistics(&aggregated, &first_result);

        Ok(())
    }
}

impl DecompileDiffArgs {
    /// Formats the diff only (no stats) as plain text for file output.
    fn format_diff_output(
        &self,
        result: &StructuredDiffResult,
        attribution: &PcAttribution,
    ) -> String {
        let mut output = String::new();

        for item in &result.items {
            if self.changed_only && !item.has_changes() {
                continue;
            }

            output.push_str(&format!("─── {} ───\n", item.kind));

            if item.has_changes() {
                if self.annotate_causes {
                    output.push_str(&annotate_diff_plain(item, attribution));
                } else {
                    output.push_str(&render_clean_diff(item, false));
                }
            } else {
                output.push_str("(no changes)\n");
            }
            output.push('\n');
        }

        output
    }

    /// Prints the structured diff to stdout with colors (no summary, just diffs).
    fn print_structured_diff(
        &self,
        result: &StructuredDiffResult,
        attribution: &PcAttribution,
    ) {
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
                if self.annotate_causes {
                    let summary = format_cause_summary(item, attribution);
                    if !summary.is_empty() {
                        println!("    {} {}", "Causes:".dimmed(), summary);
                    }
                    print!("{}", annotate_diff_colored(item, attribution));
                } else {
                    print!("{}", render_clean_diff(item, true));
                }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum DiffCause {
    FunctionDispatcher,
    SlotShuffle,
    PushSplit,
}

fn format_cause_summary(
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
) -> String {
    let causes = collect_item_causes(item, attribution);
    if causes.is_empty() {
        return String::new();
    }
    let labels: Vec<&'static str> = causes
        .into_iter()
        .map(|cause| match cause {
            DiffCause::FunctionDispatcher => "FunctionDispatcher",
            DiffCause::SlotShuffle => "SlotShuffle",
            DiffCause::PushSplit => "PushSplit",
        })
        .collect();
    labels.join(", ")
}

fn annotate_diff_plain(
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
) -> String {
    render_annotated_diff(item, attribution, false)
}

fn annotate_diff_colored(
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
) -> String {
    render_annotated_diff(item, attribution, true)
}

fn render_annotated_diff(
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
    colored: bool,
) -> String {
    let mut out = String::new();
    for raw_line in item.diff.unified_diff.lines() {
        let mut suffix = String::new();
        let mut display_line = raw_line.to_string();
        if let Some((prefix, content)) = split_diff_line(raw_line) {
            let (clean_content, pc) = strip_pc_tag(content);
            display_line = format!("{prefix}{clean_content}");
            let causes = causes_for_line(prefix, &clean_content, pc, item, attribution);
            if !causes.is_empty() {
                let tags = causes
                    .iter()
                    .map(|cause| match cause {
                        DiffCause::FunctionDispatcher => "FD",
                        DiffCause::SlotShuffle => "SS",
                        DiffCause::PushSplit => "PS",
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                suffix = format!(" [{}]", tags);
            }
        } else if let Some(stripped) = strip_context_pc(raw_line) {
            display_line = stripped;
        }
        if colored {
            display_line = colorize_diff_line(&display_line);
        }
        if !suffix.is_empty() {
            if colored {
                display_line.push_str(&suffix.dimmed().to_string());
            } else {
                display_line.push_str(&suffix);
            }
        }
        out.push_str(&display_line);
        out.push('\n');
    }
    out
}

fn render_clean_diff(item: &decompile_diff::StructuredDiffItem, colored: bool) -> String {
    let mut out = String::new();
    for raw_line in item.diff.unified_diff.lines() {
        let mut display_line = raw_line.to_string();
        if let Some((prefix, content)) = split_diff_line(raw_line) {
            let (clean_content, _) = strip_pc_tag(content);
            display_line = format!("{prefix}{clean_content}");
        } else if let Some(stripped) = strip_context_pc(raw_line) {
            display_line = stripped;
        }
        if colored {
            display_line = colorize_diff_line(&display_line);
        }
        out.push_str(&display_line);
        out.push('\n');
    }
    out
}

fn split_diff_line(line: &str) -> Option<(char, &str)> {
    let mut chars = line.chars();
    let prefix = chars.next()?;
    if prefix != '+' && prefix != '-' {
        return None;
    }
    let content = chars.as_str();
    if content.starts_with("+++") || content.starts_with("---") {
        return None;
    }
    Some((prefix, content))
}

fn strip_context_pc(line: &str) -> Option<String> {
    if !line.starts_with(' ') {
        return None;
    }
    let content = &line[1..];
    let (clean_content, _) = strip_pc_tag(content);
    Some(format!(" {}", clean_content))
}

fn strip_pc_tag(content: &str) -> (String, Option<usize>) {
    let trimmed = content.trim_end();
    if let Some(start) = trimmed.rfind("/*pc=0x") {
        if let Some(end) = trimmed[start..].find("*/") {
            let hex_start = start + "/*pc=0x".len();
            let hex_end = start + end;
            let hex = &trimmed[hex_start..hex_end];
            if let Ok(pc) = usize::from_str_radix(hex, 16) {
                let mut clean = trimmed[..start].trim_end().to_string();
                if content.ends_with('\n') {
                    clean.push('\n');
                }
                return (clean, Some(pc));
            }
        }
    }
    (content.to_string(), None)
}

fn colorize_diff_line(line: &str) -> String {
    if line.starts_with("@@") {
        return line.cyan().to_string();
    }
    if line.starts_with('+') {
        return line.green().to_string();
    }
    if line.starts_with('-') {
        return line.red().to_string();
    }
    line.to_string()
}

fn push_cause(causes: &mut Vec<DiffCause>, cause: DiffCause) {
    if !causes.contains(&cause) {
        causes.push(cause);
    }
}

fn collect_item_causes(
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
) -> Vec<DiffCause> {
    let mut causes = Vec::new();
    for raw_line in item.diff.unified_diff.lines() {
        if let Some((prefix, content)) = split_diff_line(raw_line) {
            let (clean_content, pc) = strip_pc_tag(content);
            let line_causes = causes_for_line(prefix, &clean_content, pc, item, attribution);
            for cause in line_causes {
                push_cause(&mut causes, cause);
            }
        }
    }
    causes
}

fn causes_for_line(
    prefix: char,
    content: &str,
    pc: Option<usize>,
    item: &decompile_diff::StructuredDiffItem,
    attribution: &PcAttribution,
) -> Vec<DiffCause> {
    let mut causes = Vec::new();
    if let Some(pc) = pc {
        let target = match prefix {
            '-' => attribution.pre.get(&pc),
            '+' => attribution.post.get(&pc),
            _ => None,
        };
        if let Some(set) = target {
            if set.len() == 1 {
                if let Some(cause) = set.iter().copied().next() {
                    push_cause(&mut causes, cause);
                }
            }
        }
        return causes;
    }

    if attribution
        .observed
        .contains(&DiffCause::FunctionDispatcher)
        && should_tag_dispatcher_line(content, item)
    {
        push_cause(&mut causes, DiffCause::FunctionDispatcher);
    }

    causes
}

fn should_tag_dispatcher_line(content: &str, item: &decompile_diff::StructuredDiffItem) -> bool {
    let trimmed = content.trim_start();
    let is_header = trimmed.contains("@custom:selector")
        || trimmed.contains("@custom:signature")
        || trimmed.starts_with("function ");
    if !is_header {
        return false;
    }
    match &item.kind {
        StructureKind::Function {
            original_selector,
            obfuscated_selector,
            ..
        } => original_selector != obfuscated_selector,
        StructureKind::UnmatchedOriginal { .. } | StructureKind::UnmatchedObfuscated { .. } => true,
        _ => false,
    }
}

fn build_pc_attribution(trace: &[TraceEvent]) -> PcAttribution {
    let mut attribution = PcAttribution::default();
    let mut active: Option<DiffCause> = None;
    let (pc_origin, origin_to_final) = build_pc_origin_maps(trace);

    for event in trace {
        match &event.kind {
            OperationKind::TransformStart { name } => {
                active = cause_from_name(name);
                if let Some(cause) = active {
                    attribution.observed.insert(cause);
                }
            }
            OperationKind::TransformEnd { .. } => {
                active = None;
            }
            _ => {}
        }

        match &event.diff {
            CfgIrDiff::BlockChanges(changes) => {
                let Some(cause) = active else {
                    continue;
                };
                for change in &changes.changes {
                    let (before_changed, after_changed) = diff_instruction_pcs(
                        &change.before.instructions,
                        &change.after.instructions,
                        &pc_origin,
                    );
                    for origin in before_changed {
                        attribution.pre.entry(origin).or_default().insert(cause);
                    }
                    for origin in after_changed {
                        let final_pc = origin_to_final.get(&origin).copied().unwrap_or(origin);
                        attribution.post.entry(final_pc).or_default().insert(cause);
                    }
                }
            }
            _ => {}
        }
    }

    attribution
}

fn build_pc_origin_maps(trace: &[TraceEvent]) -> (HashMap<usize, usize>, HashMap<usize, usize>) {
    let mut pc_origin: HashMap<usize, usize> = HashMap::new();
    let mut origin_to_final: HashMap<usize, usize> = HashMap::new();

    for event in trace {
        if let CfgIrDiff::PcsRemapped { instructions, .. } = &event.diff {
            for instr in instructions {
                let origin = pc_origin
                    .get(&instr.old_pc)
                    .copied()
                    .unwrap_or(instr.old_pc);
                pc_origin.insert(instr.old_pc, origin);
                pc_origin.insert(instr.new_pc, origin);
                origin_to_final.insert(origin, instr.new_pc);
            }
        }
    }

    (pc_origin, origin_to_final)
}

fn diff_instruction_pcs(
    before: &[Instruction],
    after: &[Instruction],
    pc_origin: &HashMap<usize, usize>,
) -> (HashSet<usize>, HashSet<usize>) {
    let mut before_changed = HashSet::new();
    let mut after_changed = HashSet::new();

    let mut before_by_origin: HashMap<usize, &Instruction> = HashMap::new();
    for instr in before {
        let origin = pc_origin.get(&instr.pc).copied().unwrap_or(instr.pc);
        before_by_origin.insert(origin, instr);
    }

    let mut after_by_origin: HashMap<usize, &Instruction> = HashMap::new();
    for instr in after {
        let origin = pc_origin.get(&instr.pc).copied().unwrap_or(instr.pc);
        after_by_origin.insert(origin, instr);
    }

    for (origin, before_instr) in &before_by_origin {
        match after_by_origin.get(origin) {
            Some(after_instr) => {
                if before_instr.op != after_instr.op || before_instr.imm != after_instr.imm {
                    before_changed.insert(*origin);
                    after_changed.insert(*origin);
                }
            }
            None => {
                before_changed.insert(*origin);
            }
        }
    }

    for (origin, _) in &after_by_origin {
        if !before_by_origin.contains_key(origin) {
            after_changed.insert(*origin);
        }
    }

    (before_changed, after_changed)
}

fn cause_from_name(name: &str) -> Option<DiffCause> {
    match name {
        "FunctionDispatcher" => Some(DiffCause::FunctionDispatcher),
        "SlotShuffle" => Some(DiffCause::SlotShuffle),
        "PushSplit" => Some(DiffCause::PushSplit),
        _ => None,
    }
}
