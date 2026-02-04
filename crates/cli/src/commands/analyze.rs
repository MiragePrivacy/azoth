use crate::commands::obfuscate::read_input;
use async_trait::async_trait;
use azoth_analysis::comparison::compare_to_dataset;
use azoth_analysis::dataset::{self, Dataset, DatasetError};
use azoth_core::Opcode;
use clap::Args;
use std::{error::Error, path::PathBuf};

/// Compare runtime bytecode against the Ethereum contracts dataset.
#[derive(Args)]
pub struct AnalyzeArgs {
    /// Input runtime bytecode as hex, .hex file, or binary file.
    #[arg(value_name = "BYTECODE")]
    pub bytecode: String,
    /// Override dataset root (default: ~/.azoth/datasets/ethereum_contracts).
    #[arg(long, value_name = "PATH")]
    dataset_root: Option<PathBuf>,
    /// Rebuild the dataset index before comparing.
    #[arg(long)]
    reindex: bool,
    /// Start block for filtered comparison.
    #[arg(long, value_name = "BLOCK")]
    block_start: Option<u64>,
    /// Block range length for filtered comparison.
    #[arg(long, value_name = "BLOCKS")]
    block_range: Option<u64>,
    /// Match dataset records by inferred compiler version only.
    #[arg(long)]
    match_compiler_version: bool,
    /// Match dataset records by runtime bytecode size only.
    #[arg(long)]
    match_bytecode_size: bool,
}

#[async_trait]
impl super::Command for AnalyzeArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let AnalyzeArgs {
            bytecode,
            dataset_root,
            reindex,
            block_start,
            block_range,
            match_compiler_version,
            match_bytecode_size,
        } = self;

        let input_hex = read_input(&bytecode)?;
        let bytecode_bytes = decode_hex(&input_hex)?;

        let root = dataset_root
            .clone()
            .unwrap_or_else(dataset::storage::dataset_root);

        if reindex {
            let dataset = Dataset::load(Some(root.clone()))?;
            let index = dataset::index::build_index(&dataset)?;
            dataset::save_index(Some(root.clone()), &index)?;
        }

        let inferred_version = dataset::index::extract_solc_version(&bytecode_bytes);

        let mut compiler_report = None;
        let index = if match_compiler_version || match_bytecode_size {
            let index_path = dataset::index_path(Some(root.clone()));
            if !index_path.exists() {
                println!(
                    "Dataset index not found at {}. Run `azoth dataset reindex` first.",
                    index_path.display()
                );
                return Ok(());
            }
            if match_bytecode_size {
                if block_start.is_none() && block_range.is_some() {
                    println!("Block range ignored without --block-start.");
                }
                let range = if let Some(start) = block_start {
                    let blocks = block_range.unwrap_or(0);
                    if blocks == 0 {
                        println!("Block range must be greater than 0.");
                        return Ok(());
                    }
                    let end = start.saturating_add(blocks.saturating_sub(1));
                    println!("Using block range: {}-{}", start, end);
                    Some(dataset::BlockFilter { start, end })
                } else {
                    None
                };

                let dataset = Dataset::load(Some(root.clone()))?;
                let filter = dataset::index::IndexFilter {
                    block_filter: range,
                    compiler_version: None,
                    runtime_size: Some(bytecode_bytes.len()),
                };
                match dataset::index::build_index_filtered_with_filter(&dataset, filter) {
                    Ok((filtered, _report)) => {
                        println!("Filtered dataset contracts: {}", filtered.total_count);
                        println!("Comparison scope: size matched subset");
                        filtered
                    }
                    Err(DatasetError::Format(msg)) if msg == "no opcodes indexed" => {
                        println!("No matching contracts found for size filter.");
                        return Ok(());
                    }
                    Err(err) => return Err(Box::new(err)),
                }
            } else if let Some(version) = inferred_version.clone() {
                if block_start.is_none() && block_range.is_some() {
                    println!("Block range ignored without --block-start.");
                }
                let range = if let Some(start) = block_start {
                    let blocks = block_range.unwrap_or(0);
                    if blocks == 0 {
                        println!("Block range must be greater than 0.");
                        return Ok(());
                    }
                    let end = start.saturating_add(blocks.saturating_sub(1));
                    println!("Using block range: {}-{}", start, end);
                    Some(dataset::BlockFilter { start, end })
                } else {
                    None
                };

                let dataset = Dataset::load(Some(root.clone()))?;
                let filter = dataset::index::IndexFilter {
                    block_filter: range,
                    compiler_version: Some(version),
                    runtime_size: None,
                };
                match dataset::index::build_index_filtered_with_filter(&dataset, filter) {
                    Ok((filtered, report)) => {
                        compiler_report = Some(report);
                        println!("Filtered dataset contracts: {}", filtered.total_count);
                        println!("Comparison scope: compiler matched subset");
                        filtered
                    }
                    Err(DatasetError::Format(msg)) if msg == "no opcodes indexed" => {
                        println!("No matching contracts found for compiler+size filter.");
                        return Ok(());
                    }
                    Err(err) => return Err(Box::new(err)),
                }
            } else {
                println!("No compiler metadata found in bytecode; skipping compiler match.");
                dataset::load_index(Some(root.clone()))?
            }
        } else if let Some(start) = block_start {
            let range = block_range.unwrap_or(0);
            if range == 0 {
                println!("Block range must be greater than 0.");
                return Ok(());
            }
            let end = start.saturating_add(range.saturating_sub(1));
            println!("Using block range: {}-{}", start, end);
            let dataset = Dataset::load(Some(root.clone()))?;
            dataset::index::build_index_filtered(
                &dataset,
                Some(dataset::BlockFilter { start, end }),
            )?
        } else {
            match dataset::load_index(Some(root.clone())) {
                Ok(index) => index,
                Err(DatasetError::MissingIndex) => {
                    println!(
                    "Dataset index not found at {}. Run `azoth dataset download` and `azoth dataset reindex` first.",
                    dataset::index_path(Some(root)).display()
                );
                    return Ok(());
                }
                Err(err) => return Err(Box::new(err)),
            }
        };

        let result = compare_to_dataset(&bytecode_bytes, &index)?;

        println!("============================================================");
        println!("DATASET COMPARISON");
        println!("============================================================");
        println!("Definitions:");
        println!("  Size percentile: % of dataset contracts with smaller bytecode.");
        println!("  Opcode similarity: cosine similarity vs. dataset opcode distribution (0-1).");
        println!("  Exact match: bloom-filter check of code hash (no false negatives).");
        println!("  Opcode anomaly: relative deviation from dataset mean for that opcode.");
        println!();
        println!("Bytecode size:            {} bytes", bytecode_bytes.len());
        println!("Size percentile:          {:.2}%", result.size_percentile);
        println!(
            "Size rank:                {} smaller, {} same size",
            result.size_rank, result.size_equal_count
        );
        println!(
            "Opcode similarity:        {:.3} (1.0 = identical to dataset)",
            result.opcode_similarity
        );
        if result.exact_match_found {
            println!("Exact match:              yes (bloom filter)");
        } else {
            println!("Exact match:              no (bloom filter)");
        }

        let compiler_stats_index = if match_compiler_version {
            dataset::load_index(Some(root.clone())).ok().or_else(|| {
                if !index.compiler_versions.is_empty() {
                    Some(index.clone())
                } else {
                    None
                }
            })
        } else if !index.compiler_versions.is_empty() {
            Some(index.clone())
        } else {
            dataset::load_index(Some(root.clone())).ok()
        };

        if let Some(stats_index) = compiler_stats_index.as_ref() {
            println!();
            println!("Compiler versions:");
            match inferred_version.clone() {
                Some(version) => {
                    println!("  Inferred:              {}", version);
                    if match_compiler_version {
                        println!("  Comparison subset:     {} contracts", index.total_count);
                    }
                    let mut versions = stats_index.compiler_versions.clone();
                    versions.sort_by(|a, b| b.count.cmp(&a.count));
                    if let Some((rank, entry)) = versions
                        .iter()
                        .enumerate()
                        .find(|(_, entry)| entry.version == version)
                    {
                        let percent = if stats_index.total_count > 0 {
                            (entry.count as f64 / stats_index.total_count as f64) * 100.0
                        } else {
                            0.0
                        };
                        println!(
                            "  Dataset rank:          {} ({} contracts, {:.2}%)",
                            rank + 1,
                            entry.count,
                            percent
                        );
                    } else {
                        println!("  Dataset rank:          not in dataset index");
                    }
                    if let Some(report) = compiler_report.as_ref() {
                        if let Some(min_block) = report.compiler_min_block {
                            println!("  First seen block:      {} (local dataset)", min_block);
                        } else if report.compiler_total > 0 {
                            println!("  First seen block:      unknown (local dataset)");
                        }
                    }
                }
                None => {
                    println!("  Inferred:              unknown");
                }
            }

            let mut versions = stats_index.compiler_versions.clone();
            versions.sort_by(|a, b| b.count.cmp(&a.count));
            println!("  All versions (full dataset index):");
            for entry in versions {
                let percent = if stats_index.total_count > 0 {
                    (entry.count as f64 / stats_index.total_count as f64) * 100.0
                } else {
                    0.0
                };
                println!(
                    "    {:<20} {:>10} ({:.2}%)",
                    entry.version, entry.count, percent
                );
            }
        }

        if !result.anomalous_opcodes.is_empty() {
            println!();
            println!("Top opcode anomalies (relative to dataset mean):");
            println!("  Opcode                 Deviation");
            println!("  (deviation = (sample_freq - dataset_freq) / dataset_freq)");
            for (opcode, deviation) in result.anomalous_opcodes {
                let name = Opcode::from(opcode);
                println!(
                    "  {:<22} {:+.2}%",
                    format!("{name} (0x{opcode:02x})"),
                    deviation * 100.0
                );
            }
        }
        println!("============================================================");
        Ok(())
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let stripped = input.trim().trim_start_matches("0x").replace('_', "");
    Ok(hex::decode(stripped)?)
}
