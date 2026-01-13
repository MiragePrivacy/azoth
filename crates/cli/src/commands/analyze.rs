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

        let index = if let Some(start) = block_start {
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

        if block_start.is_none() {
            if let Ok(dataset) = Dataset::load(Some(root.clone())) {
                if let Ok(manifest_hash) = dataset.manifest_hash() {
                    if manifest_hash != index.manifest_hash {
                        println!("Warning: dataset index is out of date with the manifest. Run `azoth dataset reindex`.");
                    }
                }
            }
        }

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
