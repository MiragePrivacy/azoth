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
}

#[async_trait]
impl super::Command for AnalyzeArgs {
    async fn execute(self) -> Result<(), Box<dyn Error>> {
        let AnalyzeArgs {
            bytecode,
            dataset_root,
            reindex,
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

        let index = match dataset::load_index(Some(root.clone())) {
            Ok(index) => index,
            Err(DatasetError::MissingIndex) => {
                println!(
                    "Dataset index not found at {}. Run `azoth dataset download` and `azoth dataset reindex` first.",
                    dataset::index_path(Some(root)).display()
                );
                return Ok(());
            }
            Err(err) => return Err(Box::new(err)),
        };

        if let Ok(dataset) = Dataset::load(Some(root.clone())) {
            if let Ok(manifest_hash) = dataset.manifest_hash() {
                if manifest_hash != index.manifest_hash {
                    println!("Warning: dataset index is out of date with the manifest. Run `azoth dataset reindex`.");
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
        println!("Opcode similarity:        {:.3}", result.opcode_similarity);
        if result.exact_match_found {
            println!("Exact match:              yes");
        } else {
            println!("Exact match:              no");
        }
        if !result.anomalous_opcodes.is_empty() {
            println!();
            println!("Top opcode anomalies:");
            for (opcode, deviation) in result.anomalous_opcodes {
                let name = Opcode::from(opcode);
                println!("  {} (0x{opcode:02x}): {:+.2}%", name, deviation * 100.0);
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
