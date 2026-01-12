use crate::comparison::opcode_histogram_counts;
use crate::dataset::{Dataset, DatasetError, Result, parquet::ParquetContractReader};
use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const EXPECTED_CONTRACTS: usize = 20_000_000;
const BLOOM_FP_RATE: f64 = 0.01;

/// Aggregated bytecode size count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeCount {
    /// Bytecode length in bytes.
    pub size: usize,
    /// Number of contracts with this size.
    pub count: u64,
}

/// Cached dataset statistics for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetIndex {
    /// MD5 hash of the manifest used to build this index.
    pub manifest_hash: String,
    /// Optional dataset version from the manifest.
    pub dataset_version: Option<String>,
    /// Total contracts indexed.
    pub total_count: u64,
    /// Normalized opcode frequencies across the dataset.
    pub opcode_freq: Vec<f64>,
    /// Aggregated bytecode size counts.
    pub size_counts: Vec<SizeCount>,
    /// Bloom filter for membership checks on code hashes.
    pub bloom: Bloom<[u8; 32]>,
}

/// Build a dataset index by scanning all cached parquet files.
pub fn build_index(dataset: &Dataset) -> Result<DatasetIndex> {
    println!("Indexing dataset at {}", dataset.root.display());
    let mut opcode_counts = [0u64; 256];
    let mut opcode_total = 0u64;
    let mut size_counts = BTreeMap::<usize, u64>::new();
    let mut bloom = Bloom::new_for_fp_rate(EXPECTED_CONTRACTS, BLOOM_FP_RATE);
    let mut total_count = 0u64;

    let files = dataset.parquet_files()?;
    println!("Found {} parquet files", files.len());
    for (idx, path) in files.iter().enumerate() {
        println!(
            "Indexing [{}/{}]: {}",
            idx + 1,
            files.len(),
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
        );
        let reader = ParquetContractReader::open(path)?;
        for record in reader.iter() {
            let record = record?;
            let len = record.code.len();
            *size_counts.entry(len).or_insert(0) += 1;
            total_count += 1;
            opcode_histogram_counts(&record.code, &mut opcode_counts, &mut opcode_total);
            if let Some(hash) = record.code_hash {
                bloom.set(&hash);
            }
        }
        println!("Indexed: {}", path.display());
    }

    if opcode_total == 0 {
        return Err(DatasetError::Format("no opcodes indexed".to_string()));
    }

    let opcode_freq = normalize_counts(opcode_counts, opcode_total);
    let size_counts = size_counts
        .into_iter()
        .map(|(size, count)| SizeCount { size, count })
        .collect::<Vec<_>>();

    Ok(DatasetIndex {
        manifest_hash: dataset.manifest_hash()?,
        dataset_version: dataset.manifest.version.clone(),
        total_count,
        opcode_freq,
        size_counts,
        bloom,
    })
}

/// Compute MD5 hash hex for byte slices.
pub fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn normalize_counts(counts: [u64; 256], total: u64) -> Vec<f64> {
    let total = total as f64;
    let mut freq = vec![0.0; 256];
    for (idx, count) in counts.into_iter().enumerate() {
        freq[idx] = count as f64 / total;
    }
    freq
}
