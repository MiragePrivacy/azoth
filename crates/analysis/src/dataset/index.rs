use crate::comparison::opcode_histogram_counts;
use crate::dataset::{Dataset, DatasetError, Result, parquet::ParquetContractReader, storage};
use bloomfilter::Bloom;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const EXPECTED_CONTRACTS: usize = 20_000_000;
const BLOOM_FP_RATE: f64 = 0.01;
const SIZE_BUCKET_BYTES: usize = 1024;
const BLOCK_BUCKET_SIZE: u64 = 1_000_000;

/// Aggregated bytecode size count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeCount {
    /// Bytecode length in bytes.
    pub size: usize,
    /// Number of contracts with this size.
    pub count: u64,
}

/// Aggregated bucket count with u64 ranges (used for block buckets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketCount {
    /// Bucket start value.
    pub start: u64,
    /// Number of entries in the bucket.
    pub count: u64,
}

/// Aggregated bucket count for size ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeBucket {
    /// Bucket start value.
    pub start: usize,
    /// Number of entries in the bucket.
    pub count: u64,
}

/// Aggregated compiler version counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCount {
    /// Compiler version label.
    pub version: String,
    /// Number of contracts with this version.
    pub count: u64,
}

/// Cached dataset statistics for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetIndex {
    /// Total contracts indexed.
    pub total_count: u64,
    /// Normalized opcode frequencies across the dataset.
    pub opcode_freq: Vec<f64>,
    /// Aggregated bytecode size counts.
    pub size_counts: Vec<SizeCount>,
    #[serde(default)]
    /// Size buckets for runtime bytecode.
    pub runtime_size_buckets: Vec<SizeBucket>,
    #[serde(default)]
    /// Size buckets for init bytecode.
    pub init_size_buckets: Vec<SizeBucket>,
    #[serde(default)]
    /// Block number buckets for deployment distribution.
    pub block_buckets: Vec<BucketCount>,
    #[serde(default)]
    /// Compiler version counts (best-effort).
    pub compiler_versions: Vec<VersionCount>,
    /// Bucket size used for runtime/init sizes.
    #[serde(default = "default_size_bucket_bytes")]
    pub size_bucket_bytes: u64,
    /// Bucket size used for block ranges.
    #[serde(default = "default_block_bucket_size")]
    pub block_bucket_size: u64,
    /// Bloom filter for membership checks on code hashes.
    pub bloom: Bloom<[u8; 32]>,
}

/// Block range filter for dataset indexing.
#[derive(Debug, Clone, Copy)]
pub struct BlockFilter {
    pub start: u64,
    pub end: u64,
}

/// Build a dataset index by scanning all cached parquet files.
pub fn build_index(dataset: &Dataset) -> Result<DatasetIndex> {
    build_index_filtered(dataset, None)
}

/// Build a dataset index for a specific block range.
pub fn build_index_filtered(
    dataset: &Dataset,
    filter: Option<BlockFilter>,
) -> Result<DatasetIndex> {
    println!("Indexing dataset at {}", dataset.root.display());
    if let Some(range) = filter {
        println!("Block filter: {}-{}", range.start, range.end);
    }
    let mut opcode_counts = [0u64; 256];
    let mut opcode_total = 0u64;
    let mut size_counts = BTreeMap::<usize, u64>::new();
    let mut runtime_size_buckets = BTreeMap::<usize, u64>::new();
    let mut init_size_buckets = BTreeMap::<usize, u64>::new();
    let mut block_buckets = BTreeMap::<u64, u64>::new();
    let mut compiler_versions = BTreeMap::<String, u64>::new();
    let mut bloom = Bloom::new_for_fp_rate(EXPECTED_CONTRACTS, BLOOM_FP_RATE);
    let mut total_count = 0u64;

    let files = dataset.parquet_files()?;
    println!("Found {} parquet files", files.len());
    for (idx, path) in files.iter().enumerate() {
        if let Some(range) = filter
            && let Some((file_start, file_end)) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(storage::parse_file_block_range)
            && (range.end < file_start || range.start > file_end)
        {
            continue;
        }
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
            if let Some(range) = filter {
                if let Some(block) = record.block_number {
                    if block < range.start || block > range.end {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            let len = record.code.len();
            *size_counts.entry(len).or_insert(0) += 1;
            let bucket = (len / SIZE_BUCKET_BYTES) * SIZE_BUCKET_BYTES;
            *runtime_size_buckets.entry(bucket).or_insert(0) += 1;
            if let Some(init_code) = record.init_code.as_ref() {
                let init_len = init_code.len();
                let init_bucket = (init_len / SIZE_BUCKET_BYTES) * SIZE_BUCKET_BYTES;
                *init_size_buckets.entry(init_bucket).or_insert(0) += 1;
            }
            if let Some(block) = record.block_number {
                let block_bucket = (block / BLOCK_BUCKET_SIZE) * BLOCK_BUCKET_SIZE;
                *block_buckets.entry(block_bucket).or_insert(0) += 1;
            }
            if let Some(version) = extract_solc_version(&record.code) {
                *compiler_versions.entry(version).or_insert(0) += 1;
            }
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
    let runtime_size_buckets = runtime_size_buckets
        .into_iter()
        .map(|(start, count)| SizeBucket { start, count })
        .collect::<Vec<_>>();
    let init_size_buckets = init_size_buckets
        .into_iter()
        .map(|(start, count)| SizeBucket { start, count })
        .collect::<Vec<_>>();
    let block_buckets = block_buckets
        .into_iter()
        .map(|(start, count)| BucketCount { start, count })
        .collect::<Vec<_>>();
    let compiler_versions = compiler_versions
        .into_iter()
        .map(|(version, count)| VersionCount { version, count })
        .collect::<Vec<_>>();

    Ok(DatasetIndex {
        total_count,
        opcode_freq,
        size_counts,
        runtime_size_buckets,
        init_size_buckets,
        block_buckets,
        compiler_versions,
        size_bucket_bytes: SIZE_BUCKET_BYTES as u64,
        block_bucket_size: BLOCK_BUCKET_SIZE,
        bloom,
    })
}

fn normalize_counts(counts: [u64; 256], total: u64) -> Vec<f64> {
    let total = total as f64;
    let mut freq = vec![0.0; 256];
    for (idx, count) in counts.into_iter().enumerate() {
        freq[idx] = count as f64 / total;
    }
    freq
}

fn default_size_bucket_bytes() -> u64 {
    SIZE_BUCKET_BYTES as u64
}

fn default_block_bucket_size() -> u64 {
    BLOCK_BUCKET_SIZE
}

pub fn extract_solc_version(code: &[u8]) -> Option<String> {
    let meta = extract_cbor_metadata(code)?;
    let map = match meta {
        ciborium::value::Value::Map(map) => map,
        _ => return None,
    };
    for (key, value) in map {
        let key = match key {
            ciborium::value::Value::Text(text) => text,
            _ => continue,
        };
        if key == "solc" {
            return parse_solc_value(&value);
        }
        if key == "compiler"
            && let ciborium::value::Value::Map(ref inner) = value
        {
            for (inner_key, inner_value) in inner {
                if let ciborium::value::Value::Text(name) = inner_key
                    && name == "version"
                    && let Some(version) = parse_solc_value(inner_value)
                {
                    return Some(version);
                }
            }
        }
        if key == "vyper"
            && let Some(version) = parse_solc_value(&value)
        {
            return Some(format!("vyper {version}"));
        }
    }
    None
}

fn parse_solc_value(value: &ciborium::value::Value) -> Option<String> {
    match value {
        ciborium::value::Value::Bytes(bytes) => {
            if bytes.len() >= 3 {
                return Some(format!("{}.{}.{}", bytes[0], bytes[1], bytes[2]));
            }
            None
        }
        ciborium::value::Value::Text(text) => Some(text.clone()),
        ciborium::value::Value::Array(items) => {
            if items.len() >= 3 {
                let mut parts = Vec::new();
                for item in items.iter().take(3) {
                    if let ciborium::value::Value::Integer(v) = item {
                        let value: i128 = (*v).into();
                        parts.push(value.to_string());
                    }
                }
                if parts.len() == 3 {
                    return Some(parts.join("."));
                }
            }
            None
        }
        _ => None,
    }
}

fn extract_cbor_metadata(code: &[u8]) -> Option<ciborium::value::Value> {
    if code.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([code[code.len() - 2], code[code.len() - 1]]) as usize;
    if len == 0 || len + 2 > code.len() {
        return None;
    }
    let start = code.len() - 2 - len;
    let metadata = &code[start..code.len() - 2];
    let mut cursor = std::io::Cursor::new(metadata);
    ciborium::de::from_reader(&mut cursor).ok()
}
