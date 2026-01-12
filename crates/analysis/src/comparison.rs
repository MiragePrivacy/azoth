use crate::dataset::{DatasetIndex, Result, SizeCount};
use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};

/// Comparison results against the dataset index.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Percent of contracts smaller than the input bytecode.
    pub size_percentile: f64,
    /// Cosine similarity between opcode distributions.
    pub opcode_similarity: f64,
    /// Per-opcode relative deviations from the dataset baseline.
    pub opcode_deviations: HashMap<u8, f64>,
    /// Top anomalous opcodes by absolute deviation.
    pub anomalous_opcodes: Vec<(u8, f64)>,
    /// Whether the bytecode hash is present in the dataset bloom filter.
    pub exact_match_found: bool,
}

/// Compare a bytecode blob to a dataset index.
pub fn compare_to_dataset(bytecode: &[u8], index: &DatasetIndex) -> Result<ComparisonResult> {
    let size_percentile = size_percentile(bytecode.len(), &index.size_counts, index.total_count);
    let input_freq = opcode_frequency(bytecode);
    let opcode_similarity = cosine_similarity(&input_freq, &index.opcode_freq);
    let opcode_deviations = deviation_map(&input_freq, &index.opcode_freq);
    let anomalous_opcodes = top_deviations(&opcode_deviations, 5);
    let exact_match_found = exact_match(bytecode, index);

    Ok(ComparisonResult {
        size_percentile,
        opcode_similarity,
        opcode_deviations,
        anomalous_opcodes,
        exact_match_found,
    })
}

/// Compute normalized opcode frequencies for a bytecode blob.
pub fn opcode_frequency(bytecode: &[u8]) -> Vec<f64> {
    let mut counts = [0u64; 256];
    let mut total = 0u64;
    opcode_histogram_counts(bytecode, &mut counts, &mut total);
    if total == 0 {
        return vec![0.0; 256];
    }

    let mut freq = vec![0.0; 256];
    for (idx, count) in counts.into_iter().enumerate() {
        freq[idx] = count as f64 / total as f64;
    }
    freq
}

/// Accumulate opcode counts for a bytecode blob.
pub fn opcode_histogram_counts(bytecode: &[u8], counts: &mut [u64; 256], total: &mut u64) {
    let mut pc = 0usize;
    while pc < bytecode.len() {
        let op = bytecode[pc];
        counts[op as usize] += 1;
        *total += 1;
        pc += 1;
        if (0x60..=0x7f).contains(&op) {
            let push_bytes = (op - 0x5f) as usize;
            pc = pc.saturating_add(push_bytes);
        }
    }
}

/// Compute cosine similarity between two opcode distributions.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let mut dot = 0.0;
    let mut norm_a = 0.0;
    let mut norm_b = 0.0;
    let len = a.len().min(b.len());
    for i in 0..len {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Compute size percentile using aggregated size counts.
pub fn size_percentile(size: usize, sizes: &[SizeCount], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let mut below = 0u64;
    for entry in sizes {
        if entry.size < size {
            below += entry.count;
        } else {
            break;
        }
    }
    below as f64 / total as f64 * 100.0
}

fn deviation_map(sample: &[f64], baseline: &[f64]) -> HashMap<u8, f64> {
    let mut map = HashMap::new();
    let len = sample.len().min(baseline.len());
    for idx in 0..len {
        let base = baseline[idx];
        if base == 0.0 {
            continue;
        }
        let dev = (sample[idx] - base) / base;
        if dev != 0.0 {
            map.insert(idx as u8, dev);
        }
    }
    map
}

fn top_deviations(map: &HashMap<u8, f64>, count: usize) -> Vec<(u8, f64)> {
    let mut entries: Vec<(u8, f64)> = map.iter().map(|(k, v)| (*k, *v)).collect();
    entries.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap());
    entries.truncate(count);
    entries
}

fn exact_match(bytecode: &[u8], index: &DatasetIndex) -> bool {
    let hash = keccak256(bytecode);
    index.bloom.check(&hash)
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(bytes);
    hasher.finalize(&mut out);
    out
}
