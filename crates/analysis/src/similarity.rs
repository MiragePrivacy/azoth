//! Byte-level similarity metrics for comparing original and transformed bytecode.
//!
//! The metrics in this module intentionally answer different questions:
//! - longest-common-subsequence retention is a conservative estimate of how much original byte
//!   order survives, even when bytes are moved apart by insertions;
//! - longest common contiguous run finds large untouched motifs;
//! - aligned difference is a cheap position-by-position change measure;
//! - normalized Levenshtein distance accounts for insertions and deletions; and
//! - n-gram Jaccard compares the sets of local byte patterns without depending mechanically on
//!   the number of samples in an experiment.

use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// A compact distribution summary used for per-sample and pairwise ratios.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct DistributionSummary {
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
}

/// Summarize a set of finite metric values.
pub fn summarize_distribution(values: &[f64]) -> DistributionSummary {
    if values.is_empty() {
        return DistributionSummary::default();
    }

    debug_assert!(values.iter().all(|value| value.is_finite()));
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let count = sorted.len();
    let median = if count.is_multiple_of(2) {
        (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
    } else {
        sorted[count / 2]
    };

    DistributionSummary {
        count,
        mean: sorted.iter().sum::<f64>() / count as f64,
        median,
        min: sorted[0],
        max: sorted[count - 1],
    }
}

/// Return the exact longest-common-subsequence length.
///
/// This uses the bit-parallel LCS recurrence, which is exact for arbitrary bytes and reduces the
/// dynamic-programming work by roughly the machine word size.
pub fn longest_common_subsequence_len(a: &[u8], b: &[u8]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }

    // Use the shorter input for the bit vector to minimize memory and work.
    let (rows, columns) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let word_count = columns.len().div_ceil(u64::BITS as usize);
    let mut matches = vec![vec![0u64; word_count]; 256];
    for (index, byte) in columns.iter().copied().enumerate() {
        matches[byte as usize][index / 64] |= 1u64 << (index % 64);
    }

    let mut state = vec![0u64; word_count];
    let mut shifted = vec![0u64; word_count];
    let mut difference = vec![0u64; word_count];

    for byte in rows {
        // y = (state << 1) | 1, as a little-endian multi-word bit vector.
        let mut carry = 1u64;
        for (source, target) in state.iter().copied().zip(&mut shifted) {
            *target = (source << 1) | carry;
            carry = source >> 63;
        }

        // state = x & !(x - y), where x = matches[byte] | state. Subtraction must propagate
        // borrow across words for the bit-parallel recurrence to remain exact.
        let mut borrow = false;
        for word in 0..word_count {
            let x = matches[*byte as usize][word] | state[word];
            let (partial, first_borrow) = x.overflowing_sub(shifted[word]);
            let (result, second_borrow) = partial.overflowing_sub(u64::from(borrow));
            difference[word] = result;
            borrow = first_borrow || second_borrow;
            state[word] = x & !difference[word];
        }
    }

    state.iter().map(|word| word.count_ones() as usize).sum()
}

/// Fraction of the original byte sequence retained as an ordered subsequence.
///
/// This is conservative: insertions and moved-apart regions do not count as changed when their
/// original relative order survives. An empty original has no bytes to retain and returns `1.0`.
pub fn conservative_lcs_retention(original: &[u8], candidate: &[u8]) -> f64 {
    if original.is_empty() {
        return 1.0;
    }
    longest_common_subsequence_len(original, candidate) as f64 / original.len() as f64
}

#[derive(Clone, Default)]
struct SuffixState {
    length: usize,
    link: Option<usize>,
    transitions: HashMap<u8, usize>,
    first_end: usize,
}

/// Return an exact longest common contiguous slice, borrowing from `a`.
///
/// A suffix automaton keeps this linear in the combined input lengths (expected, due to hash-map
/// transitions) rather than allocating a quadratic dynamic-programming table.
pub fn longest_common_contiguous_slice<'a>(a: &'a [u8], b: &[u8]) -> &'a [u8] {
    if a.is_empty() || b.is_empty() {
        return &[];
    }

    let mut states = vec![SuffixState::default()];
    let mut last = 0usize;

    for (position, byte) in a.iter().copied().enumerate() {
        let current = states.len();
        states.push(SuffixState {
            length: states[last].length + 1,
            link: None,
            transitions: HashMap::new(),
            first_end: position,
        });

        let mut cursor = Some(last);
        while let Some(state_index) = cursor {
            if states[state_index].transitions.contains_key(&byte) {
                break;
            }
            states[state_index].transitions.insert(byte, current);
            cursor = states[state_index].link;
        }

        if let Some(parent) = cursor {
            let target = states[parent].transitions[&byte];
            if states[parent].length + 1 == states[target].length {
                states[current].link = Some(target);
            } else {
                let clone_index = states.len();
                let mut clone = states[target].clone();
                clone.length = states[parent].length + 1;
                states.push(clone);

                let mut ancestor = Some(parent);
                while let Some(state_index) = ancestor {
                    if states[state_index].transitions.get(&byte).copied() != Some(target) {
                        break;
                    }
                    states[state_index].transitions.insert(byte, clone_index);
                    ancestor = states[state_index].link;
                }
                states[target].link = Some(clone_index);
                states[current].link = Some(clone_index);
            }
        } else {
            states[current].link = Some(0);
        }

        last = current;
    }

    let mut state = 0usize;
    let mut current_length = 0usize;
    let mut best_length = 0usize;
    let mut best_end = 0usize;

    for &byte in b {
        while state != 0 && !states[state].transitions.contains_key(&byte) {
            state = states[state]
                .link
                .expect("non-root suffix state has a link");
            current_length = current_length.min(states[state].length);
        }

        if let Some(next) = states[state].transitions.get(&byte).copied() {
            state = next;
            current_length += 1;
            if current_length > best_length {
                best_length = current_length;
                best_end = states[state].first_end;
            }
        } else {
            current_length = 0;
        }
    }

    if best_length == 0 {
        &[]
    } else {
        &a[best_end + 1 - best_length..=best_end]
    }
}

/// Length of the longest exact contiguous byte run shared by both inputs.
pub fn longest_common_contiguous_run(a: &[u8], b: &[u8]) -> usize {
    longest_common_contiguous_slice(a, b).len()
}

/// Position-aligned byte difference normalized to the longer input length.
///
/// Bytes beyond the shorter input count as differences. This is cheap and useful for same-layout
/// seed comparisons, but unlike Levenshtein distance it intentionally does not realign insertions.
pub fn aligned_byte_difference_ratio(a: &[u8], b: &[u8]) -> f64 {
    let denominator = a.len().max(b.len());
    if denominator == 0 {
        return 0.0;
    }
    let mismatches = a
        .iter()
        .zip(b)
        .filter(|(left, right)| left != right)
        .count()
        + a.len().abs_diff(b.len());
    mismatches as f64 / denominator as f64
}

/// Exact Levenshtein edit distance normalized to the longer input length.
///
/// The implementation uses `O(min(a.len(), b.len()))` memory and quadratic time. Prefer the
/// aligned metric for large, same-layout seed corpora where insertion realignment is unnecessary.
pub fn normalized_levenshtein_distance(a: &[u8], b: &[u8]) -> f64 {
    let denominator = a.len().max(b.len());
    if denominator == 0 {
        return 0.0;
    }

    let (rows, columns) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut costs: Vec<usize> = (0..=columns.len()).collect();
    for (row_index, row_byte) in rows.iter().enumerate() {
        let mut diagonal = costs[0];
        costs[0] = row_index + 1;
        for (column_index, column_byte) in columns.iter().enumerate() {
            let above = costs[column_index + 1];
            costs[column_index + 1] = if row_byte == column_byte {
                diagonal
            } else {
                1 + diagonal.min(above).min(costs[column_index])
            };
            diagonal = above;
        }
    }
    costs[columns.len()] as f64 / denominator as f64
}

/// Jaccard similarity between the sets of `n`-byte windows in two byte sequences.
///
/// `1.0` means identical n-gram sets and `0.0` means disjoint sets. When neither input contains
/// an n-gram (including `n == 0`), the two empty sets are treated as identical.
pub fn ngram_jaccard(a: &[u8], b: &[u8], n: usize) -> f64 {
    if n == 0 {
        return 1.0;
    }
    let left: HashSet<&[u8]> = a.windows(n).collect();
    let right: HashSet<&[u8]> = b.windows(n).collect();
    let union = left.union(&right).count();
    if union == 0 {
        return 1.0;
    }
    left.intersection(&right).count() as f64 / union as f64
}

/// Compute aligned normalized differences for every unordered pair of samples.
pub fn pairwise_aligned_byte_differences(samples: &[Vec<u8>]) -> Vec<f64> {
    pairwise(samples, aligned_byte_difference_ratio)
}

/// Compute n-gram Jaccard similarity for every unordered pair of samples.
pub fn pairwise_ngram_jaccard(samples: &[Vec<u8>], n: usize) -> Vec<f64> {
    pairwise(samples, |left, right| ngram_jaccard(left, right, n))
}

fn pairwise(samples: &[Vec<u8>], metric: impl Fn(&[u8], &[u8]) -> f64) -> Vec<f64> {
    let pair_count = samples
        .len()
        .saturating_mul(samples.len().saturating_sub(1))
        / 2;
    let mut values = Vec::with_capacity(pair_count);
    for left in 0..samples.len() {
        for right in left + 1..samples.len() {
            values.push(metric(&samples[left], &samples[right]));
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_lcs(a: &[u8], b: &[u8]) -> usize {
        let mut row = vec![0usize; b.len() + 1];
        for left in a {
            let mut diagonal = 0;
            for (index, right) in b.iter().enumerate() {
                let above = row[index + 1];
                row[index + 1] = if left == right {
                    diagonal + 1
                } else {
                    row[index].max(above)
                };
                diagonal = above;
            }
        }
        row[b.len()]
    }

    fn reference_contiguous_run(a: &[u8], b: &[u8]) -> usize {
        let mut previous = vec![0usize; b.len() + 1];
        let mut best = 0usize;
        for left in a {
            let mut current = vec![0usize; b.len() + 1];
            for (index, right) in b.iter().enumerate() {
                if left == right {
                    current[index + 1] = previous[index] + 1;
                    best = best.max(current[index + 1]);
                }
            }
            previous = current;
        }
        best
    }

    fn words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut result = vec![Vec::new()];
        for _ in 0..max_len {
            let existing = result.clone();
            for prefix in existing {
                if prefix.len() == result.last().map_or(0, Vec::len) {
                    for byte in alphabet {
                        let mut word = prefix.clone();
                        word.push(*byte);
                        result.push(word);
                    }
                }
            }
        }
        result.retain(|word| word.len() <= max_len);
        result
    }

    #[test]
    fn bit_parallel_lcs_matches_reference_exhaustively() {
        let corpus = words(b"ab", 4);
        for left in &corpus {
            for right in &corpus {
                assert_eq!(
                    longest_common_subsequence_len(left, right),
                    reference_lcs(left, right),
                    "left={left:?}, right={right:?}"
                );
            }
        }
    }

    #[test]
    fn bit_parallel_lcs_propagates_across_machine_words() {
        let left: Vec<u8> = (0..150).map(|index| (index % 11) as u8).collect();
        let mut right = left[7..].to_vec();
        right.splice(63..63, [42, 43, 44]);
        right.drain(101..109);
        assert_eq!(
            longest_common_subsequence_len(&left, &right),
            reference_lcs(&left, &right)
        );
    }

    #[test]
    fn conservative_retention_counts_ordered_bytes() {
        assert_eq!(conservative_lcs_retention(b"abcdef", b"aXbcYdef"), 1.0);
        assert_eq!(conservative_lcs_retention(b"abcdef", b"ace"), 0.5);
    }

    #[test]
    fn contiguous_match_is_exact_and_borrowed_from_first_input() {
        let left = b"xxabcdeyy";
        let matched = longest_common_contiguous_slice(left, b"zzabcdeqq");
        assert_eq!(matched, b"abcde");
        assert_eq!(longest_common_contiguous_run(b"abc", b"xyz"), 0);
    }

    #[test]
    fn suffix_automaton_matches_reference_exhaustively() {
        let corpus = words(b"ab", 4);
        for left in &corpus {
            for right in &corpus {
                assert_eq!(
                    longest_common_contiguous_run(left, right),
                    reference_contiguous_run(left, right),
                    "left={left:?}, right={right:?}"
                );
            }
        }
    }

    #[test]
    fn normalized_difference_metrics_handle_alignment_and_insertions() {
        assert_eq!(aligned_byte_difference_ratio(b"abc", b"abc"), 0.0);
        assert_eq!(aligned_byte_difference_ratio(b"abc", b"axc"), 1.0 / 3.0);
        assert_eq!(normalized_levenshtein_distance(b"abc", b"zabc"), 0.25);
        assert_eq!(
            normalized_levenshtein_distance(b"kitten", b"sitting"),
            3.0 / 7.0
        );
    }

    #[test]
    fn ngram_jaccard_uses_sets_not_pooled_occurrence_counts() {
        assert_eq!(ngram_jaccard(b"abcd", b"abcd", 2), 1.0);
        assert_eq!(ngram_jaccard(b"abcd", b"wxyz", 2), 0.0);
        assert_eq!(ngram_jaccard(b"a", b"b", 2), 1.0);
    }

    #[test]
    fn pairwise_helpers_return_one_value_per_unordered_pair() {
        let samples = vec![b"abc".to_vec(), b"axc".to_vec(), b"ayc".to_vec()];
        let edit = pairwise_aligned_byte_differences(&samples);
        assert_eq!(edit.len(), 3);
        assert!(edit.iter().all(|value| *value > 0.0));
        let ngrams = pairwise_ngram_jaccard(&samples, 2);
        assert_eq!(ngrams.len(), 3);
    }

    #[test]
    fn distribution_summary_reports_median_and_bounds() {
        let summary = summarize_distribution(&[0.4, 0.1, 0.3, 0.2]);
        assert_eq!(summary.count, 4);
        assert_eq!(summary.mean, 0.25);
        assert_eq!(summary.median, 0.25);
        assert_eq!(summary.min, 0.1);
        assert_eq!(summary.max, 0.4);
    }
}
