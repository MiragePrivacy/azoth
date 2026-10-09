//! Reproducible, linear-time detection features for red-team evaluation.
//!
//! The detector deliberately reports a heuristic score rather than a probability. A score only
//! measures the presence of motifs implemented here; meaningful detection claims require a
//! labelled, representative negative corpus. [`evaluate_corpus`] computes empirical ranking and
//! operating-point metrics when both labels are present and otherwise limits the report to
//! descriptive statistics.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

/// Version of the feature definitions and scoring weights.
pub const DETECTOR_VERSION: &str = "azoth-linear-signatures-v3";

const MAX_HEURISTIC_SCORE: u32 = 100;
const LOW_FPR_TARGETS: [f64; 3] = [0.01, 0.001, 0.0001];
const REPORT_THRESHOLDS: [u32; 3] = [25, 50, 75];

type FingerprintExtractor = fn(&SignatureFeatures) -> &str;

/// Resource limits for corpus evaluation.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// Maximum number of corpus records accepted in one evaluation.
    pub max_samples: usize,
    /// Maximum decoded bytecode size accepted for one record.
    pub max_bytecode_bytes: usize,
    /// Maximum number of sample identifiers retained for each metadata cluster.
    pub max_cluster_members_in_report: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            max_samples: 100_000,
            max_bytecode_bytes: 64 * 1024,
            max_cluster_members_in_report: 64,
        }
    }
}

/// One bytecode record supplied to the corpus evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusSample {
    /// Stable identifier used in the output report.
    pub id: String,
    /// Hex-encoded deployment or runtime bytecode, with an optional `0x` prefix.
    pub bytecode: String,
    /// Optional ground-truth class (`true` means Azoth-generated).
    #[serde(default)]
    pub label: Option<bool>,
    /// Optional source-family identifier used to measure metadata linkability.
    #[serde(default)]
    pub family: Option<String>,
}

/// Counts and ratios extracted from one bytecode blob.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureFeatures {
    /// Total blob length, including a recognized Solidity metadata suffix.
    pub byte_len: usize,
    /// Bytes decoded as EVM code before a recognized Solidity metadata suffix.
    pub code_len: usize,
    /// Number of decoded EVM instructions.
    pub instruction_count: usize,
    /// Number of truncated PUSH instructions encountered by the decoder.
    pub malformed_pushes: usize,
    /// Count of `JUMPDEST INVALID` sink blocks.
    pub dispatcher_invalid_sinks: usize,
    /// Count of Azoth's constant-false dispatcher decoy sequence.
    pub dispatcher_constant_false_decoys: usize,
    /// Count of high-slot `SLOAD; ISZERO` controller gates.
    pub dispatcher_storage_gates: usize,
    /// Count of selector-byte extraction controller gates.
    pub dispatcher_byte_gates: usize,
    /// Count of `PUSH0; (PUSH; arithmetic-op){2,}` chains.
    pub push_split_chains: usize,
    /// Total arithmetic terms in all detected push-split chains.
    pub push_split_terms: usize,
    /// Count of ArithmeticChain's fixed CODECOPY/MLOAD loading sequence.
    pub arithmetic_codecopy_loads: usize,
    /// Count of adjacent wide constants followed by a foldable arithmetic operation.
    pub wide_constant_chain_starts: usize,
    /// Count of constructor-mask decoder chunks (`DUP1; MLOAD; ...; XOR; SWAP1; MSTORE`).
    ///
    /// Two or more chunks are a strong signature of Azoth's current constructor-argument pass.
    pub constructor_mask_decoder_chunks: usize,
    /// Fraction of dispatcher-associated opcodes in the final instruction quartile.
    pub tail_dispatcher_opcode_density: f64,
    /// Number of instructions used to calculate the tail density.
    pub tail_instruction_count: usize,
    /// Byte length of a plausible terminal Solidity CBOR suffix, including its length word.
    pub metadata_suffix_len: Option<usize>,
    /// Keccak-256 of the exact terminal metadata suffix, useful as a cluster key.
    pub metadata_suffix_keccak256: Option<String>,
    /// Keccak-256 of the ordered opcode stream after metadata and PUSH immediates are removed.
    ///
    /// This deliberately weak normalization models a cheap analyst attack: selector relabelling,
    /// jump-address changes, and suffix-only changes cannot change this fingerprint.
    pub opcode_skeleton_keccak256: String,
    /// Keccak-256 of the opcode-only basic-block multiset.
    ///
    /// Blocks are sorted before hashing, so this also removes pure block-layout shuffling.
    pub block_multiset_keccak256: String,
    /// Ordered opcode fingerprint after constant-folding recognizable PushSplit chains.
    pub folded_opcode_skeleton_keccak256: String,
    /// Block-multiset fingerprint after constant-folding recognizable PushSplit chains.
    pub folded_block_multiset_keccak256: String,
}

/// One piece of evidence contributing to a heuristic score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEvidence {
    /// Stable feature name.
    pub feature: String,
    /// Number of occurrences in this bytecode.
    pub count: usize,
    /// Weight added before the score is capped at 100.
    pub weight: u32,
}

/// Detector output for one bytecode blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorResult {
    /// Feature-definition version.
    pub detector_version: String,
    /// Bounded heuristic score. This is not a calibrated probability.
    pub heuristic_score: u32,
    /// Evidence that contributed to the score.
    pub evidence: Vec<SignatureEvidence>,
    /// Raw extracted features.
    pub features: SignatureFeatures,
}

/// Detector output annotated with corpus ground truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredSample {
    /// Stable input identifier.
    pub id: String,
    /// Optional ground-truth class.
    pub label: Option<bool>,
    /// Optional source-family identifier.
    pub family: Option<String>,
    /// Detector result.
    pub detector: DetectorResult,
}

/// Summary of a score distribution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreDistribution {
    /// Number of observations.
    pub count: usize,
    /// Smallest score.
    pub min: Option<u32>,
    /// Largest score.
    pub max: Option<u32>,
    /// Arithmetic mean.
    pub mean: Option<f64>,
    /// Median, averaging the middle pair for an even count.
    pub median: Option<f64>,
}

/// Feature prevalence split by supplied label.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeaturePrevalence {
    /// Number of all records containing the feature.
    pub all: usize,
    /// Number of labelled-positive records containing the feature.
    pub positive: usize,
    /// Number of labelled-negative records containing the feature.
    pub negative: usize,
    /// Number of unlabelled records containing the feature.
    pub unlabelled: usize,
}

/// Confusion counts and derived rates at one fixed score threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdMetrics {
    /// Samples at or above this score are predicted positive.
    pub threshold: u32,
    /// True positives.
    pub true_positives: usize,
    /// False positives.
    pub false_positives: usize,
    /// True negatives.
    pub true_negatives: usize,
    /// False negatives.
    pub false_negatives: usize,
    /// True-positive rate.
    pub true_positive_rate: f64,
    /// False-positive rate.
    pub false_positive_rate: f64,
    /// Positive predictive value within the supplied corpus.
    pub precision: Option<f64>,
}

/// Best empirical threshold satisfying a requested false-positive-rate ceiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingPoint {
    /// Requested empirical false-positive-rate ceiling.
    pub target_false_positive_rate: f64,
    /// Selected threshold.
    pub threshold: u32,
    /// False-positive rate observed in this corpus.
    pub observed_false_positive_rate: f64,
    /// True-positive rate observed in this corpus.
    pub observed_true_positive_rate: f64,
    /// Number of false positives at the selected threshold.
    pub false_positives: usize,
    /// Number of true positives at the selected threshold.
    pub true_positives: usize,
    /// Whether the negative corpus is large enough for one false positive to resolve the target.
    pub resolution_supported: bool,
    /// One-sided 95% Wilson upper confidence bound for the observed false-positive rate.
    pub false_positive_rate_upper_95: f64,
    /// Whether that upper confidence bound is at or below the requested target.
    pub confidence_supported: bool,
}

/// Repeated normalized fingerprint in the evaluated corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedCluster {
    /// Stable name of the normalization attack.
    pub fingerprint_kind: String,
    /// Keccak-256 cluster key.
    pub fingerprint_keccak256: String,
    /// Exact number of members, including omitted identifiers.
    pub member_count: usize,
    /// Retained member identifiers, bounded by [`DetectorConfig`].
    pub sample_ids: Vec<String>,
    /// Whether identifiers were truncated in the report.
    pub sample_ids_truncated: bool,
    /// Number of distinct supplied families represented by the cluster.
    pub family_count: usize,
    /// Labelled positive members.
    pub positive_members: usize,
    /// Labelled negative members.
    pub negative_members: usize,
    /// Unlabelled members.
    pub unlabelled_members: usize,
}

/// Pairwise linkability of one normalized fingerprint when family labels are supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationLinkabilityMetrics {
    /// Stable name of the normalization attack.
    pub fingerprint_kind: String,
    /// Pairs whose records have the same supplied family.
    pub same_family_pairs: u64,
    /// Same-family pairs sharing the fingerprint.
    pub linked_same_family_pairs: u64,
    /// Fraction of same-family pairs sharing the fingerprint.
    pub same_family_pair_recall: Option<f64>,
    /// Positive/negative pairs that share a supplied family label.
    ///
    /// Unlike all-pairs recall, this directly measures whether an Azoth output links to a
    /// compiler-produced member of the same source family.
    pub cross_label_same_family_pairs: u64,
    /// Cross-label same-family pairs sharing the fingerprint.
    pub linked_cross_label_same_family_pairs: u64,
    /// Fraction of cross-label same-family pairs sharing the fingerprint.
    pub cross_label_same_family_pair_recall: Option<f64>,
    /// Pairs whose records have different supplied families.
    pub different_family_pairs: u64,
    /// Different-family pairs sharing the fingerprint.
    pub linked_different_family_pairs: u64,
    /// Fraction of different-family pairs sharing the fingerprint.
    pub different_family_pair_collision_rate: Option<f64>,
}

/// Label-dependent detector quality metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryClassificationMetrics {
    /// Number of labelled positives.
    pub positive_count: usize,
    /// Number of labelled negatives.
    pub negative_count: usize,
    /// Area under the ROC curve with ties receiving half credit.
    pub auroc: f64,
    /// Tie-invariant threshold-sweep average precision.
    pub average_precision: f64,
    /// Confusion metrics at stable report thresholds.
    pub thresholds: Vec<ThresholdMetrics>,
    /// Best empirical points under several low-FPR ceilings.
    pub low_fpr_operating_points: Vec<OperatingPoint>,
}

/// Repeated exact metadata suffix in the evaluated corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataCluster {
    /// Keccak-256 cluster key.
    pub suffix_keccak256: String,
    /// Exact number of members, including omitted identifiers.
    pub member_count: usize,
    /// Retained member identifiers, bounded by [`DetectorConfig`].
    pub sample_ids: Vec<String>,
    /// Whether identifiers were truncated in the report.
    pub sample_ids_truncated: bool,
    /// Labelled positive members.
    pub positive_members: usize,
    /// Labelled negative members.
    pub negative_members: usize,
    /// Unlabelled members.
    pub unlabelled_members: usize,
}

/// Pairwise metadata linkage metrics when source-family labels are supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataLinkabilityMetrics {
    /// Pairs whose records have the same supplied family.
    pub same_family_pairs: u64,
    /// Same-family pairs sharing an exact metadata suffix.
    pub linked_same_family_pairs: u64,
    /// Fraction of same-family pairs sharing an exact metadata suffix.
    pub same_family_pair_recall: Option<f64>,
    /// Pairs whose records have different supplied families.
    pub different_family_pairs: u64,
    /// Different-family pairs sharing an exact metadata suffix.
    pub linked_different_family_pairs: u64,
    /// Fraction of different-family pairs sharing an exact metadata suffix.
    pub different_family_pair_collision_rate: Option<f64>,
}

/// Full result of corpus scoring and optional labelled evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusReport {
    /// Feature-definition version.
    pub detector_version: String,
    /// Number of evaluated samples.
    pub sample_count: usize,
    /// Score distribution across all records.
    pub all_scores: ScoreDistribution,
    /// Score distribution for labelled positives.
    pub positive_scores: ScoreDistribution,
    /// Score distribution for labelled negatives.
    pub negative_scores: ScoreDistribution,
    /// Presence counts for every exposed feature.
    pub feature_prevalence: BTreeMap<String, FeaturePrevalence>,
    /// Per-record detector results.
    pub samples: Vec<ScoredSample>,
    /// Label-dependent metrics, absent unless both classes are supplied.
    pub binary_classification: Option<BinaryClassificationMetrics>,
    /// Exact metadata suffix clusters containing at least two records.
    pub metadata_clusters: Vec<MetadataCluster>,
    /// Pairwise linkage metrics, absent when fewer than two family labels are supplied.
    pub metadata_linkability: Option<MetadataLinkabilityMetrics>,
    /// Repeated fingerprints exposed by cheap normalization attacks.
    pub normalized_clusters: Vec<NormalizedCluster>,
    /// Pairwise source-family linkability for each normalization attack.
    pub normalization_linkability: Vec<NormalizationLinkabilityMetrics>,
    /// Limitations or data-quality conditions relevant to interpretation.
    pub warnings: Vec<String>,
}

/// Corpus decoding or resource-limit error.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Too many records were supplied.
    #[error("corpus has {actual} records; configured maximum is {maximum}")]
    TooManySamples {
        /// Actual record count.
        actual: usize,
        /// Configured limit.
        maximum: usize,
    },
    /// Two records used the same stable identifier and would be double-counted.
    #[error("corpus contains duplicate sample id `{sample_id}`")]
    DuplicateSampleId {
        /// Repeated identifier.
        sample_id: String,
    },
    /// A decoded bytecode blob would exceed the configured limit.
    #[error(
        "sample `{sample_id}` is approximately {actual} bytes; configured maximum is {maximum}"
    )]
    BytecodeTooLarge {
        /// Sample identifier.
        sample_id: String,
        /// Approximate or actual decoded size.
        actual: usize,
        /// Configured limit.
        maximum: usize,
    },
    /// Hexadecimal bytecode was malformed.
    #[error("sample `{sample_id}` has invalid bytecode hex: {source}")]
    InvalidHex {
        /// Sample identifier.
        sample_id: String,
        /// Decoder error.
        #[source]
        source: hex::FromHexError,
    },
}

#[derive(Debug, Clone)]
struct Instruction {
    opcode: u8,
    immediate: Vec<u8>,
    declared_push_width: usize,
    truncated: bool,
}

impl Instruction {
    fn is_push(&self) -> bool {
        self.opcode == 0x5f || (0x60..=0x7f).contains(&self.opcode)
    }

    fn push_width(&self) -> Option<usize> {
        self.is_push().then_some(self.declared_push_width)
    }

    fn push_value_u64(&self) -> Option<u64> {
        if !self.is_push() || self.truncated || self.immediate.len() > 8 {
            return None;
        }
        Some(
            self.immediate
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
        )
    }

    fn push_value_u128(&self) -> Option<u128> {
        if !self.is_push() || self.truncated || self.immediate.len() > 16 {
            return None;
        }
        Some(
            self.immediate
                .iter()
                .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)),
        )
    }
}

/// Extract features from raw EVM bytecode in time linear in the blob length.
#[must_use]
pub fn extract_signature_features(bytecode: &[u8]) -> SignatureFeatures {
    let metadata = metadata_suffix(bytecode);
    let code_len = metadata
        .as_ref()
        .map_or(bytecode.len(), |value| value.start);
    let instructions = decode_instructions(&bytecode[..code_len]);
    let malformed_pushes = instructions.iter().filter(|value| value.truncated).count();
    let raw_opcode_tokens = opcode_tokens(&instructions, false);
    let folded_opcode_tokens = opcode_tokens(&instructions, true);

    let dispatcher_invalid_sinks = instructions
        .windows(2)
        .filter(|window| window[0].opcode == 0x5b && window[1].opcode == 0xfe)
        .count();
    let dispatcher_constant_false_decoys = instructions
        .windows(8)
        .filter(|window| is_constant_false_decoy(window))
        .count();
    let dispatcher_storage_gates = instructions
        .windows(7)
        .filter(|window| is_storage_gate(window))
        .count();
    let dispatcher_byte_gates = instructions
        .windows(10)
        .filter(|window| is_byte_gate(window))
        .count();
    let (push_split_chains, push_split_terms) = count_push_split_chains(&instructions);
    let arithmetic_codecopy_loads = instructions
        .windows(6)
        .filter(|window| is_arithmetic_codecopy_load(window))
        .count();
    let wide_constant_chain_starts = instructions
        .windows(3)
        .filter(|window| {
            window[0].push_width().is_some_and(|width| width >= 16)
                && window[1].push_width().is_some_and(|width| width >= 16)
                && is_foldable_arithmetic(window[2].opcode)
        })
        .count();
    let constructor_mask_decoder_chunks = count_constructor_mask_decoder_chunks(&instructions);
    let tail_instruction_count = instructions.len().div_ceil(4);
    let tail_dispatcher_opcode_density = if tail_instruction_count == 0 {
        0.0
    } else {
        let dispatcher_opcodes = instructions[instructions.len() - tail_instruction_count..]
            .iter()
            .filter(|instruction| is_dispatcher_associated_opcode(instruction.opcode))
            .count();
        dispatcher_opcodes as f64 / tail_instruction_count as f64
    };

    SignatureFeatures {
        byte_len: bytecode.len(),
        code_len,
        instruction_count: instructions.len(),
        malformed_pushes,
        dispatcher_invalid_sinks,
        dispatcher_constant_false_decoys,
        dispatcher_storage_gates,
        dispatcher_byte_gates,
        push_split_chains,
        push_split_terms,
        arithmetic_codecopy_loads,
        wide_constant_chain_starts,
        constructor_mask_decoder_chunks,
        tail_dispatcher_opcode_density,
        tail_instruction_count,
        metadata_suffix_len: metadata.as_ref().map(|value| bytecode.len() - value.start),
        metadata_suffix_keccak256: metadata.map(|value| value.keccak256),
        opcode_skeleton_keccak256: hash_tokens(b"ordered-opcodes-v1", &raw_opcode_tokens),
        block_multiset_keccak256: hash_block_multiset(&raw_opcode_tokens),
        folded_opcode_skeleton_keccak256: hash_tokens(
            b"ordered-opcodes-push-split-fold-v1",
            &folded_opcode_tokens,
        ),
        folded_block_multiset_keccak256: hash_block_multiset(&folded_opcode_tokens),
    }
}

/// Score raw EVM bytecode using the versioned, bounded heuristic.
#[must_use]
pub fn score_bytecode(bytecode: &[u8]) -> DetectorResult {
    score_features(extract_signature_features(bytecode))
}

/// Decode and score a hexadecimal EVM bytecode string.
pub fn score_hex(bytecode: &str) -> Result<DetectorResult, DetectorError> {
    let decoded = decode_hex("<input>", bytecode, usize::MAX)?;
    Ok(score_bytecode(&decoded))
}

/// Evaluate a corpus using [`DetectorConfig::default`].
pub fn evaluate_corpus(samples: &[CorpusSample]) -> Result<CorpusReport, DetectorError> {
    evaluate_corpus_with_config(samples, &DetectorConfig::default())
}

/// Evaluate a corpus with explicit resource limits.
pub fn evaluate_corpus_with_config(
    samples: &[CorpusSample],
    config: &DetectorConfig,
) -> Result<CorpusReport, DetectorError> {
    if samples.len() > config.max_samples {
        return Err(DetectorError::TooManySamples {
            actual: samples.len(),
            maximum: config.max_samples,
        });
    }

    let mut sample_ids = HashSet::with_capacity(samples.len());
    let mut scored = Vec::with_capacity(samples.len());
    for sample in samples {
        if !sample_ids.insert(sample.id.as_str()) {
            return Err(DetectorError::DuplicateSampleId {
                sample_id: sample.id.clone(),
            });
        }
        let decoded = decode_hex(&sample.id, &sample.bytecode, config.max_bytecode_bytes)?;
        scored.push(ScoredSample {
            id: sample.id.clone(),
            label: sample.label,
            family: sample.family.clone(),
            detector: score_bytecode(&decoded),
        });
    }

    let all_scores: Vec<_> = scored
        .iter()
        .map(|sample| sample.detector.heuristic_score)
        .collect();
    let positive_scores: Vec<_> = scored
        .iter()
        .filter(|sample| sample.label == Some(true))
        .map(|sample| sample.detector.heuristic_score)
        .collect();
    let negative_scores: Vec<_> = scored
        .iter()
        .filter(|sample| sample.label == Some(false))
        .map(|sample| sample.detector.heuristic_score)
        .collect();

    let mut warnings = Vec::new();
    let labelled_count = positive_scores.len() + negative_scores.len();
    if labelled_count == 0 {
        warnings.push(
            "No labels supplied: report contains descriptive features only; detection quality cannot be inferred."
                .to_string(),
        );
    } else if positive_scores.is_empty() || negative_scores.is_empty() {
        warnings.push(
            "Only one labelled class supplied: AUROC, average precision, and FPR metrics are undefined."
                .to_string(),
        );
    }
    if labelled_count != scored.len() && labelled_count != 0 {
        warnings.push(format!(
            "{} of {} samples are labelled; classification metrics exclude unlabelled records.",
            labelled_count,
            scored.len()
        ));
    }

    let binary_classification = if positive_scores.is_empty() || negative_scores.is_empty() {
        None
    } else {
        let labelled: Vec<_> = scored
            .iter()
            .filter_map(|sample| {
                sample
                    .label
                    .map(|label| (sample.detector.heuristic_score, label))
            })
            .collect();
        Some(compute_binary_metrics(&labelled))
    };
    if let Some(metrics) = &binary_classification {
        warnings.push(
            "Operating points are selected and evaluated on the same supplied corpus; treat them as exploratory in-sample measurements, not out-of-sample performance."
                .to_string(),
        );
        for point in &metrics.low_fpr_operating_points {
            if !point.resolution_supported {
                warnings.push(format!(
                    "FPR target {:.4}% is below the empirical resolution of {} negatives.",
                    point.target_false_positive_rate * 100.0,
                    metrics.negative_count
                ));
            }
            if !point.confidence_supported {
                warnings.push(format!(
                    "At the {:.4}% FPR target, the one-sided 95% Wilson upper bound is {:.4}% ({} negatives, {} observed false positives); this corpus cannot support the target with 95% confidence.",
                    point.target_false_positive_rate * 100.0,
                    point.false_positive_rate_upper_95 * 100.0,
                    metrics.negative_count,
                    point.false_positives,
                ));
            }
        }
    }

    let labelled_families = scored
        .iter()
        .filter(|sample| sample.label.is_some())
        .filter_map(|sample| sample.family.as_deref())
        .collect::<Vec<_>>();
    let distinct_labelled_families = labelled_families
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len();
    if labelled_families.len() > distinct_labelled_families {
        warnings.push(format!(
            "The {} labelled records contain only {} distinct family labels. Sample-level AUROC/AP treat variants as separate observations and can overstate evidence when variants share source code.",
            labelled_families.len(),
            distinct_labelled_families,
        ));
    }

    let metadata_clusters = metadata_clusters(&scored, config.max_cluster_members_in_report);
    if metadata_clusters
        .iter()
        .any(|cluster| cluster.sample_ids_truncated)
    {
        warnings.push(format!(
            "Metadata cluster member identifiers are capped at {} per cluster.",
            config.max_cluster_members_in_report
        ));
    }

    let normalization_specs: [(&str, FingerprintExtractor); 4] = [
        ("opcode_skeleton", |features| {
            &features.opcode_skeleton_keccak256
        }),
        ("block_multiset", |features| {
            &features.block_multiset_keccak256
        }),
        ("push_split_folded_opcode_skeleton", |features| {
            &features.folded_opcode_skeleton_keccak256
        }),
        ("push_split_folded_block_multiset", |features| {
            &features.folded_block_multiset_keccak256
        }),
    ];
    let normalized_clusters: Vec<NormalizedCluster> = normalization_specs
        .iter()
        .flat_map(|(kind, fingerprint)| {
            normalized_clusters(
                &scored,
                kind,
                *fingerprint,
                config.max_cluster_members_in_report,
            )
        })
        .collect();
    if normalized_clusters
        .iter()
        .any(|cluster| cluster.sample_ids_truncated)
    {
        warnings.push(format!(
            "Normalized cluster member identifiers are capped at {} per cluster.",
            config.max_cluster_members_in_report
        ));
    }
    let normalization_linkability = normalization_specs
        .iter()
        .filter_map(|(kind, fingerprint)| normalization_linkability(&scored, kind, *fingerprint))
        .collect();

    Ok(CorpusReport {
        detector_version: DETECTOR_VERSION.to_string(),
        sample_count: scored.len(),
        all_scores: score_distribution(&all_scores),
        positive_scores: score_distribution(&positive_scores),
        negative_scores: score_distribution(&negative_scores),
        feature_prevalence: feature_prevalence(&scored),
        binary_classification,
        metadata_clusters,
        metadata_linkability: metadata_linkability(&scored),
        normalized_clusters,
        normalization_linkability,
        samples: scored,
        warnings,
    })
}

fn decode_hex(sample_id: &str, bytecode: &str, maximum: usize) -> Result<Vec<u8>, DetectorError> {
    let trimmed = bytecode.trim();
    let value = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let approximate_len = value.len().div_ceil(2);
    if approximate_len > maximum {
        return Err(DetectorError::BytecodeTooLarge {
            sample_id: sample_id.to_string(),
            actual: approximate_len,
            maximum,
        });
    }
    hex::decode(value).map_err(|source| DetectorError::InvalidHex {
        sample_id: sample_id.to_string(),
        source,
    })
}

fn decode_instructions(bytecode: &[u8]) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut pc = 0usize;
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        let width = if (0x60..=0x7f).contains(&opcode) {
            usize::from(opcode - 0x5f)
        } else {
            0
        };
        let available = bytecode.len().saturating_sub(pc + 1).min(width);
        instructions.push(Instruction {
            opcode,
            immediate: bytecode[pc + 1..pc + 1 + available].to_vec(),
            declared_push_width: width,
            truncated: available != width,
        });
        pc = pc.saturating_add(1 + width).min(bytecode.len());
    }
    instructions
}

fn opcode_tokens(instructions: &[Instruction], fold_push_split: bool) -> Vec<u8> {
    let mut tokens = Vec::with_capacity(instructions.len());
    let mut index = 0usize;
    while index < instructions.len() {
        if fold_push_split && instructions[index].opcode == 0x5f {
            let mut cursor = index + 1;
            let mut terms = 0usize;
            let mut accumulator = 0u128;
            while cursor + 1 < instructions.len() {
                let part = &instructions[cursor];
                let operation = instructions[cursor + 1].opcode;
                if !part
                    .push_width()
                    .is_some_and(|width| (1..=16).contains(&width))
                    || !matches!(operation, 0x01 | 0x03 | 0x18)
                {
                    break;
                }
                let Some(value) = part.push_value_u128() else {
                    break;
                };
                accumulator = match operation {
                    0x01 => accumulator.wrapping_add(value),
                    0x03 => accumulator.wrapping_sub(value),
                    0x18 => accumulator ^ value,
                    _ => unreachable!("operation was checked above"),
                };
                terms += 1;
                cursor += 2;
            }
            if terms >= 2 {
                let width = if accumulator == 0 {
                    0
                } else {
                    usize::try_from((128 - accumulator.leading_zeros()).div_ceil(8)).unwrap_or(16)
                };
                tokens.push(0x5f + u8::try_from(width).unwrap_or(16));
                index = cursor;
                continue;
            }
        }
        tokens.push(instructions[index].opcode);
        index += 1;
    }
    tokens
}

fn hash_tokens(domain: &[u8], tokens: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(domain);
    hasher.update((tokens.len() as u64).to_be_bytes());
    hasher.update(tokens);
    hex::encode(hasher.finalize())
}

fn hash_block_multiset(tokens: &[u8]) -> String {
    let mut blocks = Vec::<Vec<u8>>::new();
    let mut current = Vec::new();
    for opcode in tokens.iter().copied() {
        if opcode == 0x5b && !current.is_empty() {
            blocks.push(std::mem::take(&mut current));
        }
        current.push(opcode);
        if is_basic_block_terminator(opcode) {
            blocks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks.sort_unstable();

    let mut hasher = Keccak256::new();
    hasher.update(b"opcode-block-multiset-v1");
    hasher.update((blocks.len() as u64).to_be_bytes());
    for block in blocks {
        hasher.update((block.len() as u64).to_be_bytes());
        hasher.update(block);
    }
    hex::encode(hasher.finalize())
}

fn is_basic_block_terminator(opcode: u8) -> bool {
    matches!(opcode, 0x00 | 0x56 | 0x57 | 0xf3 | 0xfd..=0xff)
}

fn is_constant_false_decoy(window: &[Instruction]) -> bool {
    window[0].opcode == 0x5b
        && push_is(&window[1], 1, 1)
        && push_is(&window[2], 1, 0)
        && window[3].opcode == 0x14
        && window[4].is_push()
        && window[5].opcode == 0x57
        && window[6].is_push()
        && window[7].opcode == 0x56
}

fn is_storage_gate(window: &[Instruction]) -> bool {
    window[0]
        .push_value_u64()
        .is_some_and(|slot| (0x1000..=0xffff).contains(&slot))
        && window[1].opcode == 0x54
        && window[2].opcode == 0x15
        && window[3].is_push()
        && window[4].opcode == 0x57
        && window[5].is_push()
        && window[6].opcode == 0x56
}

fn is_byte_gate(window: &[Instruction]) -> bool {
    push_is(&window[0], 1, 0)
        && window[1].opcode == 0x35
        && window[2].push_width() == Some(1)
        && window[2].push_value_u64().is_some_and(|value| value <= 3)
        && window[3].opcode == 0x1a
        && window[4].push_width() == Some(1)
        && window[5].opcode == 0x14
        && window[6].is_push()
        && window[7].opcode == 0x57
        && window[8].is_push()
        && window[9].opcode == 0x56
}

fn is_arithmetic_codecopy_load(window: &[Instruction]) -> bool {
    push_is(&window[0], 1, 0x20)
        && window[1]
            .push_width()
            .is_some_and(|width| (1..=4).contains(&width))
        && push_is(&window[2], 1, 0)
        && window[3].opcode == 0x39
        && push_is(&window[4], 1, 0)
        && window[5].opcode == 0x51
}

fn count_constructor_mask_decoder_chunks(instructions: &[Instruction]) -> usize {
    let mut chunks = 0usize;
    let mut index = 0usize;
    while index + 1 < instructions.len() {
        if instructions[index].opcode != 0x80 || instructions[index + 1].opcode != 0x51 {
            index += 1;
            continue;
        }

        // ArithmeticChain's inline mask material consists of at least two PUSH32 values and up
        // to three arithmetic operations. Bound the scan so ordinary, distant memory writes do
        // not become evidence for the constructor pass.
        let search_end = (index + 14).min(instructions.len());
        let mut cursor = index + 2;
        let mut push32_count = 0usize;
        let mut found_end = None;
        while cursor < search_end {
            push32_count += usize::from(instructions[cursor].opcode == 0x7f);
            if cursor + 2 < search_end
                && instructions[cursor].opcode == 0x18
                && instructions[cursor + 1].opcode == 0x90
                && instructions[cursor + 2].opcode == 0x52
                && push32_count >= 2
            {
                found_end = Some(cursor + 3);
                break;
            }
            cursor += 1;
        }
        if let Some(end) = found_end {
            chunks += 1;
            index = end;
        } else {
            index += 1;
        }
    }
    chunks
}

fn count_push_split_chains(instructions: &[Instruction]) -> (usize, usize) {
    let mut chains = 0usize;
    let mut terms = 0usize;
    let mut index = 0usize;
    while index < instructions.len() {
        if instructions[index].opcode != 0x5f {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        let mut chain_terms = 0usize;
        while cursor + 1 < instructions.len()
            && instructions[cursor]
                .push_width()
                .is_some_and(|width| (1..=16).contains(&width))
            && matches!(instructions[cursor + 1].opcode, 0x01 | 0x03 | 0x18)
        {
            chain_terms += 1;
            cursor += 2;
        }
        if chain_terms >= 2 {
            chains += 1;
            terms += chain_terms;
            index = cursor;
        } else {
            index += 1;
        }
    }
    (chains, terms)
}

fn push_is(instruction: &Instruction, width: usize, value: u64) -> bool {
    instruction.push_width() == Some(width) && instruction.push_value_u64() == Some(value)
}

fn is_foldable_arithmetic(opcode: u8) -> bool {
    matches!(opcode, 0x01..=0x07 | 0x10..=0x1d)
}

fn is_dispatcher_associated_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x14 | 0x15 | 0x1a | 0x35 | 0x54 | 0x56 | 0x57 | 0x5b | 0xfe
    )
}

#[derive(Debug)]
struct MetadataSuffix {
    start: usize,
    keccak256: String,
}

fn metadata_suffix(bytecode: &[u8]) -> Option<MetadataSuffix> {
    if bytecode.len() < 3 {
        return None;
    }
    let metadata_len = usize::from(u16::from_be_bytes([
        bytecode[bytecode.len() - 2],
        bytecode[bytecode.len() - 1],
    ]));
    let suffix_len = metadata_len.checked_add(2)?;
    let start = bytecode.len().checked_sub(suffix_len)?;
    let payload = bytecode.get(start..bytecode.len() - 2)?;
    if !is_structurally_valid_compiler_cbor(payload)
        || !is_evm_instruction_boundary(bytecode, start)
    {
        return None;
    }
    let digest = Keccak256::digest(&bytecode[start..]);
    Some(MetadataSuffix {
        start,
        keccak256: hex::encode(digest),
    })
}

/// Solidity compiler auxdata is a complete definite-length CBOR map containing at least one
/// compiler metadata key. A map prefix alone is insufficient: arbitrary executable tail bytes can
/// otherwise be mistaken for metadata and removed from every normalization fingerprint.
fn is_structurally_valid_compiler_cbor(payload: &[u8]) -> bool {
    let mut cursor = 0usize;
    let initial = match payload.get(cursor) {
        Some(initial) if initial >> 5 == 5 => *initial,
        _ => return false,
    };
    cursor += 1;
    let Some(pair_count) = consume_cbor_argument(payload, &mut cursor, initial & 0x1f)
        .and_then(|count| usize::try_from(count).ok())
    else {
        return false;
    };
    if pair_count > payload.len().saturating_sub(cursor) / 2 {
        return false;
    }

    let mut has_compiler_key = false;
    for _ in 0..pair_count {
        let Some(key_initial) = payload.get(cursor).copied() else {
            return false;
        };
        if key_initial >> 5 != 3 {
            return false;
        }
        cursor += 1;
        let Some(key_len) = consume_cbor_argument(payload, &mut cursor, key_initial & 0x1f)
            .and_then(|length| usize::try_from(length).ok())
        else {
            return false;
        };
        let Some(key_end) = cursor.checked_add(key_len) else {
            return false;
        };
        let Some(key) = payload.get(cursor..key_end) else {
            return false;
        };
        has_compiler_key |= key == b"ipfs"
            || key == b"solc"
            || key == b"bzzr0"
            || key == b"bzzr1"
            || key == b"vyper";
        cursor = key_end;
        if consume_cbor_item(payload, &mut cursor, 1).is_none() {
            return false;
        }
    }

    has_compiler_key && cursor == payload.len()
}

fn consume_cbor_item(bytes: &[u8], cursor: &mut usize, depth: usize) -> Option<()> {
    const MAX_CBOR_DEPTH: usize = 32;
    if depth >= MAX_CBOR_DEPTH {
        return None;
    }

    let initial = *bytes.get(*cursor)?;
    *cursor += 1;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let argument = consume_cbor_argument(bytes, cursor, additional)?;

    match major {
        0 | 1 | 7 => Some(()),
        2 | 3 => {
            let length = usize::try_from(argument).ok()?;
            let end = cursor.checked_add(length)?;
            if end > bytes.len() {
                return None;
            }
            *cursor = end;
            Some(())
        }
        4 => {
            let items = usize::try_from(argument).ok()?;
            if items > bytes.len().saturating_sub(*cursor) {
                return None;
            }
            for _ in 0..items {
                consume_cbor_item(bytes, cursor, depth + 1)?;
            }
            Some(())
        }
        5 => {
            let pairs = usize::try_from(argument).ok()?;
            let items = pairs.checked_mul(2)?;
            if items > bytes.len().saturating_sub(*cursor) {
                return None;
            }
            for _ in 0..items {
                consume_cbor_item(bytes, cursor, depth + 1)?;
            }
            Some(())
        }
        6 => consume_cbor_item(bytes, cursor, depth + 1),
        _ => None,
    }
}

fn consume_cbor_argument(bytes: &[u8], cursor: &mut usize, additional: u8) -> Option<u64> {
    let width = match additional {
        0..=23 => return Some(u64::from(additional)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = cursor.checked_add(width)?;
    let encoded = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(
        encoded
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn is_evm_instruction_boundary(bytecode: &[u8], boundary: usize) -> bool {
    if boundary > bytecode.len() {
        return false;
    }

    let mut pc = 0usize;
    while pc < boundary {
        let immediate_width = match bytecode[pc] {
            opcode @ 0x60..=0x7f => usize::from(opcode - 0x5f),
            _ => 0,
        };
        let Some(next_pc) = pc.checked_add(1 + immediate_width) else {
            return false;
        };
        if next_pc > boundary {
            return false;
        }
        pc = next_pc;
    }
    pc == boundary
}

fn score_features(features: SignatureFeatures) -> DetectorResult {
    let mut evidence = Vec::new();
    add_evidence(
        &mut evidence,
        "dispatcher_constant_false_decoy",
        features.dispatcher_constant_false_decoys,
        30,
    );
    add_evidence(
        &mut evidence,
        "dispatcher_storage_gate",
        features.dispatcher_storage_gates,
        25,
    );
    add_evidence(
        &mut evidence,
        "dispatcher_byte_gate",
        features.dispatcher_byte_gates,
        25,
    );
    add_evidence(
        &mut evidence,
        "push_split_chain",
        features.push_split_chains,
        30,
    );
    add_evidence(
        &mut evidence,
        "arithmetic_codecopy_load",
        features.arithmetic_codecopy_loads,
        30,
    );
    add_evidence(
        &mut evidence,
        "wide_constant_chain_start",
        features.wide_constant_chain_starts,
        15,
    );
    if features.constructor_mask_decoder_chunks >= 2 {
        add_evidence(
            &mut evidence,
            "constructor_mask_decoder_chunks",
            features.constructor_mask_decoder_chunks,
            40,
        );
    }

    let has_dispatcher_core = features.dispatcher_constant_false_decoys > 0
        || features.dispatcher_storage_gates > 0
        || features.dispatcher_byte_gates > 0;
    if has_dispatcher_core {
        add_evidence(
            &mut evidence,
            "dispatcher_invalid_sink_context",
            features.dispatcher_invalid_sinks,
            10,
        );
        if features.tail_instruction_count >= 8 && features.tail_dispatcher_opcode_density >= 0.45 {
            add_evidence(&mut evidence, "dense_dispatcher_tail_context", 1, 10);
        }
    }

    let raw_score: u32 = evidence.iter().map(|item| item.weight).sum();
    DetectorResult {
        detector_version: DETECTOR_VERSION.to_string(),
        heuristic_score: raw_score.min(MAX_HEURISTIC_SCORE),
        evidence,
        features,
    }
}

fn add_evidence(
    evidence: &mut Vec<SignatureEvidence>,
    feature: &'static str,
    count: usize,
    weight: u32,
) {
    if count > 0 {
        evidence.push(SignatureEvidence {
            feature: feature.to_string(),
            count,
            weight,
        });
    }
}

fn score_distribution(scores: &[u32]) -> ScoreDistribution {
    if scores.is_empty() {
        return ScoreDistribution::default();
    }
    let mut sorted = scores.to_vec();
    sorted.sort_unstable();
    let count = sorted.len();
    let median = if count.is_multiple_of(2) {
        (f64::from(sorted[count / 2 - 1]) + f64::from(sorted[count / 2])) / 2.0
    } else {
        f64::from(sorted[count / 2])
    };
    ScoreDistribution {
        count,
        min: sorted.first().copied(),
        max: sorted.last().copied(),
        mean: Some(sorted.iter().map(|value| f64::from(*value)).sum::<f64>() / count as f64),
        median: Some(median),
    }
}

fn feature_prevalence(samples: &[ScoredSample]) -> BTreeMap<String, FeaturePrevalence> {
    let mut prevalence = BTreeMap::new();
    for sample in samples {
        let features = &sample.detector.features;
        let present = [
            (
                "dispatcher_invalid_sink",
                features.dispatcher_invalid_sinks > 0,
            ),
            (
                "dispatcher_constant_false_decoy",
                features.dispatcher_constant_false_decoys > 0,
            ),
            (
                "dispatcher_storage_gate",
                features.dispatcher_storage_gates > 0,
            ),
            ("dispatcher_byte_gate", features.dispatcher_byte_gates > 0),
            ("push_split_chain", features.push_split_chains > 0),
            (
                "arithmetic_codecopy_load",
                features.arithmetic_codecopy_loads > 0,
            ),
            (
                "wide_constant_chain_start",
                features.wide_constant_chain_starts > 0,
            ),
            (
                "constructor_mask_decoder_chunks",
                features.constructor_mask_decoder_chunks >= 2,
            ),
            (
                "dense_dispatcher_tail",
                features.tail_instruction_count >= 8
                    && features.tail_dispatcher_opcode_density >= 0.45,
            ),
            (
                "terminal_solidity_metadata_candidate",
                features.metadata_suffix_keccak256.is_some(),
            ),
            ("malformed_push", features.malformed_pushes > 0),
        ];
        for (name, is_present) in present {
            let entry = prevalence
                .entry(name.to_string())
                .or_insert_with(FeaturePrevalence::default);
            if is_present {
                entry.all += 1;
                match sample.label {
                    Some(true) => entry.positive += 1,
                    Some(false) => entry.negative += 1,
                    None => entry.unlabelled += 1,
                }
            }
        }
    }
    prevalence
}

fn compute_binary_metrics(labelled: &[(u32, bool)]) -> BinaryClassificationMetrics {
    let positive_count = labelled.iter().filter(|(_, label)| *label).count();
    let negative_count = labelled.len() - positive_count;
    BinaryClassificationMetrics {
        positive_count,
        negative_count,
        auroc: auroc(labelled, positive_count, negative_count),
        average_precision: average_precision(labelled, positive_count),
        thresholds: REPORT_THRESHOLDS
            .into_iter()
            .map(|threshold| threshold_metrics(labelled, threshold))
            .collect(),
        low_fpr_operating_points: LOW_FPR_TARGETS
            .into_iter()
            .map(|target| operating_point(labelled, target, negative_count))
            .collect(),
    }
}

fn auroc(labelled: &[(u32, bool)], positive_count: usize, negative_count: usize) -> f64 {
    let mut sorted = labelled.to_vec();
    sorted.sort_unstable_by_key(|(score, _)| *score);
    let mut index = 0usize;
    let mut negatives_below = 0usize;
    let mut winning_pairs = 0.0f64;
    while index < sorted.len() {
        let score = sorted[index].0;
        let mut end = index;
        let mut group_positives = 0usize;
        let mut group_negatives = 0usize;
        while end < sorted.len() && sorted[end].0 == score {
            if sorted[end].1 {
                group_positives += 1;
            } else {
                group_negatives += 1;
            }
            end += 1;
        }
        winning_pairs += group_positives as f64 * negatives_below as f64;
        winning_pairs += group_positives as f64 * group_negatives as f64 * 0.5;
        negatives_below += group_negatives;
        index = end;
    }
    winning_pairs / (positive_count as f64 * negative_count as f64)
}

fn average_precision(labelled: &[(u32, bool)], positive_count: usize) -> f64 {
    let mut sorted = labelled.to_vec();
    sorted.sort_unstable_by_key(|item| Reverse(item.0));
    let mut index = 0usize;
    let mut seen = 0usize;
    let mut true_positives = 0usize;
    let mut area = 0.0f64;
    while index < sorted.len() {
        let score = sorted[index].0;
        let mut end = index;
        let mut group_positives = 0usize;
        while end < sorted.len() && sorted[end].0 == score {
            group_positives += usize::from(sorted[end].1);
            end += 1;
        }
        seen += end - index;
        true_positives += group_positives;
        let recall_delta = group_positives as f64 / positive_count as f64;
        let precision = true_positives as f64 / seen as f64;
        area += recall_delta * precision;
        index = end;
    }
    area
}

fn threshold_metrics(labelled: &[(u32, bool)], threshold: u32) -> ThresholdMetrics {
    let mut true_positives = 0usize;
    let mut false_positives = 0usize;
    let mut true_negatives = 0usize;
    let mut false_negatives = 0usize;
    for (score, label) in labelled {
        match (*score >= threshold, *label) {
            (true, true) => true_positives += 1,
            (true, false) => false_positives += 1,
            (false, true) => false_negatives += 1,
            (false, false) => true_negatives += 1,
        }
    }
    let positives = true_positives + false_negatives;
    let negatives = false_positives + true_negatives;
    let predicted_positives = true_positives + false_positives;
    ThresholdMetrics {
        threshold,
        true_positives,
        false_positives,
        true_negatives,
        false_negatives,
        true_positive_rate: true_positives as f64 / positives as f64,
        false_positive_rate: false_positives as f64 / negatives as f64,
        precision: (predicted_positives > 0)
            .then_some(true_positives as f64 / predicted_positives as f64),
    }
}

fn operating_point(labelled: &[(u32, bool)], target: f64, negative_count: usize) -> OperatingPoint {
    let mut thresholds: Vec<_> = labelled.iter().map(|(score, _)| *score).collect();
    thresholds.push(MAX_HEURISTIC_SCORE + 1);
    thresholds.sort_unstable();
    thresholds.dedup();
    let mut best = threshold_metrics(labelled, MAX_HEURISTIC_SCORE + 1);
    for metrics in thresholds
        .into_iter()
        .map(|threshold| threshold_metrics(labelled, threshold))
        .filter(|metrics| metrics.false_positive_rate <= target)
    {
        let better_tpr = metrics.true_positive_rate > best.true_positive_rate;
        let equal_tpr = metrics.true_positive_rate == best.true_positive_rate;
        let lower_fpr = metrics.false_positive_rate < best.false_positive_rate;
        let equal_fpr = metrics.false_positive_rate == best.false_positive_rate;
        if better_tpr
            || (equal_tpr && lower_fpr)
            || (equal_tpr && equal_fpr && metrics.threshold > best.threshold)
        {
            best = metrics;
        }
    }
    let false_positive_rate_upper_95 = wilson_upper_bound_95(best.false_positives, negative_count);
    OperatingPoint {
        target_false_positive_rate: target,
        threshold: best.threshold,
        observed_false_positive_rate: best.false_positive_rate,
        observed_true_positive_rate: best.true_positive_rate,
        false_positives: best.false_positives,
        true_positives: best.true_positives,
        resolution_supported: (negative_count as f64) >= 1.0 / target,
        false_positive_rate_upper_95,
        confidence_supported: false_positive_rate_upper_95 <= target,
    }
}

fn wilson_upper_bound_95(successes: usize, trials: usize) -> f64 {
    if trials == 0 {
        return 1.0;
    }
    // One-sided 95% standard-normal quantile. Wilson is well behaved for zero observed events,
    // unlike the naive plug-in estimate of zero.
    const Z: f64 = 1.644_853_626_951_472_2;
    let n = trials as f64;
    let probability = successes as f64 / n;
    let z_squared = Z * Z;
    let numerator = probability
        + z_squared / (2.0 * n)
        + Z * (probability * (1.0 - probability) / n + z_squared / (4.0 * n * n)).sqrt();
    (numerator / (1.0 + z_squared / n)).min(1.0)
}

fn metadata_clusters(samples: &[ScoredSample], member_limit: usize) -> Vec<MetadataCluster> {
    let mut groups: HashMap<String, Vec<&ScoredSample>> = HashMap::new();
    for sample in samples {
        if let Some(hash) = &sample.detector.features.metadata_suffix_keccak256 {
            groups.entry(hash.clone()).or_default().push(sample);
        }
    }
    let mut clusters: Vec<_> = groups
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(hash, mut members)| {
            members.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            MetadataCluster {
                suffix_keccak256: hash,
                member_count: members.len(),
                sample_ids: members
                    .iter()
                    .take(member_limit)
                    .map(|sample| sample.id.clone())
                    .collect(),
                sample_ids_truncated: members.len() > member_limit,
                positive_members: members
                    .iter()
                    .filter(|sample| sample.label == Some(true))
                    .count(),
                negative_members: members
                    .iter()
                    .filter(|sample| sample.label == Some(false))
                    .count(),
                unlabelled_members: members
                    .iter()
                    .filter(|sample| sample.label.is_none())
                    .count(),
            }
        })
        .collect();
    clusters.sort_unstable_by(|left, right| {
        right
            .member_count
            .cmp(&left.member_count)
            .then_with(|| left.suffix_keccak256.cmp(&right.suffix_keccak256))
    });
    clusters
}

fn normalized_clusters(
    samples: &[ScoredSample],
    fingerprint_kind: &str,
    fingerprint: fn(&SignatureFeatures) -> &str,
    member_limit: usize,
) -> Vec<NormalizedCluster> {
    let mut groups: HashMap<String, Vec<&ScoredSample>> = HashMap::new();
    for sample in samples {
        groups
            .entry(fingerprint(&sample.detector.features).to_string())
            .or_default()
            .push(sample);
    }
    let mut clusters: Vec<_> = groups
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(hash, mut members)| {
            members.sort_unstable_by(|left, right| left.id.cmp(&right.id));
            let family_count = members
                .iter()
                .filter_map(|sample| sample.family.as_deref())
                .collect::<std::collections::HashSet<_>>()
                .len();
            NormalizedCluster {
                fingerprint_kind: fingerprint_kind.to_string(),
                fingerprint_keccak256: hash,
                member_count: members.len(),
                sample_ids: members
                    .iter()
                    .take(member_limit)
                    .map(|sample| sample.id.clone())
                    .collect(),
                sample_ids_truncated: members.len() > member_limit,
                family_count,
                positive_members: members
                    .iter()
                    .filter(|sample| sample.label == Some(true))
                    .count(),
                negative_members: members
                    .iter()
                    .filter(|sample| sample.label == Some(false))
                    .count(),
                unlabelled_members: members
                    .iter()
                    .filter(|sample| sample.label.is_none())
                    .count(),
            }
        })
        .collect();
    clusters.sort_unstable_by(|left, right| {
        right
            .member_count
            .cmp(&left.member_count)
            .then_with(|| left.fingerprint_kind.cmp(&right.fingerprint_kind))
            .then_with(|| left.fingerprint_keccak256.cmp(&right.fingerprint_keccak256))
    });
    clusters
}

fn normalization_linkability(
    samples: &[ScoredSample],
    fingerprint_kind: &str,
    fingerprint: fn(&SignatureFeatures) -> &str,
) -> Option<NormalizationLinkabilityMetrics> {
    let family_samples: Vec<_> = samples
        .iter()
        .filter(|sample| sample.family.is_some())
        .collect();
    if family_samples.len() < 2 {
        return None;
    }

    let mut family_counts: HashMap<&str, u64> = HashMap::new();
    let mut hash_counts: HashMap<&str, u64> = HashMap::new();
    let mut family_hash_counts: HashMap<(&str, &str), u64> = HashMap::new();
    let mut family_label_counts: HashMap<&str, (u64, u64)> = HashMap::new();
    let mut family_hash_label_counts: HashMap<(&str, &str), (u64, u64)> = HashMap::new();
    for sample in family_samples {
        let family = sample.family.as_deref().expect("filtered above");
        let hash = fingerprint(&sample.detector.features);
        *family_counts.entry(family).or_default() += 1;
        *hash_counts.entry(hash).or_default() += 1;
        *family_hash_counts.entry((family, hash)).or_default() += 1;
        if let Some(label) = sample.label {
            let counts = family_label_counts.entry(family).or_default();
            let hash_counts = family_hash_label_counts.entry((family, hash)).or_default();
            if label {
                counts.0 += 1;
                hash_counts.0 += 1;
            } else {
                counts.1 += 1;
                hash_counts.1 += 1;
            }
        }
    }

    let same_family_pairs = family_counts.values().copied().map(pair_count).sum();
    let all_pairs = pair_count(
        samples
            .iter()
            .filter(|sample| sample.family.is_some())
            .count() as u64,
    );
    let different_family_pairs = all_pairs.saturating_sub(same_family_pairs);
    let linked_same_family_pairs = family_hash_counts.values().copied().map(pair_count).sum();
    let cross_label_same_family_pairs = family_label_counts
        .values()
        .map(|(positives, negatives)| positives.saturating_mul(*negatives))
        .sum();
    let linked_cross_label_same_family_pairs = family_hash_label_counts
        .values()
        .map(|(positives, negatives)| positives.saturating_mul(*negatives))
        .sum();
    let linked_all_pairs: u64 = hash_counts.values().copied().map(pair_count).sum();
    let linked_different_family_pairs = linked_all_pairs.saturating_sub(linked_same_family_pairs);

    Some(NormalizationLinkabilityMetrics {
        fingerprint_kind: fingerprint_kind.to_string(),
        same_family_pairs,
        linked_same_family_pairs,
        same_family_pair_recall: ratio(linked_same_family_pairs, same_family_pairs),
        cross_label_same_family_pairs,
        linked_cross_label_same_family_pairs,
        cross_label_same_family_pair_recall: ratio(
            linked_cross_label_same_family_pairs,
            cross_label_same_family_pairs,
        ),
        different_family_pairs,
        linked_different_family_pairs,
        different_family_pair_collision_rate: ratio(
            linked_different_family_pairs,
            different_family_pairs,
        ),
    })
}

fn metadata_linkability(samples: &[ScoredSample]) -> Option<MetadataLinkabilityMetrics> {
    let family_samples: Vec<_> = samples
        .iter()
        .filter(|sample| sample.family.is_some())
        .collect();
    if family_samples.len() < 2 {
        return None;
    }

    let mut family_counts: HashMap<&str, u64> = HashMap::new();
    let mut hash_counts: HashMap<&str, u64> = HashMap::new();
    let mut family_hash_counts: HashMap<(&str, &str), u64> = HashMap::new();
    for sample in &family_samples {
        let Some(family) = sample.family.as_deref() else {
            continue;
        };
        *family_counts.entry(family).or_default() += 1;
        if let Some(hash) = sample
            .detector
            .features
            .metadata_suffix_keccak256
            .as_deref()
        {
            *hash_counts.entry(hash).or_default() += 1;
            *family_hash_counts.entry((family, hash)).or_default() += 1;
        }
    }

    let same_family_pairs = family_counts.values().copied().map(pair_count).sum();
    let all_pairs = pair_count(family_samples.len() as u64);
    let different_family_pairs = all_pairs.saturating_sub(same_family_pairs);
    let linked_same_family_pairs = family_hash_counts.values().copied().map(pair_count).sum();
    let linked_all_pairs: u64 = hash_counts.values().copied().map(pair_count).sum();
    let linked_different_family_pairs = linked_all_pairs.saturating_sub(linked_same_family_pairs);

    Some(MetadataLinkabilityMetrics {
        same_family_pairs,
        linked_same_family_pairs,
        same_family_pair_recall: ratio(linked_same_family_pairs, same_family_pairs),
        different_family_pairs,
        linked_different_family_pairs,
        different_family_pair_collision_rate: ratio(
            linked_different_family_pairs,
            different_family_pairs,
        ),
    })
}

fn pair_count(count: u64) -> u64 {
    count.saturating_mul(count.saturating_sub(1)) / 2
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then_some(numerator as f64 / denominator as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(score: u32, label: bool) -> (u32, bool) {
        (score, label)
    }

    fn metadata_blob(code: &[u8], tag: u8) -> String {
        // A complete compiler-keyed CBOR map followed by Solidity's two-byte length.
        let metadata = [0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, tag];
        let mut bytes = code.to_vec();
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        hex::encode(bytes)
    }

    #[test]
    fn decoder_does_not_scan_push_immediates_for_motifs() {
        let motif = [0x5b, 0x60, 0x01, 0x60, 0x00, 0x14, 0x60, 0x00];
        let mut bytecode = vec![0x7f];
        bytecode.extend_from_slice(&motif);
        bytecode.resize(33, 0);
        let features = extract_signature_features(&bytecode);
        assert_eq!(features.dispatcher_constant_false_decoys, 0);
        assert_eq!(features.instruction_count, 1);
    }

    #[test]
    fn extracts_dispatcher_motifs() {
        let bytecode = [
            0x5b, 0xfe, // invalid sink
            0x5b, 0x60, 0x01, 0x60, 0x00, 0x14, 0x60, 0x00, 0x57, 0x60, 0x00, 0x56, 0x61, 0x10,
            0x00, 0x54, 0x15, 0x60, 0x00, 0x57, 0x60, 0x00, 0x56, 0x60, 0x00, 0x35, 0x60, 0x02,
            0x1a, 0x60, 0xab, 0x14, 0x60, 0x00, 0x57, 0x60, 0x00, 0x56,
        ];
        let result = score_bytecode(&bytecode);
        assert_eq!(result.features.dispatcher_invalid_sinks, 1);
        assert_eq!(result.features.dispatcher_constant_false_decoys, 1);
        assert_eq!(result.features.dispatcher_storage_gates, 1);
        assert_eq!(result.features.dispatcher_byte_gates, 1);
        assert_eq!(result.heuristic_score, 90);
    }

    #[test]
    fn extracts_push_split_and_codecopy_motifs() {
        let bytecode = [
            0x5f, 0x64, 1, 2, 3, 4, 5, 0x18, 0x64, 6, 7, 8, 9, 10, 0x01, // split
            0x60, 0x20, 0x61, 0x12, 0x34, 0x60, 0x00, 0x39, 0x60, 0x00, 0x51,
        ];
        let features = extract_signature_features(&bytecode);
        assert_eq!(features.push_split_chains, 1);
        assert_eq!(features.push_split_terms, 2);
        assert_eq!(features.arithmetic_codecopy_loads, 1);
    }

    #[test]
    fn extracts_repeated_constructor_mask_decoder_chunks() {
        let mut bytecode = Vec::new();
        for salt in [0x11, 0x22] {
            bytecode.extend_from_slice(&[0x80, 0x51, 0x7f]);
            bytecode.extend_from_slice(&[salt; 32]);
            bytecode.push(0x7f);
            bytecode.extend_from_slice(&[salt ^ 0xff; 32]);
            bytecode.extend_from_slice(&[0x01, 0x18, 0x90, 0x52]);
        }
        let result = score_bytecode(&bytecode);
        assert_eq!(result.features.constructor_mask_decoder_chunks, 2);
        assert!(
            result
                .evidence
                .iter()
                .any(|evidence| evidence.feature == "constructor_mask_decoder_chunks")
        );
    }

    #[test]
    fn marks_truncated_push_without_panicking() {
        let features = extract_signature_features(&[0x62, 0xaa]);
        assert_eq!(features.instruction_count, 1);
        assert_eq!(features.malformed_pushes, 1);
    }

    #[test]
    fn excludes_terminal_metadata_from_instruction_scan() {
        let hex = metadata_blob(&[0x00], 0x0a);
        let result = score_hex(&hex).expect("valid hex");
        assert_eq!(result.features.code_len, 1);
        assert_eq!(result.features.byte_len, 13);
        assert_eq!(result.features.instruction_count, 1);
        assert_eq!(result.features.metadata_suffix_len, Some(12));
        assert!(result.features.metadata_suffix_keccak256.is_some());
    }

    #[test]
    fn malformed_map_like_executable_tail_is_not_metadata() {
        let bytecode = [
            0x00, 0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, 0x1e, 0x00, 0x09,
        ];
        let features = extract_signature_features(&bytecode);
        assert_eq!(features.code_len, bytecode.len());
        assert_eq!(features.metadata_suffix_len, None);
        assert_eq!(features.instruction_count, 8);
    }

    #[test]
    fn compiler_marker_in_cbor_value_is_not_treated_as_a_compiler_key() {
        let payload = [
            0xa1, 0x64, b'n', b'o', b't', b'e', 0x45, 0x64, b's', b'o', b'l', b'c',
        ];
        let mut bytecode = vec![0x00];
        bytecode.extend_from_slice(&payload);
        bytecode.extend_from_slice(&(payload.len() as u16).to_be_bytes());

        let features = extract_signature_features(&bytecode);
        assert_eq!(features.code_len, bytecode.len());
        assert_eq!(features.metadata_suffix_len, None);
    }

    #[test]
    fn compiler_cbor_inside_push_immediate_is_not_metadata() {
        let mut bytecode = vec![0x7f];
        bytecode.extend_from_slice(&[0u8; 20]);
        bytecode.extend_from_slice(&[
            0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, 0x1e, 0x00, 0x0a,
        ]);
        assert_eq!(bytecode.len(), 33);

        let features = extract_signature_features(&bytecode);
        assert_eq!(features.code_len, bytecode.len());
        assert_eq!(features.metadata_suffix_len, None);
        assert_eq!(features.instruction_count, 1);
        assert_eq!(features.malformed_pushes, 0);
    }

    #[test]
    fn binary_metrics_handle_perfect_ranking_and_ties() {
        let perfect = [
            labelled(90, true),
            labelled(80, true),
            labelled(20, false),
            labelled(10, false),
        ];
        let metrics = compute_binary_metrics(&perfect);
        assert_eq!(metrics.auroc, 1.0);
        assert_eq!(metrics.average_precision, 1.0);

        let tied = [labelled(50, true), labelled(50, false)];
        let metrics = compute_binary_metrics(&tied);
        assert_eq!(metrics.auroc, 0.5);
        assert_eq!(metrics.average_precision, 0.5);
    }

    #[test]
    fn unlabelled_corpus_does_not_claim_classification_quality() {
        let samples = [CorpusSample {
            id: "unknown".to_string(),
            bytecode: "00".to_string(),
            label: None,
            family: None,
        }];
        let report = evaluate_corpus(&samples).expect("valid corpus");
        assert!(report.binary_classification.is_none());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("No labels"))
        );
    }

    #[test]
    fn duplicate_sample_ids_are_rejected_instead_of_double_counted() {
        let samples = [
            CorpusSample {
                id: "duplicate".to_string(),
                bytecode: "00".to_string(),
                label: Some(true),
                family: None,
            },
            CorpusSample {
                id: "duplicate".to_string(),
                bytecode: "00".to_string(),
                label: Some(false),
                family: None,
            },
        ];
        assert!(matches!(
            evaluate_corpus(&samples),
            Err(DetectorError::DuplicateSampleId { .. })
        ));
    }

    #[test]
    fn reports_exact_metadata_linkability_by_family() {
        let samples = [
            CorpusSample {
                id: "a-1".to_string(),
                bytecode: metadata_blob(&[0x00], 1),
                label: Some(true),
                family: Some("a".to_string()),
            },
            CorpusSample {
                id: "a-2".to_string(),
                bytecode: metadata_blob(&[0x01], 1),
                label: Some(true),
                family: Some("a".to_string()),
            },
            CorpusSample {
                id: "b-1".to_string(),
                bytecode: metadata_blob(&[0x00], 2),
                label: Some(false),
                family: Some("b".to_string()),
            },
        ];
        let report = evaluate_corpus(&samples).expect("valid corpus");
        assert_eq!(report.metadata_clusters.len(), 1);
        let linkage = report.metadata_linkability.expect("family metrics");
        assert_eq!(linkage.same_family_pairs, 1);
        assert_eq!(linkage.linked_same_family_pairs, 1);
        assert_eq!(linkage.same_family_pair_recall, Some(1.0));
        assert_eq!(linkage.linked_different_family_pairs, 0);
    }

    #[test]
    fn normalization_erases_immediates_and_block_order() {
        let first = [
            0x5b, 0x60, 0x01, 0x50, 0x00, // JUMPDEST PUSH1 1 POP STOP
            0x5b, 0x60, 0x02, 0x51, 0x00, // JUMPDEST PUSH1 2 MLOAD STOP
        ];
        let changed_immediates = [0x5b, 0x60, 0xaa, 0x50, 0x00, 0x5b, 0x60, 0xbb, 0x51, 0x00];
        let reordered = [0x5b, 0x60, 0x02, 0x51, 0x00, 0x5b, 0x60, 0x01, 0x50, 0x00];

        let first_features = extract_signature_features(&first);
        let immediate_features = extract_signature_features(&changed_immediates);
        let reordered_features = extract_signature_features(&reordered);
        assert_eq!(
            first_features.opcode_skeleton_keccak256,
            immediate_features.opcode_skeleton_keccak256
        );
        assert_ne!(
            first_features.opcode_skeleton_keccak256,
            reordered_features.opcode_skeleton_keccak256
        );
        assert_eq!(
            first_features.block_multiset_keccak256,
            reordered_features.block_multiset_keccak256
        );
    }

    #[test]
    fn normalization_folds_push_split_chain() {
        let original = extract_signature_features(&[0x60, 0x03, 0x00]);
        let split = extract_signature_features(&[0x5f, 0x60, 0x01, 0x01, 0x60, 0x02, 0x01, 0x00]);
        assert_eq!(split.push_split_chains, 1);
        assert_ne!(
            original.opcode_skeleton_keccak256,
            split.opcode_skeleton_keccak256
        );
        assert_eq!(
            original.folded_opcode_skeleton_keccak256,
            split.folded_opcode_skeleton_keccak256
        );
    }

    #[test]
    fn low_fpr_requires_statistical_support_not_just_zero_observations() {
        let small = wilson_upper_bound_95(0, 100);
        let large = wilson_upper_bound_95(0, 1_000);
        assert!(small > 0.01);
        assert!(large < 0.01);

        let mut dataset = vec![labelled(100, true)];
        dataset.extend((0..100).map(|_| labelled(0, false)));
        let point = operating_point(&dataset, 0.01, 100);
        assert!(point.resolution_supported);
        assert!(!point.confidence_supported);
    }

    #[test]
    fn enforces_configured_corpus_bounds() {
        let samples = [CorpusSample {
            id: "large".to_string(),
            bytecode: "0000".to_string(),
            label: None,
            family: None,
        }];
        let config = DetectorConfig {
            max_samples: 1,
            max_bytecode_bytes: 1,
            max_cluster_members_in_report: 1,
        };
        assert!(matches!(
            evaluate_corpus_with_config(&samples, &config),
            Err(DetectorError::BytecodeTooLarge { .. })
        ));
    }
}
