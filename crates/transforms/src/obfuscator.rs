use crate::cluster_shuffle::ClusterShuffle;
use crate::constructor_args::{obfuscate_constructor_args, ConstructorArgsObfuscation};
use crate::function_dispatcher::FunctionDispatcher;
use crate::Transform;
use azoth_core::seed::{DeterministicRng, Seed};
use azoth_core::{
    cfg_ir::{self, snapshot_bundle_with_runtime, Block, CfgIrDiff, OperationKind, TraceEvent},
    decoder, detection, encoder, is_terminal_opcode, process_bytecode_to_cfg, validator, Opcode,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use sha3::{Digest, Keccak256, Sha3_256};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_INITCODE_SIZE: usize = 49_152;
const MAX_RUNTIME_CODE_SIZE: usize = 24_576;
const PIPELINE_PROFILE: &[u8] = b"azoth-foundation-v4";
type HmacSha3_256 = Hmac<Sha3_256>;

/// Error from the obfuscation pipeline, including a partial trace for debugging.
#[derive(Debug)]
pub struct ObfuscationError {
    /// The underlying error message.
    pub message: String,
    /// Partial trace captured before the error occurred.
    pub trace: Vec<TraceEvent>,
}

impl ObfuscationError {
    fn from_err(e: impl std::fmt::Display, trace: &[TraceEvent]) -> Self {
        Self {
            message: e.to_string(),
            trace: trace.to_vec(),
        }
    }
}

impl std::fmt::Display for ObfuscationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ObfuscationError {}

/// Configuration for the obfuscation pipeline
pub struct ObfuscationConfig {
    /// Cryptographic seed for deterministic obfuscation
    pub seed: Seed,
    /// List of transforms to apply
    pub transforms: Vec<Box<dyn Transform>>,
    /// Whether to preserve unknown opcodes
    pub preserve_unknown_opcodes: bool,
    /// Whether to relabel selectors in a detected native dispatcher.
    ///
    /// Disabled in the production profile because adapted calldata changes observable `msg.sig`
    /// and `msg.data` unless whole-program selector-taint analysis proves they are not consumed.
    pub rewrite_function_selectors: bool,
    /// Whether to rewrite an exactly located constructor-argument suffix.
    ///
    /// This is disabled in the production profile: the current decoder supports only a subset of
    /// compiler init-code shapes and its normalization resistance has not passed the red-team
    /// gate. Library callers may enable it explicitly for experimental evaluation.
    pub obfuscate_constructor_arguments: bool,
}

impl ObfuscationConfig {
    /// Create config with a specific seed
    pub fn with_seed(seed: Seed) -> Self {
        Self {
            seed,
            transforms: vec![Box::new(ClusterShuffle::new())],
            preserve_unknown_opcodes: true,
            rewrite_function_selectors: false,
            obfuscate_constructor_arguments: false,
        }
    }
}

impl std::fmt::Debug for ObfuscationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfuscationConfig")
            .field(
                "transforms",
                &format!("{} transforms", self.transforms.len()),
            )
            .field("preserve_unknown_opcodes", &self.preserve_unknown_opcodes)
            .field(
                "rewrite_function_selectors",
                &self.rewrite_function_selectors,
            )
            .field(
                "obfuscate_constructor_arguments",
                &self.obfuscate_constructor_arguments,
            )
            .finish()
    }
}

/// Result of the obfuscation pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationResult {
    /// The obfuscated deployment bytecode as hex string (with 0x prefix)
    pub obfuscated_bytecode: String,
    /// The obfuscated runtime bytecode as hex string (with 0x prefix)
    pub obfuscated_runtime: String,
    /// Original bytecode size in bytes
    pub original_size: usize,
    /// Obfuscated bytecode size in bytes  
    pub obfuscated_size: usize,
    /// Size increase as percentage
    pub size_increase_percentage: f64,
    /// Number of unknown opcodes preserved
    pub unknown_opcodes_count: usize,
    /// List of unknown opcode types found
    pub unknown_opcode_types: Vec<String>,
    /// Number of blocks in the final CFG
    pub blocks_created: usize,
    /// Number of instructions added by transforms
    pub instructions_added: usize,
    /// Total number of instructions processed
    pub total_instructions: usize,
    /// Metadata about the obfuscation process
    pub metadata: ObfuscationMetadata,
    /// Mapping from original selectors to tokens (if token dispatcher was applied)
    #[serde(serialize_with = "serialize_optional_selector_mapping")]
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
    /// Canonical, seed-bound integrity information for independent replay checks.
    pub integrity: IntegrityManifest,
    /// Trace of CFG operations captured during obfuscation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationMetadata {
    /// Names of transforms that were applied
    pub transforms_applied: Vec<String>,
    /// Whether the size limit was exceeded
    pub size_limit_exceeded: bool,
    /// Whether unknown opcodes were preserved
    pub unknown_opcodes_preserved: bool,
    /// Whether an exact constructor-argument suffix was masked and decoded during init.
    #[serde(default)]
    pub constructor_args_obfuscated: bool,
    /// Number of constructor-argument bytes masked in the creation payload.
    #[serde(default)]
    pub constructor_argument_bytes: usize,
    /// Number of seed-varied decoder bytes inserted into init code.
    #[serde(default)]
    pub constructor_decoder_bytes: usize,
}

/// Canonical integrity information bound to one deterministic pipeline result.
///
/// This manifest contains no private seed. A party that already possesses the source bytecode
/// and seed can rerun Azoth and compare every hash and the authenticated reproduction tag. The
/// tag is a seed-derived MAC, not a public signature or a proof of semantic equivalence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Versioned transformation profile used by the deterministic KDF.
    pub pipeline_profile: String,
    /// Canonical configuration needed to replay this profile exactly.
    pub pipeline_configuration: PipelineConfigurationManifest,
    /// Commitment to the private seed, without disclosing it.
    pub seed_commitment: String,
    /// Keccak-256 of the canonical input creation payload.
    pub input_deployment_keccak256: String,
    /// Keccak-256 of the caller-supplied runtime artifact.
    pub input_runtime_keccak256: String,
    /// Keccak-256 of the transformed creation payload.
    pub output_deployment_keccak256: String,
    /// Keccak-256 of the complete transformed runtime *template*, including compiler auxdata.
    /// This does not claim to be the hash of materialized deployed code: constructor execution
    /// can replace compiler immutable placeholders. Authenticate such code by deterministically
    /// replaying the creation transaction in the same environment and comparing its code hash.
    pub output_runtime_keccak256: String,
    /// Ordered list of transforms that committed a change.
    pub transforms_applied: Vec<String>,
    /// Commitment to the canonical selector map, when an interface rewrite was performed.
    pub selector_mapping_commitment: Option<String>,
    /// Domain-separated HMAC-SHA3-256 tag binding all fields above to one replay result.
    pub reproduction_commitment: String,
}

/// Public, authenticated description of every pipeline choice that can affect replay.
///
/// `transforms_applied` records only passes that committed a bytecode change. This structure also
/// records requested passes that deterministically became no-ops, plus feature switches, so two
/// different library configurations cannot silently claim the same replay recipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineConfigurationManifest {
    /// User-requested transforms, in invocation order. Repeated recipes remain repeated.
    pub requested_transforms: Vec<TransformRecipeManifest>,
    pub preserve_unknown_opcodes: bool,
    pub rewrite_function_selectors: bool,
    pub obfuscate_constructor_arguments: bool,
}

/// Canonical identity of one requested transform instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransformRecipeManifest {
    pub name: String,
    /// Versioned identifier returned by [`Transform::configuration_id`].
    pub configuration_id: String,
}

/// Off-chain interaction guide intended for seed-authorized users and nodes.
///
/// Publishing this object would disclose the original-selector to transformed-selector
/// association. It is therefore returned to the caller and emitted only on explicit CLI request;
/// it is never embedded in contract bytecode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateInteractionManifest {
    pub integrity: IntegrityManifest,
    /// Canonically ordered `0x<original selector>` to `0x<replacement>` mapping.
    pub selector_mapping: BTreeMap<String, String>,
    /// Exact calldata adaptation rule for ordinary Solidity ABI calls.
    pub calldata_rule: String,
}

impl ObfuscationResult {
    /// Builds the private, canonically serialized interaction guide for this result.
    pub fn private_interaction_manifest(&self) -> PrivateInteractionManifest {
        let selector_mapping = canonical_selector_mapping(self.selector_mapping.as_ref());
        let calldata_rule = canonical_calldata_rule(&selector_mapping);
        PrivateInteractionManifest {
            integrity: self.integrity.clone(),
            selector_mapping,
            calldata_rule: calldata_rule.to_string(),
        }
    }

    /// Verifies that this result and its manifest are bound to the supplied private inputs.
    ///
    /// This authenticates artifact integrity; it does not prove EVM semantic equivalence. The
    /// caller must keep `seed` private and separately run the behavioral/formal release gates.
    pub fn verify_integrity(
        &self,
        input_deployment: &[u8],
        input_runtime: &[u8],
        seed: &Seed,
    ) -> Result<(), String> {
        let output_deployment = decode_result_hex(&self.obfuscated_bytecode)?;
        let output_runtime = decode_result_hex(&self.obfuscated_runtime)?;
        if self.integrity.transforms_applied != self.metadata.transforms_applied {
            return Err("transform list mismatch".to_string());
        }
        if self
            .integrity
            .pipeline_configuration
            .preserve_unknown_opcodes
            != self.metadata.unknown_opcodes_preserved
        {
            return Err("unknown-opcode policy mismatch".to_string());
        }
        if self.metadata.constructor_args_obfuscated
            && !self
                .integrity
                .pipeline_configuration
                .obfuscate_constructor_arguments
        {
            return Err("constructor-argument policy mismatch".to_string());
        }

        let canonical_mapping = canonical_selector_mapping(self.selector_mapping.as_ref());
        let expected_mapping_commitment = (!canonical_mapping.is_empty()).then(|| {
            keccak_hex(
                &serde_json::to_vec(&canonical_mapping)
                    .expect("BTreeMap<String, String> serialization is infallible"),
            )
        });
        verify_manifest_integrity(
            &self.integrity,
            input_deployment,
            input_runtime,
            &output_deployment,
            &output_runtime,
            seed,
            expected_mapping_commitment.as_deref(),
        )
    }
}

impl PrivateInteractionManifest {
    /// Authenticates an emitted private guide against the private inputs and output artifacts.
    ///
    /// This is intentionally independent of [`ObfuscationResult`], because the CLI emits the
    /// guide as a standalone file. The calldata rule is required to be the canonical rule derived
    /// from the authenticated mapping, so tampering with either field fails closed.
    pub fn verify_integrity(
        &self,
        input_deployment: &[u8],
        input_runtime: &[u8],
        output_deployment: &[u8],
        output_runtime: &[u8],
        seed: &Seed,
    ) -> Result<(), String> {
        if self.calldata_rule != canonical_calldata_rule(&self.selector_mapping) {
            return Err("non-canonical calldata adaptation rule".to_string());
        }
        let mapping_commitment = (!self.selector_mapping.is_empty()).then(|| {
            keccak_hex(
                &serde_json::to_vec(&self.selector_mapping)
                    .expect("BTreeMap<String, String> serialization is infallible"),
            )
        });
        verify_manifest_integrity(
            &self.integrity,
            input_deployment,
            input_runtime,
            output_deployment,
            output_runtime,
            seed,
            mapping_commitment.as_deref(),
        )
    }
}

/// Main obfuscation pipeline
pub async fn obfuscate_bytecode(
    deployment_bytecode: &str,
    runtime_bytecode: &str,
    config: ObfuscationConfig,
) -> Result<ObfuscationResult, ObfuscationError> {
    tracing::debug!("Starting obfuscation pipeline:");
    tracing::debug!("  User transforms: {}", config.transforms.len());

    // Step 1: Process bytecode to CFG-IR
    let (mut cfg_ir, instructions, sections, bytes) =
        process_bytecode_to_cfg(deployment_bytecode, false, runtime_bytecode, false)
            .await
            .map_err(|e| ObfuscationError {
                message: e.to_string(),
                trace: Vec::new(),
            })?;
    let original_size = bytes.len();
    let normalized_runtime = azoth_core::normalize_hex_string(runtime_bytecode)
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    let original_runtime_bytes = hex::decode(normalized_runtime)
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    // Preserve the exact, unlinked runtime code template used to build the CFG. Immutable
    // relocation later authenticates references against its PUSH32-zero placeholders rather than
    // guessing from constructor arithmetic. Runtime spans are normally singular, but concatenate
    // them deterministically so the invariant remains explicit.
    let mut original_runtime_spans = cfg_ir.clean_report.runtime_layout.clone();
    original_runtime_spans.sort_by_key(|span| span.offset);
    let mut original_clean_runtime = Vec::with_capacity(cfg_ir.clean_report.clean_len);
    for span in original_runtime_spans {
        let end = span.offset.checked_add(span.len).ok_or_else(|| {
            ObfuscationError::from_err("original runtime span overflow", &cfg_ir.trace)
        })?;
        let runtime_span = bytes.get(span.offset..end).ok_or_else(|| {
            ObfuscationError::from_err("original runtime span is out of bounds", &cfg_ir.trace)
        })?;
        original_clean_runtime.extend_from_slice(runtime_span);
    }
    if original_clean_runtime.len() != cfg_ir.clean_report.clean_len {
        return Err(ObfuscationError::from_err(
            format!(
                "original clean runtime length mismatch: report={}, reconstructed={}",
                cfg_ir.clean_report.clean_len,
                original_clean_runtime.len()
            ),
            &cfg_ir.trace,
        ));
    }
    let has_init_section = cfg_ir
        .clean_report
        .removed
        .iter()
        .any(|removed| removed.kind == detection::SectionKind::Init);
    if !has_init_section && bytes != original_runtime_bytes {
        return Err(ObfuscationError::from_err(
            "deployment differs from supplied runtime but has no proven init section",
            &cfg_ir.trace,
        ));
    }
    cfg_ir
        .clean_report
        .validate_init_runtime_contract(&original_clean_runtime)
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    // Changing even a single zero/nonzero init-code byte changes the creation transaction's
    // intrinsic gas. A constructor that executes GAS can observe that difference or forward it
    // to an external call. Until a layout solver preserves the complete creation gas schedule,
    // every mutating pass is conservatively discarded for such inputs.
    let init_observes_gas = instructions.iter().any(|instruction| {
        matches!(instruction.op, Opcode::GAS)
            && sections.iter().any(|section| {
                section.kind == detection::SectionKind::Init
                    && instruction.pc >= section.offset
                    && instruction.pc < section.offset.saturating_add(section.len)
            })
    });
    // Section detection is a parsing aid, not a proof that a trailing region is unreachable.
    // Snapshot compiler-suffix candidates so finalization can enforce that no pass rewrites
    // bytes which may still be executable or code-observable.
    let original_deployed_suffixes: Vec<_> = cfg_ir
        .clean_report
        .removed
        .iter()
        .filter(|removed| {
            matches!(
                removed.kind,
                detection::SectionKind::Auxdata | detection::SectionKind::Padding
            )
        })
        .map(|removed| (removed.kind, removed.offset, removed.data.to_vec()))
        .collect();
    let pipeline_seed = derive_pipeline_seed(&config.seed, &bytes, &original_runtime_bytes);
    let pipeline_configuration = PipelineConfigurationManifest {
        requested_transforms: config
            .transforms
            .iter()
            .map(|transform| TransformRecipeManifest {
                name: transform.name().to_string(),
                configuration_id: transform.configuration_id(),
            })
            .collect(),
        preserve_unknown_opcodes: config.preserve_unknown_opcodes,
        rewrite_function_selectors: config.rewrite_function_selectors,
        obfuscate_constructor_arguments: config.obfuscate_constructor_arguments,
    };
    // Bind the commitment to this input and profile. Reusing one private seed across contracts
    // therefore does not create a stable off-chain linking identifier.
    let seed_commitment = pipeline_seed
        .derive_seed(b"integrity-seed-commitment")
        .hash_hex();
    cfg_ir
        .refresh_relationships()
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    let original_layout_order = cfg_ir.layout_order().to_vec();
    let original_control_unresolved = !cfg_ir.relationships().unresolved_control.is_empty();
    if !cfg_ir
        .relationships()
        .constructor_materialized_control
        .is_empty()
    {
        return Err(ObfuscationError::from_err(
            "constructor-materialized runtime word may determine a JUMP/JUMPI destination; layout transformation is unsupported",
            &cfg_ir.trace,
        ));
    }
    if !cfg_ir.relationships().position_sensitive.is_empty() {
        return Err(ObfuscationError::from_err(
            "runtime observes code position, size, bytes, or hash; exact observational equivalence under code variation is unsupported",
            &cfg_ir.trace,
        ));
    }

    tracing::debug!("  Input size: {} bytes", original_size);

    // Step 2: Analyze only executable runtime instructions for opcodes the CFG cannot model.
    // Init code, constructor arguments, and compiler suffixes are preserved outside this CFG and
    // may contain arbitrary data bytes. A retained runtime opcode must have known stack/control
    // semantics before any block can be relocated; merely copying its byte is not sufficient.
    let retained_runtime_instructions = extract_instructions_from_cfg(&cfg_ir);
    let (total_instructions, unknown_count, unknown_types) =
        analyze_instructions(&retained_runtime_instructions, &bytes);
    tracing::debug!("  Total instructions: {}", total_instructions);
    tracing::debug!("  Unknown opcodes: {}", unknown_count);
    if unknown_count > 0 {
        return Err(ObfuscationError::from_err(
            format!(
                "runtime contains {unknown_count} unmodelled opcode(s): {}; refusing CFG transformation",
                unknown_types.join(", ")
            ),
            &cfg_ir.trace,
        ));
    }

    // Log section info
    tracing::debug!(
        "  Detected sections: {:?}",
        sections.iter().map(|s| (s.kind, s.len)).collect::<Vec<_>>()
    );
    tracing::debug!(
        "  Clean runtime size: {} bytes",
        cfg_ir.clean_report.bytes_saved
    );
    tracing::debug!(
        "  Bytes saved by stripping: {}",
        cfg_ir.clean_report.bytes_saved
    );

    // Track initial metrics
    let original_block_count = cfg_ir.cfg.node_count();
    let original_instruction_count = count_instructions_in_cfg(&cfg_ir);
    let original_bytecode_snapshot = hex::encode(&bytes);

    tracing::debug!("  CFG blocks: {}", original_block_count);
    tracing::debug!("  CFG instructions: {}", original_instruction_count);

    // Step 3: Apply transforms conditionally based on bytecode analysis
    let mut all_transforms: Vec<Box<dyn crate::Transform>> = Vec::new();

    // Only add function dispatcher if the bytecode actually contains one
    let runtime_section = sections
        .iter()
        .find(|s| s.kind == detection::SectionKind::Runtime);
    let retained_runtime_ends_in_terminal = runtime_section.is_some_and(|runtime| {
        let runtime_end = runtime.offset.saturating_add(runtime.len);
        retained_runtime_instructions
            .iter()
            .max_by_key(|instruction| instruction.pc)
            .is_some_and(|instruction| {
                instruction.pc.checked_add(instruction.byte_size()) == Some(runtime_end)
                    && is_terminal_opcode(instruction.op)
            })
    });

    let dispatcher_info = if runtime_section.is_some() {
        tracing::debug!(
            "Checking for dispatcher in {} runtime instructions",
            retained_runtime_instructions.len()
        );
        detection::detect_function_dispatcher(&retained_runtime_instructions)
    } else {
        // No runtime section = probably pure runtime bytecode
        detection::detect_function_dispatcher(&instructions)
    };

    // Store dispatcher info in bundle for snapshot/TUI visualization
    cfg_ir.dispatcher_info = dispatcher_info.clone();

    if config.rewrite_function_selectors {
        if let Some(dispatcher) = dispatcher_info {
            tracing::debug!(
                "Function dispatcher detected with {} selectors - adding experimental FunctionDispatcher transform",
                dispatcher.selectors.len()
            );
            all_transforms.push(Box::new(FunctionDispatcher::with_dispatcher_info_and_seed(
                dispatcher,
                pipeline_seed.derive_seed(b"function-dispatcher"),
            )));
        } else {
            tracing::debug!(
                "No function dispatcher detected in runtime - skipping FunctionDispatcher transform"
            );
        }
    } else {
        tracing::debug!("FunctionDispatcher is disabled by the safe profile");
    }

    // Add user-specified transforms (this moves config.transforms)
    all_transforms.extend(config.transforms);

    // Track only transforms that committed a validated change.
    let mut transforms_applied: Vec<String> = Vec::new();

    // Track individual transform effects
    let mut transform_change_log = Vec::new();
    let mut any_transform_changed = false;

    if !all_transforms.is_empty() {
        tracing::debug!("Applying {} transforms", all_transforms.len(),);

        let mut transform_occurrences: HashMap<&'static str, u64> = HashMap::new();
        for (i, transform) in all_transforms.iter().enumerate() {
            let transform_name = transform.name();
            let occurrence = transform_occurrences.entry(transform_name).or_default();
            let transform_occurrence = *occurrence;
            *occurrence += 1;
            let pre_instruction_count = count_instructions_in_cfg(&cfg_ir);
            let pre_block_count = cfg_ir.cfg.node_count();

            tracing::debug!(
                "  Transform {}: {} (pre: {} blocks, {} instructions)",
                i,
                transform_name,
                pre_block_count,
                pre_instruction_count
            );

            // Record transform start for trace grouping
            cfg_ir.record_transform_start(transform_name);

            // Each pass works on an isolated clone and receives its own input-bound RNG stream.
            // Errors abort the pipeline; a pass returning false discards its clone. This prevents
            // partial mutations from escaping and decouples later randomness from earlier passes.
            let protected_reassembly_state =
                serde_json::to_vec(&cfg_ir.clean_report).map_err(|error| {
                    ObfuscationError::from_err(
                        format!("failed to snapshot protected reconstruction state: {error}"),
                        &cfg_ir.trace,
                    )
                })?;
            let mut candidate = cfg_ir.clone();
            let transform_configuration_id = transform.configuration_id();
            let mut pass_rng = derive_transform_rng(
                &pipeline_seed,
                transform_name,
                &transform_configuration_id,
                transform_occurrence,
            );
            let mut transform_changed =
                transform
                    .apply(&mut candidate, &mut pass_rng)
                    .map_err(|error| {
                        ObfuscationError::from_err(
                            format!("transform {transform_name} failed: {error}"),
                            &cfg_ir.trace,
                        )
                    })?;
            if transform_changed
                && serde_json::to_vec(&candidate.clean_report).map_err(|error| {
                    ObfuscationError::from_err(
                        format!("failed to inspect protected reconstruction state: {error}"),
                        &candidate.trace,
                    )
                })? != protected_reassembly_state
            {
                return Err(ObfuscationError::from_err(
                    format!(
                        "transform {transform_name} attempted to mutate protected init, constructor, or compiler-suffix reconstruction state"
                    ),
                    &candidate.trace,
                ));
            }
            if transform_changed && init_observes_gas {
                tracing::debug!(
                    "discarding {transform_name}: reachable init GAS requires byte-for-byte creation stability"
                );
                transform_changed = false;
            }
            if transform_changed {
                candidate
                    .refresh_relationships()
                    .map_err(|error| ObfuscationError::from_err(error, &candidate.trace))?;
                candidate
                    .validate_relationships()
                    .map_err(|error| ObfuscationError::from_err(error, &candidate.trace))?;
                if !candidate.relationships().is_relocatable() {
                    return Err(ObfuscationError::from_err(
                        format!(
                            "transform {transform_name} introduced unresolved or position-sensitive relationships"
                        ),
                        &candidate.trace,
                    ));
                }
                cfg_ir = candidate;
                transforms_applied.push(transform_name.to_string());
            }
            tracing::debug!("    Result: changed={}", transform_changed);

            // Record transform end for trace grouping
            cfg_ir.record_transform_end(transform_name);

            let post_instruction_count = count_instructions_in_cfg(&cfg_ir);
            let post_block_count = cfg_ir.cfg.node_count();
            let instructions_delta = post_instruction_count as i32 - pre_instruction_count as i32;
            let blocks_delta = post_block_count as i32 - pre_block_count as i32;

            transform_change_log.push(format!(
                "{transform_name}: changed={transform_changed}, blocks_delta={blocks_delta:+}, instructions_delta={instructions_delta:+}",
            ));

            any_transform_changed |= transform_changed;

            tracing::debug!(
                "    Post: {} blocks ({:+}), {} instructions ({:+})",
                post_block_count,
                blocks_delta,
                post_instruction_count,
                instructions_delta
            );
        }
    }

    let layout_changed = cfg_ir.layout_order() != original_layout_order.as_slice();
    if layout_changed && !original_deployed_suffixes.is_empty() {
        if original_control_unresolved {
            return Err(ObfuscationError::from_err(
                "layout change refused: runtime control may target detected auxdata or padding",
                &cfg_ir.trace,
            ));
        }
        if !retained_runtime_ends_in_terminal {
            return Err(ObfuscationError::from_err(
                "layout change refused: retained runtime falls through into detected auxdata or padding",
                &cfg_ir.trace,
            ));
        }
    }

    // Start finalization phase for trace grouping
    cfg_ir.record_finalize_start();

    // Step 4: Calculate metrics after transformation
    let final_block_count = cfg_ir.cfg.node_count();
    let final_instruction_count = count_instructions_in_cfg(&cfg_ir);
    let blocks_created = final_block_count.saturating_sub(original_block_count);
    let instructions_added = final_instruction_count.saturating_sub(original_instruction_count);

    tracing::debug!("Transform summary:");
    tracing::debug!("  Any transform changed: {}", any_transform_changed);
    tracing::debug!(
        "  Final blocks: {} ({:+})",
        final_block_count,
        blocks_created as i32
    );
    tracing::debug!(
        "  Final instructions: {} ({:+})",
        final_instruction_count,
        instructions_added as i32
    );
    for log_entry in &transform_change_log {
        tracing::debug!("  {}", log_entry);
    }

    // Capture exact immutable-carrier identities before reindexing. A valid carrier must remain a
    // unique PUSH32-zero instruction at its original PC. If a transform removes, replaces, or
    // aliases it, the immutable remapper below deliberately has no answer and finalization fails.
    let old_runtime_start = cfg_ir.runtime_bounds.map(|(s, _)| s).unwrap_or(0);
    let old_runtime_instruction_shapes: HashMap<usize, (usize, bool)> = {
        let mut shapes = HashMap::new();
        let rt_bounds = cfg_ir.runtime_bounds;
        for node_idx in cfg_ir.cfg.node_indices() {
            if let cfg_ir::Block::Body(body) = &cfg_ir.cfg[node_idx] {
                let in_runtime = match rt_bounds {
                    Some((start, end)) => body.start_pc >= start && body.start_pc < end,
                    None => true,
                };
                if in_runtime {
                    for instr in &body.instructions {
                        let is_placeholder_carrier = matches!(instr.op, Opcode::PUSH(32))
                            && instr.imm.as_deref().is_some_and(|immediate| {
                                immediate.len() == 64 && immediate.bytes().all(|byte| byte == b'0')
                            });
                        let entry = shapes.entry(instr.pc).or_insert((0, false));
                        entry.0 += 1;
                        entry.1 |= is_placeholder_carrier;
                    }
                }
            }
        }
        shapes
    };

    // Step 5: Reindex PCs
    tracing::debug!("  Reindexing PCs to normalize to 0-based addressing");
    let (pc_mapping, old_runtime_bounds) = cfg_ir
        .reindex_pcs()
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
    tracing::debug!("  PC reindexing complete: {} mappings", pc_mapping.len());

    // Patch jump immediates using the PC mapping
    cfg_ir
        .patch_jump_immediates(&pc_mapping, old_runtime_bounds)
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
    tracing::debug!("  Patched jump immediates after PC reindexing");

    // Re-apply dispatcher jump target patches with OLD controller PCs (before updating)
    // NOTE: These patches update the PUSH2 instructions (jump targets), not the PUSH4 token instructions
    if let (Some(controller_pcs), Some(dispatcher_patches)) = (
        cfg_ir.dispatcher_controller_pcs.clone(),
        cfg_ir.dispatcher_patches.clone(),
    ) {
        tracing::debug!(
            "  Re-applying {} dispatcher jump target patches with remapped controller PCs",
            dispatcher_patches.len()
        );
        let dispatcher = FunctionDispatcher::new();
        dispatcher
            .reapply_dispatcher_patches(
                &mut cfg_ir,
                &controller_pcs,
                &dispatcher_patches,
                &pc_mapping,
            )
            .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
        tracing::debug!("  Dispatcher jump target patches re-applied successfully");

        // Now update dispatcher_controller_pcs with remapped PCs
        let mut updated_controller_pcs = HashMap::new();
        for (selector, old_pc) in controller_pcs {
            let new_pc = pc_mapping.get(&old_pc).copied().unwrap_or(old_pc);
            updated_controller_pcs.insert(selector, new_pc);
            tracing::debug!(
                "  Updated controller PC for 0x{:08x}: 0x{:04x} -> 0x{:04x}",
                selector,
                old_pc,
                new_pc
            );
        }
        cfg_ir.dispatcher_controller_pcs = Some(updated_controller_pcs);
    }

    // Re-apply stub patches with remapped decoy PCs if FunctionDispatcher was used
    if let Some(stub_patches) = cfg_ir.stub_patches.clone() {
        tracing::debug!(
            "  Re-applying {} stub patches with remapped decoy PCs",
            stub_patches.len()
        );
        let dispatcher = FunctionDispatcher::new();

        // Build edits for stub patches
        let mut edits = Vec::new();
        for (stub_node, old_pc, push_width, decoy_node) in stub_patches {
            // Look up the decoy block's first instruction PC (which should be the JUMPDEST)
            let new_decoy_pc = match &cfg_ir.cfg[decoy_node] {
                Block::Body(body) => {
                    let first_instr_pc = body
                        .instructions
                        .first()
                        .map(|instr| instr.pc)
                        .unwrap_or(body.start_pc);
                    tracing::debug!(
                        "  Decoy block {:?}: start_pc=0x{:04x}, first_instr_pc=0x{:04x}, instruction_count={}",
                        decoy_node,
                        body.start_pc,
                        first_instr_pc,
                        body.instructions.len()
                    );
                    // Use the first instruction's PC, not the block's start_pc
                    first_instr_pc
                }
                _ => {
                    tracing::warn!("  Decoy node is not a Body block, skipping stub patch");
                    continue;
                }
            };

            // Map the stub instruction's PC
            let new_pc = pc_mapping.get(&old_pc).copied().unwrap_or(old_pc);

            // Calculate the new relative address
            let decoy_rel = if let Some((start, _)) = cfg_ir.runtime_bounds {
                new_decoy_pc.saturating_sub(start)
            } else {
                new_decoy_pc
            };

            let formatted = format!("{:0width$x}", decoy_rel, width = push_width as usize * 2);

            tracing::debug!(
                "  Reapplying stub patch: decoy_node={:?}, push_width={}, new_decoy_pc=0x{:04x}, old_pc=0x{:04x}, new_pc=0x{:04x}, decoy_rel=0x{:04x}",
                decoy_node,
                push_width,
                new_decoy_pc,
                old_pc,
                new_pc,
                decoy_rel
            );

            edits.push((stub_node, new_pc, Opcode::PUSH(push_width), Some(formatted)));
        }

        if !edits.is_empty() {
            dispatcher
                .apply_instruction_replacements(&mut cfg_ir, edits)
                .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
        }
        // Debug: show resulting stub PUSH widths
        if let Some(stub_patches) = cfg_ir.stub_patches.clone() {
            for (stub_node, _, _, decoy_node) in stub_patches {
                if let Some(Block::Body(body)) = cfg_ir.cfg.node_weight(stub_node) {
                    for instr in &body.instructions {
                        tracing::debug!(
                            "    Stub node {:?} instr pc=0x{:04x} op={:?} imm={:?}",
                            stub_node,
                            instr.pc,
                            instr.op,
                            instr.imm
                        );
                    }
                }
                if let Some(Block::Body(body)) = cfg_ir.cfg.node_weight(decoy_node) {
                    for instr in &body.instructions {
                        tracing::debug!(
                            "    Decoy node {:?} instr pc=0x{:04x} op={:?} imm={:?}",
                            decoy_node,
                            instr.pc,
                            instr.op,
                            instr.imm
                        );
                    }
                }
            }
        }
        tracing::debug!("  Stub patches re-applied successfully");
    }

    // Re-apply decoy patches with remapped target PCs if FunctionDispatcher was used
    if let Some(decoy_patches) = cfg_ir.decoy_patches.clone() {
        tracing::debug!(
            "  Re-applying {} decoy patches with remapped target PCs",
            decoy_patches.len()
        );
        let dispatcher = FunctionDispatcher::new();

        // Build edits for decoy patches
        let mut edits = Vec::new();
        for (decoy_node, old_pc, push_width, old_target_pc) in decoy_patches {
            // Map the target PC using the PC mapping
            let new_target_pc = pc_mapping
                .get(&old_target_pc)
                .copied()
                .unwrap_or(old_target_pc);

            // Map the decoy instruction's PC
            let new_pc = pc_mapping.get(&old_pc).copied().unwrap_or(old_pc);

            // Calculate the new relative address
            let target_rel = if let Some((start, _)) = cfg_ir.runtime_bounds {
                new_target_pc.saturating_sub(start)
            } else {
                new_target_pc
            };

            let formatted = format!("{:0width$x}", target_rel, width = push_width as usize * 2);

            tracing::debug!(
                "  Reapplying decoy patch: decoy_node={:?}, push_width={}, old_target_pc=0x{:04x}, new_target_pc=0x{:04x}, old_pc=0x{:04x}, new_pc=0x{:04x}, target_rel=0x{:04x}",
                decoy_node,
                push_width,
                old_target_pc,
                new_target_pc,
                old_pc,
                new_pc,
                target_rel
            );

            edits.push((
                decoy_node,
                new_pc,
                Opcode::PUSH(push_width),
                Some(formatted),
            ));
        }

        if !edits.is_empty() {
            dispatcher
                .apply_instruction_replacements(&mut cfg_ir, edits)
                .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
        }
        tracing::debug!("  Decoy patches re-applied successfully");
    }

    // Re-apply controller patches with remapped jump targets if FunctionDispatcher was used
    if let Some(controller_patches) = cfg_ir.controller_patches.clone() {
        tracing::debug!(
            "  Re-applying {} controller patches with remapped jump targets",
            controller_patches.len()
        );
        let dispatcher = FunctionDispatcher::new();
        dispatcher
            .reapply_controller_patches(&mut cfg_ir, &controller_patches, &pc_mapping)
            .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
        tracing::debug!("  Controller patches re-applied successfully");
    }

    // After all Step 5 dispatcher reapplies may have grown some PUSH widths
    // post-reindex, recompute the actual runtime length and shift AC-emitted
    // CODECOPY offsets so the data section still lines up. This is a no-op
    // when ArithmeticChain didn't run or when the estimate already matches
    // the real runtime length.
    cfg_ir
        .patch_arithmetic_chain_codecopy_offsets()
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;

    // Step 6: Extract and encode instructions
    let all_instructions = extract_instructions_from_cfg(&cfg_ir);
    tracing::debug!(
        "  Extracted {} instructions from CFG",
        all_instructions.len()
    );

    // Step 7: Encode back to bytecode (always with original for unknown opcode preservation)
    let mut obfuscated_bytes = encoder::encode(&all_instructions, &bytes)
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;

    tracing::debug!("  Encoded to {} bytes", obfuscated_bytes.len());

    // Validate BEFORE appending data section - data section bytes would be
    // misinterpreted as code by the decoder, causing spurious validation failures
    tracing::debug!(
        "  Validating obfuscated runtime jump targets ({} bytes)",
        obfuscated_bytes.len()
    );
    if let Err(e) = validator::validate_jump_targets(&obfuscated_bytes).await {
        tracing::warn!("Validation failed: {}", e);
        return Err(ObfuscationError::from_err(e, &cfg_ir.trace));
    }
    tracing::debug!("  Jump validation passed");

    // Append arithmetic chain data section to runtime bytecode AFTER validation
    // This data is loaded via CODECOPY at runtime
    if let Some(ref data_section) = cfg_ir.arithmetic_chain_data {
        tracing::debug!(
            "  Appending {} bytes of arithmetic chain data section to runtime",
            data_section.len()
        );
        obfuscated_bytes.extend_from_slice(data_section);
        tracing::debug!(
            "  Runtime bytecode size with data section: {} bytes",
            obfuscated_bytes.len()
        );
    }

    // Step 7b: Patch exact Solidity immutable references in the init code. Only an original
    // PUSH32-zero placeholder whose carrier instruction survived uniquely can be relocated.
    if cfg_ir
        .clean_report
        .removed
        .iter()
        .any(|removed| removed.kind == detection::SectionKind::Init)
    {
        let new_runtime_start = cfg_ir.runtime_bounds.map(|(s, _)| s).unwrap_or(0);
        let remap = |old_offset: usize| -> Option<usize> {
            // Placeholder offsets point to the first immediate byte, one byte after PUSH32.
            let old_opcode_relative = old_offset.checked_sub(1)?;
            let old_opcode_pc = old_runtime_start.checked_add(old_opcode_relative)?;
            match old_runtime_instruction_shapes.get(&old_opcode_pc) {
                Some(&(1, true)) => {}
                _ => return None,
            }
            let new_opcode_pc = *pc_mapping.get(&old_opcode_pc)?;
            let new_opcode_relative = new_opcode_pc.checked_sub(new_runtime_start)?;
            new_opcode_relative.checked_add(1)
        };

        cfg_ir
            .clean_report
            .patch_init_immutable_refs(&original_clean_runtime, &remap)
            .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    }

    // Step 7c: Mask an exact constructor-argument suffix and inject a seed-varied decoder.
    // This runs after init immutable patching so its insertion can remap all existing init jumps
    // once. It fails closed when arguments exist but their copy site is unsupported.
    let constructor_args = if config.obfuscate_constructor_arguments && !init_observes_gas {
        obfuscate_constructor_args(
            &mut cfg_ir.clean_report,
            pipeline_seed
                .derive_seed(b"constructor-arguments")
                .as_bytes(),
        )
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?
    } else {
        if config.obfuscate_constructor_arguments && init_observes_gas {
            tracing::debug!(
                "discarding ConstructorArgs: init GAS requires byte-for-byte creation stability"
            );
        }
        ConstructorArgsObfuscation::default()
    };
    if constructor_args.applied {
        transforms_applied.push("ConstructorArgs".to_string());
        tracing::debug!(
            "  Obfuscated {} constructor argument bytes with a {}-byte decoder",
            constructor_args.argument_bytes,
            constructor_args.decoder_bytes
        );
    }

    let final_deployed_suffixes: Vec<_> = cfg_ir
        .clean_report
        .removed
        .iter()
        .filter(|removed| {
            matches!(
                removed.kind,
                detection::SectionKind::Auxdata | detection::SectionKind::Padding
            )
        })
        .map(|removed| (removed.kind, removed.offset, removed.data.to_vec()))
        .collect();
    if final_deployed_suffixes != original_deployed_suffixes {
        return Err(ObfuscationError::from_err(
            "compiler auxdata or padding changed; the production pipeline preserves all detected suffix bytes",
            &cfg_ir.trace,
        ));
    }

    // Step 8: Reassemble final bytecode (init + runtime with data section + auxdata)
    let final_bytecode = cfg_ir
        .clean_report
        .reassemble_checked(&obfuscated_bytes)
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    if init_observes_gas && final_bytecode != bytes {
        return Err(ObfuscationError::from_err(
            "init GAS identity fallback failed: final creation bytecode differs from the input",
            &cfg_ir.trace,
        ));
    }
    let obfuscated_size = final_bytecode.len();

    // The public runtime result is the complete code that init code returns, including ordinary
    // compiler padding and auxdata. Constructor arguments are creation-transaction data and are
    // deliberately excluded. Keeping this byte sequence complete makes integrity hashes and
    // deployed-runtime comparisons unambiguous.
    let mut complete_runtime = obfuscated_bytes.clone();
    let mut deployed_suffixes: Vec<_> = cfg_ir
        .clean_report
        .removed
        .iter()
        .filter(|removed| {
            matches!(
                removed.kind,
                detection::SectionKind::Auxdata | detection::SectionKind::Padding
            )
        })
        .collect();
    deployed_suffixes.sort_by_key(|removed| removed.offset);
    for removed in deployed_suffixes {
        complete_runtime.extend_from_slice(&removed.data);
    }

    // CRITICAL DEBUGGING: Compare final bytecode to original
    let final_bytecode_snapshot = hex::encode(&final_bytecode);
    let bytecode_actually_changed = original_bytecode_snapshot != final_bytecode_snapshot;

    tracing::debug!("Bytecode comparison:");
    tracing::debug!("  Original size: {} bytes", original_size);
    tracing::debug!("  Final size: {} bytes", obfuscated_size);
    tracing::debug!("  Bytecode actually changed: {}", bytecode_actually_changed);

    if !bytecode_actually_changed {
        tracing::warn!("WARNING: Final bytecode is identical to original despite transforms!");
        tracing::warn!("  This suggests transforms didn't actually modify the bytecode");
        tracing::warn!("  Transform change flags: {:?}", transform_change_log);
    }

    // Step 9: Detailed gas analysis
    let original_zero_bytes = bytes.iter().filter(|&&b| b == 0).count();
    let original_nonzero_bytes = bytes.len() - original_zero_bytes;
    let obfuscated_zero_bytes = final_bytecode.iter().filter(|&&b| b == 0).count();
    let obfuscated_nonzero_bytes = final_bytecode.len() - obfuscated_zero_bytes;

    tracing::debug!("Gas analysis breakdown:");
    tracing::debug!(
        "  Original: {} zeros, {} non-zeros",
        original_zero_bytes,
        original_nonzero_bytes
    );
    tracing::debug!(
        "  Obfuscated: {} zeros, {} non-zeros",
        obfuscated_zero_bytes,
        obfuscated_nonzero_bytes
    );

    let original_gas =
        21_000 + (original_zero_bytes as u64 * 4) + (original_nonzero_bytes as u64 * 16);
    let obfuscated_gas =
        21_000 + (obfuscated_zero_bytes as u64 * 4) + (obfuscated_nonzero_bytes as u64 * 16);
    let gas_delta = obfuscated_gas as i64 - original_gas as i64;

    tracing::debug!("  Original gas: {}", original_gas);
    tracing::debug!("  Obfuscated gas: {}", obfuscated_gas);
    tracing::debug!("  Gas delta: {:+}", gas_delta);

    // Step 10: Enforce protocol size limits. Constructor arguments are part of the creation
    // transaction's initcode for EIP-3860 accounting, while compiler auxdata is part of the
    // EIP-170 deployed-code limit.
    let size_increase_percentage = if original_size > 0 {
        ((obfuscated_size as f64 - original_size as f64) / original_size as f64) * 100.0
    } else {
        0.0
    };
    let deployed_runtime_size = complete_runtime.len();
    let size_limit_exceeded =
        obfuscated_size > MAX_INITCODE_SIZE || deployed_runtime_size > MAX_RUNTIME_CODE_SIZE;
    if size_limit_exceeded {
        return Err(ObfuscationError::from_err(
            format!(
                "obfuscated bytecode exceeds an EVM size limit: initcode {obfuscated_size}/{MAX_INITCODE_SIZE} bytes, deployed runtime {deployed_runtime_size}/{MAX_RUNTIME_CODE_SIZE} bytes"
            ),
            &cfg_ir.trace,
        ));
    }

    // Step 11: Build result
    tracing::debug!("=== Building ObfuscationResult ===");
    if let Some(ref mapping) = cfg_ir.selector_mapping {
        // Selector maps are private interaction material. Never print their contents, including
        // at debug level, because logs are frequently shipped to shared observability systems.
        tracing::debug!("Selector mapping has {} entries", mapping.len());
    } else {
        tracing::debug!("No selector mapping in result");
    }

    let final_snapshot = snapshot_bundle_with_runtime(&cfg_ir, obfuscated_bytes.clone());
    cfg_ir.record_operation(
        OperationKind::Finalize,
        CfgIrDiff::FullSnapshot(Box::new(final_snapshot)),
        None,
    );
    let trace = cfg_ir.trace.clone();

    let canonical_mapping = canonical_selector_mapping(cfg_ir.selector_mapping.as_ref());
    let selector_mapping_commitment = (!canonical_mapping.is_empty()).then(|| {
        let encoded = serde_json::to_vec(&canonical_mapping)
            .expect("BTreeMap<String, String> serialization is infallible");
        keccak_hex(&encoded)
    });
    let input_deployment_keccak256 = keccak_hex(&bytes);
    let input_runtime_keccak256 = keccak_hex(&original_runtime_bytes);
    let output_deployment_keccak256 = keccak_hex(&final_bytecode);
    let output_runtime_keccak256 = keccak_hex(&complete_runtime);
    let reproduction_commitment = reproduction_commitment(
        &pipeline_seed,
        &pipeline_configuration,
        &seed_commitment,
        &input_deployment_keccak256,
        &input_runtime_keccak256,
        &output_deployment_keccak256,
        &output_runtime_keccak256,
        &transforms_applied,
        selector_mapping_commitment.as_deref(),
    );
    let integrity = IntegrityManifest {
        schema_version: 2,
        pipeline_profile: String::from_utf8_lossy(PIPELINE_PROFILE).into_owned(),
        pipeline_configuration,
        seed_commitment,
        input_deployment_keccak256,
        input_runtime_keccak256,
        output_deployment_keccak256,
        output_runtime_keccak256,
        transforms_applied: transforms_applied.clone(),
        selector_mapping_commitment,
        reproduction_commitment,
    };

    Ok(ObfuscationResult {
        obfuscated_bytecode: format!("0x{}", hex::encode(&final_bytecode)),
        obfuscated_runtime: format!("0x{}", hex::encode(&complete_runtime)),
        original_size,
        obfuscated_size,
        size_increase_percentage,
        unknown_opcodes_count: unknown_count,
        unknown_opcode_types: unknown_types,
        blocks_created,
        instructions_added,
        total_instructions,
        metadata: ObfuscationMetadata {
            transforms_applied,
            size_limit_exceeded,
            unknown_opcodes_preserved: config.preserve_unknown_opcodes,
            constructor_args_obfuscated: constructor_args.applied,
            constructor_argument_bytes: constructor_args.argument_bytes,
            constructor_decoder_bytes: constructor_args.decoder_bytes,
        },
        selector_mapping: cfg_ir.selector_mapping,
        integrity,
        trace,
    })
}

fn canonical_selector_mapping(mapping: Option<&HashMap<u32, Vec<u8>>>) -> BTreeMap<String, String> {
    mapping
        .into_iter()
        .flatten()
        .map(|(selector, replacement)| {
            (
                format!("0x{selector:08x}"),
                format!("0x{}", hex::encode(replacement)),
            )
        })
        .collect()
}

fn canonical_calldata_rule(mapping: &BTreeMap<String, String>) -> &'static str {
    if mapping.is_empty() {
        "No selector rewrite was applied; submit ordinary ABI calldata unchanged"
    } else {
        "Replace calldata bytes 0..4 using selector_mapping; preserve bytes 4.. unchanged"
    }
}

fn serialize_optional_selector_mapping<S>(
    mapping: &Option<HashMap<u32, Vec<u8>>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    mapping
        .as_ref()
        .map(|map| map.iter().collect::<BTreeMap<_, _>>())
        .serialize(serializer)
}

fn keccak_hex(bytes: &[u8]) -> String {
    let digest = Keccak256::digest(bytes);
    format!("0x{}", hex::encode(digest))
}

fn decode_result_hex(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| format!("invalid result hex: {error}"))
}

fn derive_pipeline_seed(seed: &Seed, input_deployment: &[u8], input_runtime: &[u8]) -> Seed {
    let mut input_hasher = Sha3_256::new();
    input_hasher.update(PIPELINE_PROFILE);
    input_hasher.update(b"deployment");
    input_hasher.update((input_deployment.len() as u64).to_be_bytes());
    input_hasher.update(input_deployment);
    input_hasher.update(b"runtime");
    input_hasher.update((input_runtime.len() as u64).to_be_bytes());
    input_hasher.update(input_runtime);
    let input_digest: [u8; 32] = input_hasher.finalize().into();
    seed.derive_seed(&input_digest)
}

fn derive_transform_rng(
    pipeline_seed: &Seed,
    transform_name: &str,
    configuration_id: &str,
    occurrence: u64,
) -> DeterministicRng {
    let mut domain = b"AZOTH_TRANSFORM_STREAM_V1".to_vec();
    for field in [
        PIPELINE_PROFILE,
        transform_name.as_bytes(),
        configuration_id.as_bytes(),
    ] {
        domain.extend_from_slice(&(field.len() as u64).to_be_bytes());
        domain.extend_from_slice(field);
    }
    domain.extend_from_slice(&occurrence.to_be_bytes());
    pipeline_seed.derive_rng(&domain)
}

#[allow(clippy::too_many_arguments)]
fn verify_manifest_integrity(
    manifest: &IntegrityManifest,
    input_deployment: &[u8],
    input_runtime: &[u8],
    output_deployment: &[u8],
    output_runtime: &[u8],
    seed: &Seed,
    selector_mapping_commitment: Option<&str>,
) -> Result<(), String> {
    if manifest.schema_version != 2
        || manifest.pipeline_profile != String::from_utf8_lossy(PIPELINE_PROFILE)
    {
        return Err("unsupported integrity manifest profile".to_string());
    }
    if selector_mapping_commitment.is_some()
        && !manifest.pipeline_configuration.rewrite_function_selectors
    {
        return Err(
            "selector mapping is incompatible with the declared pipeline configuration".to_string(),
        );
    }
    if manifest
        .transforms_applied
        .iter()
        .any(|name| name == "ConstructorArgs")
        && !manifest
            .pipeline_configuration
            .obfuscate_constructor_arguments
    {
        return Err(
            "constructor-argument transform is incompatible with the declared pipeline configuration"
                .to_string(),
        );
    }

    let pipeline_seed = derive_pipeline_seed(seed, input_deployment, input_runtime);
    let expected_seed_commitment = pipeline_seed
        .derive_seed(b"integrity-seed-commitment")
        .hash_hex();
    if manifest.seed_commitment != expected_seed_commitment {
        return Err("seed commitment mismatch".to_string());
    }

    for (label, actual, expected) in [
        (
            "input deployment",
            manifest.input_deployment_keccak256.as_str(),
            keccak_hex(input_deployment),
        ),
        (
            "input runtime",
            manifest.input_runtime_keccak256.as_str(),
            keccak_hex(input_runtime),
        ),
        (
            "output deployment",
            manifest.output_deployment_keccak256.as_str(),
            keccak_hex(output_deployment),
        ),
        (
            "output runtime",
            manifest.output_runtime_keccak256.as_str(),
            keccak_hex(output_runtime),
        ),
    ] {
        if actual != expected {
            return Err(format!("{label} hash mismatch"));
        }
    }
    if manifest.selector_mapping_commitment.as_deref() != selector_mapping_commitment {
        return Err("selector mapping commitment mismatch".to_string());
    }

    let expected_reproduction = reproduction_commitment(
        &pipeline_seed,
        &manifest.pipeline_configuration,
        &manifest.seed_commitment,
        &manifest.input_deployment_keccak256,
        &manifest.input_runtime_keccak256,
        &manifest.output_deployment_keccak256,
        &manifest.output_runtime_keccak256,
        &manifest.transforms_applied,
        manifest.selector_mapping_commitment.as_deref(),
    );
    if manifest.reproduction_commitment != expected_reproduction {
        return Err("authenticated reproduction tag mismatch".to_string());
    }
    Ok(())
}

fn update_commitment_field(mac: &mut HmacSha3_256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

#[allow(clippy::too_many_arguments)]
fn reproduction_commitment(
    pipeline_seed: &Seed,
    pipeline_configuration: &PipelineConfigurationManifest,
    seed_commitment: &str,
    input_deployment: &str,
    input_runtime: &str,
    output_deployment: &str,
    output_runtime: &str,
    transforms: &[String],
    selector_mapping: Option<&str>,
) -> String {
    let authentication_key = pipeline_seed.derive_seed(b"integrity-reproduction-hmac");
    let mut mac = HmacSha3_256::new_from_slice(authentication_key.as_bytes())
        .expect("HMAC-SHA3-256 accepts a 32-byte key");
    mac.update(b"AZOTH_REPRODUCTION_COMMITMENT_V2");
    mac.update(&(pipeline_configuration.requested_transforms.len() as u64).to_be_bytes());
    for transform in &pipeline_configuration.requested_transforms {
        update_commitment_field(&mut mac, transform.name.as_bytes());
        update_commitment_field(&mut mac, transform.configuration_id.as_bytes());
    }
    mac.update(&[
        u8::from(pipeline_configuration.preserve_unknown_opcodes),
        u8::from(pipeline_configuration.rewrite_function_selectors),
        u8::from(pipeline_configuration.obfuscate_constructor_arguments),
    ]);
    for field in [
        PIPELINE_PROFILE,
        seed_commitment.as_bytes(),
        input_deployment.as_bytes(),
        input_runtime.as_bytes(),
        output_deployment.as_bytes(),
        output_runtime.as_bytes(),
    ] {
        update_commitment_field(&mut mac, field);
    }
    mac.update(&(transforms.len() as u64).to_be_bytes());
    for transform in transforms {
        update_commitment_field(&mut mac, transform.as_bytes());
    }
    match selector_mapping {
        Some(commitment) => {
            mac.update(&[1]);
            update_commitment_field(&mut mac, commitment.as_bytes());
        }
        None => mac.update(&[0]),
    }
    format!("0x{}", hex::encode(mac.finalize().into_bytes()))
}

/// Analyzes instructions to count unknown opcodes and provide feedback.
fn analyze_instructions(
    instructions: &[decoder::Instruction],
    original_bytecode: &[u8],
) -> (usize, usize, Vec<String>) {
    let total_count = instructions.len();
    let mut unknown_count = 0;
    let mut unknown_types = HashSet::new();

    for instruction in instructions {
        // Native decoding distinguishes the real 0xfe INVALID opcode from every unassigned raw
        // byte. A final truncated PUSH is executable via EVM zero-extension, but cannot safely be
        // relocated or followed by inserted code, so it is unsupported by transformations too.
        let is_unmodelled = instruction.op.is_unknown() || instruction.is_truncated_push();
        if is_unmodelled {
            unknown_count += 1;
            let raw = original_bytecode
                .get(instruction.pc)
                .map(|byte| format!("0x{byte:02x}"))
                .unwrap_or_else(|| "out-of-bounds".to_string());
            unknown_types.insert(format!("{} ({raw})", instruction.op));
        }
    }

    let mut unknown_types: Vec<_> = unknown_types.into_iter().collect();
    unknown_types.sort();
    (total_count, unknown_count, unknown_types)
}

/// Count instructions in CFG
fn count_instructions_in_cfg(cfg_ir: &cfg_ir::CfgIrBundle) -> usize {
    cfg_ir
        .cfg
        .node_indices()
        .filter_map(|n| {
            if let cfg_ir::Block::Body(body) = &cfg_ir.cfg[n] {
                Some(body.instructions.len())
            } else {
                None
            }
        })
        .sum()
}

/// Extract all instructions from CFG
fn extract_instructions_from_cfg(cfg_ir: &cfg_ir::CfgIrBundle) -> Vec<decoder::Instruction> {
    let mut all_instructions = Vec::new();

    for node_idx in cfg_ir.cfg.node_indices() {
        if let cfg_ir::Block::Body(body) = &cfg_ir.cfg[node_idx] {
            all_instructions.extend(body.instructions.clone());
        }
    }

    // CRITICAL: Sort instructions by PC before encoding!
    // Without this, blocks added at high PCs could end up out of order,
    // causing them to be embedded in PUSH instruction immediates.
    all_instructions.sort_by_key(|instr| instr.pc);

    // Debug: Check what instructions are at controller PCs
    if let Some(controller_pcs) = &cfg_ir.dispatcher_controller_pcs {
        for (selector, &pc) in controller_pcs.iter() {
            let controller_instrs: Vec<_> = all_instructions
                .iter()
                .filter(|i| i.pc >= pc && i.pc < pc + 50)
                .take(5)
                .map(|i| format!("0x{:04x}:{:?}", i.pc, i.op))
                .collect();

            tracing::debug!(
                "  Extract: Controller 0x{:08x} at PC 0x{:04x}: {:?}",
                selector,
                pc,
                controller_instrs
            );
        }
    }

    all_instructions
}

/// Prints detailed analysis of the obfuscation process
pub fn print_obfuscation_analysis(result: &ObfuscationResult) {
    // Print input analysis if unknown opcodes were found
    if result.unknown_opcodes_count > 0 {
        println!("Input Analysis:");
        println!("Total instructions: {}", result.total_instructions);
        println!(
            "Unknown opcodes: {} ({:.1}%)",
            result.unknown_opcodes_count,
            100.0 * result.unknown_opcodes_count as f64 / result.total_instructions as f64
        );
        println!("Unknown types found: {:?}", result.unknown_opcode_types);
        println!("   → These will be preserved as raw bytes in the output.");
        println!("   → If the original contract works, the obfuscated version should too.");
        println!();
    }

    // Print transform analysis
    println!("Transform Analysis:");
    println!("Original size: {} bytes", result.original_size);
    println!(
        "Applying {} transforms: {:?}",
        result.metadata.transforms_applied.len(),
        result.metadata.transforms_applied
    );

    if result.blocks_created > 0 {
        println!("Blocks created: {}", result.blocks_created);
    }
    if result.instructions_added > 0 {
        println!("Instructions added: {}", result.instructions_added);
    }
    if result.metadata.constructor_args_obfuscated {
        println!(
            "Constructor arguments: {} bytes obfuscated, {} decoder bytes",
            result.metadata.constructor_argument_bytes, result.metadata.constructor_decoder_bytes
        );
    }

    // Print success summary
    if result.unknown_opcodes_count > 0 {
        println!(
            "Obfuscation complete with {} unknown opcodes preserved",
            result.unknown_opcodes_count
        );
    } else {
        println!("Obfuscation complete");
    }

    println!(
        "Size change: {} → {} bytes ({:+.1}%)",
        result.original_size, result.obfuscated_size, result.size_increase_percentage
    );
    println!();
}

/// Creates a gas report from obfuscation results
pub fn create_gas_report(result: &ObfuscationResult) -> serde_json::Value {
    let gas = |bytes| 32_000 + 200 * bytes as u64;

    json!({
        "original_bytes": result.original_size,
        "obfuscated_bytes": result.obfuscated_size,
        "size_delta_bytes": (result.obfuscated_size as i64 - result.original_size as i64),
        "original_deploy_gas": gas(result.original_size),
        "obfuscated_deploy_gas": gas(result.obfuscated_size),
        "gas_delta": (gas(result.obfuscated_size) as i64 - gas(result.original_size) as i64),
        "percent_size": result.size_increase_percentage,
        "unknown_opcodes_preserved": result.unknown_opcodes_count,
        "blocks_created": result.blocks_created,
        "instructions_added": result.instructions_added,
        "transforms_applied": result.metadata.transforms_applied,
        "constructor_args_obfuscated": result.metadata.constructor_args_obfuscated,
        "constructor_argument_bytes": result.metadata.constructor_argument_bytes,
        "constructor_decoder_bytes": result.metadata.constructor_decoder_bytes,
        "notes": if result.unknown_opcodes_count > 0 {
            "Unknown opcodes were preserved as raw bytes to maintain functionality"
        } else {
            "All opcodes were standard and successfully obfuscated"
        }
    })
}

#[cfg(test)]
mod safety_tests {
    use super::{
        analyze_instructions, derive_pipeline_seed, derive_transform_rng, obfuscate_bytecode,
        ObfuscationConfig,
    };
    use azoth_core::{decoder::Instruction, seed::Seed, Opcode};
    use rand::RngCore;

    async fn assert_init_contract_rejected(deployment: &str, runtime: &str) -> String {
        obfuscate_bytecode(
            deployment,
            runtime,
            ObfuscationConfig::with_seed(Seed::from_bytes([1; 32])),
        )
        .await
        .expect_err("unsafe init/runtime provenance must fail closed")
        .message
    }

    #[test]
    fn pipeline_seed_is_bound_to_both_bytecode_inputs() {
        let root = Seed::from_bytes([0x42; 32]);
        let baseline = derive_pipeline_seed(&root, b"deployment", b"runtime");
        assert_ne!(
            baseline.as_bytes(),
            derive_pipeline_seed(&root, b"other deployment", b"runtime").as_bytes()
        );
        assert_ne!(
            baseline.as_bytes(),
            derive_pipeline_seed(&root, b"deployment", b"other runtime").as_bytes()
        );
    }

    #[test]
    fn transform_rng_is_bound_to_name_configuration_and_occurrence() {
        let pipeline_seed = Seed::from_bytes([0x51; 32]);
        let sample = |name, configuration, occurrence| {
            derive_transform_rng(&pipeline_seed, name, configuration, occurrence).next_u64()
        };

        assert_eq!(
            sample("Pass", "Pass@v1;a=1", 0),
            sample("Pass", "Pass@v1;a=1", 0)
        );
        assert_ne!(
            sample("Pass", "Pass@v1;a=1", 0),
            sample("Other", "Pass@v1;a=1", 0)
        );
        assert_ne!(
            sample("Pass", "Pass@v1;a=1", 0),
            sample("Pass", "Pass@v1;a=2", 0)
        );
        assert_ne!(
            sample("Pass", "Pass@v1;a=1", 0),
            sample("Pass", "Pass@v1;a=1", 1)
        );
    }

    #[tokio::test]
    async fn authenticated_recipe_records_requested_noop_passes() {
        let seed = Seed::from_bytes([0x19; 32]);
        let with_default_pass =
            obfuscate_bytecode("0x00", "0x00", ObfuscationConfig::with_seed(seed.clone()))
                .await
                .expect("single terminal runtime is supported");
        let mut empty_config = ObfuscationConfig::with_seed(seed.clone());
        empty_config.transforms.clear();
        let without_pass = obfuscate_bytecode("0x00", "0x00", empty_config)
            .await
            .expect("empty pass list is supported");

        assert_eq!(
            with_default_pass.obfuscated_bytecode, without_pass.obfuscated_bytecode,
            "the default layout pass is a no-op for one block"
        );
        assert_ne!(
            with_default_pass.integrity.pipeline_configuration,
            without_pass.integrity.pipeline_configuration,
            "the authenticated replay recipe must distinguish a requested no-op pass"
        );
        assert_ne!(
            with_default_pass.integrity.reproduction_commitment,
            without_pass.integrity.reproduction_commitment,
            "configuration changes must alter the authenticated reproduction tag"
        );

        with_default_pass
            .verify_integrity(&[0x00], &[0x00], &seed)
            .expect("default recipe authenticates");
        without_pass
            .verify_integrity(&[0x00], &[0x00], &seed)
            .expect("empty recipe authenticates");
    }

    #[test]
    fn invalid_is_known_and_unknown_bytes_are_not() {
        let invalid = Instruction {
            pc: 0,
            op: Opcode::INVALID,
            imm: None,
        };
        assert_eq!(
            analyze_instructions(std::slice::from_ref(&invalid), &[0xfe]).1,
            0
        );
        assert_eq!(analyze_instructions(&[invalid], &[0xaa]).1, 0);

        let unknown = Instruction {
            pc: 0,
            op: Opcode::UNKNOWN(0xaa),
            imm: None,
        };
        assert_eq!(analyze_instructions(&[unknown], &[0xaa]).1, 1);
    }

    #[tokio::test]
    async fn constructor_materialized_jump_destination_is_rejected_before_layout() {
        // The constructor copies the 48-byte runtime then writes 0x23 over the PUSH32-zero
        // immediate at runtime offset 2. In the deployed code the first JUMP therefore enters the
        // `return 42` block at 0x23. Reading the unlinked template as `PUSH32 0` would instead
        // invent an edge to PC 0 and permit a shuffle to put the revert block at 0x23.
        let runtime = format!("0x5b7f{}565b602a5f5260205ff35b5f5ffd", "00".repeat(32));
        let deployment = format!(
            "0x60235f603090816016823950505f6002015260305ff3{}",
            runtime.trim_start_matches("0x")
        );

        let error = obfuscate_bytecode(
            &deployment,
            &runtime,
            ObfuscationConfig::with_seed(Seed::from_bytes([1; 32])),
        )
        .await
        .expect_err("a constructor-materialized jump destination must fail closed");

        assert!(
            error
                .message
                .contains("constructor-materialized runtime word"),
            "unexpected error: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn init_returning_a_different_code_range_is_rejected() {
        let runtime = "0x005b6001005b6002005b600300";
        let deployment = "0x600160175f3960015ff3005b6001005b6002005b60030000";

        let message = assert_init_contract_rejected(deployment, runtime).await;

        assert!(
            message.contains("no proven runtime CODECOPY")
                || message.contains("deployment differs from supplied runtime"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn runtime_at_offset_zero_with_extra_deployment_bytes_is_rejected() {
        let message = assert_init_contract_rejected("0x5b0001", "0x5b00").await;

        assert!(
            message.contains("deployment differs from supplied runtime")
                || message.contains("runtime"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn arbitrary_post_copy_runtime_patch_is_rejected() {
        let runtime = "0x6003565b60005f5260205ff35b60995f5260205ff3";
        let deployment = format!("0x6015600f5f39602a60055360155ff3{}", &runtime[2..]);

        let message = assert_init_contract_rejected(&deployment, runtime).await;

        assert!(
            message.contains("opcode 0x53"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn post_copy_runtime_observation_and_side_effect_are_rejected() {
        let runtime = "0x005b6001005b6002005b600300";
        let deployment = format!("0x600d60105f39600d5ff205f55600d5ff3{}", &runtime[2..]);

        let message = assert_init_contract_rejected(&deployment, runtime).await;

        assert!(
            message.contains("opcode 0xf2")
                || message.contains("before proven RETURN")
                || message.contains("no proven runtime CODECOPY"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn secondary_runtime_codecopy_observation_is_rejected() {
        let runtime = "0x6003565b5f545f5260205ff35b60995f5260205ff3";
        let deployment = format!(
            "0x602e3850506001601e5f395f515f55601560195f3960155ff3{}",
            &runtime[2..]
        );

        let message = assert_init_contract_rejected(&deployment, runtime).await;

        assert!(
            message.contains("secondary CODECOPY") || message.contains("CODESIZE"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn secondary_codecopy_cannot_observe_rewritten_init_immediate() {
        let runtime = format!("0x6027565b7f{}50005b5f545f5260205ff3", "00".repeat(32));
        let deployment = format!(
            "0x600160145f395f515f556030601b5f39602a5f6005015260305ff3{}",
            &runtime[2..]
        );

        let message = assert_init_contract_rejected(&deployment, &runtime).await;

        assert!(
            message.contains("secondary CODECOPY"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn immutable_write_with_unrelated_memory_base_is_rejected() {
        let runtime = format!(
            "0x6027565b7f{}50005b7f01{}5f5260205ff3",
            "00".repeat(32),
            "00".repeat(31)
        );
        let deployment = format!("0x604f60125f39602a602460050152604f5ff3{}", &runtime[2..]);

        let message = assert_init_contract_rejected(&deployment, &runtime).await;

        assert!(
            message.contains("proven copy destination"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn constructor_controlled_free_memory_pointer_cannot_hide_runtime_read() {
        // The constructor argument sets memory[0x40] to 0x20. The compiler-shaped terminal copy
        // therefore places the runtime at 0x20, and the following MLOAD feeds those bytes to
        // storage before RETURN. A syntactic "initial free-memory value" fallback would mistake
        // the destination for 0x80 and incorrectly call the MLOAD disjoint.
        let runtime = "0x005b6001005b6002005b600300";
        let mut argument = "00".repeat(31);
        argument.push_str("20");
        let deployment = format!(
            "0x60808060405250602b35604052604051600d9081601e82396020515f55f3{}{}",
            &runtime[2..],
            argument
        );

        let message = assert_init_contract_rejected(&deployment, runtime).await;

        assert!(
            message.contains("lower bound") || message.contains("MLOAD"),
            "unexpected error: {message}"
        );
    }
}
