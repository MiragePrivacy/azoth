use crate::cluster_shuffle::ClusterShuffle;
use crate::constructor_args::obfuscate_constructor_args;
use crate::function_dispatcher::FunctionDispatcher;
use crate::jump_trampoline::JumpTrampoline;
use crate::metadata::diversify_metadata;
use crate::{has_gas_observation, has_self_code_layout_semantics, Transform};
use azoth_core::seed::Seed;
use azoth_core::{
    cfg_ir::{self, snapshot_bundle_with_runtime, Block, CfgIrDiff, OperationKind, TraceEvent},
    decoder, detection, encoder, process_bytecode_to_cfg, validator, Opcode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};

const MAX_INITCODE_SIZE: usize = 49_152;
const MAX_RUNTIME_CODE_SIZE: usize = 24_576;

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
}

impl ObfuscationConfig {
    /// Create config with a specific seed
    pub fn with_seed(seed: Seed) -> Self {
        Self {
            seed,
            transforms: production_transforms(),
            preserve_unknown_opcodes: true,
        }
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            seed: Seed::generate(),
            transforms: production_transforms(),
            preserve_unknown_opcodes: true,
        }
    }
}

fn production_transforms() -> Vec<Box<dyn Transform>> {
    vec![
        Box::new(JumpTrampoline::new()),
        Box::new(ClusterShuffle::new()),
    ]
}

impl std::fmt::Debug for ObfuscationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfuscationConfig")
            .field(
                "transforms",
                &format!("{} transforms", self.transforms.len()),
            )
            .field("preserve_unknown_opcodes", &self.preserve_unknown_opcodes)
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
    /// Original deployed runtime size, including compiler auxdata and padding.
    #[serde(default)]
    pub original_runtime_size: usize,
    /// Obfuscated deployed runtime size, including compiler auxdata and padding.
    #[serde(default)]
    pub obfuscated_runtime_size: usize,
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
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
    /// Trace of CFG operations captured during obfuscation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationMetadata {
    /// Exact generation seed required to reproduce this variant.
    #[serde(default)]
    pub generation_seed: String,
    /// Names of transforms that were applied
    pub transforms_applied: Vec<String>,
    /// Every pass that was attempted, including passes which safely made no change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transforms_attempted: Vec<String>,
    /// Transactional outcome and committed structural delta for each attempted pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transform_outcomes: Vec<TransformOutcome>,
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
    /// Number of compiler metadata content digests diversified for this seed.
    #[serde(default)]
    pub metadata_digests_diversified: usize,
}

/// Truthful result of one transactionally executed transform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransformOutcome {
    /// Transform name.
    pub name: String,
    /// `applied` or `no_change`.
    pub status: String,
    /// Committed body-block count delta.
    pub blocks_delta: i32,
    /// Committed instruction count delta.
    pub instructions_delta: i32,
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

    tracing::debug!("  Input size: {} bytes", original_size);

    // Step 2: Analyze instructions for unknown opcodes
    let executable_instructions: Vec<_> = instructions
        .iter()
        .filter(|instruction| {
            sections.iter().any(|section| {
                matches!(
                    section.kind,
                    detection::SectionKind::Init | detection::SectionKind::Runtime
                ) && instruction.pc >= section.offset
                    && instruction.pc < section.offset + section.len
            })
        })
        .cloned()
        .collect();
    let (total_instructions, unknown_count, unknown_types) =
        analyze_instructions(&executable_instructions, &bytes);
    tracing::debug!("  Total instructions: {}", total_instructions);
    tracing::debug!("  Unknown opcodes: {}", unknown_count);
    if unknown_count > 0 && !config.preserve_unknown_opcodes {
        return Err(ObfuscationError::from_err(
            format!(
                "input contains {unknown_count} decoder-unknown opcode(s) ({}) but preserve_unknown_opcodes is disabled",
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
    let original_runtime_size: usize = sections
        .iter()
        .filter(|section| {
            matches!(
                section.kind,
                detection::SectionKind::Runtime
                    | detection::SectionKind::Auxdata
                    | detection::SectionKind::Padding
            )
        })
        .map(|section| section.len)
        .sum();

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

    let dispatcher_info = if let Some(runtime_sec) = runtime_section {
        // Filter instructions to only those in runtime section
        let runtime_instructions: Vec<_> = instructions
            .iter()
            .filter(|instruction| {
                instruction.pc >= runtime_sec.offset
                    && instruction.pc < runtime_sec.offset + runtime_sec.len
            })
            .cloned()
            .collect();

        tracing::debug!(
            "Checking for dispatcher in {} runtime instructions",
            runtime_instructions.len()
        );
        detection::detect_function_dispatcher(&runtime_instructions)
    } else {
        // No runtime section = probably pure runtime bytecode
        detection::detect_function_dispatcher(&instructions)
    };

    // Store dispatcher info in bundle for snapshot/TUI visualization
    cfg_ir.dispatcher_info = dispatcher_info.clone();

    if let Some(dispatcher) = dispatcher_info {
        tracing::debug!(
            "Function dispatcher detected with {} selectors - adding FunctionDispatcher transform",
            dispatcher.selectors.len()
        );
        all_transforms.push(Box::new(FunctionDispatcher::with_dispatcher_info_and_seed(
            dispatcher,
            config.seed.clone(),
        )));
    } else {
        tracing::debug!(
            "No function dispatcher detected in runtime - skipping FunctionDispatcher transform"
        );
    }

    // Add user-specified transforms (this moves config.transforms)
    all_transforms.extend(config.transforms);

    // Runtime code-layout introspection needs typed data/code relocation and alias
    // analysis which this IR cannot yet prove. EXTCODE* is conservatively included
    // because its target may be self.
    let self_code_sensitive = has_self_code_layout_semantics(&cfg_ir);
    if self_code_sensitive && !all_transforms.is_empty() {
        return Err(ObfuscationError::from_err(
            "runtime uses PC/CODESIZE/CODECOPY/EXTCODESIZE/EXTCODECOPY/EXTCODEHASH; typed relocation or self-address alias analysis is not supported",
            &cfg_ir.trace,
        ));
    }
    if let Some(transform) = has_gas_observation(&cfg_ir)
        .then(|| {
            all_transforms
                .iter()
                .find(|transform| !transform.supports_gas_observation())
        })
        .flatten()
    {
        return Err(ObfuscationError::from_err(
            format!(
                "transform {} may add executed gas before a GAS observation; only gas-neutral selector replacement/layout shuffling and the self-skipping JumpTrampoline are supported",
                transform.name()
            ),
            &cfg_ir.trace,
        ));
    }

    // Track only transforms whose changes were transactionally committed.
    let mut transforms_applied: Vec<String> = Vec::new();
    let mut transforms_attempted: Vec<String> = Vec::new();
    let mut transform_outcomes: Vec<TransformOutcome> = Vec::new();

    // Track individual transform effects
    let mut transform_change_log = Vec::new();
    let mut any_transform_changed = false;

    if !all_transforms.is_empty() {
        tracing::debug!("Applying {} transforms", all_transforms.len(),);

        for (i, transform) in all_transforms.iter().enumerate() {
            let transform_name = transform.name();
            transforms_attempted.push(transform_name.to_string());
            let pre_instruction_count = count_instructions_in_cfg(&cfg_ir);
            let pre_block_count = cfg_ir.cfg.node_count();

            tracing::debug!(
                "  Transform {}: {} (pre: {} blocks, {} instructions)",
                i,
                transform_name,
                pre_block_count,
                pre_instruction_count
            );

            // Execute against a clone. Errors abort the whole pipeline and a
            // false/no-change result cannot leak partial mutations.
            let mut candidate = cfg_ir.clone();
            candidate.record_transform_start(transform_name);
            let domain = format!("{transform_name}:{i}");
            let mut transform_rng = config.seed.create_domain_rng(domain.as_bytes());
            let transform_changed = transform
                .apply(&mut candidate, &mut transform_rng)
                .map_err(|error| {
                    ObfuscationError::from_err(
                        format!("transform {transform_name} failed: {error}"),
                        &candidate.trace,
                    )
                })?;
            candidate.record_transform_end(transform_name);

            let (post_instruction_count, post_block_count) = if transform_changed {
                let counts = (
                    count_instructions_in_cfg(&candidate),
                    candidate.cfg.node_count(),
                );
                cfg_ir = candidate;
                transforms_applied.push(transform_name.to_string());
                counts
            } else {
                (pre_instruction_count, pre_block_count)
            };
            let instructions_delta = post_instruction_count as i32 - pre_instruction_count as i32;
            let blocks_delta = post_block_count as i32 - pre_block_count as i32;

            transform_outcomes.push(TransformOutcome {
                name: transform_name.to_string(),
                status: if transform_changed {
                    "applied".to_string()
                } else {
                    "no_change".to_string()
                },
                blocks_delta,
                instructions_delta,
            });

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

    // Build typed relocation evidence while instruction PCs still refer to the
    // original layout. This follows stack-carried Solidity return addresses
    // across CFG edges and rejects unresolved dynamic jumps or mixed data/address
    // uses instead of guessing from numeric equality with a JUMPDEST.
    let proven_jump_pushes = cfg_ir
        .prove_jump_address_pushes()
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;

    // Capture old instruction layout before reindexing (needed for immutable ref patching).
    // For each runtime instruction, record (old_pc, byte_size) so we can build a byte-level
    // displacement map after reindex_pcs remaps instruction PCs.
    let old_runtime_start = cfg_ir.runtime_bounds.map(|(s, _)| s).unwrap_or(0);
    let old_instr_layout: Vec<(usize, usize)> = {
        let mut layout = Vec::new();
        let rt_bounds = cfg_ir.runtime_bounds;
        for node_idx in cfg_ir.cfg.node_indices() {
            if let cfg_ir::Block::Body(body) = &cfg_ir.cfg[node_idx] {
                let in_runtime = match rt_bounds {
                    Some((start, end)) => body.start_pc >= start && body.start_pc < end,
                    None => true,
                };
                if in_runtime {
                    for instr in &body.instructions {
                        layout.push((instr.pc, instr.byte_size()));
                    }
                }
            }
        }
        layout.sort_by_key(|(pc, _)| *pc);
        layout
    };

    // Step 5: Reindex PCs
    tracing::debug!("  Reindexing PCs to normalize to 0-based addressing");
    let (pc_mapping, old_runtime_bounds) = cfg_ir
        .reindex_pcs()
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
    tracing::debug!("  PC reindexing complete: {} mappings", pc_mapping.len());

    // PUSH0 can encode only runtime-relative target zero. It is safe only
    // while the original runtime entry remains the transformed runtime entry;
    // unlike PUSH1 0x00, there is no immediate to rewrite.
    if proven_jump_pushes.uses_push0_target {
        let old_runtime_start = old_runtime_bounds.map(|(start, _)| start).unwrap_or(0);
        let new_runtime_start = cfg_ir.runtime_bounds.map(|(start, _)| start).unwrap_or(0);
        let relocated_entry = pc_mapping.get(&old_runtime_start).copied().ok_or_else(|| {
            ObfuscationError::from_err(
                "PUSH0 jump target has no runtime-entry relocation",
                &cfg_ir.trace,
            )
        })?;
        if relocated_entry != new_runtime_start {
            return Err(ObfuscationError::from_err(
                "PUSH0 jump target cannot be relocated away from runtime-relative PC zero",
                &cfg_ir.trace,
            ));
        }
    }

    // Patch jump immediates using the PC mapping
    cfg_ir
        .patch_jump_immediates(&pc_mapping, old_runtime_bounds)
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
    tracing::debug!("  Patched jump immediates after PC reindexing");

    // Remap only PUSHes proven to flow exclusively into JUMP/JUMPI targets.
    cfg_ir
        .remap_proven_jump_pushes(&proven_jump_pushes.pushes, &pc_mapping, old_runtime_bounds)
        .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;

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

    // Step 7b: Patch compiler-proven immutable reference offsets in init code.
    // Build a byte-level displacement map, but only apply it to exact Solidity
    // PUSH32-placeholder/ADD/MSTORE sites in the runtime CODECOPY/RETURN region.
    {
        let mut original_clean_runtime = Vec::with_capacity(cfg_ir.clean_report.clean_len);
        for span in &cfg_ir.clean_report.runtime_layout {
            let end = span.offset.checked_add(span.len).ok_or_else(|| {
                ObfuscationError::from_err("original runtime span overflowed", &cfg_ir.trace)
            })?;
            let source = bytes.get(span.offset..end).ok_or_else(|| {
                ObfuscationError::from_err(
                    "original runtime span is outside deployment bytecode",
                    &cfg_ir.trace,
                )
            })?;
            original_clean_runtime.extend_from_slice(source);
        }
        if original_clean_runtime.len() != cfg_ir.clean_report.clean_len {
            return Err(ObfuscationError::from_err(
                "original clean-runtime length disagrees with strip report",
                &cfg_ir.trace,
            ));
        }
        let new_runtime_start = cfg_ir.runtime_bounds.map(|(s, _)| s).unwrap_or(0);
        // Build byte-level remap: for each byte in the old runtime, compute where it lands
        // in the new runtime. We build a sorted list of (old_rel_offset, new_rel_offset) for
        // each instruction start, then for any query offset, find the containing instruction
        // and compute the intra-instruction delta.
        let mut byte_remap_entries: Vec<(usize, usize, usize)> = Vec::new(); // (old_rel, new_rel, size)
        for &(old_pc, byte_size) in &old_instr_layout {
            if let Some(&new_pc) = pc_mapping.get(&old_pc) {
                let old_rel = old_pc.saturating_sub(old_runtime_start);
                let new_rel = new_pc.saturating_sub(new_runtime_start);
                byte_remap_entries.push((old_rel, new_rel, byte_size));
            }
        }
        byte_remap_entries.sort_by_key(|(old_rel, _, _)| *old_rel);

        let remap = |old_offset: usize| -> Option<usize> {
            // Binary search for the instruction containing this byte offset
            match byte_remap_entries.binary_search_by_key(&old_offset, |(old_rel, _, _)| *old_rel) {
                Ok(i) => {
                    // Exact match on instruction start
                    Some(byte_remap_entries[i].1)
                }
                Err(i) if i > 0 => {
                    // old_offset falls within the instruction at index i-1
                    let (old_rel, new_rel, size) = byte_remap_entries[i - 1];
                    let delta = old_offset - old_rel;
                    if delta < size {
                        Some(new_rel + delta)
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };

        cfg_ir
            .clean_report
            .patch_init_immutable_refs(&remap, &original_clean_runtime)
            .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    }

    // Step 7c: Mask an exact constructor-argument suffix and inject a seed-varied decoder.
    // This runs after init immutable patching so its insertion can remap all existing init jumps
    // once. It fails closed when arguments exist but their copy site is unsupported.
    transforms_attempted.push("ConstructorArgs".to_string());
    let constructor_args =
        obfuscate_constructor_args(&mut cfg_ir.clean_report, config.seed.as_bytes())
            .map_err(|e| ObfuscationError::from_err(e, &cfg_ir.trace))?;
    if constructor_args.applied {
        transforms_applied.push("ConstructorArgs".to_string());
        tracing::debug!(
            "  Obfuscated {} constructor argument bytes with a {}-byte decoder",
            constructor_args.argument_bytes,
            constructor_args.decoder_bytes
        );
    }
    transform_outcomes.push(TransformOutcome {
        name: "ConstructorArgs".to_string(),
        status: if constructor_args.applied {
            "applied".to_string()
        } else {
            "no_change".to_string()
        },
        blocks_delta: 0,
        instructions_delta: 0,
    });

    // Preserve the ordinary Solidity CBOR envelope and compiler marker while
    // removing the source-linked digest shared by every seed. Self-code-aware
    // runtimes were rejected above, so this cannot affect runtime CODECOPY data.
    transforms_attempted.push("MetadataDigest".to_string());
    let metadata_digests_diversified = if self_code_sensitive {
        0
    } else {
        diversify_metadata(&mut cfg_ir.clean_report, config.seed.as_bytes())
    };
    if metadata_digests_diversified > 0 {
        transforms_applied.push("MetadataDigest".to_string());
    }
    transform_outcomes.push(TransformOutcome {
        name: "MetadataDigest".to_string(),
        status: if metadata_digests_diversified > 0 {
            "applied".to_string()
        } else {
            "no_change".to_string()
        },
        blocks_delta: 0,
        instructions_delta: 0,
    });

    // Step 8: Reassemble final bytecode (init + runtime with data section + auxdata)
    let final_bytecode = cfg_ir
        .clean_report
        .reassemble_checked(&obfuscated_bytes)
        .map_err(|error| ObfuscationError::from_err(error, &cfg_ir.trace))?;
    let obfuscated_size = final_bytecode.len();

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

    // Step 9: Account only for the byte-dependent portion of transaction calldata.
    // This is not a deployment-gas estimate: the transaction base charge, create
    // charge, init execution, code deposit, and EIP-3860 are separate.
    let original_zero_bytes = bytes.iter().filter(|&&b| b == 0).count();
    let original_nonzero_bytes = bytes.len() - original_zero_bytes;
    let obfuscated_zero_bytes = final_bytecode.iter().filter(|&&b| b == 0).count();
    let obfuscated_nonzero_bytes = final_bytecode.len() - obfuscated_zero_bytes;

    tracing::debug!("Creation-input calldata byte-gas breakdown:");
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

    let original_calldata_byte_gas =
        (original_zero_bytes as u64 * 4) + (original_nonzero_bytes as u64 * 16);
    let obfuscated_calldata_byte_gas =
        (obfuscated_zero_bytes as u64 * 4) + (obfuscated_nonzero_bytes as u64 * 16);
    let calldata_byte_gas_delta =
        obfuscated_calldata_byte_gas as i64 - original_calldata_byte_gas as i64;

    tracing::debug!(
        "  Original creation-input calldata byte gas: {}",
        original_calldata_byte_gas
    );
    tracing::debug!(
        "  Obfuscated creation-input calldata byte gas: {}",
        obfuscated_calldata_byte_gas
    );
    tracing::debug!(
        "  Creation-input calldata byte-gas delta: {:+}",
        calldata_byte_gas_delta
    );

    // Step 10: Enforce protocol size limits. Constructor arguments are part of the creation
    // transaction's initcode for EIP-3860 accounting, while compiler auxdata is part of the
    // EIP-170 deployed-code limit.
    let size_increase_percentage = if original_size > 0 {
        ((obfuscated_size as f64 - original_size as f64) / original_size as f64) * 100.0
    } else {
        0.0
    };
    let deployed_suffix_size: usize = sections
        .iter()
        .filter(|section| {
            matches!(
                section.kind,
                detection::SectionKind::Auxdata | detection::SectionKind::Padding
            )
        })
        .map(|section| section.len)
        .sum();
    let deployed_runtime_size = obfuscated_bytes.len() + deployed_suffix_size;
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
        tracing::debug!("Selector mapping has {} entries:", mapping.len());
        for (selector, token) in mapping {
            tracing::debug!(
                "  Selector 0x{:08x} -> Token 0x{}",
                selector,
                hex::encode(token)
            );
        }
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

    Ok(ObfuscationResult {
        obfuscated_bytecode: format!("0x{}", hex::encode(&final_bytecode)),
        obfuscated_runtime: format!("0x{}", hex::encode(&obfuscated_bytes)),
        original_size,
        obfuscated_size,
        original_runtime_size,
        obfuscated_runtime_size: deployed_runtime_size,
        size_increase_percentage,
        unknown_opcodes_count: unknown_count,
        unknown_opcode_types: unknown_types,
        blocks_created,
        instructions_added,
        total_instructions,
        metadata: ObfuscationMetadata {
            generation_seed: config.seed.to_hex(),
            transforms_applied,
            transforms_attempted,
            transform_outcomes,
            size_limit_exceeded,
            unknown_opcodes_preserved: config.preserve_unknown_opcodes,
            constructor_args_obfuscated: constructor_args.applied,
            constructor_argument_bytes: constructor_args.argument_bytes,
            constructor_decoder_bytes: constructor_args.decoder_bytes,
            metadata_digests_diversified,
        },
        selector_mapping: cfg_ir.selector_mapping,
        trace,
    })
}

/// Analyzes instructions to count unknown opcodes and provide feedback.
fn analyze_instructions(
    instructions: &[decoder::Instruction],
    original_bytes: &[u8],
) -> (usize, usize, Vec<String>) {
    let total_count = instructions.len();
    let mut unknown_count = 0;
    let mut unknown_types = HashSet::new();

    for instruction in instructions {
        // INVALID (0xfe) is a real Solidity opcode used for unreachable data and
        // must not be reported as an unknown instruction. The decoder also uses
        // INVALID as a placeholder for unrecognized disassembler output; compare
        // the source byte to distinguish that marker from genuine 0xfe.
        let is_unknown = matches!(instruction.op, Opcode::UNKNOWN(_))
            || (matches!(instruction.op, Opcode::INVALID)
                && original_bytes.get(instruction.pc).copied() != Some(0xfe));
        if is_unknown {
            unknown_count += 1;
            unknown_types.insert(format!("{}", instruction.op));
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
    let code_deposit_gas = |bytes| 200 * bytes as u64;

    json!({
        "original_bytes": result.original_size,
        "obfuscated_bytes": result.obfuscated_size,
        "size_delta_bytes": (result.obfuscated_size as i64 - result.original_size as i64),
        "original_runtime_bytes": result.original_runtime_size,
        "obfuscated_runtime_bytes": result.obfuscated_runtime_size,
        "original_code_deposit_gas": code_deposit_gas(result.original_runtime_size),
        "obfuscated_code_deposit_gas": code_deposit_gas(result.obfuscated_runtime_size),
        "code_deposit_gas_delta": (code_deposit_gas(result.obfuscated_runtime_size) as i64 - code_deposit_gas(result.original_runtime_size) as i64),
        "percent_size": result.size_increase_percentage,
        "unknown_opcodes_preserved": result.unknown_opcodes_count,
        "blocks_created": result.blocks_created,
        "instructions_added": result.instructions_added,
        "transforms_applied": result.metadata.transforms_applied,
        "constructor_args_obfuscated": result.metadata.constructor_args_obfuscated,
        "constructor_argument_bytes": result.metadata.constructor_argument_bytes,
        "constructor_decoder_bytes": result.metadata.constructor_decoder_bytes,
        "notes": "Code-deposit gas is exact for deployed bytes. Creation transaction calldata, EIP-3860 word cost, and init/runtime execution gas require an EVM measurement and are intentionally not fabricated here."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, Result};
    use rand::rngs::StdRng;

    const COUNTER_DEPLOYMENT: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

    struct MutateThenFalse;

    impl Transform for MutateThenFalse {
        fn name(&self) -> &'static str {
            "MutateThenFalse"
        }

        fn apply(&self, ir: &mut cfg_ir::CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
            for node in ir.cfg.node_indices().collect::<Vec<_>>() {
                if let Block::Body(body) = &mut ir.cfg[node] {
                    if let Some(instruction) = body.instructions.first_mut() {
                        instruction.op = Opcode::INVALID;
                        break;
                    }
                }
            }
            Ok(false)
        }
    }

    struct MutateThenError;

    impl Transform for MutateThenError {
        fn name(&self) -> &'static str {
            "MutateThenError"
        }

        fn apply(&self, ir: &mut cfg_ir::CfgIrBundle, _rng: &mut StdRng) -> Result<bool> {
            for node in ir.cfg.node_indices().collect::<Vec<_>>() {
                if let Block::Body(body) = &mut ir.cfg[node] {
                    if let Some(instruction) = body.instructions.first_mut() {
                        instruction.op = Opcode::INVALID;
                        break;
                    }
                }
            }
            Err(Error::Generic("intentional failure".into()))
        }
    }

    #[tokio::test]
    async fn no_change_transform_cannot_leak_partial_mutation() {
        let seed = Seed::from_bytes([0x42; 32]);
        let mut baseline_config = ObfuscationConfig::with_seed(seed.clone());
        baseline_config.transforms.clear();
        let baseline = obfuscate_bytecode(COUNTER_DEPLOYMENT, COUNTER_RUNTIME, baseline_config)
            .await
            .unwrap();

        let mut candidate_config = ObfuscationConfig::with_seed(seed);
        candidate_config.transforms = vec![Box::new(MutateThenFalse)];
        let candidate = obfuscate_bytecode(COUNTER_DEPLOYMENT, COUNTER_RUNTIME, candidate_config)
            .await
            .unwrap();

        assert_eq!(candidate.obfuscated_bytecode, baseline.obfuscated_bytecode);
        assert!(!candidate
            .metadata
            .transforms_applied
            .contains(&"MutateThenFalse".to_string()));
        assert!(candidate
            .metadata
            .transform_outcomes
            .iter()
            .any(|outcome| { outcome.name == "MutateThenFalse" && outcome.status == "no_change" }));
    }

    #[tokio::test]
    async fn transform_error_aborts_the_pipeline() {
        let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x24; 32]));
        config.transforms = vec![Box::new(MutateThenError)];
        let error = obfuscate_bytecode(COUNTER_DEPLOYMENT, COUNTER_RUNTIME, config)
            .await
            .unwrap_err();
        assert!(error.message.contains("MutateThenError"));
        assert!(error.message.contains("intentional failure"));
    }

    #[tokio::test]
    async fn default_pipeline_rejects_external_code_introspection_that_may_target_self() {
        // The runtime jumps to ADDRESS; EXTCODESIZE and returns the observed size.
        // A layout-changing transform would change that result, so the production
        // pipeline must reject the input before applying any transform.
        let fixtures = [
            (
                "EXTCODESIZE",
                "0x6011600a5f3960115ff361000856000000005b303b5f5260205ff3",
                "0x61000856000000005b303b5f5260205ff3",
            ),
            (
                "EXTCODECOPY",
                "0x6011600a5f3960115ff361000856000000005b303c5f5260205ff3",
                "0x61000856000000005b303c5f5260205ff3",
            ),
            (
                "EXTCODEHASH",
                "0x6011600a5f3960115ff361000856000000005b303f5f5260205ff3",
                "0x61000856000000005b303f5f5260205ff3",
            ),
        ];

        for (opcode, deployment, runtime) in fixtures {
            let config = ObfuscationConfig::with_seed(Seed::from_bytes([0x73; 32]));
            let error = obfuscate_bytecode(deployment, runtime, config)
                .await
                .expect_err("external-code introspection must fail closed");

            assert!(error.message.contains(opcode), "{}", error.message);
            assert!(error.message.contains("not supported"), "{}", error.message);
        }
    }

    #[test]
    fn genuine_invalid_is_not_reported_as_an_unknown_opcode() {
        let instructions = vec![
            decoder::Instruction {
                pc: 0,
                op: Opcode::INVALID,
                imm: None,
            },
            decoder::Instruction {
                pc: 1,
                op: Opcode::INVALID,
                imm: None,
            },
            decoder::Instruction {
                pc: 2,
                op: Opcode::UNKNOWN(0xaa),
                imm: None,
            },
        ];
        let (total, unknown, kinds) = analyze_instructions(&instructions, &[0xfe, 0xaa, 0xaa]);

        assert_eq!(total, 3);
        assert_eq!(unknown, 2);
        assert!(!kinds.is_empty());
    }

    #[tokio::test]
    async fn preserve_unknown_opcodes_false_rejects_decoder_unknown_input() {
        // Twelve-byte init wrapper returning the single raw runtime byte 0xaa.
        let deployment = "0x6001600c60003960016000f3aa";
        let runtime = "0xaa";
        let mut config = ObfuscationConfig::with_seed(Seed::from_bytes([0x9a; 32]));
        config.transforms.clear();
        config.preserve_unknown_opcodes = false;

        let error = obfuscate_bytecode(deployment, runtime, config)
            .await
            .expect_err("disabled unknown-opcode preservation must fail closed");
        assert!(error.message.contains("decoder-unknown opcode"));
        assert!(error
            .message
            .contains("preserve_unknown_opcodes is disabled"));
    }
}
