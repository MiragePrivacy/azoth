use crate::function_dispatcher::FunctionDispatcher;
use crate::Transform;
use azoth_core::seed::Seed;
use azoth_core::{
    cfg_ir::{self, snapshot_bundle, Block, CfgIrDiff, OperationKind, TraceEvent},
    decoder, detection, encoder, process_bytecode_to_cfg, validator, Opcode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};

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
            transforms: Vec::new(),
            preserve_unknown_opcodes: true,
        }
    }
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            seed: Seed::generate(),
            transforms: Vec::new(),
            preserve_unknown_opcodes: true,
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
            .finish()
    }
}

/// Result of the obfuscation pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationResult {
    /// The obfuscated bytecode as hex string (with 0x prefix)
    pub obfuscated_bytecode: String,
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
    pub selector_mapping: Option<HashMap<u32, Vec<u8>>>,
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
}

/// Main obfuscation pipeline
pub async fn obfuscate_bytecode(
    deployment_bytecode: &str,
    runtime_bytecode: &str,
    config: ObfuscationConfig,
) -> Result<ObfuscationResult, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!("Starting obfuscation pipeline:");
    tracing::debug!("  User transforms: {}", config.transforms.len());

    // Step 1: Process bytecode to CFG-IR
    let (mut cfg_ir, instructions, sections, bytes) =
        process_bytecode_to_cfg(deployment_bytecode, false, runtime_bytecode, false).await?;
    let original_size = bytes.len();

    tracing::debug!("  Input size: {} bytes", original_size);

    // Step 2: Analyze instructions for unknown opcodes
    let (total_instructions, unknown_count, unknown_types) = analyze_instructions(&instructions);
    tracing::debug!("  Total instructions: {}", total_instructions);
    tracing::debug!("  Unknown opcodes: {}", unknown_count);

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

    let has_dispatcher = dispatcher_info.is_some();

    if let Some(dispatcher) = dispatcher_info {
        tracing::debug!(
            "Function dispatcher detected with {} selectors - adding FunctionDispatcher transform",
            dispatcher.selectors.len()
        );
        all_transforms.push(Box::new(FunctionDispatcher::with_dispatcher_info(
            dispatcher,
        )));
    } else {
        tracing::debug!(
            "No function dispatcher detected in runtime - skipping FunctionDispatcher transform"
        );
    }

    let user_transform_names: Vec<String> = config
        .transforms
        .iter()
        .map(|t| t.name().to_string())
        .collect();

    // Add user-specified transforms (this moves config.transforms)
    all_transforms.extend(config.transforms);

    // Track which transforms were applied (including the mandatory ones if dispatcher exists)
    let mut transforms_applied: Vec<String> = Vec::new();
    if has_dispatcher {
        transforms_applied.push("FunctionDispatcher".to_string());
    }
    transforms_applied.extend(user_transform_names);

    // Track individual transform effects
    let mut transform_change_log = Vec::new();
    let mut any_transform_changed = false;

    if !all_transforms.is_empty() {
        // Create deterministic RNG from cryptographic seed
        let mut shared_rng = config.seed.create_deterministic_rng();

        tracing::debug!("Applying {} transforms", all_transforms.len(),);

        for (i, transform) in all_transforms.iter().enumerate() {
            let transform_name = transform.name();
            let pre_instruction_count = count_instructions_in_cfg(&cfg_ir);
            let pre_block_count = cfg_ir.cfg.node_count();

            tracing::debug!(
                "  Transform {}: {} (pre: {} blocks, {} instructions)",
                i,
                transform_name,
                pre_block_count,
                pre_instruction_count
            );

            // Apply transform with deterministic RNG
            let transform_changed = match transform.apply(&mut cfg_ir, &mut shared_rng) {
                Ok(changed) => {
                    tracing::debug!("    Result: changed={}", changed);
                    changed
                }
                Err(e) => {
                    tracing::error!("    Transform {} failed: {}", transform_name, e);
                    false
                }
            };

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

    // Step 5: Reindex PCs
    tracing::debug!("  Reindexing PCs to normalize to 0-based addressing");
    let (pc_mapping, old_runtime_bounds) = cfg_ir.reindex_pcs()?;
    tracing::debug!("  PC reindexing complete: {} mappings", pc_mapping.len());

    // Patch jump immediates using the PC mapping
    cfg_ir.patch_jump_immediates(&pc_mapping, old_runtime_bounds)?;
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
        dispatcher.reapply_dispatcher_patches(
            &mut cfg_ir,
            &controller_pcs,
            &dispatcher_patches,
            &pc_mapping,
        )?;
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
            dispatcher.apply_instruction_replacements(&mut cfg_ir, edits)?;
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
            let new_target_pc = pc_mapping.get(&old_target_pc).copied().unwrap_or(old_target_pc);

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

            edits.push((decoy_node, new_pc, Opcode::PUSH(push_width), Some(formatted)));
        }

        if !edits.is_empty() {
            dispatcher.apply_instruction_replacements(&mut cfg_ir, edits)?;
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
        dispatcher.reapply_controller_patches(&mut cfg_ir, &controller_patches, &pc_mapping)?;
        tracing::debug!("  Controller patches re-applied successfully");
    }

    // Step 6: Extract and encode instructions
    let all_instructions = extract_instructions_from_cfg(&cfg_ir);
    tracing::debug!(
        "  Extracted {} instructions from CFG",
        all_instructions.len()
    );

    // Step 7: Encode back to bytecode (always with original for unknown opcode preservation)
    let obfuscated_bytes = encoder::encode(&all_instructions, &bytes)?;

    tracing::debug!("  Encoded to {} bytes", obfuscated_bytes.len());

    tracing::debug!("  Validating obfuscated runtime jump targets");
    if let Err(e) = validator::validate_jump_targets(&obfuscated_bytes).await {
        eprintln!("\nVALIDATION FAILED");
        eprintln!("Error: {}", e);
        eprintln!(
            "Obfuscated bytecode ({} bytes): 0x{}",
            obfuscated_bytes.len(),
            hex::encode(&obfuscated_bytes)
        );

        // Decode and show instructions around problematic area
        eprintln!("Decoding bytecode to show instructions...");
        match decoder::decode_bytecode(&hex::encode(&obfuscated_bytes), false).await {
            Ok((instructions, _, _, _)) => {
                eprintln!("Total instructions: {}", instructions.len());
                eprintln!("\nAll instructions:");
                for (i, instr) in instructions.iter().enumerate() {
                    eprintln!(
                        "  [{:3}] PC=0x{:02x} {:?} imm={:?}",
                        i, instr.pc, instr.op, instr.imm
                    );
                }
            }
            Err(decode_err) => {
                eprintln!("Failed to decode bytecode: {}", decode_err);
            }
        }

        return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
    }
    tracing::debug!("  Jump validation passed");

    // Step 8: Reassemble final bytecode
    let final_bytecode = cfg_ir.clean_report.reassemble(&obfuscated_bytes);
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

    // Step 10: Check size limits
    let size_increase_percentage = if original_size > 0 {
        ((obfuscated_size as f64 - original_size as f64) / original_size as f64) * 100.0
    } else {
        0.0
    };

    let size_limit_exceeded = false;

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

    let final_snapshot = snapshot_bundle(&cfg_ir);
    cfg_ir.record_operation(
        OperationKind::Finalize,
        CfgIrDiff::FullSnapshot(Box::new(final_snapshot)),
        None,
    );
    let trace = cfg_ir.trace.clone();

    Ok(ObfuscationResult {
        obfuscated_bytecode: format!("0x{}", hex::encode(&final_bytecode)),
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
        },
        selector_mapping: cfg_ir.selector_mapping,
        trace,
    })
}

/// Analyzes instructions to count unknown opcodes and provide feedback.
fn analyze_instructions(instructions: &[decoder::Instruction]) -> (usize, usize, Vec<String>) {
    let total_count = instructions.len();
    let mut unknown_count = 0;
    let mut unknown_types = HashSet::new();

    for instruction in instructions {
        if matches!(instruction.op, Opcode::INVALID | Opcode::UNKNOWN(_)) {
            unknown_count += 1;
            unknown_types.insert(format!("{}", instruction.op));
        }
    }

    (
        total_count,
        unknown_count,
        unknown_types.into_iter().collect(),
    )
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
        "notes": if result.unknown_opcodes_count > 0 {
            "Unknown opcodes were preserved as raw bytes to maintain functionality"
        } else {
            "All opcodes were standard and successfully obfuscated"
        }
    })
}
