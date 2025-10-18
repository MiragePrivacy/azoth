// ! Module for tracking bytecode transformations and generating mapping outputs.
//!
//! This module provides comprehensive tracking of how bytecode is transformed through
//! each obfuscation pass, enabling analysis, debugging, and verification of the
//! obfuscation process. The mapping structures capture block-level and instruction-level
//! changes, including program counter adjustments, block modifications, and semantic
//! transformations like function selector remapping.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a bytecode section.
///
/// Captures the boundaries and type of different sections in the bytecode
/// such as init code, runtime code, and auxiliary data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Type of section (Init, Runtime, Auxdata, etc.)
    pub kind: String,
    /// Start offset in bytes
    pub offset: usize,
    /// Length in bytes
    pub len: usize,
}

/// Complete mapping output for an obfuscation session.
///
/// Contains all transformations applied to the bytecode, with detailed tracking
/// of each obfuscation pass and its effects on the program structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationMapping {
    /// Original bytecode before any transformations (hex string without 0x prefix)
    pub original_bytecode: String,
    /// Final obfuscated bytecode (hex string without 0x prefix)
    pub final_bytecode: String,
    /// Original bytecode size in bytes
    pub original_size: usize,
    /// Final bytecode size in bytes
    pub final_size: usize,
    /// Ordered list of transformation steps applied
    pub transform_steps: Vec<TransformStep>,
    /// Overall program counter mapping from original to final bytecode
    pub final_pc_mapping: HashMap<usize, usize>,
    /// Bytecode sections detected in the original bytecode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sections: Option<Vec<SectionInfo>>,
}

/// Captures the state changes from a single obfuscation transform.
///
/// Each transform step records the complete state of the bytecode before and after
/// the transform is applied, enabling precise tracking of what changed and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformStep {
    /// Name of the transform that was applied (e.g., "Shuffle", "OpaquePredicate")
    pub transform_name: String,
    /// Step number in the transformation sequence (0-indexed)
    pub step_number: usize,
    /// Whether this transform actually modified the bytecode
    pub changed: bool,
    /// Snapshot of bytecode state before this transform
    pub before: BytecodeSnapshot,
    /// Snapshot of bytecode state after this transform
    pub after: BytecodeSnapshot,
    /// Program counter mapping: old PC → new PC for this transform
    pub pc_mapping: HashMap<usize, usize>,
    /// Blocks that were added by this transform
    pub blocks_added: Vec<BlockInfo>,
    /// Blocks that were removed by this transform
    pub blocks_removed: Vec<BlockInfo>,
    /// Blocks that were modified by this transform
    pub blocks_modified: Vec<BlockModification>,
    /// Semantic transformations (function selectors, etc.)
    pub semantic_changes: Option<SemanticChanges>,
    /// Statistics for this transform
    pub statistics: TransformStatistics,
}

/// Snapshot of bytecode state at a point in the transformation pipeline.
///
/// Captures the complete structure of the bytecode including all blocks and
/// their instruction sequences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeSnapshot {
    /// Total number of blocks in the CFG
    pub block_count: usize,
    /// Total number of instructions
    pub instruction_count: usize,
    /// Total bytecode size in bytes
    pub byte_size: usize,
    /// All blocks in the CFG at this point
    pub blocks: Vec<BlockInfo>,
}

/// Detailed information about a CFG block.
///
/// Represents a basic block in the control flow graph with its instruction
/// sequence and position in the bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block identifier (CFG node index)
    pub block_id: usize,
    /// Program counter where this block starts
    pub start_pc: usize,
    /// Program counter where this block ends (exclusive)
    pub end_pc: usize,
    /// Number of instructions in this block
    pub instruction_count: usize,
    /// Byte size of this block
    pub byte_size: usize,
    /// Instructions in this block
    pub instructions: Vec<InstructionInfo>,
}

/// Information about a single EVM instruction.
///
/// Captures the complete state of an instruction including its opcode,
/// immediate value, and position in the bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    /// Program counter (bytecode offset) for this instruction
    pub pc: usize,
    /// Opcode mnemonic (e.g., "PUSH1", "JUMP", "ADD")
    pub opcode: String,
    /// Immediate value as hex string (if applicable)
    pub immediate: Option<String>,
    /// Byte size of this instruction
    pub byte_size: usize,
}

/// Describes how a block was modified by a transform.
///
/// Tracks changes to existing blocks including instruction additions/removals
/// and program counter adjustments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockModification {
    /// Block identifier
    pub block_id: usize,
    /// Original start PC before modification
    pub old_start_pc: usize,
    /// New start PC after modification
    pub new_start_pc: usize,
    /// Change in instruction count (positive = added, negative = removed)
    pub instruction_delta: i32,
    /// Change in byte size (positive = grew, negative = shrunk)
    pub byte_delta: i32,
    /// Specific instruction-level changes within this block
    pub instruction_changes: Vec<InstructionChange>,
}

/// Describes a change to a specific instruction.
///
/// Captures transformations at the instruction level including opcode changes,
/// immediate value modifications, and instruction insertions/deletions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionChange {
    /// Type of change that occurred
    pub change_type: InstructionChangeType,
    /// Original instruction state (if applicable)
    pub before: Option<InstructionInfo>,
    /// New instruction state (if applicable)
    pub after: Option<InstructionInfo>,
}

/// Type of instruction-level change.
///
/// Enumerates the different ways an instruction can be modified during
/// obfuscation transforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionChangeType {
    /// Instruction was inserted at this location
    Inserted,
    /// Instruction was removed from this location
    Removed,
    /// Instruction's immediate value was modified (e.g., jump target updated)
    ImmediateModified,
    /// Instruction's opcode was changed
    OpcodeModified,
    /// Instruction's position changed but content is identical
    PositionChanged,
}

/// Semantic-level changes made by a transform.
///
/// Captures high-level transformations that affect the bytecode's meaning
/// beyond just instruction sequences, such as function selector remapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticChanges {
    /// Function selector mappings (original 4-byte selector → token)
    /// Key is the selector as a hex string, value is the token bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_mapping: Option<HashMap<String, Vec<u8>>>,
    /// Jump target remappings (old target PC → new target PC)
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub jump_target_remapping: HashMap<usize, usize>,
    /// Other semantic annotations specific to the transform
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub annotations: HashMap<String, String>,
}

/// Statistical metrics for a transform step.
///
/// Provides quantitative analysis of how a transform affected the bytecode
/// including size changes, complexity increases, and structural modifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformStatistics {
    /// Number of blocks before this transform
    pub blocks_before: usize,
    /// Number of blocks after this transform
    pub blocks_after: usize,
    /// Change in block count
    pub blocks_delta: i32,
    /// Number of instructions before this transform
    pub instructions_before: usize,
    /// Number of instructions after this transform
    pub instructions_after: usize,
    /// Change in instruction count
    pub instructions_delta: i32,
    /// Bytecode size before this transform
    pub bytes_before: usize,
    /// Bytecode size after this transform
    pub bytes_after: usize,
    /// Change in byte size
    pub bytes_delta: i32,
}

impl ObfuscationMapping {
    /// Creates a new empty mapping for tracking obfuscation transformations.
    ///
    /// # Arguments
    /// * `original_bytecode` - The original bytecode hex string (without 0x prefix)
    /// * `original_size` - Size of the original bytecode in bytes
    ///
    /// # Returns
    /// A new `ObfuscationMapping` instance ready to record transform steps.
    pub fn new(original_bytecode: String, original_size: usize) -> Self {
        Self {
            original_bytecode,
            final_bytecode: String::new(),
            original_size,
            final_size: 0,
            transform_steps: Vec::new(),
            final_pc_mapping: HashMap::new(),
            sections: None,
        }
    }

    /// Sets section information for the mapping.
    ///
    /// # Arguments
    /// * `sections` - Detected bytecode sections from the original bytecode
    pub fn set_sections(&mut self, sections: Vec<SectionInfo>) {
        self.sections = Some(sections);
    }

    /// Adds a transform step to the mapping.
    ///
    /// Records the effects of applying a single obfuscation transform to the bytecode.
    ///
    /// # Arguments
    /// * `step` - The transform step to add
    pub fn add_step(&mut self, step: TransformStep) {
        self.transform_steps.push(step);
    }

    /// Finalizes the mapping with the final bytecode state.
    ///
    /// Should be called after all transforms have been applied to record
    /// the final obfuscated bytecode and compute the overall PC mapping.
    ///
    /// # Arguments
    /// * `final_bytecode` - The final obfuscated bytecode hex string (without 0x prefix)
    /// * `final_size` - Size of the final bytecode in bytes
    pub fn finalize(&mut self, final_bytecode: String, final_size: usize) {
        self.final_bytecode = final_bytecode;
        self.final_size = final_size;

        // Compose all PC mappings to create final original→final mapping
        self.final_pc_mapping = self.compute_final_pc_mapping();
    }

    /// Computes the overall PC mapping from original to final bytecode.
    ///
    /// Chains together all individual transform PC mappings to create
    /// a direct mapping from original bytecode positions to final positions.
    ///
    /// # Returns
    /// A map of original PC → final PC for all instructions.
    fn compute_final_pc_mapping(&self) -> HashMap<usize, usize> {
        let mut mapping = HashMap::new();

        // If no transforms, identity mapping would be implied
        if self.transform_steps.is_empty() {
            return mapping;
        }

        // Start with the first transform's PC mapping as base
        if let Some(first_step) = self.transform_steps.first() {
            mapping = first_step.pc_mapping.clone();
        }

        // Chain subsequent mappings: if PC x→y in step N and y→z in step N+1, then x→z overall
        for step in self.transform_steps.iter().skip(1) {
            let mut new_mapping = HashMap::new();

            for (&original_pc, &intermediate_pc) in &mapping {
                // Look up where this PC ends up after this step
                let final_pc = step.pc_mapping.get(&intermediate_pc).copied().unwrap_or(intermediate_pc);
                new_mapping.insert(original_pc, final_pc);
            }

            // Also add any new PCs introduced by this transform
            for (&pc, &new_pc) in &step.pc_mapping {
                new_mapping.entry(pc).or_insert(new_pc);
            }

            mapping = new_mapping;
        }

        mapping
    }

    /// Exports the mapping as pretty-printed JSON.
    ///
    /// Generates a human-readable JSON representation of all obfuscation
    /// transformations suitable for analysis and debugging.
    ///
    /// # Returns
    /// A `Result` containing the JSON string or a serialization error.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Exports the mapping as compact JSON.
    ///
    /// Generates a space-efficient JSON representation without formatting.
    ///
    /// # Returns
    /// A `Result` containing the JSON string or a serialization error.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
