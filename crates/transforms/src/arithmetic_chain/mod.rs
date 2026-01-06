//! Arithmetic chain obfuscation transform.
//!
//! This transform protects PUSH constants (16-32 bytes) by replacing them with
//! arithmetic chains that compute the same value at runtime from scattered
//! initial values.
//!
//! ## How It Works
//!
//! 1. **Target Identification**: Find all PUSH16-PUSH32 instructions not in
//!    protected regions (dispatcher selectors, controller targets, etc.)
//!
//! 2. **Chain Generation**: For each target, generate a random sequence of
//!    arithmetic operations (ADD, SUB, XOR, AND, OR, MUL, DIV)
//!
//! 3. **Backward Computation**: Work backwards from the target constant to
//!    compute what initial values, when processed through the operations,
//!    will produce the desired result
//!
//! 4. **Value Scattering**: Embed initial values either in a data section
//!    (loaded via CODECOPY) or in dead code paths
//!
//! 5. **Code Replacement**: Replace each PUSH with the compiled chain
//!
//! ## Example
//!
//! Original:
//! ```text
//! PUSH8 0xdeadbeef12345678
//! ```
//!
//! Transformed (conceptually):
//! ```text
//! ; Load scattered values and compute
//! PUSH1 0x00          ; memory dest
//! PUSH2 0x1234        ; code offset
//! PUSH1 0x20          ; 32 bytes
//! CODECOPY
//! PUSH1 0x00
//! MLOAD               ; v0 on stack
//! ; ... load v1 ...
//! ADD                 ; v0 + v1
//! ; ... load v2 ...
//! XOR                 ; result
//! ; Result equals original 0x00...00deadbeef12345678 (padded to 32 bytes)
//! ```

pub mod chain;
pub mod compiler;
pub mod reverse;
pub mod scatter;
pub mod types;

use crate::{Error, Result, Transform};
use azoth_core::cfg_ir::{Block, BlockBody, CfgIrBundle};
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::Rng;
use std::collections::HashSet;
use tracing::debug;

pub use chain::{estimate_gas_cost, evaluate_forward, generate_chain};
pub use compiler::{compile_chain, compile_chain_inline, estimate_bytecode_size, stack_delta};
pub use scatter::{apply_scattering, generate_load_instructions};
pub use types::{
    ArithmeticChainDef, ArithmeticOp, ChainConfig, ChainReverseData, ScatterContext, ScatterInfo,
    ScatterLocation, ScatterStrategy,
};

/// Collect PCs that should not be transformed (dispatcher controller targets, etc.).
fn collect_protected_pcs(ir: &CfgIrBundle) -> HashSet<usize> {
    let mut protected = HashSet::new();

    if let Some(controller_pcs) = &ir.dispatcher_controller_pcs {
        for &pc in controller_pcs.values() {
            protected.insert(pc);
        }
    }

    protected
}

/// Minimum PUSH size to consider for arithmetic chain transformation.
/// Set to 16 to avoid transforming smaller values that may be jump targets,
/// function selectors, or other semantic constants.
const MIN_PUSH_SIZE: u8 = 16;

/// Maximum PUSH size to consider for arithmetic chain transformation.
const MAX_PUSH_SIZE: u8 = 32;

/// Arithmetic chain transform for PUSH constant obfuscation.
///
/// This transform replaces PUSH16-PUSH32 instructions with computed values
/// derived from scattered initial values through arithmetic operation chains.
#[derive(Debug)]
pub struct ArithmeticChain {
    config: ChainConfig,
}

impl Default for ArithmeticChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ArithmeticChain {
    /// Create a new arithmetic chain transform with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ChainConfig::default(),
        }
    }

    /// Create a new arithmetic chain transform with custom configuration.
    #[must_use]
    pub fn with_config(config: ChainConfig) -> Self {
        Self { config }
    }

    /// Find all PUSH16-PUSH32 instructions that should be transformed.
    ///
    /// Returns tuples of (node_index, instruction_index, push_size, value).
    /// Uses `transform_probability` to randomly skip some eligible targets.
    fn find_targets(
        &self,
        ir: &CfgIrBundle,
        protected_pcs: &HashSet<usize>,
        rng: &mut StdRng,
    ) -> Vec<(NodeIndex, usize, u8, [u8; 32])> {
        let mut targets = Vec::new();

        for node_idx in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node_idx] {
                for (instr_idx, instr) in body.instructions.iter().enumerate() {
                    // Check if this is a PUSH in the target range (4-32 bytes)
                    let push_size = match instr.op {
                        Opcode::PUSH(n) if (MIN_PUSH_SIZE..=MAX_PUSH_SIZE).contains(&n) => n,
                        _ => continue,
                    };

                    // Skip protected PCs
                    if self.config.respect_protected_pcs && protected_pcs.contains(&instr.pc) {
                        debug!("Skipping protected PUSH{} at PC {:#x}", push_size, instr.pc);
                        continue;
                    }

                    // Skip PUSH immediately followed by JUMP/JUMPI - these are jump targets
                    if body
                        .instructions
                        .get(instr_idx + 1)
                        .is_some_and(|next| matches!(next.op, Opcode::JUMP | Opcode::JUMPI))
                    {
                        debug!(
                            "Skipping PUSH{} at PC {:#x} - immediate jump target",
                            push_size, instr.pc
                        );
                        continue;
                    }

                    // Skip known semantic constants and trivial values
                    if let Some(ref imm) = instr.imm {
                        // Panic(uint256) selector: 0x4e487b71
                        if imm.starts_with("4e487b71") {
                            debug!(
                                "Skipping PUSH{} at PC {:#x} - Solidity panic selector",
                                push_size, instr.pc
                            );
                            continue;
                        }
                        // Error(string) selector: 0x08c379a0
                        if imm.starts_with("08c379a0") {
                            debug!(
                                "Skipping PUSH{} at PC {:#x} - Solidity error selector",
                                push_size, instr.pc
                            );
                            continue;
                        }
                        // Max value (all 0xff) - used in overflow checks
                        if imm.chars().all(|c| c == 'f' || c == 'F') {
                            debug!(
                                "Skipping PUSH{} at PC {:#x} - max value",
                                push_size, instr.pc
                            );
                            continue;
                        }
                        // Zero value (all 0x00) - trivial, not worth transforming
                        if imm.chars().all(|c| c == '0') {
                            debug!(
                                "Skipping PUSH{} at PC {:#x} - zero value",
                                push_size, instr.pc
                            );
                            continue;
                        }
                    }

                    // Extract the value (padded to 32 bytes)
                    if let Some(ref imm) = instr.imm {
                        if let Ok(value) = parse_push_value(imm) {
                            // Apply transform probability
                            if rng.random::<f32>() > self.config.transform_probability {
                                continue;
                            }

                            debug!(
                                "Found PUSH{} target at PC {:#x}, node {:?}, value: 0x{}",
                                push_size,
                                instr.pc,
                                node_idx,
                                hex::encode(&value[32 - push_size as usize..])
                            );
                            targets.push((node_idx, instr_idx, push_size, value));
                        }
                    }
                }
            }
        }

        // Apply max_targets limit if configured
        if let Some(max) = self.config.max_targets {
            targets.truncate(max);
        }

        targets
    }

    /// Replace a PUSH instruction with a compiled chain.
    fn replace_instruction(
        &self,
        ir: &mut CfgIrBundle,
        node_idx: NodeIndex,
        instr_idx: usize,
        chain: &ArithmeticChainDef,
        ctx: &ScatterContext,
        runtime_length: usize,
    ) -> Result<()> {
        if let Block::Body(body) = &ir.cfg[node_idx] {
            // Compile the chain to instructions
            let compiled = compile_chain(chain, ctx, runtime_length);

            if compiled.is_empty() {
                return Err(Error::Generic(
                    "compiled chain produced no instructions".to_string(),
                ));
            }

            // Create new body with replaced instructions
            let mut new_instructions = body.instructions.clone();
            new_instructions.splice(instr_idx..=instr_idx, compiled);

            let new_body = BlockBody {
                start_pc: body.start_pc,
                max_stack: body.max_stack,
                control: body.control.clone(),
                instructions: new_instructions,
            };

            // Use overwrite_block to record the trace
            ir.overwrite_block(node_idx, new_body)
                .map_err(|e| Error::Generic(e.to_string()))?;
        }

        Ok(())
    }
}

impl Transform for ArithmeticChain {
    fn name(&self) -> &'static str {
        "ArithmeticChain"
    }

    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool> {
        debug!("=== ArithmeticChain Transform Start ===");

        let protected_pcs = if self.config.respect_protected_pcs {
            collect_protected_pcs(ir)
        } else {
            HashSet::new()
        };

        let targets = self.find_targets(ir, &protected_pcs, rng);

        if targets.is_empty() {
            debug!("No PUSH targets found - skipping");
            return Ok(false);
        }

        debug!("Found {} PUSH targets for transformation", targets.len());

        // Store (node_idx, instr_idx, push_size, chain) for each target
        let mut chains: Vec<(NodeIndex, usize, u8, ArithmeticChainDef)> = Vec::new();
        for (node_idx, instr_idx, push_size, value) in targets {
            let chain = generate_chain(value, &self.config, rng);

            debug_assert_eq!(
                evaluate_forward(&chain.initial_values, &chain.operations),
                value,
                "Chain forward evaluation must match target"
            );

            chains.push((node_idx, instr_idx, push_size, chain));
        }

        if chains.is_empty() {
            debug!("No valid chains generated - skipping");
            return Ok(false);
        }

        let mut scatter_ctx = ScatterContext::new();
        for (_, _, _, chain) in &mut chains {
            apply_scattering(ir, chain, &mut scatter_ctx, rng)?;
        }

        // Estimate runtime code length for CODECOPY offset calculation
        // We need to account for the size increase from replacing PUSH instructions with chains
        let base_runtime_length = estimate_runtime_length(ir);

        // Calculate how much the runtime will grow from chain replacements
        // Each PUSH{n} (1+n bytes) is replaced with CODECOPY load sequences + operations
        let mut growth: usize = 0;
        for (_, _, push_size, chain) in &chains {
            // Each value load is 11 bytes for typical offsets < 65536:
            // PUSH1 mem(2) + PUSH2 offset(3) + PUSH1 size(2) + CODECOPY(1) + PUSH1 mem(2) + MLOAD(1)
            let load_size = chain.initial_values.len() * 11;
            // Each operation is 1-2 bytes (SUB/DIV need SWAP1 prefix)
            let ops_size: usize = chain
                .operations
                .iter()
                .map(|op| {
                    if matches!(op, ArithmeticOp::Sub | ArithmeticOp::Div(_)) {
                        2 // SWAP1 + op
                    } else {
                        1 // just op
                    }
                })
                .sum();
            // Chain size minus the original PUSH instruction (1 + push_size bytes)
            let original_size = 1 + *push_size as usize;
            let chain_size = load_size + ops_size;
            debug!(
                "Chain: {} values, {} ops, load_size={}, ops_size={}, chain_size={}, original={}, growth={}",
                chain.initial_values.len(),
                chain.operations.len(),
                load_size,
                ops_size,
                chain_size,
                original_size,
                chain_size.saturating_sub(original_size)
            );
            growth += chain_size.saturating_sub(original_size);
        }

        // Total offset: runtime code + growth from chains
        // Note: data section is appended to runtime BEFORE auxdata, so no auxdata offset needed
        let runtime_length = base_runtime_length + growth;
        debug!(
            "Runtime length estimate: base={}, growth={}, total={}",
            base_runtime_length, growth, runtime_length
        );

        for (node_idx, instr_idx, _push_size, chain) in chains.into_iter().rev() {
            self.replace_instruction(
                ir,
                node_idx,
                instr_idx,
                &chain,
                &scatter_ctx,
                runtime_length,
            )?;
        }

        if !scatter_ctx.data_section.is_empty() {
            ir.arithmetic_chain_data = Some(scatter_ctx.data_section);
            debug!(
                "Data section: {} bytes",
                ir.arithmetic_chain_data.as_ref().unwrap().len()
            );
        }

        debug!("=== ArithmeticChain Transform Complete ===");
        Ok(true)
    }
}

/// Parse a PUSH immediate value from hex string into a 32-byte array.
///
/// The value is right-aligned (padded with leading zeros) to match EVM semantics.
fn parse_push_value(hex_str: &str) -> std::result::Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(hex_str)?;
    // Pad with leading zeros to 32 bytes
    let mut value = [0u8; 32];
    let offset = 32 - bytes.len();
    value[offset..].copy_from_slice(&bytes);
    Ok(value)
}

/// Estimate the runtime code length from the CFG.
///
/// Only counts blocks within the runtime section bounds to ensure CODECOPY
/// offsets are correct for deployed bytecode.
fn estimate_runtime_length(ir: &CfgIrBundle) -> usize {
    let runtime_bounds = ir.runtime_bounds();

    let mut total = 0;
    for node_idx in ir.cfg.node_indices() {
        if let Block::Body(body) = &ir.cfg[node_idx] {
            // Only count blocks within runtime bounds
            let in_runtime = match runtime_bounds {
                Some((start, end)) => body.start_pc >= start && body.start_pc < end,
                None => true, // No bounds = assume all is runtime
            };

            if in_runtime {
                for instr in &body.instructions {
                    total += instruction_size(instr);
                }
            }
        }
    }
    total
}

/// Calculate the bytecode size of an instruction.
fn instruction_size(instr: &azoth_core::decoder::Instruction) -> usize {
    match instr.op {
        Opcode::PUSH(n) => 1 + n as usize,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_push_value_full() {
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let result = parse_push_value(hex).unwrap();
        assert_eq!(&result[0..4], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_push_value_short_pads_zeros() {
        let hex = "42";
        let result = parse_push_value(hex).unwrap();
        assert_eq!(result[31], 0x42);
        assert_eq!(result[0..31], [0u8; 31]);
    }

    #[test]
    fn parse_push_value_4_bytes() {
        let hex = "deadbeef";
        let result = parse_push_value(hex).unwrap();
        assert_eq!(&result[28..32], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(result[0..28], [0u8; 28]);
    }

    #[test]
    fn parse_push_value_8_bytes() {
        let hex = "1234567890abcdef";
        let result = parse_push_value(hex).unwrap();
        assert_eq!(
            &result[24..32],
            &[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
        );
        assert_eq!(result[0..24], [0u8; 24]);
    }
}
