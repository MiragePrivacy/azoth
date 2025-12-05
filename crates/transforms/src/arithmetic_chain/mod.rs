//! Arithmetic chain obfuscation transform.
//!
//! This transform protects PUSH32 constants by replacing them with arithmetic
//! chains that compute the same value at runtime from scattered initial values.
//!
//! ## How It Works
//!
//! 1. **Target Identification**: Find all PUSH32 instructions not in protected
//!    regions (dispatcher selectors, controller targets, etc.)
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
//! 5. **Code Replacement**: Replace each PUSH32 with the compiled chain
//!
//! ## Example
//!
//! Original:
//! ```text
//! PUSH32 0xdeadbeef...
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
//! ; Result equals original 0xdeadbeef...
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
use std::collections::HashSet;
use tracing::debug;

pub use chain::{estimate_gas_cost, evaluate_forward, generate_chain, validate_chain};
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

/// Arithmetic chain transform for PUSH32 constant obfuscation.
///
/// This transform replaces PUSH32 instructions with computed values derived
/// from scattered initial values through arithmetic operation chains.
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

    /// Find all PUSH32 instructions that should be transformed.
    fn find_targets(
        &self,
        ir: &CfgIrBundle,
        protected_pcs: &HashSet<usize>,
    ) -> Vec<(NodeIndex, usize, [u8; 32])> {
        let mut targets = Vec::new();

        for node_idx in ir.cfg.node_indices() {
            if let Block::Body(body) = &ir.cfg[node_idx] {
                for (instr_idx, instr) in body.instructions.iter().enumerate() {
                    // Check if this is a PUSH32
                    if !matches!(instr.op, Opcode::PUSH(32)) {
                        continue;
                    }

                    // Skip protected PCs
                    if self.config.respect_protected_pcs && protected_pcs.contains(&instr.pc) {
                        debug!("Skipping protected PUSH32 at PC {:#x}", instr.pc);
                        continue;
                    }

                    // Skip PUSH32 immediately followed by JUMP/JUMPI - these are jump targets
                    if body
                        .instructions
                        .get(instr_idx + 1)
                        .is_some_and(|next| matches!(next.op, Opcode::JUMP | Opcode::JUMPI))
                    {
                        debug!(
                            "Skipping PUSH32 at PC {:#x} - immediate jump target",
                            instr.pc
                        );
                        continue;
                    }

                    // Skip known semantic constants and trivial values
                    if let Some(ref imm) = instr.imm {
                        // Panic(uint256) selector: 0x4e487b71
                        if imm.starts_with("4e487b71") {
                            debug!(
                                "Skipping PUSH32 at PC {:#x} - Solidity panic selector",
                                instr.pc
                            );
                            continue;
                        }
                        // Error(string) selector: 0x08c379a0
                        if imm.starts_with("08c379a0") {
                            debug!(
                                "Skipping PUSH32 at PC {:#x} - Solidity error selector",
                                instr.pc
                            );
                            continue;
                        }
                        // Max uint256 (all 0xff) - used in overflow checks
                        if imm.chars().all(|c| c == 'f' || c == 'F') {
                            debug!("Skipping PUSH32 at PC {:#x} - max uint256 value", instr.pc);
                            continue;
                        }
                        // Zero value (all 0x00) - trivial, not worth transforming
                        if imm.chars().all(|c| c == '0') {
                            debug!("Skipping PUSH32 at PC {:#x} - zero value", instr.pc);
                            continue;
                        }
                    }

                    // Extract the 32-byte value
                    if let Some(ref imm) = instr.imm {
                        if let Ok(value) = parse_push32_value(imm) {
                            debug!(
                                "Found PUSH32 target at PC {:#x}, node {:?}, value: 0x{}",
                                instr.pc,
                                node_idx,
                                hex::encode(&value[..8]) // First 8 bytes for brevity
                            );
                            targets.push((node_idx, instr_idx, value));
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

    /// Replace a PUSH32 instruction with a compiled chain.
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

        let targets = self.find_targets(ir, &protected_pcs);

        if targets.is_empty() {
            debug!("No PUSH32 targets found - skipping");
            return Ok(false);
        }

        debug!("Found {} PUSH32 targets for transformation", targets.len());

        let mut chains: Vec<(NodeIndex, usize, ArithmeticChainDef)> = Vec::new();
        for (node_idx, instr_idx, value) in targets {
            let chain = generate_chain(value, &self.config, rng);

            if let Err(e) = validate_chain(&chain) {
                debug!("Chain validation failed: {}, skipping target", e);
                continue;
            }

            let computed = evaluate_forward(&chain.initial_values, &chain.operations);
            if computed != value {
                debug!("Chain forward evaluation mismatch, skipping target");
                continue;
            }

            chains.push((node_idx, instr_idx, chain));
        }

        if chains.is_empty() {
            debug!("No valid chains generated - skipping");
            return Ok(false);
        }

        let mut scatter_ctx = ScatterContext::new();
        for (_, _, chain) in &mut chains {
            apply_scattering(ir, chain, &mut scatter_ctx, rng)?;
        }

        // Estimate runtime code length for CODECOPY offset calculation
        // We need to account for the size increase from replacing PUSH32s with chains
        let base_runtime_length = estimate_runtime_length(ir);

        // Calculate how much the runtime will grow from chain replacements
        // Each PUSH32 (33 bytes) is replaced with CODECOPY load sequences + operations
        let mut growth: usize = 0;
        for (_, _, chain) in &chains {
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
            // Chain size minus the PUSH32 it replaces (33 bytes)
            let chain_size = load_size + ops_size;
            debug!(
                "Chain: {} values, {} ops, load_size={}, ops_size={}, chain_size={}, growth={}",
                chain.initial_values.len(),
                chain.operations.len(),
                load_size,
                ops_size,
                chain_size,
                chain_size.saturating_sub(33)
            );
            growth += chain_size.saturating_sub(33);
        }

        // Total offset: runtime code + growth from chains
        // Note: data section is appended to runtime BEFORE auxdata, so no auxdata offset needed
        let runtime_length = base_runtime_length + growth;
        debug!(
            "Runtime length estimate: base={}, growth={}, total={}",
            base_runtime_length, growth, runtime_length
        );

        for (node_idx, instr_idx, chain) in chains.into_iter().rev() {
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

/// Parse a PUSH32 immediate value from hex string.
fn parse_push32_value(hex_str: &str) -> std::result::Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        // Pad with leading zeros if needed
        let mut value = [0u8; 32];
        let offset = 32 - bytes.len();
        value[offset..].copy_from_slice(&bytes);
        return Ok(value);
    }
    let mut value = [0u8; 32];
    value.copy_from_slice(&bytes);
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
    fn parse_push32_value_full() {
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let result = parse_push32_value(hex).unwrap();
        assert_eq!(&result[0..4], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_push32_value_short_pads_zeros() {
        let hex = "42";
        let result = parse_push32_value(hex).unwrap();
        assert_eq!(result[31], 0x42);
        assert_eq!(result[0..31], [0u8; 31]);
    }
}
