//! Scattering mechanisms for arithmetic chain values.
//!
//! This module implements two strategies for embedding initial chain values
//! in the bytecode:
//!
//! 1. **CODECOPY**: Values are appended to a data section at the end of the
//!    bytecode and loaded at runtime using CODECOPY + MLOAD.
//!
//! 2. **Dead Path**: Values are embedded as PUSH32 instructions in unreachable
//!    code paths, typically combined with opaque predicates.
//!
//! The choice between strategies affects gas cost, bytecode size, and
//! obfuscation strength.

use super::types::{ArithmeticChainDef, ScatterContext, ScatterStrategy};
use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;
use rand::rngs::StdRng;

/// Apply scattering to a chain, populating the scatter context with data
/// section bytes and dead path blocks as needed.
///
/// This function modifies the chain's scatter locations in-place to reflect
/// actual offsets and block indices.
///
/// # Arguments
///
/// * `ir` - The CFG IR bundle to modify (for dead path blocks)
/// * `chain` - The chain definition with scatter strategies to finalize
/// * `ctx` - Scatter context accumulating data section and dead path info
/// * `rng` - Random number generator
///
/// # Returns
///
/// The updated chain definition with finalized scatter locations.
pub fn apply_scattering(
    _ir: &mut CfgIrBundle,
    chain: &mut ArithmeticChainDef,
    ctx: &mut ScatterContext,
    _rng: &mut StdRng,
) -> crate::Result<()> {
    for (i, (value, strategy)) in chain
        .initial_values
        .iter()
        .zip(chain.scatter_locations.iter_mut())
        .enumerate()
    {
        match strategy {
            ScatterStrategy::CodeCopy { ref mut offset } => {
                *offset = ctx.data_offset;
                ctx.data_section.extend_from_slice(value);
                ctx.data_offset += 32;
                tracing::debug!("Scattered value {} via CODECOPY at offset {}", i, offset);
            }
            ScatterStrategy::Inline => {
                tracing::debug!("Scattered value {} via inline PUSH32", i);
            }
            ScatterStrategy::DeadPath { .. } => {
                unimplemented!("dead path scattering not yet implemented")
            }
        }
    }

    Ok(())
}

/// Generate EVM instructions to load a scattered value onto the stack.
///
/// # Arguments
///
/// * `strategy` - The scatter strategy used for this value
/// * `value` - The 32-byte value to load (needed for inline strategy)
/// * `runtime_code_length` - Length of runtime code (for CODECOPY offset calculation)
///
/// # Returns
///
/// Vector of instructions that load the 32-byte value onto the stack.
pub fn generate_load_instructions(
    strategy: &ScatterStrategy,
    value: &[u8; 32],
    runtime_code_length: usize,
) -> Vec<Instruction> {
    match strategy {
        ScatterStrategy::CodeCopy { offset } => {
            let code_offset = runtime_code_length + offset;
            let mem_dest = 0x00;

            vec![
                Instruction {
                    pc: 0,
                    op: Opcode::PUSH(1),
                    imm: Some(format!("{:02x}", mem_dest)),
                },
                Instruction {
                    pc: 0,
                    op: push_for_value(code_offset),
                    imm: Some(format_push_value(code_offset)),
                },
                Instruction {
                    pc: 0,
                    op: Opcode::PUSH(1),
                    imm: Some("20".to_string()),
                },
                Instruction {
                    pc: 0,
                    op: Opcode::CODECOPY,
                    imm: None,
                },
                Instruction {
                    pc: 0,
                    op: Opcode::PUSH(1),
                    imm: Some(format!("{:02x}", mem_dest)),
                },
                Instruction {
                    pc: 0,
                    op: Opcode::MLOAD,
                    imm: None,
                },
            ]
        }
        ScatterStrategy::Inline => {
            let (push_size, hex_value) = minimal_push_for_value(value);
            vec![Instruction {
                pc: 0,
                op: Opcode::PUSH(push_size),
                imm: Some(hex_value),
            }]
        }
        ScatterStrategy::DeadPath { .. } => {
            unimplemented!("dead path loading not yet implemented")
        }
    }
}

/// Determine the minimal PUSH size needed for a 32-byte value.
///
/// Returns (push_size, hex_string) where push_size is 1-32 and hex_string
/// is the minimal hex representation without leading zeros.
fn minimal_push_for_value(value: &[u8; 32]) -> (u8, String) {
    // Find first non-zero byte
    let first_nonzero = value.iter().position(|&b| b != 0);

    match first_nonzero {
        None => {
            // All zeros - use PUSH1 0x00
            (1, "00".to_string())
        }
        Some(idx) => {
            let significant_bytes = 32 - idx;
            let push_size = significant_bytes as u8;
            let hex_value = hex::encode(&value[idx..]);
            (push_size, hex_value)
        }
    }
}

/// Determine the appropriate PUSH opcode for a value.
fn push_for_value(value: usize) -> Opcode {
    if value <= 0xFF {
        Opcode::PUSH(1)
    } else if value <= 0xFFFF {
        Opcode::PUSH(2)
    } else if value <= 0xFF_FFFF {
        Opcode::PUSH(3)
    } else {
        Opcode::PUSH(4)
    }
}

/// Format a value for use as PUSH immediate.
fn format_push_value(value: usize) -> String {
    if value <= 0xFF {
        format!("{:02x}", value)
    } else if value <= 0xFFFF {
        format!("{:04x}", value)
    } else if value <= 0xFF_FFFF {
        format!("{:06x}", value)
    } else {
        format!("{:08x}", value)
    }
}

/// Calculate the total size of the data section.
pub fn data_section_size(ctx: &ScatterContext) -> usize {
    ctx.data_section.len()
}

/// Finalize scatter context and return the data section bytes.
pub fn finalize_data_section(ctx: ScatterContext) -> Vec<u8> {
    ctx.data_section
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_codecopy_load_instructions() {
        let strategy = ScatterStrategy::CodeCopy { offset: 0 };
        let value = [0xab; 32];

        let instructions = generate_load_instructions(&strategy, &value, 100);

        assert_eq!(instructions.len(), 6);
        assert!(matches!(instructions[3].op, Opcode::CODECOPY));
        assert!(matches!(instructions[5].op, Opcode::MLOAD));
    }

    #[test]
    fn generate_inline_load_instructions() {
        let strategy = ScatterStrategy::Inline;
        let value = [0xcd; 32];

        let instructions = generate_load_instructions(&strategy, &value, 100);

        assert_eq!(instructions.len(), 1);
        assert!(matches!(instructions[0].op, Opcode::PUSH(32)));
        assert_eq!(instructions[0].imm, Some(hex::encode(value)));
    }

    #[test]
    fn generate_inline_load_minimal_push() {
        let strategy = ScatterStrategy::Inline;

        // Value that fits in 1 byte
        let mut value = [0u8; 32];
        value[31] = 0x42;
        let instructions = generate_load_instructions(&strategy, &value, 100);
        assert!(matches!(instructions[0].op, Opcode::PUSH(1)));
        assert_eq!(instructions[0].imm, Some("42".to_string()));

        // Value that fits in 2 bytes
        let mut value = [0u8; 32];
        value[30] = 0x12;
        value[31] = 0x34;
        let instructions = generate_load_instructions(&strategy, &value, 100);
        assert!(matches!(instructions[0].op, Opcode::PUSH(2)));
        assert_eq!(instructions[0].imm, Some("1234".to_string()));

        // Zero value
        let value = [0u8; 32];
        let instructions = generate_load_instructions(&strategy, &value, 100);
        assert!(matches!(instructions[0].op, Opcode::PUSH(1)));
        assert_eq!(instructions[0].imm, Some("00".to_string()));
    }
}
