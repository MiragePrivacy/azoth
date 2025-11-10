//! Controller-level obfuscation patterns for multi-tier dispatcher.
//!
//! This module provides various obfuscation patterns that can be applied within
//! dispatcher controller blocks. Each pattern adds a layer of complexity and
//! indirection before reaching the actual function entry point.

use azoth_core::decoder::Instruction;
use azoth_core::Opcode;

/// Configuration for byte extraction pattern in a controller block.
///
/// This pattern re-extracts a single byte from the calldata within the controller
/// and compares it against a derived token value. This adds an additional layer
/// of verification beyond the main dispatcher's 4-byte selector comparison.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ByteExtractionPattern {
    /// The byte index to extract (typically 0-3 for selector bytes)
    pub byte_index: u8,
    /// The expected byte value to compare against
    pub expected_value: u8,
    /// Program counter where the pattern should be inserted
    pub insert_pc: usize,
}

/// Configuration for storage-based routing pattern in a controller block.
///
/// This pattern checks storage slot values to determine routing decisions,
/// making control flow dependent on contract state.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct StorageRoutingPattern {
    /// Storage slot to load
    pub slot: u64,
    /// Expected value in the storage slot
    pub expected_value: u128,
    /// Target PC if the condition matches
    pub target_pc: usize,
}

/// Configuration for opaque predicate pattern in a controller block.
///
/// This pattern inserts conditionals that always evaluate to a known value
/// but are difficult to statically analyze, creating dead code paths.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct OpaquePredicatePattern {
    /// The predicate type (e.g., "1 == 0" always false, "x | !x" always true)
    pub predicate_type: PredicateType,
    /// Target PC for the "true" branch (typically invalid/decoy)
    pub true_target: usize,
    /// Target PC for the "false" branch (typically real path)
    pub false_target: usize,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum PredicateType {
    /// Always false: 1 == 0
    AlwaysFalse,
    /// Always true: 0 == 0
    AlwaysTrue,
    /// More complex: (x | !x) == all_bits_set (always true)
    BitwiseIdentity,
}

/// Generates instructions for a storage check pattern.
///
/// Creates a sequence that loads a value from a storage slot and checks if it
/// equals zero (the default state). This pattern leverages the fact that uninitialized
/// storage slots default to zero, creating functional routing without requiring SSTORE.
///
/// # Parameters
///
/// * `start_pc` - Starting program counter for the pattern
/// * `slot` - Storage slot to check
/// * `match_target` - Where to jump if the slot value is zero
/// * `fallback_target` - Where to jump if the slot value is non-zero
///
/// # Returns
///
/// A tuple of (generated instructions, next available PC).
pub fn generate_storage_check_instructions(
    start_pc: usize,
    slot: u64,
    match_target: usize,
    fallback_target: usize,
) -> (Vec<Instruction>, usize) {
    let mut instructions = Vec::new();
    let mut pc = start_pc;

    // Determine push width for slot
    let slot_width = minimal_push_width_u64(slot);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(slot_width),
        imm: Some(format!(
            "{:0width$x}",
            slot,
            width = slot_width as usize * 2
        )),
    });
    pc += 1 + slot_width as usize;

    // SLOAD - load value from storage slot
    instructions.push(Instruction {
        pc,
        op: Opcode::SLOAD,
        imm: None,
    });
    pc += 1;

    // ISZERO - check if value is zero (default state)
    instructions.push(Instruction {
        pc,
        op: Opcode::ISZERO,
        imm: None,
    });
    pc += 1;

    // Determine push width for match target
    let match_width = minimal_push_width(match_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(match_width),
        imm: Some(format!(
            "{:0width$x}",
            match_target,
            width = match_width as usize * 2
        )),
    });
    pc += 1 + match_width as usize;

    // JUMPI - conditional jump to match target if zero
    instructions.push(Instruction {
        pc,
        op: Opcode::JUMPI,
        imm: None,
    });
    pc += 1;

    // Determine push width for fallback target
    let fallback_width = minimal_push_width(fallback_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(fallback_width),
        imm: Some(format!(
            "{:0width$x}",
            fallback_target,
            width = fallback_width as usize * 2
        )),
    });
    pc += 1 + fallback_width as usize;

    // JUMP - unconditional jump to fallback
    instructions.push(Instruction {
        pc,
        op: Opcode::JUMP,
        imm: None,
    });
    pc += 1;

    (instructions, pc)
}

/// Generates instructions for a byte extraction pattern.
///
/// Creates a sequence that re-extracts a single byte from calldata and compares
/// it against an expected value. This can be used within controller blocks to add
/// an additional verification layer.
///
/// # Parameters
///
/// * `start_pc` - Starting program counter for the pattern
/// * `byte_index` - Which byte to extract (0-3 for selector)
/// * `expected_value` - The byte value to compare against
/// * `match_target` - Where to jump if the comparison succeeds
/// * `fallback_target` - Where to jump if the comparison fails
///
/// # Returns
///
/// A tuple of (generated instructions, next available PC).
pub fn generate_byte_extraction_instructions(
    start_pc: usize,
    byte_index: u8,
    expected_value: u8,
    match_target: usize,
    fallback_target: usize,
) -> (Vec<Instruction>, usize) {
    let mut instructions = Vec::new();
    let mut pc = start_pc;

    // PUSH1 0x00 - prepare for calldata load
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(1),
        imm: Some("00".to_string()),
    });
    pc += 2;

    // CALLDATALOAD - load 32 bytes from calldata
    instructions.push(Instruction {
        pc,
        op: Opcode::CALLDATALOAD,
        imm: None,
    });
    pc += 1;

    // PUSH1 <byte_index> - byte position to extract
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(1),
        imm: Some(format!("{:02x}", byte_index)),
    });
    pc += 2;

    // BYTE - extract the byte at the specified index
    instructions.push(Instruction {
        pc,
        op: Opcode::BYTE,
        imm: None,
    });
    pc += 1;

    // PUSH1 <expected_value> - the value to compare against
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(1),
        imm: Some(format!("{:02x}", expected_value)),
    });
    pc += 2;

    // EQ - compare extracted byte with expected value
    instructions.push(Instruction {
        pc,
        op: Opcode::EQ,
        imm: None,
    });
    pc += 1;

    // Determine push width for match target
    let match_width = minimal_push_width(match_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(match_width),
        imm: Some(format!(
            "{:0width$x}",
            match_target,
            width = match_width as usize * 2
        )),
    });
    pc += 1 + match_width as usize;

    // JUMPI - conditional jump to match target
    instructions.push(Instruction {
        pc,
        op: Opcode::JUMPI,
        imm: None,
    });
    pc += 1;

    // Determine push width for fallback target
    let fallback_width = minimal_push_width(fallback_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(fallback_width),
        imm: Some(format!(
            "{:0width$x}",
            fallback_target,
            width = fallback_width as usize * 2
        )),
    });
    pc += 1 + fallback_width as usize;

    // JUMP - unconditional jump to fallback
    instructions.push(Instruction {
        pc,
        op: Opcode::JUMP,
        imm: None,
    });
    pc += 1;

    (instructions, pc)
}

/// Generates instructions for an opaque predicate pattern.
///
/// Creates a conditional that always evaluates to a known value but appears
/// complex to static analysis, creating believable decoy paths.
///
/// # Parameters
///
/// * `start_pc` - Starting program counter for the pattern
/// * `predicate_type` - The type of opaque predicate to generate
/// * `true_target` - Where to jump if condition is true
/// * `false_target` - Where to jump if condition is false
///
/// # Returns
///
/// A tuple of (generated instructions, next available PC).
#[allow(dead_code)]
pub fn generate_opaque_predicate_instructions(
    start_pc: usize,
    predicate_type: &PredicateType,
    true_target: usize,
    false_target: usize,
) -> (Vec<Instruction>, usize) {
    let mut instructions = Vec::new();
    let mut pc = start_pc;

    match predicate_type {
        PredicateType::AlwaysFalse => {
            // PUSH1 0x01
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(1),
                imm: Some("01".to_string()),
            });
            pc += 2;

            // PUSH1 0x00
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(1),
                imm: Some("00".to_string()),
            });
            pc += 2;

            // EQ (always false: 1 == 0)
            instructions.push(Instruction {
                pc,
                op: Opcode::EQ,
                imm: None,
            });
            pc += 1;
        }
        PredicateType::AlwaysTrue => {
            // PUSH1 0x00
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(1),
                imm: Some("00".to_string()),
            });
            pc += 2;

            // PUSH1 0x00
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(1),
                imm: Some("00".to_string()),
            });
            pc += 2;

            // EQ (always true: 0 == 0)
            instructions.push(Instruction {
                pc,
                op: Opcode::EQ,
                imm: None,
            });
            pc += 1;
        }
        PredicateType::BitwiseIdentity => {
            // PUSH1 0x42 (arbitrary value)
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(1),
                imm: Some("42".to_string()),
            });
            pc += 2;

            // DUP1
            instructions.push(Instruction {
                pc,
                op: Opcode::DUP(1),
                imm: None,
            });
            pc += 1;

            // NOT
            instructions.push(Instruction {
                pc,
                op: Opcode::NOT,
                imm: None,
            });
            pc += 1;

            // OR (x | !x = all bits set)
            instructions.push(Instruction {
                pc,
                op: Opcode::OR,
                imm: None,
            });
            pc += 1;

            // PUSH32 0xff...ff (all bits set)
            instructions.push(Instruction {
                pc,
                op: Opcode::PUSH(32),
                imm: Some("ff".repeat(32)),
            });
            pc += 33;

            // EQ (always true)
            instructions.push(Instruction {
                pc,
                op: Opcode::EQ,
                imm: None,
            });
            pc += 1;
        }
    }

    // Add conditional jump
    let true_width = minimal_push_width(true_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(true_width),
        imm: Some(format!(
            "{:0width$x}",
            true_target,
            width = true_width as usize * 2
        )),
    });
    pc += 1 + true_width as usize;

    instructions.push(Instruction {
        pc,
        op: Opcode::JUMPI,
        imm: None,
    });
    pc += 1;

    // Add unconditional jump to false target
    let false_width = minimal_push_width(false_target);
    instructions.push(Instruction {
        pc,
        op: Opcode::PUSH(false_width),
        imm: Some(format!(
            "{:0width$x}",
            false_target,
            width = false_width as usize * 2
        )),
    });
    pc += 1 + false_width as usize;

    instructions.push(Instruction {
        pc,
        op: Opcode::JUMP,
        imm: None,
    });
    pc += 1;

    (instructions, pc)
}

fn minimal_push_width(value: usize) -> u8 {
    for width in 1..=32 {
        let max = if width == 32 {
            usize::MAX
        } else {
            (1usize << (width * 8)) - 1
        };
        if value <= max {
            return width as u8;
        }
    }
    32
}

fn minimal_push_width_u64(value: u64) -> u8 {
    if value == 0 {
        return 1;
    }
    for width in 1..=8 {
        let max = if width == 8 {
            u64::MAX
        } else {
            (1u64 << (width * 8)) - 1
        };
        if value <= max {
            return width as u8;
        }
    }
    8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_extraction_instructions() {
        let (instructions, next_pc) = generate_byte_extraction_instructions(
            0x1000, 3,      // byte index
            0x7f,   // expected value
            0x2000, // match target
            0x3000, // fallback target
        );

        // Verify we have all expected instructions
        assert!(!instructions.is_empty());
        assert_eq!(instructions[0].pc, 0x1000);
        assert!(matches!(instructions[0].op, Opcode::PUSH(1)));

        // Verify CALLDATALOAD is present
        assert!(instructions
            .iter()
            .any(|i| matches!(i.op, Opcode::CALLDATALOAD)));

        // Verify BYTE is present
        assert!(instructions.iter().any(|i| matches!(i.op, Opcode::BYTE)));

        // Verify EQ is present
        assert!(instructions.iter().any(|i| matches!(i.op, Opcode::EQ)));

        // Verify next_pc is after all instructions
        assert!(next_pc > 0x1000);
    }

    #[test]
    fn test_opaque_predicate_always_false() {
        let (instructions, next_pc) = generate_opaque_predicate_instructions(
            0x1000,
            &PredicateType::AlwaysFalse,
            0x2000,
            0x3000,
        );

        assert!(!instructions.is_empty());
        assert_eq!(instructions[0].pc, 0x1000);

        // Should contain EQ instruction
        assert!(instructions.iter().any(|i| matches!(i.op, Opcode::EQ)));

        // Should contain JUMPI
        assert!(instructions.iter().any(|i| matches!(i.op, Opcode::JUMPI)));

        assert!(next_pc > 0x1000);
    }

    #[test]
    fn test_storage_check_instructions() {
        let (instructions, next_pc) = generate_storage_check_instructions(
            0x1000, 0x7a3c, // Random storage slot
            0x2000, // Match target (if zero)
            0x3000, // Fallback target (if non-zero)
        );

        // Verify we have all expected instructions
        assert!(!instructions.is_empty());
        assert_eq!(instructions[0].pc, 0x1000);

        // First instruction should be PUSH for the slot
        assert!(matches!(instructions[0].op, Opcode::PUSH(_)));

        // Verify SLOAD is present
        assert!(
            instructions.iter().any(|i| matches!(i.op, Opcode::SLOAD)),
            "Should contain SLOAD instruction"
        );

        // Verify ISZERO is present
        assert!(
            instructions.iter().any(|i| matches!(i.op, Opcode::ISZERO)),
            "Should contain ISZERO instruction"
        );

        // Verify JUMPI is present (conditional jump)
        assert!(
            instructions.iter().any(|i| matches!(i.op, Opcode::JUMPI)),
            "Should contain JUMPI instruction"
        );

        // Verify JUMP is present (unconditional fallback)
        assert!(
            instructions.iter().any(|i| matches!(i.op, Opcode::JUMP)),
            "Should contain JUMP instruction"
        );

        // Verify next_pc is after all instructions
        assert!(next_pc > 0x1000);
    }

    #[test]
    fn test_storage_check_small_slot() {
        // Test with a small slot value (1-byte PUSH)
        let (instructions, _) = generate_storage_check_instructions(
            0x1000, 0x05, // Small slot
            0x2000, 0x3000,
        );

        // First instruction should be PUSH1 for small slot
        assert!(matches!(instructions[0].op, Opcode::PUSH(1)));
        assert_eq!(instructions[0].imm.as_deref(), Some("05"));
    }

    #[test]
    fn test_storage_check_large_slot() {
        // Test with a larger slot value (2-byte PUSH)
        let (instructions, _) = generate_storage_check_instructions(
            0x1000, 0xabcd, // Larger slot requiring 2 bytes
            0x2000, 0x3000,
        );

        // First instruction should be PUSH2 for larger slot
        assert!(matches!(instructions[0].op, Opcode::PUSH(2)));
        assert_eq!(instructions[0].imm.as_deref(), Some("abcd"));
    }

    #[test]
    fn test_storage_check_instruction_sequence() {
        let (instructions, _) = generate_storage_check_instructions(0x1000, 0x100, 0x2000, 0x3000);

        // Verify the sequence order
        let opcodes: Vec<_> = instructions.iter().map(|i| &i.op).collect();

        // Should have: PUSH(slot), SLOAD, ISZERO, PUSH(match), JUMPI, PUSH(fallback), JUMP
        assert!(matches!(opcodes[0], Opcode::PUSH(_)));
        assert!(matches!(opcodes[1], Opcode::SLOAD));
        assert!(matches!(opcodes[2], Opcode::ISZERO));
        assert!(matches!(opcodes[3], Opcode::PUSH(_)));
        assert!(matches!(opcodes[4], Opcode::JUMPI));
        assert!(matches!(opcodes[5], Opcode::PUSH(_)));
        assert!(matches!(opcodes[6], Opcode::JUMP));
    }
}
