//! Validate that all statically resolvable JUMP/JUMPI instructions target valid JUMPDESTs.
//!
//! `validate_jump_targets` is deliberately designed to work as it does right now i.e it only understands patterns
//! where a destination can be decoded from immediates (PUSHn right before the jump, or the PC-relative dispatcher).
//! Any other shape would require symbolic execution or full interpretation, which is out of scope for this helper.

use std::collections::HashSet;

use crate::{
    Opcode, decoder,
    result::{Error, Result},
};

/// Validate that all statically resolvable JUMP/JUMPI instructions target valid JUMPDESTs.
///
/// The validator checks two common patterns:
/// * Direct `PUSHn <addr>; JUMP/JUMPI`
/// * PC-relative dispatcher pattern `PUSHn <delta>; PC; ADD; JUMPI`
///
/// If a target falls outside the bytecode range or does not land on a JUMPDEST the function
/// returns an error listing all invalid jump targets found.
pub async fn validate_jump_targets(bytecode: &[u8]) -> Result<()> {
    let (instructions, _, _, _) = decoder::decode_bytecode(&hex::encode(bytecode), false)
        .await
        .map_err(|e| Error::Heimdall(format!("Failed to decode bytecode for validation: {}", e)))?;
    let jumpdests: HashSet<usize> = instructions
        .iter()
        .filter_map(|instr| matches!(instr.op, Opcode::JUMPDEST).then_some(instr.pc))
        .collect();

    eprintln!("\nValidator Found {} JUMPDESTs", jumpdests.len());
    let mut jumpdest_list: Vec<_> = jumpdests.iter().copied().collect();
    jumpdest_list.sort();
    for (i, pc) in jumpdest_list.iter().enumerate() {
        eprintln!("  [{}] PC 0x{:x}", i + 1, pc);
    }
    eprintln!();

    let mut invalid_jumps = Vec::new();

    for idx in 0..instructions.len() {
        let instr = &instructions[idx];
        if !matches!(instr.op, Opcode::JUMP | Opcode::JUMPI) {
            continue;
        }

        let Some(target) = resolve_jump_target(&instructions, idx) else {
            continue;
        };

        let is_valid = target < bytecode.len() && jumpdests.contains(&target);
        if !is_valid {
            eprintln!(
                "  DEBUG: JUMP at PC 0x{:x} targets 0x{:x} - valid={}, in_bounds={}, has_jumpdest={}",
                instr.pc,
                target,
                is_valid,
                target < bytecode.len(),
                jumpdests.contains(&target)
            );
            invalid_jumps.push((instr.pc, target));
        }
    }

    if !invalid_jumps.is_empty() {
        eprintln!("Found {} Invalid Jump(s)", invalid_jumps.len());
        for (i, (pc, target)) in invalid_jumps.iter().enumerate() {
            eprintln!("  [{}] PC 0x{:x} -> 0x{:x}", i + 1, pc, target);
        }
        eprintln!();

        return Err(Error::InvalidJumpTarget(invalid_jumps.len()));
    }

    Ok(())
}

// It tries to figure out where a JUMP/JUMPI will jump to by looking at the instructions before it.
// Returns:
//   - Some(target_address) if it can determine the target
//   - None if the pattern is unrecognizable or dynamic
fn resolve_jump_target(instructions: &[decoder::Instruction], idx: usize) -> Option<usize> {
    let instr = &instructions[idx];

    let previous_instr = instructions.get(idx.checked_sub(1)?)?;

    // PUSHn <addr>; JUMP/JUMPI
    match previous_instr.op {
        Opcode::PUSH0 => return Some(0),
        Opcode::PUSH(_) => {
            if let Some(target) = previous_instr
                .imm
                .as_deref()
                .and_then(|hex| usize::from_str_radix(hex, 16).ok())
            {
                return Some(target);
            }
        }
        _ => {}
    }

    // PUSHn <delta>; PC; ADD; JUMPI
    if matches!(instr.op, Opcode::JUMPI) {
        let push = instructions.get(idx.checked_sub(3)?)?;
        let pc_instr = instructions.get(idx.checked_sub(2)?)?;
        let add = instructions.get(idx.checked_sub(1)?)?;

        if matches!(push.op, Opcode::PUSH(_))
            && matches!(pc_instr.op, Opcode::PC)
            && matches!(add.op, Opcode::ADD)
        {
            return push
                .imm
                .as_deref()
                .and_then(|hex| usize::from_str_radix(hex, 16).ok())
                .map(|delta| pc_instr.pc.saturating_add(delta));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::validate_jump_targets;
    use crate::result::Error;

    #[tokio::test]
    async fn detects_valid_direct_jump() {
        // push1 0x03; jump; jumpdest; stop
        let bytecode = [0x60, 0x03, 0x56, 0x5b, 0x00];
        assert!(validate_jump_targets(&bytecode).await.is_ok());
    }

    #[tokio::test]
    async fn detects_invalid_direct_jump() {
        // push1 0x10; jump (no jumpdest at 0x10)
        let bytecode = [0x60, 0x10, 0x56, 0x5b, 0x00];
        let err = validate_jump_targets(&bytecode).await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("invalid jump target"));
    }

    #[tokio::test]
    async fn validates_pc_relative_pattern() {
        // push1 0x03; pc; add; jumpi; jumpdest; stop
        let bytecode = [0x60, 0x03, 0x58, 0x01, 0x57, 0x5b, 0x00];
        assert!(validate_jump_targets(&bytecode).await.is_ok());
    }

    #[tokio::test]
    async fn detects_invalid_pc_relative_pattern() {
        // push1 0x04; pc; add; jumpi; jumpdest (at 0x05, delta targets 0x06)
        let bytecode = [0x60, 0x04, 0x58, 0x01, 0x57, 0x5b, 0x00];
        let err = validate_jump_targets(&bytecode).await.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("invalid jump target"));
    }

    #[tokio::test]
    async fn ignores_dynamic_jump_pattern() {
        // treating dynamic jumps as errors would produce false positives for
        // perfectly valid runtime behavior
        // push1 0x00; dup1; jump; stop
        let bytecode = [0x60, 0x00, 0x80, 0x56, 0x00];
        assert!(validate_jump_targets(&bytecode).await.is_ok());
    }

    #[tokio::test]
    async fn reports_count_of_invalid_jumps() {
        // two invalid jumps:
        //   - jump to stop (no jumpdest)
        //   - jump past end of bytecode
        let bytecode = [0x60, 0x07, 0x56, 0x60, 0x09, 0x56, 0x5b, 0x00];
        match validate_jump_targets(&bytecode).await.unwrap_err() {
            Error::InvalidJumpTarget(count) => assert_eq!(count, 2),
            other => panic!("unexpected error: {other}"),
        }
    }
}
