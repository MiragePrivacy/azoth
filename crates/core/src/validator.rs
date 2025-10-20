//! Validate that all statically resolvable JUMP/JUMPI instructions target valid JUMPDESTs.

use std::collections::HashSet;

use crate::{
    Opcode,
    result::{Error, Result},
};

#[derive(Debug, Clone)]
struct SimpleInstruction {
    pc: usize,
    opcode: Opcode,
    immediate: Option<Vec<u8>>,
}

/// Validate that all statically resolvable JUMP/JUMPI instructions target valid JUMPDESTs.
///
/// The validator checks two common patterns:
/// * Direct `PUSHn <addr>; JUMP/JUMPI`
/// * PC-relative dispatcher pattern `PUSHn <delta>; PC; ADD; JUMPI`
///
/// If a target falls outside the bytecode range or does not land on a JUMPDEST the function
/// returns `Error::InvalidJumpTarget` identifying the faulty PC and computed destination.
pub fn validate_jump_targets(bytecode: &[u8]) -> Result<()> {
    let instructions = parse_instructions(bytecode)?;
    let jumpdests: HashSet<usize> = instructions
        .iter()
        .filter_map(|instr| matches!(instr.opcode, Opcode::JUMPDEST).then_some(instr.pc))
        .collect();

    for idx in 0..instructions.len() {
        let instr = &instructions[idx];
        if matches!(instr.opcode, Opcode::JUMP | Opcode::JUMPI) {
            if let Some(target) = resolve_jump_target(&instructions, idx) {
                if target >= bytecode.len() || !jumpdests.contains(&target) {
                    return Err(Error::InvalidJumpTarget {
                        pc: instr.pc,
                        target,
                    });
                }
            }
        }
    }

    Ok(())
}

fn parse_instructions(bytecode: &[u8]) -> Result<Vec<SimpleInstruction>> {
    let mut instructions = Vec::new();
    let mut pc = 0usize;

    while pc < bytecode.len() {
        let opcode = Opcode::from(bytecode[pc]);
        let imm_len = match opcode {
            Opcode::PUSH0 => 0,
            Opcode::PUSH(n) => n as usize,
            _ => 0,
        };

        let end = pc + 1 + imm_len;
        if end > bytecode.len() {
            return Err(Error::InvalidImmediate(format!(
                "PUSH{} at pc 0x{:x} exceeds bytecode bounds",
                imm_len, pc
            )));
        }

        let immediate = if imm_len > 0 {
            Some(bytecode[(pc + 1)..end].to_vec())
        } else {
            None
        };

        instructions.push(SimpleInstruction {
            pc,
            opcode,
            immediate,
        });

        pc = end;
    }

    Ok(instructions)
}

fn resolve_jump_target(instructions: &[SimpleInstruction], idx: usize) -> Option<usize> {
    if idx == 0 {
        return None;
    }

    let instr = &instructions[idx];
    let prev = &instructions[idx - 1];

    // Direct pattern: PUSHn <addr>; JUMP/JUMPI
    match prev.opcode {
        Opcode::PUSH0 => return Some(0),
        Opcode::PUSH(_) => {
            if let Some(imm) = &prev.immediate {
                return Some(bytes_to_usize(imm));
            }
        }
        _ => {}
    }

    // PC-relative pattern: PUSHn <delta>; PC; ADD; JUMPI
    if matches!(instr.opcode, Opcode::JUMPI) && idx >= 3 {
        let push = &instructions[idx - 3];
        let pc_instr = &instructions[idx - 2];
        let add = &instructions[idx - 1];

        if matches!(push.opcode, Opcode::PUSH(_))
            && matches!(pc_instr.opcode, Opcode::PC)
            && matches!(add.opcode, Opcode::ADD)
            && push.immediate.is_some()
        {
            let delta = bytes_to_usize(push.immediate.as_ref().unwrap());
            return Some(pc_instr.pc.saturating_add(delta));
        }
    }

    None
}

fn bytes_to_usize(bytes: &[u8]) -> usize {
    let mut value: usize = 0;
    for &byte in bytes {
        value = (value << 8) | byte as usize;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::validate_jump_targets;

    #[test]
    fn detects_valid_direct_jump() {
        // push 0x03; jump; jumpdest; stop
        let bytecode = [0x60, 0x03, 0x56, 0x5b, 0x00];
        assert!(validate_jump_targets(&bytecode).is_ok());
    }

    #[test]
    fn detects_invalid_direct_jump() {
        // push 0x10; jump (no jumpdest at 0x10)
        let bytecode = [0x60, 0x10, 0x56, 0x5b, 0x00];
        let err = validate_jump_targets(&bytecode).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("invalid jump target"));
    }

    #[test]
    fn validates_pc_relative_pattern() {
        // push 0x03; pc; add; jumpi; jumpdest; stop
        let bytecode = [0x60, 0x03, 0x58, 0x01, 0x57, 0x5b, 0x00];
        assert!(validate_jump_targets(&bytecode).is_ok());
    }

    #[test]
    fn detects_invalid_pc_relative_pattern() {
        // push 0x04; pc; add; jumpi; jumpdest (at 0x05, delta targets 0x06)
        let bytecode = [0x60, 0x04, 0x58, 0x01, 0x57, 0x5b, 0x00];
        let err = validate_jump_targets(&bytecode).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("invalid jump target"));
    }
}
