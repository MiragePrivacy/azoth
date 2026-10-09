//! Encode EVM instructions into bytecode

use crate::Opcode;
use crate::decoder::Instruction;
use crate::result::Error;
use crate::strip::CleanReport;
use hex;

/// Encodes a sequence of EVM instructions into bytecode.
///
/// # Arguments
/// * `instructions` - A slice of `Instruction` structs, each containing an opcode and optional
///   immediate data.
/// * `bytecode` - Retained for source compatibility; native opcodes are self-contained and this
///   reference is never consulted.
///
/// # Returns
/// A `Result` containing the encoded bytecode as a `Vec<u8>` or an `Error` if encoding fails.
///
/// # Examples
/// ```rust,ignore
/// use azoth_core::Opcode;
/// let ins = Instruction {
///     pc: 0,
///     op: Opcode::PUSH(1),
///     imm: Some("aa".to_string()),
/// };
/// let bytes = encode(&[ins], &[0x60, 0xaa]).unwrap();
/// assert_eq!(bytes, vec![0x60, 0xaa]);
/// ```
pub fn encode(instructions: &[Instruction], _bytecode: &[u8]) -> Result<Vec<u8>, Error> {
    let capacity = validate_instruction_stream(instructions)?;
    let mut bytes = Vec::with_capacity(capacity);

    for ins in instructions {
        tracing::debug!(
            "Encoding instruction: pc={}, opcode='{}', imm={:?}",
            ins.pc,
            ins.op,
            ins.imm
        );

        let opcode = ins.op;
        let opcode_byte = opcode
            .try_to_byte()
            .map_err(|error| Error::UnsupportedOpcode(error.to_string()))?;

        tracing::debug!("Encoding opcode '{}' -> byte 0x{:02x}", opcode, opcode_byte);
        bytes.push(opcode_byte);

        if let Opcode::PUSH(_) = opcode {
            let immediate = ins.imm.as_deref().ok_or_else(|| {
                Error::InvalidImmediate(format!("{opcode} missing immediate at pc={}", ins.pc))
            })?;
            let imm_bytes = hex::decode(immediate).map_err(|error| {
                Error::InvalidImmediate(format!(
                    "invalid hex immediate '{immediate}' for {opcode} at pc={}: {error}",
                    ins.pc
                ))
            })?;
            bytes.extend_from_slice(&imm_bytes);
            tracing::debug!("Added {} immediate bytes for {}", imm_bytes.len(), opcode);
        }
    }

    tracing::debug!(
        "Successfully encoded {} instructions into {} bytes",
        instructions.len(),
        bytes.len()
    );
    Ok(bytes)
}

fn validate_instruction_stream(instructions: &[Instruction]) -> Result<usize, Error> {
    let mut capacity = 0usize;
    let mut expected_pc = instructions.first().map_or(0, |instruction| instruction.pc);

    for (index, instruction) in instructions.iter().enumerate() {
        if instruction.pc != expected_pc {
            return Err(Error::InvalidBlockStructure(format!(
                "non-contiguous instruction PCs: expected 0x{expected_pc:x}, found 0x{:x}",
                instruction.pc
            )));
        }
        instruction
            .op
            .try_to_byte()
            .map_err(|error| Error::UnsupportedOpcode(error.to_string()))?;

        let encoded_size = match instruction.op {
            Opcode::PUSH(width) => {
                let immediate = instruction.imm.as_deref().ok_or_else(|| {
                    Error::InvalidImmediate(format!(
                        "PUSH{width} missing immediate at pc={}",
                        instruction.pc
                    ))
                })?;
                let maximum_hex_len = usize::from(width) * 2;
                if immediate.len() > maximum_hex_len {
                    return Err(Error::InvalidImmediate(format!(
                        "PUSH{width} accepts at most {width} immediate bytes, got {} bytes at pc={}",
                        immediate.len().div_ceil(2),
                        instruction.pc
                    )));
                }
                if immediate.len() % 2 != 0
                    || !immediate.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(Error::InvalidImmediate(format!(
                        "PUSH{width} immediate at pc={} must be whole-byte hexadecimal",
                        instruction.pc
                    )));
                }
                let immediate_bytes = immediate.len() / 2;
                if immediate_bytes < usize::from(width) && index + 1 != instructions.len() {
                    return Err(Error::InvalidImmediate(format!(
                        "truncated PUSH{width} at pc={} must be the final instruction",
                        instruction.pc
                    )));
                }
                1usize.checked_add(immediate_bytes).ok_or_else(|| {
                    Error::InvalidBlockStructure("encoded instruction size overflow".into())
                })?
            }
            _ if instruction.imm.is_some() => {
                return Err(Error::InvalidImmediate(format!(
                    "{} at pc={} cannot carry immediate data",
                    instruction.op, instruction.pc
                )));
            }
            _ => 1,
        };

        capacity = capacity.checked_add(encoded_size).ok_or_else(|| {
            Error::InvalidBlockStructure("encoded bytecode length overflow".into())
        })?;
        expected_pc = expected_pc
            .checked_add(encoded_size)
            .ok_or_else(|| Error::InvalidBlockStructure("instruction PC overflow".into()))?;
    }

    Ok(capacity)
}

/// Reassembles the original bytecode by combining runtime bytecode with non-runtime sections.
///
/// Uses the `CleanReport` from the `strip` module to restore sections like init code, constructor
/// arguments, and auxdata that were removed during stripping.
///
/// # Arguments
/// * `runtime` - The cleaned runtime bytecode as a slice of bytes.
/// * `report` - The `CleanReport` containing metadata about removed sections (mutable to update init code).
///
/// # Returns
/// The reassembled bytecode, or an error when init-code relocation cannot be proven safe.
pub fn rebuild(runtime: &[u8], report: &mut CleanReport) -> Result<Vec<u8>, Error> {
    report.reassemble(runtime).map_err(Error::ObfuscationFailed)
}

#[cfg(test)]
mod tests {
    use super::encode;
    use crate::Opcode;
    use crate::decoder::Instruction;
    use crate::result::Error;

    #[test]
    fn encodes_push_and_standard_opcodes() {
        let instructions = vec![
            Instruction {
                pc: 0,
                op: Opcode::PUSH(1),
                imm: Some("aa".into()),
            },
            Instruction {
                pc: 2,
                op: Opcode::ADD,
                imm: None,
            },
            Instruction {
                pc: 3,
                op: Opcode::STOP,
                imm: None,
            },
        ];

        let bytes = encode(&instructions, &[]).expect("encodes push/add/stop");
        assert_eq!(bytes, vec![0x60, 0xaa, 0x01, 0x00]);
    }

    #[test]
    fn invalid_always_encodes_as_fe() {
        let instructions = vec![Instruction {
            pc: 5,
            op: Opcode::INVALID,
            imm: None,
        }];

        let bytes = encode(&instructions, &[]).expect("encodes invalid");
        assert_eq!(bytes, vec![0xfe]);
    }

    #[test]
    fn rejects_immediate_on_non_push_opcode() {
        let instructions = vec![Instruction {
            pc: 5,
            op: Opcode::JUMP,
            imm: Some("1234".into()),
        }];

        let error = encode(&instructions, &[]).unwrap_err();
        assert!(matches!(error, Error::InvalidImmediate(_)));
        assert!(error.to_string().contains("cannot carry immediate data"));
    }

    #[test]
    fn rejects_non_contiguous_program_counters() {
        let instructions = vec![
            Instruction {
                pc: 4,
                op: Opcode::STOP,
                imm: None,
            },
            Instruction {
                pc: 6,
                op: Opcode::ADD,
                imm: None,
            },
        ];

        let error = encode(&instructions, &[]).unwrap_err();
        assert!(matches!(error, Error::InvalidBlockStructure(_)));
        assert!(error.to_string().contains("non-contiguous instruction PCs"));
    }

    #[test]
    fn rejects_oversized_immediate_before_hex_decoding() {
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(1),
            imm: Some("z".repeat(1_000_000)),
        }];

        let error = encode(&instructions, &[]).unwrap_err();
        assert!(matches!(error, Error::InvalidImmediate(_)));
        assert!(error.to_string().contains("at most 1 immediate bytes"));
        assert!(error.to_string().len() < 200);
    }

    #[test]
    fn invalid_never_uses_reference_bytecode() {
        let instructions = vec![Instruction {
            pc: 2,
            op: Opcode::INVALID,
            imm: None,
        }];
        let reference = [0xaa, 0xbb, 0xcc, 0xdd];

        let bytes = encode(&instructions, &reference).expect("encodes invalid from bytecode");
        assert_eq!(bytes, vec![0xfe]);
    }

    #[test]
    fn rejects_assigned_byte_disguised_as_unknown() {
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::UNKNOWN(0x56),
            imm: None,
        }];

        let error = encode(&instructions, &[]).unwrap_err();
        assert!(matches!(error, Error::UnsupportedOpcode(_)));
        assert!(error.to_string().contains("cannot be marked UNKNOWN"));
    }

    #[test]
    fn errors_on_missing_push_immediate() {
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(2),
            imm: None,
        }];

        let err = encode(&instructions, &[]).unwrap_err();
        assert!(
            matches!(err, Error::InvalidImmediate(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn encodes_truncated_push_only_at_end() {
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(2),
            imm: Some("aa".into()),
        }];

        assert_eq!(encode(&instructions, &[]).unwrap(), vec![0x61, 0xaa]);

        let mut followed = instructions;
        followed.push(Instruction {
            pc: 2,
            op: Opcode::STOP,
            imm: None,
        });
        let err = encode(&followed, &[]).unwrap_err();
        assert!(matches!(err, Error::InvalidImmediate(_)));
    }
}
