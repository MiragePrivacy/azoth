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
/// * `bytecode` - Reference bytecode to extract unknown opcode bytes from using PC.
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
pub fn encode(instructions: &[Instruction], bytecode: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(instructions.len() * 3);
    let mut unknown_count = 0;

    for ins in instructions {
        tracing::debug!(
            "Encoding instruction: pc={}, opcode='{}', imm={:?}",
            ins.pc,
            ins.op,
            ins.imm
        );

        // Handle INVALID opcodes by preserving the exact original byte.
        //
        // Note: INVALID here is often a placeholder from the decoder, not the actual 0xFE opcode.
        // When heimdall outputs "unknown" without a hex byte, the decoder uses INVALID as a marker.
        // We recover the actual byte value from the original bytecode using PC and
        // fail closed if recovery is impossible.
        if matches!(ins.op, Opcode::INVALID) {
            let recovered = ins
                .imm
                .as_deref()
                .and_then(|immediate| u8::from_str_radix(immediate, 16).ok())
                .or_else(|| bytecode.get(ins.pc).copied())
                .ok_or_else(|| {
                    Error::UnsupportedOpcode(format!(
                        "cannot recover INVALID/raw byte at pc 0x{:x}",
                        ins.pc
                    ))
                })?;
            bytes.push(recovered);
            if recovered == Opcode::INVALID.to_byte() {
                tracing::debug!(pc = ins.pc, "Encoded explicit EVM INVALID (0xfe)");
            } else {
                unknown_count += 1;
                tracing::warn!(
                    pc = ins.pc,
                    byte = recovered,
                    "Preserved decoder-unknown opcode as its exact raw byte"
                );
            }
            continue;
        }

        let opcode = ins.op;

        tracing::debug!(
            "Encoding opcode '{}' -> byte 0x{:02x}",
            opcode,
            opcode.to_byte()
        );
        bytes.push(opcode.to_byte());

        // Handle immediate data for PUSH opcodes
        if let Opcode::PUSH(n) = opcode {
            if let Some(immediate) = &ins.imm {
                let imm_bytes = match hex::decode(immediate) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!(
                            "Failed to decode immediate '{}' (len {}) for {} at pc={}: {:?}",
                            immediate,
                            immediate.len(),
                            opcode,
                            ins.pc,
                            e
                        );
                        return Err(Error::InvalidImmediate(format!(
                            "invalid hex immediate '{}' for {} at pc={}: {:?}",
                            immediate, opcode, ins.pc, e
                        )));
                    }
                };
                if imm_bytes.len() != n as usize {
                    tracing::error!(
                        "Invalid immediate length for {}: expected {} bytes, got {} bytes",
                        opcode,
                        n,
                        imm_bytes.len()
                    );
                    return Err(Error::InvalidImmediate(format!(
                        "PUSH{} requires {}-byte immediate, got {} bytes at pc={}",
                        n,
                        n,
                        imm_bytes.len(),
                        ins.pc
                    )));
                }
                bytes.extend_from_slice(&imm_bytes);
                tracing::debug!("Added {} immediate bytes for {}", imm_bytes.len(), opcode);
            } else {
                tracing::error!("Missing immediate for {} at pc={}", opcode, ins.pc);
                return Err(Error::InvalidImmediate(format!(
                    "PUSH{} missing immediate at pc={}",
                    n, ins.pc
                )));
            }
        }
    }

    if unknown_count > 0 {
        tracing::warn!(
            "Encoded {} decoder-unknown opcode(s) as exact raw bytes.",
            unknown_count
        );
    }

    tracing::debug!(
        "Successfully encoded {} instructions into {} bytes",
        instructions.len(),
        bytes.len()
    );
    Ok(bytes)
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
/// The reassembled bytecode as a `Vec<u8>`.
pub fn rebuild(runtime: &[u8], report: &mut CleanReport) -> Vec<u8> {
    report.reassemble(runtime)
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
    fn preserves_invalid_from_immediate() {
        let instructions = vec![Instruction {
            pc: 5,
            op: Opcode::INVALID,
            imm: Some("fe".into()),
        }];

        let bytes = encode(&instructions, &[]).expect("encodes invalid from imm");
        assert_eq!(bytes, vec![0xfe]);
    }

    #[test]
    fn preserves_invalid_from_bytecode_fallback() {
        let instructions = vec![Instruction {
            pc: 2,
            op: Opcode::INVALID,
            imm: None,
        }];
        let reference = [0xaa, 0xbb, 0xcc, 0xdd];

        let bytes = encode(&instructions, &reference).expect("encodes invalid from bytecode");
        assert_eq!(bytes, vec![reference[2]]);
    }

    #[test]
    fn errors_when_invalid_raw_byte_cannot_be_recovered() {
        let instructions = vec![Instruction {
            pc: 7,
            op: Opcode::INVALID,
            imm: None,
        }];

        let err = encode(&instructions, &[]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedOpcode(_)),
            "unexpected error: {err:?}"
        );
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
    fn errors_on_wrong_immediate_length() {
        let instructions = vec![Instruction {
            pc: 0,
            op: Opcode::PUSH(2),
            imm: Some("aa".into()),
        }];

        let err = encode(&instructions, &[]).unwrap_err();
        assert!(
            matches!(err, Error::InvalidImmediate(_)),
            "unexpected error: {err:?}"
        );
    }
}
