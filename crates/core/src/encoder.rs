//! Module for encoding EVM instructions into bytecode and reassembling bytecode with
//! non-runtime sections.

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

        // Handle INVALID opcodes by attempting to preserve the original byte.
        //
        // Note: INVALID here is often a placeholder from the decoder, not the actual 0xFE opcode.
        // When heimdall outputs "unknown" without a hex byte, the decoder uses INVALID as a marker.
        // We recover the actual byte value from the original bytecode using PC, or skip if unavailable.
        if matches!(ins.op, Opcode::INVALID) {
            unknown_count += 1;
            tracing::warn!("Encoding INVALID opcode at pc={}", ins.pc);

            // First try immediate data (might contain the original byte value)
            if let Some(immediate) = &ins.imm
                && let Ok(byte_val) = u8::from_str_radix(immediate, 16)
            {
                bytes.push(byte_val);
                tracing::debug!(
                    "Preserved INVALID opcode from immediate as byte 0x{:02x}",
                    byte_val
                );
                continue;
            }

            // Then try bytecode lookup
            if ins.pc < bytecode.len() {
                let byte_val = bytecode[ins.pc];
                bytes.push(byte_val);
                tracing::debug!(
                    "Preserved INVALID opcode from bytecode as byte 0x{:02x} at pc={}",
                    byte_val,
                    ins.pc
                );
                continue;
            }

            // Last resort: SKIP the instruction (cannot determine byte value)
            tracing::error!(
                "Cannot determine byte value for INVALID opcode at pc={}, skipping (this may break functionality)",
                ins.pc
            );
            continue; // Skip this instruction instead of encoding 0xFE
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
                let imm_bytes = hex::decode(immediate).inspect_err(|&e| {
                    tracing::error!(
                        "Failed to decode immediate '{}' for {} at pc={}: {:?}",
                        immediate,
                        opcode,
                        ins.pc,
                        e
                    );
                })?;
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
            "Encoded {} unknown opcodes as raw bytes. The resulting bytecode preserves the original bytes but these may represent invalid EVM instructions.",
            unknown_count
        );
        tracing::warn!(
            "If the original contract works, the obfuscated version should too. If not, the input bytecode may be corrupted."
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
