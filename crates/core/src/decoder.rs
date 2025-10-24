//! Azoth's single entry-point for turning byte-sequences into Heimdall instruction streams.

use crate::Opcode;
use crate::result::Error;
use heimdall::{DisassemblerArgsBuilder, disassemble};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

/// Single disassembled EVM instruction with PC, opcode, and optional immediate data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Instruction {
    /// Program counter (byte offset)
    pub pc: usize,
    /// Parsed opcode
    pub op: Opcode,
    /// Immediate data (hex string without 0x prefix)
    pub imm: Option<String>,
}

/// Decoded bytecode metadata (length, hash, source).
#[derive(Debug)]
pub struct DecodeInfo {
    /// Bytecode length in bytes
    pub byte_length: usize,
    /// Keccak-256 hash
    pub keccak_hash: [u8; 32],
    /// Input source type
    pub source: SourceType,
}

/// Bytecode input source type.
#[derive(Debug, PartialEq, Eq)]
pub enum SourceType {
    HexString,
    File,
}

/// Decodes raw EVM bytecode into an instruction stream with metadata and raw assembly.
pub async fn decode_bytecode(
    input: &str,
    is_file: bool,
) -> Result<(Vec<Instruction>, DecodeInfo, String, Vec<u8>), Error> {
    let bytes = crate::input_to_bytes(input, is_file)?;
    let source = if is_file {
        SourceType::File
    } else {
        SourceType::HexString
    };

    let byte_length = bytes.len();
    let mut keccak = Keccak::v256();
    keccak.update(&bytes);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let target_arg = format!("0x{}", hex::encode(&bytes));
    let args = DisassemblerArgsBuilder::new()
        .target(target_arg)
        .output("print".into())
        .decimal_counter(false)
        .build()
        .map_err(|e| Error::Heimdall(e.to_string()))?;

    let asm = disassemble(args)
        .await
        .map_err(|e| Error::Heimdall(e.to_string()))?;

    let instructions = parse_assembly(&asm)?;

    Ok((
        instructions,
        DecodeInfo {
            byte_length,
            keccak_hash: hash,
            source,
        },
        asm,
        bytes,
    ))
}

/// Parses Heimdall assembly output into structured instructions.
pub fn parse_assembly(asm: &str) -> Result<Vec<Instruction>, Error> {
    // Fail on empty assembly
    if asm.trim().is_empty() {
        return Err(Error::ParseError {
            line: 0,
            msg: "empty assembly".into(),
            raw: asm.to_string(),
        });
    }

    let mut instructions = Vec::new();
    for (line_no, raw) in asm.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("label_") {
            continue; // Skip blank lines and label lines
        }

        let mut parts = line.split_whitespace();
        let pc_hex = parts.next().ok_or_else(|| Error::ParseError {
            line: line_no,
            msg: "missing PC".to_string(),
            raw: raw.to_string(),
        })?;
        let opcode = parts.next().ok_or_else(|| Error::ParseError {
            line: line_no,
            msg: "missing opcode".to_string(),
            raw: raw.to_string(),
        })?;
        let immediate = parts
            .next()
            .map(|s| s.trim_start_matches("0x").to_ascii_lowercase());

        let pc = usize::from_str_radix(pc_hex.trim_start_matches("0x"), 16).map_err(|_| {
            Error::ParseError {
                line: line_no,
                msg: "invalid PC".to_string(),
                raw: raw.to_string(),
            }
        })?;

        if opcode.is_empty() || opcode.chars().all(|c| !c.is_alphanumeric()) {
            return Err(Error::ParseError {
                line: line_no,
                msg: "invalid opcode".to_string(),
                raw: raw.to_string(),
            });
        }

        // Parse opcode once during decoding for efficient access
        let parsed_opcode = Opcode::from_str(opcode).unwrap_or_else(|_| {
            // Try to extract byte value from UNKNOWN_0x?? format
            if let Some(hex_part) = opcode.strip_prefix("UNKNOWN_0x")
                && let Ok(byte_val) = u8::from_str_radix(hex_part, 16)
            {
                tracing::debug!(
                    "Unknown opcode '{}' at PC 0x{:x}, storing as UNKNOWN(0x{:02x})",
                    opcode,
                    pc,
                    byte_val
                );
                return Opcode::UNKNOWN(byte_val);
            }

            // For generic "unknown" or other unrecognized opcodes, use INVALID as a placeholder.
            //
            // Note: INVALID here does NOT mean the opcode is actually 0xFE (the INVALID opcode).
            // It's used as a marker for "we don't know what byte this is from the disassembly alone".
            // The encoder will recover the actual byte value from the original bytecode using the PC.
            // This is the least-bad choice when heimdall gives us "unknown" without a hex byte value.
            //
            // If we can't recover the byte during encoding (e.g., PC out of bounds), the instruction
            // will be skipped rather than encoded as 0xFE.
            tracing::warn!(
                "Unrecognized opcode '{}' at PC 0x{:x}, using INVALID as placeholder (byte will be recovered from original during encode)",
                opcode,
                pc
            );
            Opcode::INVALID
        });

        instructions.push(Instruction {
            pc,
            op: parsed_opcode,
            imm: immediate,
        });
    }
    Ok(instructions)
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // pc: six-digit hex, opcode left-padded to 8 chars, then optional imm
        if let Some(immediate) = &self.imm {
            write!(f, "{:06x}  {:<8} {}", self.pc, self.op, immediate)
        } else {
            write!(f, "{:06x}  {}", self.pc, self.op)
        }
    }
}

impl Instruction {
    /// Returns the byte size of this instruction (1 for most opcodes, 1+N for PUSH(N)).
    #[inline]
    pub fn byte_size(&self) -> usize {
        match self.op {
            Opcode::PUSH0 => 1,
            Opcode::PUSH(n) => 1 + n as usize,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceType, decode_bytecode, parse_assembly};
    use crate::Opcode;
    use crate::encoder;
    use crate::result::Error;

    const SAMPLE_ASM: &str = "
000000 PUSH1 0x01
000002 PUSH1 0xff
000004 ADD
000005 STOP
";

    #[test]
    fn parse_basic_assembly_stream() {
        let instructions = parse_assembly(SAMPLE_ASM).expect("parse sample asm");
        assert_eq!(instructions.len(), 4);

        assert_eq!(instructions[0].pc, 0);
        assert!(matches!(instructions[0].op, Opcode::PUSH(1)));
        assert_eq!(instructions[0].imm.as_deref(), Some("01"));

        assert_eq!(instructions[2].pc, 4);
        assert_eq!(instructions[2].op, Opcode::ADD);
        assert!(instructions[2].imm.is_none());
    }

    #[test]
    fn parse_unknown_opcode_with_hex_suffix() {
        let asm = "\
000000 UNKNOWN_0xaa\n";
        let instructions = parse_assembly(asm).expect("parse unknown hex");
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].pc, 0);
        assert_eq!(instructions[0].op, Opcode::UNKNOWN(0xaa));
        assert!(instructions[0].imm.is_none());
    }

    #[test]
    fn unknown_opcode_without_hex_becomes_invalid() {
        let asm = "\
000000 unknown\n";
        let instructions = parse_assembly(asm).expect("parse generic unknown");
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].op, Opcode::INVALID);
    }

    #[test]
    fn parse_assembly_rejects_empty_input() {
        let err = parse_assembly("").unwrap_err();
        assert!(matches!(err, Error::ParseError { .. }));
    }

    #[test]
    fn parse_assembly_errors_on_malformed_line() {
        // Missing opcode after PC
        let err = parse_assembly("000000").unwrap_err();
        assert!(matches!(err, Error::ParseError { .. }));
    }

    #[tokio::test]
    async fn decode_bytecode_produces_instructions_and_metadata() {
        let bytecode = include_str!("../../../tests/bytecode/storage.hex");
        let (instructions, info, asm, bytes) = decode_bytecode(bytecode, false)
            .await
            .expect("decode bytecode");

        assert!(!instructions.is_empty());
        assert!(!asm.is_empty());
        assert_eq!(info.byte_length, bytes.len());
        assert_eq!(info.source, SourceType::HexString);

        let reparsed = parse_assembly(&asm).expect("parse decoded assembly");
        assert_eq!(reparsed, instructions);

        let reencoded =
            encoder::encode(&instructions, &bytes).expect("encode decoded instructions");
        assert_eq!(reencoded, bytes);

        // storage hex starts with PUSH1 0x80 at pc=0
        let first = &instructions[0];
        assert_eq!(first.pc, 0);
        assert!(matches!(first.op, Opcode::PUSH(1)));
        assert_eq!(first.imm.as_deref(), Some("80"));
    }
}
