//! azoth's single entry-point for turning byte-sequences into Heimdall instruction streams.

use crate::Opcode;
use crate::result::Error;
use heimdall::{DisassemblerArgsBuilder, disassemble};
use std::fmt;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

/// Single disassembled EVM instruction with PC, opcode, and optional immediate data.
#[derive(Clone, Debug, PartialEq)]
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
        let imm = parts
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
            imm,
        });
    }
    Ok(instructions)
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // pc: six-digit hex, opcode left-padded to 8 chars, then optional imm
        if let Some(imm) = &self.imm {
            write!(f, "{:06x}  {:<8} {}", self.pc, self.op, imm)
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
