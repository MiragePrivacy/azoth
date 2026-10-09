//! Native legacy-EVM bytecode decoding.
//!
//! Core decoding is synchronous and self-contained: Azoth walks input bytes directly instead of
//! converting them to third-party assembly text and parsing that text back into instructions.

use crate::Opcode;
use crate::result::Error;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Write};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

/// One decoded EVM instruction and its exact byte offset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Program counter (byte offset).
    pub pc: usize,
    /// Decoded opcode.
    pub op: Opcode,
    /// PUSH immediate as lowercase hexadecimal without a `0x` prefix.
    ///
    /// A final, EVM-zero-extended PUSH can contain fewer bytes than its declared width. Keeping
    /// only the bytes physically present makes raw decode/encode exactly lossless.
    pub imm: Option<String>,
}

/// Metadata calculated while accepting bytecode input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeInfo {
    /// Bytecode length in bytes.
    pub byte_length: usize,
    /// Keccak-256 hash of the exact input bytes.
    pub keccak_hash: [u8; 32],
    /// Input source type.
    pub source: SourceType,
}

/// Native decode result without eagerly rendered assembly text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBytecode {
    /// Decoded instruction stream.
    pub instructions: Vec<Instruction>,
    /// Length, hash, and source metadata.
    pub info: DecodeInfo,
    /// Exact input bytes.
    pub bytes: Vec<u8>,
}

impl DecodedBytecode {
    /// Render this result as deterministic, human-readable assembly.
    pub fn format_assembly(&self) -> String {
        format_assembly(&self.instructions)
    }
}

/// Bytecode input source type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceType {
    /// Hexadecimal supplied directly by the caller.
    HexString,
    /// Hexadecimal read from a file.
    File,
}

/// Decode a raw legacy-EVM byte slice in one pass, preserving every physical byte.
///
/// Only `PUSH1` through `PUSH32` consume following bytes. Unknown opcode bytes are retained as
/// [`Opcode::UNKNOWN`]. The EVM defines absent bytes at the end of a PUSH immediate as zero, so a
/// final truncated PUSH is represented losslessly by an immediate shorter than its declared
/// width. Transformation callers must use [`decode_executable_bytes`] or explicitly reject
/// [`Instruction::is_truncated_push`] before relocating or appending code.
pub fn decode_bytes(bytes: &[u8]) -> Result<Vec<Instruction>, Error> {
    // Most bytecode contains many one-byte operations, while PUSH-dense data can contain only one
    // instruction per 33 bytes. Start modestly and let Vec grow so multi-megabyte offline blobs do
    // not reserve tens of times more instruction storage than they use.
    let initial_capacity = bytes.len().div_ceil(8).min(4_096);
    let mut instructions = Vec::with_capacity(initial_capacity);
    let mut pc = 0usize;

    while pc < bytes.len() {
        let instruction_pc = pc;
        let (op, immediate_size) = Opcode::parse(bytes[pc]);
        pc += 1;

        let imm = if immediate_size == 0 {
            None
        } else {
            let available = immediate_size.min(bytes.len() - pc);
            let end = pc + available;
            let encoded = hex::encode(&bytes[pc..end]);
            pc = end;
            Some(encoded)
        };

        instructions.push(Instruction {
            pc: instruction_pc,
            op,
            imm,
        });
    }

    Ok(instructions)
}

/// Decode executable code and reject a final PUSH with physically missing immediate bytes.
///
/// Such bytecode is executable because the EVM reads zeros beyond the end, but Azoth cannot move
/// or append code after it without changing which bytes the PUSH consumes. Failing closed at the
/// transformation boundary preserves semantics.
pub fn decode_executable_bytes(bytes: &[u8]) -> Result<Vec<Instruction>, Error> {
    let instructions = decode_bytes(bytes)?;
    reject_truncated_final_push(&instructions)?;
    Ok(instructions)
}

/// Decode one independently executable byte range and report absolute program counters.
///
/// Creation code and deployed runtime are separate EVM executions and can have overlapping linear
/// interpretations at their boundary. Callers must decode a proven runtime range from its own
/// first byte instead of filtering instruction boundaries decoded from the complete deployment
/// payload.
pub fn decode_executable_range(
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> Result<Vec<Instruction>, Error> {
    let end = offset
        .checked_add(len)
        .ok_or(Error::SectionOutOfBounds(offset))?;
    let executable = bytes
        .get(offset..end)
        .ok_or(Error::SectionOutOfBounds(end))?;
    let mut instructions = decode_bytes(executable)?;
    for instruction in &mut instructions {
        instruction.pc += offset;
    }
    reject_truncated_final_push(&instructions)?;
    Ok(instructions)
}

fn reject_truncated_final_push(instructions: &[Instruction]) -> Result<(), Error> {
    if let Some(instruction) = instructions.last()
        && let Some((width, available)) = instruction.truncated_push_widths()
    {
        return Err(Error::TruncatedPush {
            pc: instruction.pc,
            width,
            available,
        });
    }
    Ok(())
}

/// Read and decode hexadecimal bytecode without eagerly rendering assembly text.
pub fn decode_input(input: &str, is_file: bool) -> Result<DecodedBytecode, Error> {
    let bytes = crate::input_to_bytes(input, is_file)?;
    let source = if is_file {
        SourceType::File
    } else {
        SourceType::HexString
    };

    let mut keccak = Keccak::v256();
    keccak.update(&bytes);
    let mut keccak_hash = [0u8; 32];
    keccak.finalize(&mut keccak_hash);

    let instructions = decode_bytes(&bytes)?;
    let info = DecodeInfo {
        byte_length: bytes.len(),
        keccak_hash,
        source,
    };

    Ok(DecodedBytecode {
        instructions,
        info,
        bytes,
    })
}

/// Compatibility wrapper returning the historical tuple, now backed entirely by native decode.
///
/// New hot-path callers should use [`decode_input`] so assembly is rendered only when requested.
pub async fn decode_bytecode(
    input: &str,
    is_file: bool,
) -> Result<(Vec<Instruction>, DecodeInfo, String, Vec<u8>), Error> {
    let decoded = decode_input(input, is_file)?;
    let assembly = decoded.format_assembly();
    Ok((decoded.instructions, decoded.info, assembly, decoded.bytes))
}

/// Render instructions in Azoth's stable assembly format.
pub fn format_assembly(instructions: &[Instruction]) -> String {
    let mut assembly = String::with_capacity(instructions.len().saturating_mul(18));
    for instruction in instructions {
        // Writing to a String cannot fail.
        writeln!(&mut assembly, "{instruction}").expect("String writes are infallible");
    }
    assembly
}

/// Parse Azoth's textual assembly format.
///
/// This is a diagnostics/import helper. Production bytecode decoding uses [`decode_bytes`]
/// directly and never round-trips through text.
pub fn parse_assembly(assembly: &str) -> Result<Vec<Instruction>, Error> {
    if assembly.trim().is_empty() {
        return Err(Error::ParseError {
            line: 0,
            msg: "empty assembly".into(),
            raw: assembly.to_string(),
        });
    }

    let mut instructions: Vec<Instruction> = Vec::new();
    for (line_no, raw) in assembly.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("label_") {
            continue;
        }

        let mut parts = line.split_whitespace();
        let pc_hex = parse_part(parts.next(), line_no, raw, "missing PC")?;
        let opcode_name = parse_part(parts.next(), line_no, raw, "missing opcode")?;
        let immediate = parts
            .next()
            .map(|value| value.trim_start_matches("0x").to_ascii_lowercase());
        if parts.next().is_some() {
            return parse_error(line_no, raw, "unexpected trailing assembly fields");
        }

        let pc = usize::from_str_radix(pc_hex.trim_start_matches("0x"), 16).map_err(|_| {
            Error::ParseError {
                line: line_no,
                msg: "invalid PC".into(),
                raw: raw.to_string(),
            }
        })?;
        let op = parse_opcode_name(opcode_name).ok_or_else(|| Error::ParseError {
            line: line_no,
            msg: format!("unknown opcode '{opcode_name}'"),
            raw: raw.to_string(),
        })?;

        match op {
            Opcode::PUSH(width) => {
                let Some(value) = immediate.as_deref() else {
                    return parse_error(line_no, raw, "PUSH is missing its immediate");
                };
                if value.len() % 2 != 0
                    || value.len() > usize::from(width) * 2
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return parse_error(
                        line_no,
                        raw,
                        "PUSH immediate exceeds its width or is not whole-byte hexadecimal",
                    );
                }
            }
            _ if immediate.is_some() => {
                return parse_error(
                    line_no,
                    raw,
                    "only PUSH instructions may have immediate data",
                );
            }
            _ => {}
        }

        let instruction = Instruction {
            pc,
            op,
            imm: immediate,
        };
        if let Some(previous) = instructions.last() {
            if previous.is_truncated_push() {
                return parse_error(
                    line_no,
                    raw,
                    "only the final instruction may be a truncated PUSH",
                );
            }
            let expected_pc = previous
                .pc
                .checked_add(previous.byte_size())
                .ok_or_else(|| Error::ParseError {
                    line: line_no,
                    msg: "instruction PC overflows usize".into(),
                    raw: raw.to_string(),
                })?;
            if pc != expected_pc {
                return parse_error(
                    line_no,
                    raw,
                    &format!("non-contiguous PC: expected 0x{expected_pc:x}, found 0x{pc:x}"),
                );
            }
        }
        instructions.push(instruction);
    }

    if instructions.is_empty() {
        return Err(Error::ParseError {
            line: 0,
            msg: "assembly contains no instructions".into(),
            raw: assembly.to_string(),
        });
    }
    Ok(instructions)
}

fn parse_part<'a>(
    part: Option<&'a str>,
    line: usize,
    raw: &str,
    message: &str,
) -> Result<&'a str, Error> {
    part.ok_or_else(|| Error::ParseError {
        line,
        msg: message.to_string(),
        raw: raw.to_string(),
    })
}

fn parse_opcode_name(name: &str) -> Option<Opcode> {
    Opcode::from_str(name).ok()
}

fn parse_error<T>(line: usize, raw: &str, message: &str) -> Result<T, Error> {
    Err(Error::ParseError {
        line,
        msg: message.to_string(),
        raw: raw.to_string(),
    })
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(immediate) = &self.imm {
            write!(f, "{:06x}  {:<8} 0x{immediate}", self.pc, self.op)
        } else {
            write!(f, "{:06x}  {}", self.pc, self.op)
        }
    }
}

impl Instruction {
    /// Return the number of immediate bytes physically represented by this instruction.
    pub fn immediate_byte_len(&self) -> Option<usize> {
        self.imm
            .as_deref()
            .filter(|value| value.len() % 2 == 0)
            .map(|value| value.len() / 2)
    }

    /// Return true when a final PUSH has fewer physical immediate bytes than its declared width.
    pub fn is_truncated_push(&self) -> bool {
        self.truncated_push_widths().is_some()
    }

    fn truncated_push_widths(&self) -> Option<(usize, usize)> {
        let Opcode::PUSH(width) = self.op else {
            return None;
        };
        let available = self.immediate_byte_len()?;
        (available < usize::from(width)).then_some((usize::from(width), available))
    }

    /// Return the number of physical bytes emitted for this instruction.
    #[inline]
    pub fn byte_size(&self) -> usize {
        match self.op {
            Opcode::PUSH(width) => self
                .immediate_byte_len()
                .map_or(1 + usize::from(width), |available| 1 + available),
            _ => 1,
        }
    }
}

/// Trait for computing the encoded byte size of instructions or collections of instructions.
pub trait EncodedSize {
    /// Return the encoded size in bytes.
    fn size(&self) -> usize;
}

impl EncodedSize for Instruction {
    #[inline]
    fn size(&self) -> usize {
        self.byte_size()
    }
}

impl<T: EncodedSize> EncodedSize for [T] {
    fn size(&self) -> usize {
        self.iter().map(EncodedSize::size).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SourceType, decode_bytes, decode_executable_bytes, decode_input, format_assembly,
        parse_assembly,
    };
    use crate::Opcode;
    use crate::encoder;
    use crate::result::Error;

    #[test]
    fn native_decode_produces_metadata_and_roundtrips() {
        let bytecode = include_str!("../../../tests/bytecode/storage.hex");
        let decoded = decode_input(bytecode, false).expect("decode bytecode");

        assert!(!decoded.instructions.is_empty());
        assert_eq!(decoded.info.byte_length, decoded.bytes.len());
        assert_eq!(decoded.info.source, SourceType::HexString);
        assert_eq!(decoded.instructions[0].pc, 0);
        assert_eq!(decoded.instructions[0].op, Opcode::PUSH(1));
        assert_eq!(decoded.instructions[0].imm.as_deref(), Some("80"));

        let assembly = format_assembly(&decoded.instructions);
        assert_eq!(parse_assembly(&assembly).unwrap(), decoded.instructions);
        assert_eq!(
            encoder::encode(&decoded.instructions, &decoded.bytes).unwrap(),
            decoded.bytes
        );
    }

    #[test]
    fn empty_bytecode_is_a_valid_empty_stream() {
        let decoded = decode_input("0x", false).expect("empty code decodes");
        assert!(decoded.instructions.is_empty());
        assert!(decoded.bytes.is_empty());
        assert!(decoded.format_assembly().is_empty());
    }

    #[test]
    fn executable_decode_rejects_truncated_push_without_partial_success() {
        let lossless = decode_bytes(&[0x00, 0x61, 0xaa]).unwrap();
        assert_eq!(lossless.len(), 2);
        assert!(lossless[1].is_truncated_push());
        let err = decode_executable_bytes(&[0x00, 0x61, 0xaa]).unwrap_err();
        assert!(matches!(
            err,
            Error::TruncatedPush {
                pc: 1,
                width: 2,
                available: 1
            }
        ));
    }

    #[test]
    fn executable_range_decodes_from_its_own_boundary_and_rebases_pcs() {
        // At deployment PC 2, PUSH2 consumes the byte at PC 4 in a whole-payload linear view.
        // The independent runtime beginning at PC 4 must nevertheless decode that byte as PUSH1.
        let bytes = [0x00, 0x00, 0x61, 0xaa, 0x60, 0x00, 0x00];
        let instructions = super::decode_executable_range(&bytes, 4, 3).unwrap();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].pc, 4);
        assert_eq!(instructions[0].op, Opcode::PUSH(1));
        assert_eq!(instructions[0].imm.as_deref(), Some("00"));
        assert_eq!(instructions[1].pc, 6);
        assert_eq!(instructions[1].op, Opcode::STOP);

        let error = super::decode_executable_range(&[0x00, 0x61, 0xaa], 1, 2).unwrap_err();
        assert!(matches!(
            error,
            Error::TruncatedPush {
                pc: 1,
                width: 2,
                available: 1
            }
        ));
    }

    #[test]
    fn immediate_opcode_bytes_are_data() {
        let instructions = decode_bytes(&[0x63, 0x5b, 0x60, 0xfe, 0xff, 0x00]).unwrap();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].imm.as_deref(), Some("5b60feff"));
        assert_eq!(instructions[1].op, Opcode::STOP);
    }

    #[test]
    fn text_parser_rejects_ambiguous_or_malformed_input() {
        assert!(matches!(parse_assembly(""), Err(Error::ParseError { .. })));
        assert!(matches!(
            parse_assembly("000000"),
            Err(Error::ParseError { .. })
        ));
        assert!(matches!(
            parse_assembly("000000 unknown"),
            Err(Error::ParseError { .. })
        ));
        assert!(matches!(
            parse_assembly("000000 PUSH2 0xaaaaaa"),
            Err(Error::ParseError { .. })
        ));
        assert!(matches!(
            parse_assembly("000001 STOP\n000000 ADD"),
            Err(Error::ParseError { .. })
        ));
        assert!(matches!(
            parse_assembly("000000 STOP\n000002 ADD"),
            Err(Error::ParseError { .. })
        ));
    }
}
