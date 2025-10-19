pub mod cfg_ir;
pub mod decoder;
pub mod detection;
pub mod encoder;
pub mod result;
pub mod seed;
pub mod strip;

use hex::FromHex;
pub use result::{Error, Result};
use std::fs;
use std::path::Path;

pub use eot::UnifiedOpcode as Opcode;

/// Returns true if the opcode terminates execution.
///
/// Terminal opcodes are those that end the execution of a program or transaction,
/// such as STOP, RETURN, REVERT, SELFDESTRUCT, and INVALID.
#[inline]
pub fn is_terminal_opcode(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::STOP | Opcode::RETURN | Opcode::REVERT | Opcode::SELFDESTRUCT | Opcode::INVALID
    )
}

/// Returns true if the opcode ends a basic block.
///
/// Block-ending opcodes include terminal opcodes as well as control flow opcodes
/// like JUMP and JUMPI that transfer control to different parts of the program.
#[inline]
pub fn is_block_ending_opcode(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::STOP
            | Opcode::RETURN
            | Opcode::REVERT
            | Opcode::SELFDESTRUCT
            | Opcode::INVALID
            | Opcode::JUMP
            | Opcode::JUMPI
    )
}

/// Normalizes hex strings by removing whitespace, 0x prefix, and ensuring even length.
pub fn normalize_hex_string(input: &str) -> Result<String> {
    let clean = input
        .trim()
        .replace(['\n', '\r', ' ', '\t'], "")
        .strip_prefix("0x")
        .unwrap_or(input.trim().replace(['\n', '\r', ' ', '\t'], "").as_str())
        .to_string();

    // Validate hex characters
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::HexDecode(hex::FromHexError::InvalidHexCharacter {
            c: clean
                .chars()
                .find(|c| !c.is_ascii_hexdigit())
                .unwrap_or('?'),
            index: 0,
        }));
    }

    // Ensure even length by padding with leading zero if necessary
    Ok(if clean.len() % 2 == 1 {
        format!("0{}", clean)
    } else {
        clean
    })
}

/// Normalizes input into a byte vector from hex string or file.
pub fn input_to_bytes(input: &str, is_file: bool) -> Result<Vec<u8>> {
    if is_file {
        let path = Path::new(input);
        let file_content = fs::read_to_string(path).map_err(|e| Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;
        let normalized = normalize_hex_string(&file_content)?;
        Vec::from_hex(&normalized).map_err(Error::HexDecode)
    } else {
        let normalized = normalize_hex_string(input)?;
        Vec::from_hex(&normalized).map_err(Error::HexDecode)
    }
}

/// High-level convenience function to process raw bytecode into a CFG-IR bundle.
///
/// This function handles the complete pipeline from raw bytecode to CFG-IR, performing
/// all necessary preprocessing steps that `cfg_ir::build_cfg_ir` expects to be done already.
pub async fn process_bytecode_to_cfg(
    bytecode: &str,
    is_file: bool,
) -> std::result::Result<
    (
        cfg_ir::CfgIrBundle,
        Vec<decoder::Instruction>,
        Vec<detection::Section>,
        Vec<u8>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, is_file).await?;
    let sections = detection::locate_sections(&bytes, &instructions)?;
    let (_, report) = strip::strip_bytecode(&bytes, &sections)?;

    // CRITICAL FIX: Filter instructions to only runtime section before building CFG
    // The CFG should only contain runtime code, not init code or metadata
    let runtime_section = sections
        .iter()
        .find(|s| matches!(s.kind, detection::SectionKind::Runtime))
        .ok_or("No Runtime section found in bytecode")?;

    let runtime_start_pc = runtime_section.offset;
    let runtime_end_pc = runtime_section.offset + runtime_section.len;

    tracing::debug!(
        "Filtering instructions to runtime section: PC range [{}, {})",
        runtime_start_pc,
        runtime_end_pc
    );

    let runtime_instructions: Vec<decoder::Instruction> = instructions
        .iter()
        .filter(|instr| instr.pc >= runtime_start_pc && instr.pc < runtime_end_pc)
        .cloned()
        .collect();

    tracing::debug!(
        "Filtered from {} total instructions to {} runtime instructions",
        instructions.len(),
        runtime_instructions.len()
    );

    // Build CFG from ONLY runtime instructions
    let cfg_bundle = cfg_ir::build_cfg_ir(&runtime_instructions, &sections, report, &bytes)?;

    Ok((cfg_bundle, instructions, sections, bytes))
}
