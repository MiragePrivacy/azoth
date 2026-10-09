pub mod cfg_ir;
pub mod decoder;
pub mod detection;
pub mod encoder;
pub mod opcode;
pub mod result;
pub mod seed;
pub mod strip;
pub mod validator;

use hex::{FromHex, FromHexError};
pub use result::{Error, Result};
use std::fs;
use std::path::Path;

pub use opcode::Opcode;

/// Returns true if the opcode terminates execution.
///
/// Terminal opcodes are those that end the execution of a program or transaction,
/// such as STOP, RETURN, REVERT, SELFDESTRUCT, and INVALID.
#[inline]
pub const fn is_terminal_opcode(opcode: Opcode) -> bool {
    opcode.is_terminal()
}

/// Returns true if the opcode ends a basic block.
///
/// Block-ending opcodes include terminal opcodes as well as control flow opcodes
/// like JUMP and JUMPI that transfer control to different parts of the program.
#[inline]
pub const fn is_block_ending_opcode(opcode: Opcode) -> bool {
    opcode.is_block_ending()
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
        return Err(Error::HexDecode(FromHexError::InvalidHexCharacter {
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
    deployment_bytecode: &str,
    deployment_is_file: bool,
    runtime_bytecode: &str,
    runtime_is_file: bool,
) -> std::result::Result<
    (
        cfg_ir::CfgIrBundle,
        Vec<decoder::Instruction>,
        Vec<detection::Section>,
        Vec<u8>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // CFG construction does not consume display/hash metadata, so keep the production hot path
    // to one input normalization and one native byte walk.
    let bytes = input_to_bytes(deployment_bytecode, deployment_is_file)?;
    let instructions = decoder::decode_bytes(&bytes)?;
    let runtime_bytes = input_to_bytes(runtime_bytecode, runtime_is_file)?;
    let sections = detection::locate_sections(&bytes, &instructions, &runtime_bytes)?;
    let (_, report) = strip::strip_bytecode(&bytes, &sections)?;

    // Filter instructions to only runtime section before building CFG
    // The CFG should only contain runtime code, not init code or metadata
    let runtime_section = sections
        .iter()
        .find(|s| matches!(s.kind, detection::SectionKind::Runtime))
        .ok_or("No Runtime section found in bytecode")?;

    let runtime_start_pc = runtime_section.offset;
    let runtime_end_pc = runtime_section
        .offset
        .checked_add(runtime_section.len)
        .ok_or(Error::SectionOutOfBounds(runtime_section.offset))?;

    tracing::debug!(
        "Filtering instructions to runtime section: PC range [{}, {})",
        runtime_start_pc,
        runtime_end_pc
    );

    let runtime_instructions =
        decoder::decode_executable_range(&bytes, runtime_section.offset, runtime_section.len)?;

    tracing::debug!(
        "Filtered from {} total instructions to {} runtime instructions",
        instructions.len(),
        runtime_instructions.len()
    );

    // Build CFG from only runtime instructions
    let cfg_bundle = cfg_ir::build_cfg_ir(&runtime_instructions, &sections, report, &bytes)?;

    Ok((cfg_bundle, instructions, sections, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::SectionKind;
    use std::fs;

    const COUNTER_DEPLOYMENT_BYTECODE: &str =
        include_str!("../../../tests/bytecode/counter/counter_deployment.hex");
    const COUNTER_RUNTIME_BYTECODE: &str =
        include_str!("../../../tests/bytecode/counter/counter_runtime.hex");

    #[test]
    fn normalize_hex_handles_whitespace_and_padding() {
        let raw = "  0xabc\n";
        let normalized = normalize_hex_string(raw).expect("normalized");
        assert_eq!(normalized, "0abc"); // padding guarantees even length
    }

    #[test]
    fn input_to_bytes_parses_literal_and_file() {
        let literal = "\n 60 01 00";
        let literal_bytes = input_to_bytes(literal, false).expect("literal bytes");
        assert_eq!(literal_bytes, vec![0x60, 0x01, 0x00]);

        let temp_path = std::env::temp_dir().join("azoth_core_input_to_bytes_test.hex");
        fs::write(&temp_path, "0x600200").expect("write temp file");
        let file_bytes = input_to_bytes(temp_path.to_str().unwrap(), true).expect("file bytes");
        assert_eq!(file_bytes, vec![0x60, 0x02, 0x00]);
        let _ = fs::remove_file(&temp_path);
    }

    #[tokio::test]
    async fn process_bytecode_builds_runtime_cfg() {
        let (bundle, instructions, sections, bytes) = process_bytecode_to_cfg(
            COUNTER_DEPLOYMENT_BYTECODE,
            false,
            COUNTER_RUNTIME_BYTECODE,
            false,
        )
        .await
        .expect("cfg build");
        assert!(!instructions.is_empty());

        let runtime_section = sections
            .iter()
            .find(|s| s.kind == SectionKind::Runtime)
            .expect("runtime section present");
        // Counter contract has runtime at offset 28 (0x1c)
        assert!(runtime_section.offset > 0);
        assert!(runtime_section.len > 0);

        assert!(bundle.cfg.node_count() > 0, "cfg contains blocks");
        assert_eq!(bundle.original_bytecode, bytes);
    }

    #[tokio::test]
    async fn process_bytecode_rejects_runtime_with_truncated_push() {
        let error = process_bytecode_to_cfg("0x0061aa", false, "0x0061aa", false)
            .await
            .expect_err("moving code after a short final PUSH must fail closed");
        assert!(
            error.to_string().contains("truncated PUSH2 at byte 0x1"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn process_bytecode_decodes_runtime_independently_of_init_data() {
        // Init returns the three bytes at 0x0c. Dead init data at 0x0a begins PUSH2 and consumes
        // byte 0x60 at 0x0c in the creation-code linear view; deployed execution starts fresh at
        // 0x0c and must see that byte as PUSH1.
        let deployment = "0x6003600c5f3960035ff361aa600000";
        let runtime = "0x600000";
        let (bundle, _, sections, _) = process_bytecode_to_cfg(deployment, false, runtime, false)
            .await
            .expect("valid overlapping init/runtime interpretations must be accepted");

        let runtime_section = sections
            .iter()
            .find(|section| section.kind == SectionKind::Runtime)
            .unwrap();
        assert_eq!((runtime_section.offset, runtime_section.len), (0x0c, 3));
        let runtime_instructions: Vec<_> = bundle
            .cfg
            .node_weights()
            .filter_map(|block| match block {
                cfg_ir::Block::Body(body) => Some(body.instructions.as_slice()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(runtime_instructions[0].pc, 0x0c);
        assert_eq!(runtime_instructions[0].op, Opcode::PUSH(1));
        assert_eq!(runtime_instructions[0].imm.as_deref(), Some("00"));
    }
}
