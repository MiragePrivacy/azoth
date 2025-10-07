pub mod cfg_ir;
pub mod decoder;
pub mod detection;
pub mod encoder;
pub mod strip;

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

/// High-level convenience function to process raw bytecode into a CFG-IR bundle.
///
/// This function handles the complete pipeline from raw bytecode to CFG-IR, performing
/// all necessary preprocessing steps that `cfg_ir::build_cfg_ir` expects to be done already.
///
/// # Difference from `cfg_ir::build_cfg_ir`
/// - `cfg_ir::build_cfg_ir` is a low-level function that expects pre-processed inputs
///   (decoded instructions, detected sections, strip report)
/// - This function is a high-level wrapper that handles all preprocessing:
///   1. Decodes the bytecode into instructions
///   2. Detects sections (Init, Runtime, ConstructorArgs, etc.)
///   3. Strips non-runtime sections
///   4. Builds the CFG-IR
///
/// # Arguments
/// * `bytecode` - Hex-encoded bytecode string (with or without "0x" prefix)
/// * `is_file` - Flag indicating if the input is a file path (false for hex string).
///
/// # Returns
/// A tuple containing:
/// * The built CFG-IR bundle
/// * The decoded instructions
/// * The detected sections
/// * The raw bytes
///
/// # Example
/// ```rust,ignore
/// // Instead of doing this manually:
/// let (instructions, _, _) = decoder::decode_bytecode(bytecode, false).await?;
/// let bytes = hex::decode(bytecode.trim_start_matches("0x"))?;
/// let sections = detection::locate_sections(&bytes, &instructions)?;
/// let (_, report) = strip::strip_bytecode(&bytes, &sections)?;
/// let cfg_bundle = cfg_ir::build_cfg_ir(&instructions, &sections, &bytes, report)?;
///
/// // You can simply do:
/// let (cfg_bundle, instructions, sections, bytes) =
///     process_bytecode_to_cfg(bytecode, false).await?;
/// ```
pub async fn process_bytecode_to_cfg(
    bytecode: &str,
    is_file: bool,
) -> Result<
    (
        cfg_ir::CfgIrBundle,
        Vec<decoder::Instruction>,
        Vec<detection::Section>,
        Vec<u8>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Decode bytecode - this now returns the bytes directly, no redundant parsing
    let (instructions, _, _, bytes) = decoder::decode_bytecode(bytecode, is_file).await?;

    // Detect sections
    let sections = detection::locate_sections(&bytes, &instructions)?;

    // Strip non-runtime sections
    let (_, report) = strip::strip_bytecode(&bytes, &sections)?;

    // Build CFG-IR (using the low-level function with pre-processed inputs)
    let cfg_bundle = cfg_ir::build_cfg_ir(&instructions, &sections, report)?;

    Ok((cfg_bundle, instructions, sections, bytes))
}

/// High-level convenience function that processes bytecode and returns only the CFG-IR bundle.
///
/// This is a simplified version of `process_bytecode_to_cfg` for cases where you don't
/// need access to the intermediate results (instructions, sections, bytes).
///
/// # Example
/// ```rust,ignore
/// let mut cfg_bundle = process_bytecode_to_cfg_only("0x6001600260016003", false).await?;
/// ```
pub async fn process_bytecode_to_cfg_only(
    bytecode: &str,
    is_file: bool,
) -> Result<cfg_ir::CfgIrBundle, Box<dyn std::error::Error + Send + Sync>> {
    let (cfg_bundle, _, _, _) = process_bytecode_to_cfg(bytecode, is_file).await?;
    Ok(cfg_bundle)
}
