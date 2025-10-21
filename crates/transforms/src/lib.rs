pub mod function_dispatcher;
pub mod jump_address_transformer;
pub mod obfuscator;
pub mod opaque_predicate;
pub mod shuffle;

use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::Opcode;
use rand::rngs::StdRng;

use azoth_analysis::Error as MetricsError;
use thiserror::Error;

/// Transform error type encompassing all transform module errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Core operation failed.
    #[error("core operation failed: {0}")]
    CoreError(String),
    /// Instruction encoding failed.
    #[error("instruction encoding failed: {0}")]
    EncodingError(String),
    /// Generic error.
    #[error("generic error: {0}")]
    Generic(String),
    /// Invalid jump target.
    #[error("invalid jump target: {0}")]
    InvalidJumpTarget(usize),
    /// Metrics computation failed.
    #[error("metrics computation failed: {0}")]
    Metrics(#[from] MetricsError),
    /// Bytecode size exceeds maximum allowed delta.
    #[error("bytecode size exceeds maximum allowed delta")]
    SizeLimitExceeded,
    /// Stack depth exceeds maximum limit of 1024.
    #[error("stack depth exceeds maximum limit of 1024")]
    StackOverflow,
}

/// Transform result type
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for bytecode obfuscation transforms.
pub trait Transform: Send + Sync {
    /// Returns the transform's name for logging and identification.
    fn name(&self) -> &'static str;
    /// Applies the transform to the CFG IR, returning whether changes were made.
    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool>;
}

/// Parses a PUSH opcode string and returns the corresponding Opcode enum and immediate size.
///
/// This helper function centralizes the parsing of PUSH opcodes (PUSH1-PUSH32) and eliminates
/// repetitive matching patterns throughout the transforms codebase.
///
/// # Arguments
/// * `opcode_str` - The opcode string (e.g., "PUSH1", "PUSH32")
///
/// # Returns
/// * `Some((Opcode, usize))` - The parsed opcode and its immediate size (1-32 bytes)
/// * `None` - If the input is not a valid PUSH opcode
pub fn parse_push_opcode(opcode_str: &str) -> Option<(Opcode, usize)> {
    if let Some(push_num_str) = opcode_str.strip_prefix("PUSH") {
        if let Ok(push_num) = push_num_str.parse::<u8>() {
            if (1..=32).contains(&push_num) {
                let opcode_byte = 0x60 + (push_num - 1);
                return Some(Opcode::parse(opcode_byte));
            }
        }
    }
    None
}
