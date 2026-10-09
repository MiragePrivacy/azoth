//! Core results and error types

use thiserror::Error;

/// Core error type encompassing all core module errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Auxiliary data overlaps with other sections.
    #[error("auxdata overlap detected")]
    AuxdataOverlap,

    /// Failed to read file at the specified path.
    #[error("could not read file '{path}': {source}")]
    FileRead {
        /// The path to the file that could not be read.
        path: String,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to decode hex string.
    #[error("hex decode failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Block structure is malformed or inconsistent.
    #[error("invalid block structure: {0}")]
    InvalidBlockStructure(String),

    /// A JUMP/JUMPI instruction targets an invalid destination.
    #[error("bytecode validation failed: {0} invalid jump target(s) found")]
    InvalidJumpTarget(usize),

    /// The immediate data for a PUSH opcode is invalid.
    #[error("invalid immediate: {0}")]
    InvalidImmediate(String),

    /// A final PUSH has fewer physical immediate bytes than its declared width.
    #[error(
        "truncated PUSH{width} at byte 0x{pc:x}: expected {width} immediate bytes, found {available}"
    )]
    TruncatedPush {
        /// Byte offset of the PUSH opcode.
        pc: usize,
        /// Declared PUSH immediate width.
        width: usize,
        /// Number of immediate bytes physically present.
        available: usize,
    },

    /// Invalid hexadecimal in seed.
    #[error("invalid hexadecimal in seed")]
    InvalidSeedHex,

    /// Invalid seed length.
    #[error("invalid seed length: expected 64 hex chars, got {0}")]
    InvalidSeedLength(usize),

    /// The section configuration is invalid.
    #[error("invalid section configuration")]
    InvalidSectionConfig,

    /// The instruction sequence contains invalid control flow patterns.
    #[error("invalid instruction sequence")]
    InvalidSequence,

    /// No valid entry block was found in the instruction sequence.
    #[error("no valid entry block found")]
    NoEntryBlock,

    /// No valid exit block was found in the instruction sequence.
    #[error("no valid exit block found")]
    NoExitBlock,

    /// No runtime section was found in the bytecode.
    #[error("no runtime found")]
    NoRuntimeFound,

    /// The caller-supplied runtime does not occur in the deployment payload.
    #[error("caller-supplied runtime was not found in deployment bytecode")]
    SuppliedRuntimeNotFound,

    /// The caller-supplied runtime occurs more than once, so its boundary is ambiguous.
    #[error("caller-supplied runtime occurs {0} times in deployment bytecode")]
    AmbiguousRuntimeMatch(usize),

    /// Obfuscation operation failed.
    #[error("obfuscation failed: {0}")]
    ObfuscationFailed(String),

    /// Failed to parse assembly at the specified line.
    #[error("assembly parse error at line {line}: {msg} ⇒ `{raw}`")]
    ParseError {
        /// The line number where parsing failed.
        line: usize,
        /// Description of the parsing error.
        msg: String,
        /// The raw content that failed to parse.
        raw: String,
    },

    /// A gap was detected between sections at the specified offset.
    #[error("gap detected at offset {0}")]
    SectionGap(usize),

    /// A section extends beyond the bytecode boundaries.
    #[error("section extends beyond bytecode bounds at offset {0}")]
    SectionOutOfBounds(usize),

    /// Detected sections overlap at the specified offset.
    #[error("overlapping sections detected at offset {0}")]
    SectionOverlap(usize),

    /// A section is located beyond the bytecode boundaries.
    #[error("section out of bounds at offset {0}")]
    StripOutOfBounds(usize),

    /// The opcode is not supported by the encoder.
    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(String),
}

/// Core result type
pub type Result<T> = std::result::Result<T, Error>;
