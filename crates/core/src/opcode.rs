//! Native opcode definitions for the active Ethereum legacy EVM.
//!
//! This module deliberately fixes Azoth's opcode vocabulary to the Fulu/Osaka
//! execution-layer revision activated by [EIP-7607].  In particular, `CLZ`
//! (`0x1e`) is active, while the withdrawn EOF proposal opcodes remain unknown
//! bytes in legacy bytecode.  Keeping the revision explicit and local makes
//! decoding deterministic and prevents a dependency update from silently
//! changing CFG semantics.
//!
//! [EIP-7607]: https://eips.ethereum.org/EIPS/eip-7607

#![allow(non_camel_case_types, clippy::upper_case_acronyms)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// The stack effect of a known opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpcodeInfo {
    /// Number of stack values consumed by the opcode.
    pub inputs: u8,
    /// Number of stack values present in place of the consumed values.
    pub outputs: u8,
}

impl OpcodeInfo {
    const fn new(inputs: u8, outputs: u8) -> Self {
        Self { inputs, outputs }
    }

    /// Returns the signed change in stack height.
    #[must_use]
    pub const fn stack_delta(self) -> i16 {
        self.outputs as i16 - self.inputs as i16
    }
}

/// Failure to encode a non-canonical parameterized opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpcodeEncodingError {
    /// `PUSH(n)` is valid only for widths 1 through 32; zero uses `PUSH0`.
    InvalidPushWidth(u8),
    /// `DUP(n)` is valid only for depths 1 through 16.
    InvalidDupDepth(u8),
    /// `SWAP(n)` is valid only for depths 1 through 16.
    InvalidSwapDepth(u8),
    /// `UNKNOWN(byte)` may contain only a byte that is actually unassigned.
    AssignedByteMarkedUnknown(u8),
}

impl fmt::Display for OpcodeEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPushWidth(width) => {
                write!(f, "PUSH width must be in 1..=32, got {width}")
            }
            Self::InvalidDupDepth(depth) => {
                write!(f, "DUP depth must be in 1..=16, got {depth}")
            }
            Self::InvalidSwapDepth(depth) => {
                write!(f, "SWAP depth must be in 1..=16, got {depth}")
            }
            Self::AssignedByteMarkedUnknown(byte) => {
                write!(
                    f,
                    "assigned opcode byte 0x{byte:02x} cannot be marked UNKNOWN"
                )
            }
        }
    }
}

impl std::error::Error for OpcodeEncodingError {}

// The fixed entries below are the single source of truth for byte mapping,
// names, and stack effects. Parameterized PUSH/DUP/SWAP families are handled
// separately because their metadata is derived from the encoded byte.
macro_rules! define_opcodes {
    ($(
        $variant:ident = $byte:literal => ($inputs:literal, $outputs:literal);
    )+) => {
        /// A pattern-matchable opcode from the active Osaka legacy EVM.
        ///
        /// Unassigned bytes are represented losslessly as [`Opcode::UNKNOWN`].
        /// Parameterized families retain their natural one-based width/depth.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum Opcode {
            $(
                #[doc = concat!("The `", stringify!($variant), "` opcode (`", stringify!($byte), "`).")]
                $variant,
            )+
            /// Pushes 1 through 32 immediate bytes.
            PUSH(#[serde(deserialize_with = "deserialize_push_width")] u8),
            /// Duplicates stack item 1 through 16.
            DUP(#[serde(deserialize_with = "deserialize_dup_depth")] u8),
            /// Swaps the top with stack item 2 through 17 (`SWAP1` through `SWAP16`).
            SWAP(#[serde(deserialize_with = "deserialize_swap_depth")] u8),
            /// An unassigned legacy opcode byte, preserved exactly.
            UNKNOWN(#[serde(deserialize_with = "deserialize_unknown_byte")] u8),
        }

        impl Opcode {
            /// Converts a raw legacy-EVM byte into its lossless opcode representation.
            #[must_use]
            pub const fn from_byte(byte: u8) -> Self {
                match byte {
                    $($byte => Self::$variant,)+
                    0x60..=0x7f => Self::PUSH(byte - 0x5f),
                    0x80..=0x8f => Self::DUP(byte - 0x7f),
                    0x90..=0x9f => Self::SWAP(byte - 0x8f),
                    _ => Self::UNKNOWN(byte),
                }
            }

            /// Returns the encoded byte, or `None` for an invalid PUSH/DUP/SWAP parameter.
            #[must_use]
            pub const fn encoded_byte(self) -> Option<u8> {
                match self {
                    $(Self::$variant => Some($byte),)+
                    Self::PUSH(width) if matches!(width, 1..=32) => Some(0x5f + width),
                    Self::DUP(depth) if matches!(depth, 1..=16) => Some(0x7f + depth),
                    Self::SWAP(depth) if matches!(depth, 1..=16) => Some(0x8f + depth),
                    Self::UNKNOWN(byte) if matches!(Self::from_byte(byte), Self::UNKNOWN(_)) => {
                        Some(byte)
                    }
                    Self::PUSH(_) | Self::DUP(_) | Self::SWAP(_) | Self::UNKNOWN(_) => None,
                }
            }

            /// Returns the encoded byte with a precise error for an invalid parameter.
            pub const fn try_to_byte(self) -> Result<u8, OpcodeEncodingError> {
                match self {
                    $(Self::$variant => Ok($byte),)+
                    Self::PUSH(width) if matches!(width, 1..=32) => Ok(0x5f + width),
                    Self::DUP(depth) if matches!(depth, 1..=16) => Ok(0x7f + depth),
                    Self::SWAP(depth) if matches!(depth, 1..=16) => Ok(0x8f + depth),
                    Self::UNKNOWN(byte) if matches!(Self::from_byte(byte), Self::UNKNOWN(_)) => {
                        Ok(byte)
                    }
                    Self::PUSH(width) => Err(OpcodeEncodingError::InvalidPushWidth(width)),
                    Self::DUP(depth) => Err(OpcodeEncodingError::InvalidDupDepth(depth)),
                    Self::SWAP(depth) => Err(OpcodeEncodingError::InvalidSwapDepth(depth)),
                    Self::UNKNOWN(byte) => {
                        Err(OpcodeEncodingError::AssignedByteMarkedUnknown(byte))
                    }
                }
            }

            /// Converts the opcode to its encoded byte for compatibility with the former API.
            ///
            /// New encoding code should use [`Opcode::try_to_byte`] so malformed IR is returned
            /// as an error instead of panicking.
            ///
            /// # Panics
            ///
            /// Panics when a manually constructed PUSH/DUP/SWAP has an out-of-range parameter.
            #[must_use]
            pub fn to_byte(self) -> u8 {
                match self.try_to_byte() {
                    Ok(byte) => byte,
                    Err(error) => panic!("cannot encode opcode: {error}"),
                }
            }

            /// Returns stack metadata for a known opcode.
            ///
            /// Unknown bytes deliberately return `None`; treating an unassigned byte as a
            /// zero-effect instruction would make control-flow and stack analyses unsound.
            #[must_use]
            pub const fn info(self) -> Option<OpcodeInfo> {
                match self {
                    $(Self::$variant => Some(OpcodeInfo::new($inputs, $outputs)),)+
                    Self::PUSH(width) if matches!(width, 1..=32) => {
                        Some(OpcodeInfo::new(0, 1))
                    }
                    Self::DUP(depth) if matches!(depth, 1..=16) => {
                        Some(OpcodeInfo::new(depth, depth + 1))
                    }
                    Self::SWAP(depth) if matches!(depth, 1..=16) => {
                        Some(OpcodeInfo::new(depth + 1, depth + 1))
                    }
                    Self::UNKNOWN(_) | Self::PUSH(_) | Self::DUP(_) | Self::SWAP(_) => None,
                }
            }

            /// Returns the PUSH immediate width, excluding `PUSH0`.
            #[must_use]
            pub const fn push_width(self) -> Option<u8> {
                match self {
                    Self::PUSH(width) if matches!(width, 1..=32) => Some(width),
                    _ => None,
                }
            }

            /// Returns the number of immediate bytes consumed in legacy bytecode.
            #[must_use]
            pub const fn immediate_size(self) -> usize {
                match self.push_width() {
                    Some(width) => width as usize,
                    None => 0,
                }
            }

            /// Decodes an opcode byte and reports its fixed immediate width.
            #[must_use]
            pub const fn parse(byte: u8) -> (Self, usize) {
                let opcode = Self::from_byte(byte);
                let immediate_size = opcode.immediate_size();
                (opcode, immediate_size)
            }

            /// Returns whether this value represents an unassigned byte.
            #[must_use]
            pub const fn is_unknown(&self) -> bool {
                matches!(self, Self::UNKNOWN(_))
            }

            /// Returns whether execution ends at this opcode in the active legacy EVM.
            ///
            /// Unassigned bytes terminate exceptionally and are therefore terminal too.
            #[must_use]
            pub const fn is_terminal(&self) -> bool {
                matches!(
                    self,
                    Self::STOP
                        | Self::RETURN
                        | Self::REVERT
                        | Self::INVALID
                        | Self::SELFDESTRUCT
                        | Self::UNKNOWN(_)
                )
            }

            /// Returns whether this opcode ends a legacy basic block.
            #[must_use]
            pub const fn is_block_ending(&self) -> bool {
                self.is_terminal() || matches!(self, Self::JUMP | Self::JUMPI)
            }

            /// Returns whether this opcode directly marks or changes control flow.
            #[must_use]
            pub const fn is_control_flow(&self) -> bool {
                self.is_block_ending() || matches!(self, Self::JUMPDEST)
            }

            /// Returns the canonical mnemonic, including parameters and unknown-byte values.
            #[must_use]
            pub fn name(&self) -> String {
                self.to_string()
            }

            fn fmt_name(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant => f.write_str(stringify!($variant)),)+
                    Self::PUSH(width) => write!(f, "PUSH{width}"),
                    Self::DUP(depth) => write!(f, "DUP{depth}"),
                    Self::SWAP(depth) => write!(f, "SWAP{depth}"),
                    Self::UNKNOWN(byte) => write!(f, "UNKNOWN(0x{byte:02x})"),
                }
            }
        }

        impl fmt::Display for Opcode {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_name(f)
            }
        }

        impl FromStr for Opcode {
            type Err = String;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                let normalized = input.trim().to_ascii_uppercase();

                if let Some(byte) = parse_unknown_byte(&normalized) {
                    let opcode = Self::from_byte(byte);
                    return if opcode.is_unknown() {
                        Ok(opcode)
                    } else {
                        Err(format!(
                            "assigned opcode byte 0x{byte:02x} is canonically {opcode}"
                        ))
                    };
                }

                match normalized.as_str() {
                    $(stringify!($variant) => Ok(Self::$variant),)+
                    "SHA3" => Ok(Self::KECCAK256),
                    "PREVRANDAO" => Ok(Self::DIFFICULTY),
                    name => parse_parameterized(name)
                        .ok_or_else(|| format!("unknown opcode: {input}")),
                }
            }
        }
    };
}

define_opcodes! {
    STOP = 0x00 => (0, 0);
    ADD = 0x01 => (2, 1);
    MUL = 0x02 => (2, 1);
    SUB = 0x03 => (2, 1);
    DIV = 0x04 => (2, 1);
    SDIV = 0x05 => (2, 1);
    MOD = 0x06 => (2, 1);
    SMOD = 0x07 => (2, 1);
    ADDMOD = 0x08 => (3, 1);
    MULMOD = 0x09 => (3, 1);
    EXP = 0x0a => (2, 1);
    SIGNEXTEND = 0x0b => (2, 1);

    LT = 0x10 => (2, 1);
    GT = 0x11 => (2, 1);
    SLT = 0x12 => (2, 1);
    SGT = 0x13 => (2, 1);
    EQ = 0x14 => (2, 1);
    ISZERO = 0x15 => (1, 1);
    AND = 0x16 => (2, 1);
    OR = 0x17 => (2, 1);
    XOR = 0x18 => (2, 1);
    NOT = 0x19 => (1, 1);
    BYTE = 0x1a => (2, 1);
    SHL = 0x1b => (2, 1);
    SHR = 0x1c => (2, 1);
    SAR = 0x1d => (2, 1);
    CLZ = 0x1e => (1, 1);

    KECCAK256 = 0x20 => (2, 1);

    ADDRESS = 0x30 => (0, 1);
    BALANCE = 0x31 => (1, 1);
    ORIGIN = 0x32 => (0, 1);
    CALLER = 0x33 => (0, 1);
    CALLVALUE = 0x34 => (0, 1);
    CALLDATALOAD = 0x35 => (1, 1);
    CALLDATASIZE = 0x36 => (0, 1);
    CALLDATACOPY = 0x37 => (3, 0);
    CODESIZE = 0x38 => (0, 1);
    CODECOPY = 0x39 => (3, 0);
    GASPRICE = 0x3a => (0, 1);
    EXTCODESIZE = 0x3b => (1, 1);
    EXTCODECOPY = 0x3c => (4, 0);
    RETURNDATASIZE = 0x3d => (0, 1);
    RETURNDATACOPY = 0x3e => (3, 0);
    EXTCODEHASH = 0x3f => (1, 1);

    BLOCKHASH = 0x40 => (1, 1);
    COINBASE = 0x41 => (0, 1);
    TIMESTAMP = 0x42 => (0, 1);
    NUMBER = 0x43 => (0, 1);
    DIFFICULTY = 0x44 => (0, 1);
    GASLIMIT = 0x45 => (0, 1);
    CHAINID = 0x46 => (0, 1);
    SELFBALANCE = 0x47 => (0, 1);
    BASEFEE = 0x48 => (0, 1);
    BLOBHASH = 0x49 => (1, 1);
    BLOBBASEFEE = 0x4a => (0, 1);

    POP = 0x50 => (1, 0);
    MLOAD = 0x51 => (1, 1);
    MSTORE = 0x52 => (2, 0);
    MSTORE8 = 0x53 => (2, 0);
    SLOAD = 0x54 => (1, 1);
    SSTORE = 0x55 => (2, 0);
    JUMP = 0x56 => (1, 0);
    JUMPI = 0x57 => (2, 0);
    PC = 0x58 => (0, 1);
    MSIZE = 0x59 => (0, 1);
    GAS = 0x5a => (0, 1);
    JUMPDEST = 0x5b => (0, 0);
    TLOAD = 0x5c => (1, 1);
    TSTORE = 0x5d => (2, 0);
    MCOPY = 0x5e => (3, 0);
    PUSH0 = 0x5f => (0, 1);

    LOG0 = 0xa0 => (2, 0);
    LOG1 = 0xa1 => (3, 0);
    LOG2 = 0xa2 => (4, 0);
    LOG3 = 0xa3 => (5, 0);
    LOG4 = 0xa4 => (6, 0);

    CREATE = 0xf0 => (3, 1);
    CALL = 0xf1 => (7, 1);
    CALLCODE = 0xf2 => (7, 1);
    RETURN = 0xf3 => (2, 0);
    DELEGATECALL = 0xf4 => (6, 1);
    CREATE2 = 0xf5 => (4, 1);
    STATICCALL = 0xfa => (6, 1);
    REVERT = 0xfd => (2, 0);
    INVALID = 0xfe => (0, 0);
    SELFDESTRUCT = 0xff => (1, 0);
}

impl Opcode {
    /// Post-Merge name for opcode `0x44`.
    pub const PREVRANDAO: Self = Self::DIFFICULTY;
    /// Historical alias for `KECCAK256` (`0x20`).
    pub const SHA3: Self = Self::KECCAK256;
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        Self::from_byte(byte)
    }
}

impl From<Opcode> for u8 {
    /// Converts a canonical opcode to a byte.
    ///
    /// This compatibility conversion panics for an invalid parameterized opcode. Code handling
    /// untrusted or transform-produced IR should call [`Opcode::try_to_byte`] instead.
    fn from(opcode: Opcode) -> Self {
        opcode.to_byte()
    }
}

fn parse_parameterized(name: &str) -> Option<Opcode> {
    if let Some(width) = parse_decimal_suffix(name, "PUSH")
        && (1..=32).contains(&width)
    {
        return Some(Opcode::PUSH(width));
    }
    if let Some(depth) = parse_decimal_suffix(name, "DUP")
        && (1..=16).contains(&depth)
    {
        return Some(Opcode::DUP(depth));
    }
    if let Some(depth) = parse_decimal_suffix(name, "SWAP")
        && (1..=16).contains(&depth)
    {
        return Some(Opcode::SWAP(depth));
    }
    None
}

fn parse_decimal_suffix(name: &str, prefix: &str) -> Option<u8> {
    let suffix = name.strip_prefix(prefix)?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

fn parse_unknown_byte(name: &str) -> Option<u8> {
    let hex = name.strip_prefix("UNKNOWN_0X").or_else(|| {
        name.strip_prefix("UNKNOWN(0X")
            .and_then(|suffix| suffix.strip_suffix(')'))
    })?;
    if hex.is_empty() || hex.len() > 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(hex, 16).ok()
}

fn deserialize_push_width<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let width = u8::deserialize(deserializer)?;
    if (1..=32).contains(&width) {
        Ok(width)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "PUSH width must be in 1..=32, got {width}"
        )))
    }
}

fn deserialize_dup_depth<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let depth = u8::deserialize(deserializer)?;
    if (1..=16).contains(&depth) {
        Ok(depth)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "DUP depth must be in 1..=16, got {depth}"
        )))
    }
}

fn deserialize_swap_depth<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let depth = u8::deserialize(deserializer)?;
    if (1..=16).contains(&depth) {
        Ok(depth)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "SWAP depth must be in 1..=16, got {depth}"
        )))
    }
}

fn deserialize_unknown_byte<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let byte = u8::deserialize(deserializer)?;
    let opcode = Opcode::from_byte(byte);
    if opcode.is_unknown() {
        Ok(byte)
    } else {
        Err(serde::de::Error::custom(format_args!(
            "assigned opcode byte 0x{byte:02x} is canonically {opcode}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{Opcode, OpcodeEncodingError, OpcodeInfo};
    use std::str::FromStr;

    #[test]
    fn every_byte_round_trips_losslessly() {
        for byte in u8::MIN..=u8::MAX {
            let opcode = Opcode::from_byte(byte);
            assert_eq!(opcode.encoded_byte(), Some(byte), "byte 0x{byte:02x}");
            assert_eq!(opcode.try_to_byte(), Ok(byte), "byte 0x{byte:02x}");
            assert_eq!(u8::from(opcode), byte, "byte 0x{byte:02x}");
        }
    }

    #[test]
    fn known_byte_set_matches_osaka_legacy_evm() {
        for byte in u8::MIN..=u8::MAX {
            let expected_known = matches!(
                byte,
                0x00..=0x0b
                    | 0x10..=0x1e
                    | 0x20
                    | 0x30..=0x4a
                    | 0x50..=0xa4
                    | 0xf0..=0xf5
                    | 0xfa
                    | 0xfd..=0xff
            );
            assert_eq!(
                !Opcode::from_byte(byte).is_unknown(),
                expected_known,
                "known-byte classification differs at 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn current_fork_opcodes_are_modelled() {
        let cases = [
            (0x1e, Opcode::CLZ, OpcodeInfo::new(1, 1)),
            (0x49, Opcode::BLOBHASH, OpcodeInfo::new(1, 1)),
            (0x4a, Opcode::BLOBBASEFEE, OpcodeInfo::new(0, 1)),
            (0x5c, Opcode::TLOAD, OpcodeInfo::new(1, 1)),
            (0x5d, Opcode::TSTORE, OpcodeInfo::new(2, 0)),
            (0x5e, Opcode::MCOPY, OpcodeInfo::new(3, 0)),
            (0x5f, Opcode::PUSH0, OpcodeInfo::new(0, 1)),
        ];

        for (byte, opcode, info) in cases {
            assert_eq!(Opcode::from_byte(byte), opcode);
            assert_eq!(opcode.info(), Some(info));
        }
    }

    #[test]
    fn withdrawn_eof_proposal_bytes_remain_unknown_in_legacy_code() {
        const EOF_PROPOSAL_BYTES: &[u8] = &[
            0xd0, 0xd1, 0xd2, 0xd3, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xec,
            0xee, 0xf7, 0xf8, 0xf9, 0xfb,
        ];

        for &byte in EOF_PROPOSAL_BYTES {
            let opcode = Opcode::from_byte(byte);
            assert_eq!(opcode, Opcode::UNKNOWN(byte));
            assert_eq!(opcode.info(), None);
            assert!(opcode.is_terminal());
        }
    }

    #[test]
    fn stack_effects_are_exhaustive_for_known_bytes() {
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(
                Opcode::from_byte(byte).info(),
                expected_stack_info(byte),
                "stack metadata differs at 0x{byte:02x}"
            );
        }
    }

    #[test]
    fn parameterized_opcode_boundaries_are_checked() {
        assert_eq!(Opcode::PUSH(1).try_to_byte(), Ok(0x60));
        assert_eq!(Opcode::PUSH(32).try_to_byte(), Ok(0x7f));
        assert_eq!(Opcode::DUP(1).try_to_byte(), Ok(0x80));
        assert_eq!(Opcode::DUP(16).try_to_byte(), Ok(0x8f));
        assert_eq!(Opcode::SWAP(1).try_to_byte(), Ok(0x90));
        assert_eq!(Opcode::SWAP(16).try_to_byte(), Ok(0x9f));

        for width in [0, 33, u8::MAX] {
            assert_eq!(Opcode::PUSH(width).encoded_byte(), None);
            assert_eq!(
                Opcode::PUSH(width).try_to_byte(),
                Err(OpcodeEncodingError::InvalidPushWidth(width))
            );
            assert_eq!(Opcode::PUSH(width).info(), None);
        }
        for depth in [0, 17, u8::MAX] {
            assert_eq!(Opcode::DUP(depth).encoded_byte(), None);
            assert_eq!(
                Opcode::DUP(depth).try_to_byte(),
                Err(OpcodeEncodingError::InvalidDupDepth(depth))
            );
            assert_eq!(Opcode::DUP(depth).info(), None);

            assert_eq!(Opcode::SWAP(depth).encoded_byte(), None);
            assert_eq!(
                Opcode::SWAP(depth).try_to_byte(),
                Err(OpcodeEncodingError::InvalidSwapDepth(depth))
            );
            assert_eq!(Opcode::SWAP(depth).info(), None);
        }

        for byte in [0x00, 0x56, 0x60, 0xfe, 0xff] {
            assert_eq!(Opcode::UNKNOWN(byte).encoded_byte(), None);
            assert_eq!(
                Opcode::UNKNOWN(byte).try_to_byte(),
                Err(OpcodeEncodingError::AssignedByteMarkedUnknown(byte))
            );
        }

        assert_eq!(Opcode::UNKNOWN(0x0c).encoded_byte(), Some(0x0c));
        assert_eq!(Opcode::UNKNOWN(0xd0).try_to_byte(), Ok(0xd0));
    }

    #[test]
    fn parse_reports_only_push_immediate_widths() {
        assert_eq!(Opcode::parse(0x5f), (Opcode::PUSH0, 0));
        for width in 1..=32 {
            let byte = 0x5f + width;
            assert_eq!(Opcode::parse(byte), (Opcode::PUSH(width), width as usize));
        }
        assert_eq!(Opcode::parse(0xd1), (Opcode::UNKNOWN(0xd1), 0));
    }

    #[test]
    fn names_parse_with_required_aliases_and_unknown_formats() {
        assert_eq!(Opcode::from_str("sha3"), Ok(Opcode::KECCAK256));
        assert_eq!(Opcode::from_str("PREVRANDAO"), Ok(Opcode::DIFFICULTY));
        assert_eq!(Opcode::from_str("push32"), Ok(Opcode::PUSH(32)));
        assert_eq!(Opcode::from_str("dup16"), Ok(Opcode::DUP(16)));
        assert_eq!(Opcode::from_str("swap16"), Ok(Opcode::SWAP(16)));
        assert_eq!(Opcode::from_str("UNKNOWN_0xaa"), Ok(Opcode::UNKNOWN(0xaa)));
        assert_eq!(Opcode::from_str("UNKNOWN(0x0c)"), Ok(Opcode::UNKNOWN(0x0c)));

        assert!(Opcode::from_str("unknown").is_err());
        assert!(Opcode::from_str("PUSH00").is_err());
        assert!(Opcode::from_str("PUSH33").is_err());
        assert!(Opcode::from_str("DUP0").is_err());
        assert!(Opcode::from_str("SWAP17").is_err());
        assert!(Opcode::from_str("UNKNOWN(0x56)").is_err());
        assert!(Opcode::from_str("UNKNOWN_0xfe").is_err());
    }

    #[test]
    fn canonical_names_round_trip() {
        for byte in u8::MIN..=u8::MAX {
            let opcode = Opcode::from_byte(byte);
            let rendered = opcode.to_string();
            assert_eq!(Opcode::from_str(&rendered), Ok(opcode), "byte 0x{byte:02x}");
            assert_eq!(opcode.name(), rendered);
        }
    }

    #[test]
    fn terminal_and_block_helpers_follow_legacy_execution() {
        for opcode in [
            Opcode::STOP,
            Opcode::RETURN,
            Opcode::REVERT,
            Opcode::INVALID,
            Opcode::SELFDESTRUCT,
            Opcode::UNKNOWN(0x0c),
        ] {
            assert!(opcode.is_terminal());
            assert!(opcode.is_block_ending());
            assert!(opcode.is_control_flow());
        }

        for opcode in [Opcode::JUMP, Opcode::JUMPI] {
            assert!(!opcode.is_terminal());
            assert!(opcode.is_block_ending());
            assert!(opcode.is_control_flow());
        }

        assert!(!Opcode::JUMPDEST.is_terminal());
        assert!(!Opcode::JUMPDEST.is_block_ending());
        assert!(Opcode::JUMPDEST.is_control_flow());
        assert!(!Opcode::ADD.is_control_flow());
    }

    fn expected_stack_info(byte: u8) -> Option<OpcodeInfo> {
        let info = match byte {
            0x00 | 0x5b | 0xfe => (0, 0),

            0x30
            | 0x32..=0x34
            | 0x36
            | 0x38
            | 0x3a
            | 0x3d
            | 0x41..=0x48
            | 0x4a
            | 0x58..=0x5a
            | 0x5f
            | 0x60..=0x7f => (0, 1),

            0x50 | 0x56 | 0xff => (1, 0),

            0x15 | 0x19 | 0x1e | 0x31 | 0x35 | 0x3b | 0x3f | 0x40 | 0x49 | 0x51 | 0x54 | 0x5c => {
                (1, 1)
            }

            0x52 | 0x53 | 0x55 | 0x57 | 0x5d | 0xf3 | 0xfd => (2, 0),

            0x01..=0x07 | 0x0a..=0x0b | 0x10..=0x14 | 0x16..=0x18 | 0x1a..=0x1d | 0x20 => (2, 1),

            0x37 | 0x39 | 0x3e | 0x5e => (3, 0),
            0x3c => (4, 0),
            0x08 | 0x09 | 0xf0 => (3, 1),
            0xf5 => (4, 1),
            0xf1 | 0xf2 => (7, 1),
            0xf4 | 0xfa => (6, 1),

            0x80..=0x8f => {
                let depth = byte - 0x7f;
                (depth, depth + 1)
            }
            0x90..=0x9f => {
                let depth = byte - 0x8f;
                (depth + 1, depth + 1)
            }
            0xa0..=0xa4 => (byte - 0x9e, 0),
            _ => return None,
        };
        Some(OpcodeInfo::new(info.0, info.1))
    }
}
