//! Compiler-emitted facts that ride along with `CfgIrBundle`.
//!
//! Today, azoth recovers many of these facts heuristically from raw bytecode:
//! it pattern-matches `PUSH4 EQ JUMPI` chains to find selectors, scans
//! `PUSH; ADD; MSTORE` sequences to find immutable writes, and infers section
//! boundaries from `CODECOPY+RETURN`. When the compiler artifact is available
//! (which is always true for the escrow contracts we obfuscate), all of those
//! facts are right there in the json — no guessing required.
//!
//! This module defines the `CompilerContext` type, a typed bundle of those
//! facts, and a loader from foundry artifact json. Existing code paths can
//! consult `Option<&CompilerContext>` to prefer artifact data when present and
//! fall back to heuristics when absent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Errors produced when loading a `CompilerContext` from an artifact.
#[derive(Debug, thiserror::Error)]
pub enum CompilerContextError {
    /// Failed to read the artifact file.
    #[error("artifact io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse error.
    #[error("artifact json: {0}")]
    Json(#[from] serde_json::Error),
    /// A selector hex string was malformed.
    #[error("invalid selector hex `{selector}` for `{signature}`: {source}")]
    BadSelector {
        /// Function signature the bad selector belongs to.
        signature: String,
        /// The offending hex string.
        selector: String,
        /// Underlying parse error.
        #[source]
        source: hex::FromHexError,
    },
    /// A bytecode hex string was malformed.
    #[error("invalid bytecode hex: {0}")]
    BadBytecode(#[source] hex::FromHexError),
    /// A required artifact field was missing.
    #[error("artifact missing field `{0}`")]
    Missing(&'static str),
}

/// A contiguous byte range within a piece of bytecode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteRange {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Length in bytes.
    pub length: usize,
}

/// A storage variable as solc lays it out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageVariable {
    /// AST id of the declaration (matches `ast_id` in `immutable_references`
    /// for immutables, or the declaration id of a state variable).
    #[serde(rename = "astId")]
    pub ast_id: i64,
    /// Fully qualified contract path.
    pub contract: String,
    /// Variable name.
    pub label: String,
    /// Byte offset within the slot (0..32). Non-zero means slot packing.
    pub offset: u8,
    /// Slot number as a decimal string (slots are uint256).
    pub slot: String,
    /// Type key, indexed into `StorageLayout::types`.
    #[serde(rename = "type")]
    pub type_name: String,
}

/// Type metadata for a storage type referenced by `StorageVariable::type_name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageType {
    /// `inplace`, `mapping`, `dynamic_array`, `bytes`.
    pub encoding: String,
    /// Source-level type name.
    pub label: String,
    /// Width in bytes (decimal string).
    #[serde(rename = "numberOfBytes")]
    pub number_of_bytes: String,
}

/// Solc storage layout, comprising the variable list and the type table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLayout {
    /// State variable layout entries.
    pub storage: Vec<StorageVariable>,
    /// Type metadata, keyed by the `type` field of `StorageVariable`.
    pub types: HashMap<String, StorageType>,
}

/// All compiler-emitted facts attached to a contract.
#[derive(Debug, Clone)]
pub struct CompilerContext {
    /// Raw deployment bytecode (init + runtime + auxdata).
    pub deployment_bytecode: Vec<u8>,
    /// Raw runtime bytecode (what lives on chain).
    pub runtime_bytecode: Vec<u8>,
    /// Public function signatures and their PUSH4 selectors.
    pub method_identifiers: HashMap<String, [u8; 4]>,
    /// Immutable byte ranges in the runtime, keyed by ast id.
    pub immutable_references: HashMap<String, Vec<ByteRange>>,
    /// Library link placeholders in the runtime, keyed by source file then library name.
    pub link_references: HashMap<String, HashMap<String, Vec<ByteRange>>>,
    /// Storage layout, when emitted by the compiler (foundry needs `extra_output = ["storageLayout"]`).
    pub storage_layout: Option<StorageLayout>,
}

impl CompilerContext {
    /// Load from a foundry artifact json (typically `out/Foo.sol/Foo.json`).
    pub fn load_foundry_artifact(path: impl AsRef<Path>) -> Result<Self, CompilerContextError> {
        let raw = std::fs::read_to_string(path)?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        Self::from_json(&v)
    }

    /// Build a `CompilerContext` from a parsed foundry artifact json value.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, CompilerContextError> {
        let deployment_bytecode = parse_bytecode_field(v, "bytecode")?;
        let runtime_bytecode = parse_bytecode_field(v, "deployedBytecode")?;
        let method_identifiers = parse_method_identifiers(v)?;
        let immutable_references = parse_immutable_references(v);
        let link_references = parse_link_references(v);
        let storage_layout = v
            .get("storageLayout")
            .map(|sl| serde_json::from_value::<StorageLayout>(sl.clone()))
            .transpose()?;

        Ok(Self {
            deployment_bytecode,
            runtime_bytecode,
            method_identifiers,
            immutable_references,
            link_references,
            storage_layout,
        })
    }

    /// Returns the canonical set of public selectors as `u32` (big-endian
    /// interpretation of the 4 selector bytes — matches what we get from
    /// `PUSH4 <selector>` in bytecode).
    pub fn selector_set(&self) -> std::collections::HashSet<u32> {
        self.method_identifiers
            .values()
            .map(|bytes| u32::from_be_bytes(*bytes))
            .collect()
    }
}

fn parse_bytecode_field(
    v: &serde_json::Value,
    field: &'static str,
) -> Result<Vec<u8>, CompilerContextError> {
    let hex_str = v
        .get(field)
        .and_then(|b| b.get("object"))
        .and_then(|o| o.as_str())
        .ok_or(CompilerContextError::Missing(field))?
        .trim_start_matches("0x");
    hex::decode(hex_str).map_err(CompilerContextError::BadBytecode)
}

fn parse_method_identifiers(
    v: &serde_json::Value,
) -> Result<HashMap<String, [u8; 4]>, CompilerContextError> {
    let mut out = HashMap::new();
    let Some(obj) = v.get("methodIdentifiers").and_then(|m| m.as_object()) else {
        return Ok(out);
    };
    for (sig, val) in obj {
        let hex_str = val.as_str().unwrap_or("");
        let bytes = hex::decode(hex_str).map_err(|e| CompilerContextError::BadSelector {
            signature: sig.clone(),
            selector: hex_str.to_string(),
            source: e,
        })?;
        if bytes.len() != 4 {
            return Err(CompilerContextError::BadSelector {
                signature: sig.clone(),
                selector: hex_str.to_string(),
                source: hex::FromHexError::InvalidStringLength,
            });
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        out.insert(sig.clone(), arr);
    }
    Ok(out)
}

fn parse_immutable_references(v: &serde_json::Value) -> HashMap<String, Vec<ByteRange>> {
    let mut out = HashMap::new();
    let Some(obj) = v
        .get("deployedBytecode")
        .and_then(|d| d.get("immutableReferences"))
        .and_then(|i| i.as_object())
    else {
        return out;
    };
    for (ast_id, ranges_v) in obj {
        let Some(arr) = ranges_v.as_array() else {
            continue;
        };
        let ranges: Vec<ByteRange> = arr
            .iter()
            .filter_map(|r| serde_json::from_value::<ByteRange>(r.clone()).ok())
            .collect();
        if !ranges.is_empty() {
            out.insert(ast_id.clone(), ranges);
        }
    }
    out
}

fn parse_link_references(
    v: &serde_json::Value,
) -> HashMap<String, HashMap<String, Vec<ByteRange>>> {
    let mut out = HashMap::new();
    let Some(files) = v
        .get("deployedBytecode")
        .and_then(|d| d.get("linkReferences"))
        .and_then(|l| l.as_object())
    else {
        return out;
    };
    for (file, libs_v) in files {
        let Some(libs) = libs_v.as_object() else {
            continue;
        };
        let mut per_file = HashMap::new();
        for (lib, ranges_v) in libs {
            let Some(arr) = ranges_v.as_array() else {
                continue;
            };
            let ranges: Vec<ByteRange> = arr
                .iter()
                .filter_map(|r| serde_json::from_value::<ByteRange>(r.clone()).ok())
                .collect();
            if !ranges.is_empty() {
                per_file.insert(lib.clone(), ranges);
            }
        }
        if !per_file.is_empty() {
            out.insert(file.clone(), per_file);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESCROW_ERC20: &str =
        "../../examples/escrow-bytecode/out/EscrowERC20.sol/EscrowERC20.json";
    const ESCROW_NATIVE: &str =
        "../../examples/escrow-bytecode/out/EscrowNative.sol/EscrowNative.json";

    #[test]
    fn loads_escrow_erc20_context() {
        let ctx = CompilerContext::load_foundry_artifact(ESCROW_ERC20)
            .expect("load EscrowERC20 artifact");

        assert!(!ctx.deployment_bytecode.is_empty(), "deployment bytecode empty");
        assert!(!ctx.runtime_bytecode.is_empty(), "runtime bytecode empty");

        // EscrowERC20 has a known set of public functions; spot check a few.
        let selector = ctx
            .method_identifiers
            .get("fund(uint256,uint256)")
            .expect("fund selector");
        assert_eq!(selector, &[0xa6, 0x5e, 0x2c, 0xfd]);

        let selector = ctx
            .method_identifiers
            .get("withdraw()")
            .expect("withdraw selector");
        assert_eq!(selector, &[0x3c, 0xcf, 0xd6, 0x0b]);

        // Four immutables: deployerAddress, expectedRecipient, expectedAmount, tokenContract.
        // ast ids confirmed against the artifact: 40183, 40191, 40193, 40607.
        assert_eq!(ctx.immutable_references.len(), 4, "expected 4 immutables");
        for ast_id in ["40183", "40191", "40193", "40607"] {
            assert!(
                ctx.immutable_references.contains_key(ast_id),
                "missing immutable ast id {ast_id}",
            );
        }

        // tokenContract has 7 references in the runtime.
        assert_eq!(ctx.immutable_references["40607"].len(), 7);

        // No libraries in escrow.
        assert!(ctx.link_references.is_empty());

        // Storage layout includes the packed slot 7 with cancellationRequest + funded.
        let layout = ctx.storage_layout.as_ref().expect("storage layout present");
        let slot_7_vars: Vec<_> = layout
            .storage
            .iter()
            .filter(|v| v.slot == "7")
            .collect();
        assert!(!slot_7_vars.is_empty(), "expected packed vars in slot 7");
    }

    #[test]
    fn loads_escrow_native_context() {
        let ctx = CompilerContext::load_foundry_artifact(ESCROW_NATIVE)
            .expect("load EscrowNative artifact");
        assert!(!ctx.method_identifiers.is_empty());
        assert!(!ctx.immutable_references.is_empty());
        assert!(ctx.storage_layout.is_some());
    }

    #[test]
    fn selector_set_round_trips() {
        let ctx = CompilerContext::load_foundry_artifact(ESCROW_ERC20).unwrap();
        let set = ctx.selector_set();

        // PUSH4 0xa65e2cfd in bytecode is u32::from_be_bytes([0xa6,0x5e,0x2c,0xfd])
        assert!(set.contains(&0xa65e2cfd));
        assert!(set.contains(&0x3ccfd60b)); // withdraw
        assert!(set.contains(&0x55a373d6)); // tokenContract

        // A random PUSH4 value that's NOT a selector should be absent.
        assert!(!set.contains(&0xdeadbeef));
    }
}
