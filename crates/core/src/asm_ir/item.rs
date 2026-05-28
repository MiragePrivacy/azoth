//! Typed Rust mirror of solc's `legacyAssembly` JSON schema.
//!
//! See `libevmasm/Assembly.cpp::validateSingleInstruction` in the solc source
//! for the canonical schema. The shape:
//!
//! ```jsonc
//! {
//!   ".code":   [ AsmItem, ... ],            // outer code = init bytecode
//!   ".data":   { "0": SubAssembly, ... },   // sub-assemblies (runtime is "0")
//!   "sourceList": [ "Foo.sol", ... ]
//! }
//! ```
//!
//! Each item has a `name` (opcode mnemonic or special form like `PUSH [tag]`,
//! `tag`, `PUSHIMMUTABLE`, `VERBATIM`) and an optional `value` (literal hex,
//! tag id, immutable id). Source-map fields (`begin`, `end`, `source`,
//! `jumpType`, `modifierDepth`) are preserved for round-trip fidelity.

use crate::Opcode;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A single solc legacy-assembly item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmItem {
    /// Opcode mnemonic or special form (`PUSH`, `PUSH [tag]`, `tag`,
    /// `JUMPDEST`, `PUSHIMMUTABLE`, `ASSIGNIMMUTABLE`, `PUSH [$]`,
    /// `PUSH #[$]`, `PUSHSIZE`, `PUSHLIB`, `VERBATIM`, `RJUMP`, etc.).
    pub name: String,
    /// Optional value: hex literal for `PUSH`, decimal id for `tag` / `PUSH
    /// [tag]`, ast id for `PUSHIMMUTABLE` / `ASSIGNIMMUTABLE`, sub-assembly
    /// key for `PUSH [$]` / `PUSH #[$]`, hash for `PUSHLIB`, or hex bytes for
    /// `VERBATIM`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Source range start byte (source-map field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub begin: Option<i64>,
    /// Source range end byte (source-map field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
    /// Source file index (into `LegacyAssembly::source_list`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<i64>,
    /// Jump kind: `[in]`, `[out]`, or absent.
    #[serde(rename = "jumpType", skip_serializing_if = "Option::is_none")]
    pub jump_type: Option<String>,
    /// Modifier nesting depth.
    #[serde(rename = "modifierDepth", skip_serializing_if = "Option::is_none")]
    pub modifier_depth: Option<i64>,
}

impl AsmItem {
    /// Construct a name-only item (no value, no source-map fields). Useful for
    /// transforms that emit synthetic items.
    pub fn op(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
            begin: None,
            end: None,
            source: None,
            jump_type: None,
            modifier_depth: None,
        }
    }

    /// Construct an item with a name and a value (e.g. `PUSH` with a hex
    /// literal, or `tag` with a decimal id).
    pub fn op_with_value(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            begin: None,
            end: None,
            source: None,
            jump_type: None,
            modifier_depth: None,
        }
    }

    /// Returns true if this item is a `tag` declaration. The accompanying
    /// `JUMPDEST` byte is emitted by a separate adjacent item.
    pub fn is_tag(&self) -> bool {
        self.name == "tag"
    }

    /// Returns true if this item names a jump target via `PUSH [tag]`.
    pub fn is_push_tag(&self) -> bool {
        self.name == "PUSH [tag]"
    }

    /// Parse `self.name` into a typed `eot::UnifiedOpcode`, when the item
    /// actually represents a real EVM opcode. Returns `None` for the
    /// asm-item-only special kinds (`tag`, `PUSH [tag]`, `PUSH [$]`,
    /// `PUSH #[$]`, `PUSHIMMUTABLE`, `ASSIGNIMMUTABLE`, `PUSHLIB`,
    /// `PUSHSIZE`, `VERBATIM`, etc.) since those aren't EVM opcodes at all
    /// — they only have a name because that's how solc encodes them in
    /// legacy assembly json.
    pub fn opcode(&self) -> Option<Opcode> {
        Opcode::from_str(&self.name).ok()
    }

    /// Returns true if this item terminates a basic block — either a halt
    /// (`STOP`/`RETURN`/`REVERT`/`INVALID`/`SELFDESTRUCT`) or a control
    /// transfer (`JUMP`/`JUMPI`/EOF jumps). Implemented via `eot::Opcode`'s
    /// own classification rather than a hand-maintained string list.
    pub fn is_terminator(&self) -> bool {
        let Some(op) = self.opcode() else {
            return false;
        };
        // `as_opcode().terminates()` covers halts (STOP/RETURN/REVERT/INVALID
        // /SELFDESTRUCT + EOF RETF/RETURNCONTRACT). `is_control_flow()` also
        // covers JUMP, JUMPI, JUMPDEST, plus EOF jumps
        // RJUMP/RJUMPI/RJUMPV/CALLF/JUMPF. We don't want JUMPDEST to count
        // as a terminator (it's a label), so subtract it explicitly.
        op.as_opcode().terminates() || (op.is_control_flow() && op != Opcode::JUMPDEST)
    }

    /// For `tag` and `PUSH [tag]` items, parse the decimal tag id from
    /// `value`. Returns `None` for items without a tag-id value.
    pub fn tag_id(&self) -> Option<u64> {
        if !self.is_tag() && !self.is_push_tag() {
            return None;
        }
        self.value.as_deref().and_then(|s| s.parse().ok())
    }
}

/// A value in a `.data` map: either a nested sub-assembly (the runtime is
/// conventionally `data["0"]`) or a raw hex blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DataValue {
    /// A nested sub-assembly with its own code, data, and auxdata.
    SubAssembly(SubAssembly),
    /// A raw hex data blob (no executable code).
    Raw(String),
}

/// A sub-assembly nested under `.data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAssembly {
    /// Code items for this sub-assembly.
    #[serde(rename = ".code")]
    pub code: Vec<AsmItem>,
    /// Recursive nested data map.
    #[serde(rename = ".data", default, skip_serializing_if = "IndexMap::is_empty")]
    pub data: IndexMap<String, DataValue>,
    /// Auxdata trailer (typically the CBOR metadata blob for the runtime).
    #[serde(rename = ".auxdata", skip_serializing_if = "Option::is_none")]
    pub auxdata: Option<String>,
}

/// The top-level legacy assembly emitted by solc.
///
/// `code` is the init bytecode (the constructor). `data["0"]` is conventionally
/// the runtime sub-assembly (what gets returned and lives on chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyAssembly {
    /// Init code items.
    #[serde(rename = ".code")]
    pub code: Vec<AsmItem>,
    /// Sub-assemblies and data blobs.
    #[serde(rename = ".data", default, skip_serializing_if = "IndexMap::is_empty")]
    pub data: IndexMap<String, DataValue>,
    /// Source file paths referenced by item `source` indices.
    #[serde(rename = "sourceList", default, skip_serializing_if = "Option::is_none")]
    pub source_list: Option<Vec<String>>,
}

impl LegacyAssembly {
    /// Mutable handle to the runtime sub-assembly (conventionally `data["0"]`).
    pub fn runtime_mut(&mut self) -> Option<&mut SubAssembly> {
        match self.data.get_mut("0")? {
            DataValue::SubAssembly(sub) => Some(sub),
            DataValue::Raw(_) => None,
        }
    }

    /// Immutable handle to the runtime sub-assembly.
    pub fn runtime(&self) -> Option<&SubAssembly> {
        match self.data.get("0")? {
            DataValue::SubAssembly(sub) => Some(sub),
            DataValue::Raw(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_classification() {
        assert!(AsmItem::op("STOP").is_terminator());
        assert!(AsmItem::op("JUMP").is_terminator());
        assert!(!AsmItem::op("ADD").is_terminator());

        assert!(AsmItem::op_with_value("tag", "5").is_tag());
        assert!(!AsmItem::op_with_value("PUSH", "deadbeef").is_tag());

        assert!(AsmItem::op_with_value("PUSH [tag]", "5").is_push_tag());
        assert!(!AsmItem::op_with_value("PUSH", "deadbeef").is_push_tag());

        assert_eq!(
            AsmItem::op_with_value("tag", "42").tag_id(),
            Some(42)
        );
        assert_eq!(
            AsmItem::op_with_value("PUSH [tag]", "7").tag_id(),
            Some(7)
        );
        assert_eq!(AsmItem::op_with_value("PUSH", "deadbeef").tag_id(), None);
    }

    #[test]
    fn legacy_assembly_round_trips() {
        let json = r#"{
            ".code": [
                {"name":"PUSH","value":"80"},
                {"name":"tag","value":"1"},
                {"name":"JUMPDEST"}
            ],
            ".data": {
                "0": {
                    ".code": [{"name":"STOP"}],
                    ".auxdata": "deadbeef"
                }
            },
            "sourceList": ["foo.sol"]
        }"#;
        let asm: LegacyAssembly = serde_json::from_str(json).expect("parse");
        assert_eq!(asm.code.len(), 3);
        let runtime = asm.runtime().expect("runtime");
        assert_eq!(runtime.code.len(), 1);
        assert_eq!(runtime.auxdata.as_deref(), Some("deadbeef"));

        let back = serde_json::to_string(&asm).expect("serialize");
        let asm2: LegacyAssembly = serde_json::from_str(&back).expect("reparse");
        assert_eq!(asm2.code.len(), 3);
        assert_eq!(asm2.runtime().unwrap().code.len(), 1);
    }
}
