//! The labelled-assembly IR: typed mirror of solc's `legacyAssembly` schema,
//! plus a CFG built over it where blocks are keyed by tag id rather than pc.
//!
//! Today, azoth's `cfg_ir` operates on `Vec<Instruction>` — flat opcodes with
//! resolved program counters. Every transform that resizes code invalidates
//! those pcs, so the obfuscator pipeline runs `reindex_pcs()` and a long
//! finalisation dance (`patch_jump_immediates`, dispatcher reapply, decoy /
//! controller / orphan-push remap) after every change.
//!
//! This module is the alternative: items reference jumps by symbolic `tag`
//! ids (`PUSH [tag]` items name their target block), pushes don't carry an
//! explicit width (solc picks the smallest one that fits), and the CFG is a
//! view over the item list with blocks identified by the tag id at their
//! head. Transforms that operate on items never touch a pc and never need
//! reindexing — solc resolves everything at the bottom when it assembles.

pub mod cfg;
pub mod item;

pub use cfg::{AsmBlock, AsmBlockId, AsmCfg, AsmEdge, AsmEdgeKind, AsmEdgeTarget, build_asm_cfg};
pub use item::{AsmItem, DataValue, LegacyAssembly, SubAssembly};

#[cfg(test)]
mod roundtrip_tests {
    //! Proof that the IR faithfully mirrors solc's `legacyAssembly`: load the
    //! artifact's assembly, serialize it back, hand it to
    //! `solc --import-asm-json`, and confirm the bytecode is byte-identical to
    //! the artifact's own `bytecode.object`.

    use super::LegacyAssembly;
    use std::process::Command;

    const ESCROW_ERC20: &str =
        "../../examples/escrow-bytecode/out/EscrowERC20.sol/EscrowERC20.json";
    const ESCROW_NATIVE: &str =
        "../../examples/escrow-bytecode/out/EscrowNative.sol/EscrowNative.json";

    /// Returns true if `solc` on PATH supports `--import-asm-json`.
    fn solc_supports_import_asm_json() -> bool {
        let Ok(out) = Command::new("solc").arg("--help").output() else {
            return false;
        };
        String::from_utf8_lossy(&out.stdout).contains("import-asm-json")
            || String::from_utf8_lossy(&out.stderr).contains("import-asm-json")
    }

    /// Load `legacyAssembly` and `bytecode.object` from a foundry artifact.
    fn load(path: &str) -> Option<(LegacyAssembly, String)> {
        let raw = std::fs::read_to_string(path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let asm: LegacyAssembly = serde_json::from_value(v.get("legacyAssembly")?.clone()).ok()?;
        let bytecode = v
            .get("bytecode")?
            .get("object")?
            .as_str()?
            .trim_start_matches("0x")
            .to_string();
        Some((asm, bytecode))
    }

    /// Serialize `asm` and assemble it via `solc --import-asm-json`, returning
    /// the produced bytecode hex (no `0x` prefix).
    fn assemble(asm: &LegacyAssembly) -> Option<String> {
        let json = serde_json::to_string(asm).ok()?;
        let mut tmp = tempfile::NamedTempFile::new().ok()?;
        use std::io::Write as _;
        tmp.write_all(json.as_bytes()).ok()?;
        tmp.flush().ok()?;
        let out = Command::new("solc")
            .arg("--import-asm-json")
            .arg("--bin")
            .arg(tmp.path())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .skip_while(|l| !l.starts_with("Binary:"))
            .nth(1)
            .map(|l| l.trim().to_string())
    }

    fn assert_roundtrip(path: &str) {
        if !solc_supports_import_asm_json() {
            eprintln!("skipping {path}: solc with --import-asm-json not on PATH");
            return;
        }
        let Some((asm, expected)) = load(path) else {
            eprintln!("skipping {path}: missing legacyAssembly (run forge build with extra_output)");
            return;
        };
        let produced = assemble(&asm).expect("solc --import-asm-json should succeed");
        assert_eq!(
            produced.to_lowercase(),
            expected.to_lowercase(),
            "round-trip bytecode mismatch for {path}",
        );
    }

    #[test]
    fn roundtrip_escrow_erc20_byte_identical() {
        assert_roundtrip(ESCROW_ERC20);
    }

    #[test]
    fn roundtrip_escrow_native_byte_identical() {
        assert_roundtrip(ESCROW_NATIVE);
    }
}
