pub mod arithmetic_chain;
pub mod cluster_shuffle;
pub mod constructor_args;
pub mod function_dispatcher;
pub mod jump_address_transformer;
pub mod jump_trampoline;
pub mod literal_synthesis;
pub mod metadata;
pub mod obfuscator;
pub mod opaque_predicate;
pub mod push_split;
pub mod shuffle;
pub mod slot_shuffle;
pub mod splice;
pub mod storage_gates;
pub mod string_obfuscate;

use azoth_core::cfg_ir::CfgIrBundle;
use azoth_core::Opcode;
use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use std::collections::HashSet;

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
    /// Whether applying this pass to a runtime containing `GAS` is sound.
    ///
    /// The default is fail-closed. A pass may return true when it is exactly
    /// runtime-gas neutral or when it detects `GAS` and commits no mutation.
    fn supports_gas_observation(&self) -> bool {
        false
    }
    /// Applies the transform to the CFG IR, returning whether changes were made.
    fn apply(&self, ir: &mut CfgIrBundle, rng: &mut StdRng) -> Result<bool>;
}

/// Whether the runtime may observe its physical code layout.
///
/// Azoth does not yet have typed relocation records for embedded runtime data.
/// Layout-changing transforms must therefore fail closed on these opcodes rather
/// than guessing which numeric literals are code/data offsets. External-code
/// introspection is also rejected conservatively: an `EXTCODE*` target may be
/// `ADDRESS`, an alias of the current contract, or otherwise resolve to it through
/// stack computation.
pub fn has_self_code_layout_semantics(ir: &CfgIrBundle) -> bool {
    let bounds = ir.runtime_bounds;
    ir.cfg.node_indices().any(|node| match &ir.cfg[node] {
        azoth_core::cfg_ir::Block::Body(body)
            if bounds.is_none_or(|(start, end)| body.start_pc >= start && body.start_pc < end) =>
        {
            body.instructions.iter().any(|instruction| {
                matches!(
                    instruction.op,
                    Opcode::PC
                        | Opcode::CODESIZE
                        | Opcode::CODECOPY
                        | Opcode::EXTCODESIZE
                        | Opcode::EXTCODECOPY
                        | Opcode::EXTCODEHASH
                )
            })
        }
        _ => false,
    })
}

/// Whether the runtime reads remaining gas.
///
/// Even the compiler-standard `GAS; CALL` sequence is observable: adding a
/// trampoline before it changes the amount forwarded after EIP-150 rounding and
/// can change callee behavior. Passes that add executed instructions must skip
/// such runtimes unless they can prove an exact gas relation.
pub fn has_gas_observation(ir: &CfgIrBundle) -> bool {
    let bounds = ir.runtime_bounds;
    ir.cfg.node_indices().any(|node| match &ir.cfg[node] {
        azoth_core::cfg_ir::Block::Body(body)
            if bounds.is_none_or(|(start, end)| body.start_pc >= start && body.start_pc < end) =>
        {
            body.instructions
                .iter()
                .any(|instruction| matches!(instruction.op, Opcode::GAS))
        }
        _ => false,
    })
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

/// Collect PCs tied to dispatcher/controller metadata that should not be rewritten by
/// transforms that target generic PUSH patterns.
pub fn collect_protected_pcs(ir: &CfgIrBundle) -> HashSet<usize> {
    let mut set = HashSet::new();
    if let Some(patches) = &ir.dispatcher_patches {
        for (_, pc, _, _) in patches {
            set.insert(*pc);
        }
    }
    if let Some(patches) = &ir.stub_patches {
        for (_, pc, _, _) in patches {
            set.insert(*pc);
        }
    }
    if let Some(patches) = &ir.decoy_patches {
        for (_, pc, _, _) in patches {
            set.insert(*pc);
        }
    }
    if let Some(patches) = &ir.controller_patches {
        for (_, pc, _, _) in patches {
            set.insert(*pc);
        }
    }
    set
}

/// Collect nodes associated with dispatcher/controller metadata so transforms can skip
/// whole blocks if desired.
pub fn collect_protected_nodes(ir: &CfgIrBundle) -> HashSet<NodeIndex> {
    let mut nodes = HashSet::new();
    if let Some(patches) = &ir.dispatcher_patches {
        for (node, _, _, _) in patches {
            nodes.insert(*node);
        }
    }
    if let Some(patches) = &ir.stub_patches {
        for (node, _, _, _) in patches {
            nodes.insert(*node);
        }
    }
    if let Some(patches) = &ir.decoy_patches {
        for (node, _, _, _) in patches {
            nodes.insert(*node);
        }
    }
    if let Some(patches) = &ir.controller_patches {
        for (node, _, _, _) in patches {
            nodes.insert(*node);
        }
    }
    if let Some(controller_pcs) = &ir.dispatcher_controller_pcs {
        for pc in controller_pcs.values() {
            if let Some(node) = ir.pc_to_block.get(pc) {
                nodes.insert(*node);
            }
        }
    }
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use azoth_core::cfg_ir::Block;
    use azoth_core::process_bytecode_to_cfg;

    const STORAGE_BYTECODE: &str = include_str!("../../../tests/bytecode/storage.hex");

    #[tokio::test]
    async fn collect_protected_helpers_mark_dispatcher_metadata() {
        // let's build a small CFG and synthesize dispatcher-related metadata.
        let bytecode = STORAGE_BYTECODE.trim();
        let (mut cfg_ir, _, _, _) = process_bytecode_to_cfg(bytecode, false, bytecode, false)
            .await
            .unwrap();

        // two body nodes to tag; fallback to first two bodies.
        let mut bodies: Vec<_> = cfg_ir
            .cfg
            .node_indices()
            .filter(|n| matches!(cfg_ir.cfg[*n], Block::Body(_)))
            .collect();
        assert!(bodies.len() >= 2, "storage fixture should have body blocks");
        bodies.sort_by_key(|n| {
            if let Block::Body(ref b) = cfg_ir.cfg[*n] {
                b.start_pc
            } else {
                0
            }
        });
        let dnode = bodies[0];
        let cnode = bodies[1];

        // fake dispatcher patch and controller patch entries.
        cfg_ir.dispatcher_patches = Some(vec![(dnode, 10, 2, 0xdeadbeef)]);
        cfg_ir.controller_patches = Some(vec![(cnode, 20, 2, 0xcafebabe)]);
        cfg_ir.dispatcher_controller_pcs = Some(vec![(0xdeadbeef, 10)].into_iter().collect());

        let pcs = collect_protected_pcs(&cfg_ir);
        let nodes = collect_protected_nodes(&cfg_ir);

        assert!(pcs.contains(&10), "dispatcher push pc should be protected");
        assert!(pcs.contains(&20), "controller push pc should be protected");
        assert!(
            nodes.contains(&dnode),
            "dispatcher node should be protected"
        );
        assert!(
            nodes.contains(&cnode),
            "controller node should be protected"
        );
    }
}
