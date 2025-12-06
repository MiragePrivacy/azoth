//! Decompile diff computation from bytecode snapshots.

use std::collections::HashMap;

use azoth_analysis::decompile_diff::{compare_sources_structured, decompile, StructuredDiffResult};
use azoth_core::cfg_ir::{CfgIrDiff, OperationKind, TraceEvent};
use revm::primitives::Bytes;

/// Bytecode snapshots extracted from trace events.
#[derive(Debug)]
pub struct BytecodeSnapshots {
    /// Original runtime bytecode (from Build event).
    pub original: Bytes,
    /// Obfuscated runtime bytecode (from Finalize event).
    pub obfuscated: Bytes,
    /// Selector mapping for structured diff (original -> token).
    pub selector_mapping: HashMap<u32, Vec<u8>>,
}

/// Extract bytecode snapshots from trace events for decompile diff.
///
/// Looks for Build (original) and Finalize (obfuscated) events with FullSnapshot diffs.
/// For the original, extracts the runtime portion using runtime_bounds.
/// For the obfuscated, uses the encoded_runtime field which contains the final encoded bytecode.
pub fn extract_bytecode_snapshots(trace: &[TraceEvent]) -> Option<BytecodeSnapshots> {
    let mut original: Option<Bytes> = None;
    let mut obfuscated: Option<Bytes> = None;
    let mut selector_mapping: HashMap<u32, Vec<u8>> = HashMap::new();

    for event in trace {
        match (&event.kind, &event.diff) {
            (OperationKind::Build { .. }, CfgIrDiff::FullSnapshot(snapshot)) => {
                // Extract just the runtime portion using runtime_bounds
                original = extract_runtime_bytecode(snapshot);
                if let Some(ref mapping) = snapshot.selector_mapping {
                    selector_mapping = mapping.clone();
                }
            }
            (OperationKind::Finalize, CfgIrDiff::FullSnapshot(snapshot)) => {
                // Use the encoded_runtime which is the actual obfuscated bytecode
                obfuscated = snapshot.encoded_runtime.clone();
                // Prefer selector mapping from Finalize if available
                if let Some(ref mapping) = snapshot.selector_mapping {
                    selector_mapping = mapping.clone();
                }
            }
            _ => {}
        }
    }

    match (original, obfuscated) {
        (Some(orig), Some(obf)) => Some(BytecodeSnapshots {
            original: orig,
            obfuscated: obf,
            selector_mapping,
        }),
        _ => None,
    }
}

/// Extract just the runtime portion of bytecode from a snapshot.
fn extract_runtime_bytecode(snapshot: &azoth_core::cfg_ir::CfgIrSnapshot) -> Option<Bytes> {
    let full_bytecode = &snapshot.original_bytecode;

    if let Some((start, end)) = snapshot.runtime_bounds {
        // Extract only runtime portion
        if end <= full_bytecode.len() {
            Some(Bytes::from(full_bytecode[start..end].to_vec()))
        } else {
            // Bounds exceed bytecode length, use full bytecode
            Some(full_bytecode.clone())
        }
    } else {
        // No runtime bounds, use full bytecode (might be pure runtime already)
        Some(full_bytecode.clone())
    }
}

/// Compute decompile diff from bytecode snapshots.
///
/// This function decompiles both bytecodes and computes a structured diff.
/// Returns None if decompilation fails.
#[allow(unreachable_pub)]
pub async fn compute_decompile_diff(
    snapshots: BytecodeSnapshots,
) -> Option<StructuredDiffResult> {
    // Suppress Heimdall's logging during decompilation (it outputs warnings to stderr)
    let original_source = decompile_quiet(snapshots.original).await.ok()?;
    let obfuscated_source = decompile_quiet(snapshots.obfuscated).await.ok()?;
    Some(compare_sources_structured(
        &original_source,
        &obfuscated_source,
        snapshots.selector_mapping,
    ))
}

/// Decompile bytecode with Heimdall logging suppressed.
async fn decompile_quiet(
    bytecode: Bytes,
) -> Result<String, azoth_analysis::decompile_diff::DecompileDiffError> {
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;

    // Create a no-op subscriber to suppress all logs
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(LevelFilter::OFF));

    decompile(bytecode).await
}
