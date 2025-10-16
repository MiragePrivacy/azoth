//! Module for stripping EVM bytecode to extract the runtime blob and prepare it for
//! obfuscation.

use crate::detection::{Section, SectionKind};
use crate::result::Error;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Represents a runtime section with its original offset and length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeSpan {
    pub offset: usize,
    pub len: usize,
}

/// Represents a removed section with its original data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Removed {
    pub offset: usize,
    pub kind: SectionKind,
    pub data: Vec<u8>,
}

/// Report detailing the stripping process and enabling reassembly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanReport {
    /// Layout of runtime spans with their original offsets and lengths.
    pub runtime_layout: Vec<RuntimeSpan>,
    /// List of removed sections with their original data.
    pub removed: Vec<Removed>,
    /// Optional Keccak-256 hash of the original Swarm data (if Auxdata provides it).
    pub swarm_hash: Option<[u8; 32]>,
    /// Number of bytes saved by removing non-runtime sections.
    pub bytes_saved: usize,
    /// Length of the cleaned runtime bytecode.
    pub clean_len: usize,
    /// Keccak-256 hash of the cleaned runtime bytecode.
    pub clean_keccak: [u8; 32],
    /// Mapping of old PCs to new PCs after stripping.
    pub program_counter_mapping: Vec<(usize, usize)>,
}

/// Strips non-runtime sections from bytecode, returning clean runtime and report.
///
/// This function identifies and removes constructor code, auxdata, padding, and
/// optionally constructor arguments, leaving only the runtime bytecode that gets
/// executed after deployment.
///
/// # Arguments
/// * `bytes` - The complete bytecode including constructor and runtime
/// * `sections` - Detected sections from `detection::locate_sections`
///
/// # Returns
/// A tuple of (clean_runtime_bytes, cleanup_report)
pub fn strip_bytecode(bytes: &[u8], sections: &[Section]) -> Result<(Vec<u8>, CleanReport), Error> {
    let mut clean_runtime = Vec::new();
    let mut report = CleanReport {
        removed: Vec::new(),
        runtime_layout: Vec::new(),
        swarm_hash: None,                    // Will be populated if found
        clean_len: 0,                        // Will be set at the end
        clean_keccak: [0u8; 32],             // Will be calculated at the end
        program_counter_mapping: Vec::new(), // Will be populated if needed
        bytes_saved: 0,
    };

    tracing::debug!("Stripping bytecode with {} sections", sections.len());

    // Process each section and decide whether to strip or keep
    for s in sections {
        tracing::debug!(
            "Processing section: {:?} at offset {} (len: {})",
            s.kind,
            s.offset,
            s.len
        );

        match s.kind {
            SectionKind::Runtime => {
                tracing::debug!("Keeping Runtime section in clean bytecode");
                // Runtime code goes into both the clean bytecode AND layout for reassembly
                report.runtime_layout.push(RuntimeSpan {
                    offset: s.offset,
                    len: s.len,
                });
                clean_runtime.extend_from_slice(&bytes[s.offset..s.end()]);
            }

            // All non-runtime sections get removed and preserved for reassembly
            _ => {
                tracing::debug!("Stripping section: {:?}", s.kind);
                report.removed.push(Removed {
                    kind: s.kind,
                    offset: s.offset,
                    data: bytes[s.offset..s.end()].to_vec(),
                });
                // Count ALL non-runtime bytes as "bytes saved"
                report.bytes_saved += s.len;
            }
        }
    }

    // Validation
    if clean_runtime.is_empty() {
        return Err(Error::NoRuntimeFound);
    }

    // Set final metadata
    report.clean_len = clean_runtime.len();

    // Calculate keccak hash of clean runtime
    let mut hasher = Keccak256::new();
    hasher.update(&clean_runtime);
    let hash_result = hasher.finalize();
    report.clean_keccak.copy_from_slice(&hash_result);

    tracing::debug!(
        "Stripping complete: {} bytes clean runtime, {} bytes saved",
        report.clean_len,
        report.bytes_saved
    );

    Ok((clean_runtime, report))
}

impl CleanReport {
    /// Reassemble bytecode by placing the clean runtime at original offsets
    /// and filling removed sections with their original data.
    pub fn reassemble(&self, clean: &[u8]) -> Vec<u8> {
        // Calculate required buffer size defensively
        let max_runtime_end = self
            .runtime_layout
            .iter()
            .map(|span| span.offset + span.len)
            .max()
            .unwrap_or(0);

        let max_removed_end = self
            .removed
            .iter()
            .map(|r| r.offset + r.data.len())
            .max()
            .unwrap_or(0);

        let required_size = max_runtime_end.max(max_removed_end).max(clean.len());

        tracing::debug!(
            "Reassembling: clean_len={}, bytes_saved={}, required_size={}",
            clean.len(),
            self.bytes_saved,
            required_size
        );

        let mut out = vec![0u8; required_size];

        // Copy clean runtime to original positions
        let mut clean_pos = 0;
        for span in &self.runtime_layout {
            let end_pos = clean_pos + span.len;
            if end_pos <= clean.len() && span.offset + span.len <= out.len() {
                out[span.offset..span.offset + span.len]
                    .copy_from_slice(&clean[clean_pos..end_pos]);
                clean_pos = end_pos;
            } else {
                tracing::error!(
                    "Reassembly bounds error: clean_pos={}, span.offset={}, span.len={}, out.len()={}",
                    clean_pos,
                    span.offset,
                    span.len,
                    out.len()
                );
            }
        }

        // Restore removed sections (constructor, auxdata, etc.)
        for removed in &self.removed {
            if removed.offset + removed.data.len() <= out.len() {
                out[removed.offset..removed.offset + removed.data.len()]
                    .copy_from_slice(&removed.data);
            } else {
                tracing::error!(
                    "Reassembly bounds error: removed.offset={}, removed.data.len()={}, out.len()={}",
                    removed.offset,
                    removed.data.len(),
                    out.len()
                );
            }
        }

        out
    }
}
