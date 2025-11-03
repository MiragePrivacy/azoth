//! Module for stripping EVM bytecode to extract the runtime blob and prepare it for
//! obfuscation.

mod parser;

use self::parser::rewrite_init_code;
use crate::{
    detection::{Section, SectionKind},
    result::Error,
};
use revm::primitives::{B256, Bytes};
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
    pub data: Bytes,
}

/// Report detailing the stripping process and enabling reassembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanReport {
    /// Layout of runtime spans with their original offsets and lengths.
    pub runtime_layout: Vec<RuntimeSpan>,
    /// List of removed sections with their original data.
    pub removed: Vec<Removed>,
    /// Optional Keccak-256 hash of the original Swarm data (if Auxdata provides it).
    pub swarm_hash: Option<B256>,
    /// Number of bytes saved by removing non-runtime sections.
    pub bytes_saved: usize,
    /// Length of the cleaned runtime bytecode.
    pub clean_len: usize,
    /// Keccak-256 hash of the cleaned runtime bytecode.
    pub clean_keccak: B256,
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
        swarm_hash: None,
        clean_len: 0,
        clean_keccak: B256::ZERO,
        program_counter_mapping: Vec::new(),
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
                    data: Bytes::from(bytes[s.offset..s.end()].to_vec()),
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
    report.clean_keccak = B256::from_slice(&hash_result);

    tracing::debug!(
        "Stripping complete: {} bytes clean runtime, {} bytes saved",
        report.clean_len,
        report.bytes_saved
    );

    Ok((clean_runtime, report))
}

impl CleanReport {
    /// Updates init code CODECOPY and RETURN parameters to reflect new runtime length and offset.
    ///
    /// After obfuscation modifies the runtime bytecode, the init code's CODECOPY instruction
    /// must be updated to copy the correct number of bytes from the correct offset. The typical
    /// init code pattern is:
    ///
    /// ```text
    /// PUSH1/PUSH2 <destOffset>  (usually 0)
    /// PUSH1/PUSH2 <offset>      (runtime_start) <- UPDATE THIS (new init size)
    /// PUSH1/PUSH2 <size>        (runtime_len) <- UPDATE THIS
    /// CODECOPY
    /// PUSH1/PUSH2 <size>        (runtime_len) <- AND THIS
    /// PUSH1 <destOffset>        (usually 0)
    /// RETURN
    /// ```
    fn update_init_code_size(&mut self, new_runtime_len: usize) -> Result<(), String> {
        // Find Init section in removed
        let init_index = self
            .removed
            .iter()
            .position(|r| matches!(r.kind, SectionKind::Init))
            .ok_or("No Init section found")?;
        let init_bytes = self.removed[init_index].data.clone();

        // Get the runtime offset from runtime_layout
        let new_runtime_offset = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .ok_or("No runtime layout found")?;

        // Determine how much non-runtime data (typically metadata) follows the runtime.
        let metadata_len: usize = self
            .removed
            .iter()
            .filter(|r| matches!(r.kind, SectionKind::Auxdata))
            .map(|r| r.data.len())
            .sum();

        let copy_target_len = new_runtime_len
            .checked_add(metadata_len)
            .ok_or("Overflow calculating runtime + metadata length")?;

        tracing::debug!(
            "Init code size={} bytes, runtime offset={}, runtime len={}, auxdata len={}, CODECOPY target len={}",
            init_bytes.len(),
            new_runtime_offset,
            new_runtime_len,
            metadata_len,
            copy_target_len
        );

        let patched_init =
            rewrite_init_code(init_bytes.as_ref(), new_runtime_offset, copy_target_len)
                .map_err(|e| format!("Failed to rewrite init code: {e}"))?;

        self.removed[init_index].data = Bytes::from(patched_init);

        Ok(())
    }

    /// Reassemble bytecode by placing the clean runtime at original offsets
    /// and filling removed sections with their original data.
    pub fn reassemble(&mut self, clean: &[u8]) -> Vec<u8> {
        // Check if runtime length changed and update init code if needed
        let original_runtime_len = self.clean_len;
        let new_runtime_len = clean.len();

        if new_runtime_len != original_runtime_len {
            tracing::debug!(
                "Runtime length changed from {} to {} bytes, updating init code",
                original_runtime_len,
                new_runtime_len
            );

            if let Err(e) = self.update_init_code_size(new_runtime_len) {
                tracing::error!("Failed to update init code CODECOPY parameters: {}", e);
                tracing::error!("Deployment will be broken - runtime will be truncated!");
            }
        }
        // Check if runtime size changed - if so, use simple sequential assembly
        let runtime_size_changed = clean.len() != original_runtime_len;

        if runtime_size_changed {
            tracing::debug!(
                "Runtime size changed - using sequential reassembly: prefix + runtime + suffix"
            );

            // Get the original runtime start offset to determine prefix/suffix split
            let runtime_start_offset = self
                .runtime_layout
                .iter()
                .map(|span| span.offset)
                .min()
                .unwrap_or(0);

            tracing::debug!(
                "Original runtime started at offset {}, preserving prefix structure",
                runtime_start_offset
            );

            let mut out = Vec::new();

            // Sort removed sections by their original offset
            let mut sorted_removed = self.removed.clone();
            sorted_removed.sort_by_key(|r| r.offset);

            // Add all sections that were BEFORE the runtime (prefix: init + any padding/constructor args)
            for removed in &sorted_removed {
                if removed.offset < runtime_start_offset {
                    out.extend_from_slice(&removed.data);
                    tracing::debug!(
                        "Added pre-runtime {:?} section: {} bytes (original offset: {})",
                        removed.kind,
                        removed.data.len(),
                        removed.offset
                    );
                }
            }

            // Add obfuscated runtime
            out.extend_from_slice(clean);
            tracing::debug!("Added runtime code: {} bytes", clean.len());

            // Add all sections that were AFTER the runtime (suffix: auxdata, etc.)
            for removed in &sorted_removed {
                if removed.offset >= runtime_start_offset {
                    out.extend_from_slice(&removed.data);
                    tracing::debug!(
                        "Added post-runtime {:?} section: {} bytes (original offset: {})",
                        removed.kind,
                        removed.data.len(),
                        removed.offset
                    );
                }
            }

            tracing::debug!("Sequential reassembly complete: {} bytes total", out.len());
            out
        } else {
            // Original logic for unchanged runtime size
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
}

#[cfg(test)]
mod tests {
    use super::strip_bytecode;
    use crate::detection::{Section, SectionKind};
    use crate::result::Error;
    use revm::primitives::B256;
    use sha3::{Digest, Keccak256};

    fn section(kind: SectionKind, offset: usize, len: usize) -> Section {
        Section { kind, offset, len }
    }

    fn contains_push_value(bytes: &[u8], target: usize) -> bool {
        let mut pc = 0;
        while pc < bytes.len() {
            let opcode = bytes[pc];
            pc += 1;

            if (0x60..=0x7f).contains(&opcode) {
                let width = (opcode - 0x60 + 1) as usize;
                if pc + width > bytes.len() {
                    break;
                }

                if width <= std::mem::size_of::<usize>() {
                    let mut value = 0usize;
                    for &byte in &bytes[pc..pc + width] {
                        value = (value << 8) | byte as usize;
                    }
                    if value == target {
                        return true;
                    }
                }

                pc += width;
            }
        }
        false
    }

    //   0x00..0x1a : init (constructor)
    //   0x1a..0x23 : runtime
    //   0x23..end  : auxdata (Solidity CBOR metadata)
    const STORAGE_HEX: &str = include_str!("../../../../tests/bytecode/storage.hex");

    #[test]
    fn returns_error_when_runtime_missing() {
        let bytes = hex::decode(STORAGE_HEX.trim()).unwrap();
        let sections = vec![
            section(SectionKind::Init, 0, 0x1a),
            section(SectionKind::Auxdata, 0x23, bytes.len() - 0x23),
        ];

        let err = strip_bytecode(&bytes, &sections).unwrap_err();
        assert!(matches!(err, Error::NoRuntimeFound));
    }

    #[test]
    fn strips_non_runtime_sections_and_preserves_metadata() {
        let bytes = hex::decode(STORAGE_HEX.trim()).unwrap();
        let sections = vec![
            section(SectionKind::Init, 0, 0x1a),
            section(SectionKind::Runtime, 0x1a, 0x9),
            section(SectionKind::Auxdata, 0x23, bytes.len() - 0x23),
        ];

        let (clean, report) = strip_bytecode(&bytes, &sections).unwrap();

        assert_eq!(clean, bytes[0x1a..0x23].to_vec());
        assert_eq!(report.runtime_layout.len(), 1);
        assert_eq!(report.runtime_layout[0].offset, 0x1a);
        assert_eq!(report.runtime_layout[0].len, 0x9);
        assert_eq!(report.removed.len(), 2);
        assert_eq!(report.removed[0].kind, SectionKind::Init);
        assert_eq!(report.removed[0].offset, 0);
        assert_eq!(report.removed[0].data.as_ref(), &bytes[0..0x1a]);
        assert_eq!(report.removed[1].kind, SectionKind::Auxdata);
        assert_eq!(report.removed[1].offset, 0x23);
        assert_eq!(report.removed[1].data.as_ref(), &bytes[0x23..]);
        assert_eq!(report.bytes_saved, bytes.len() - clean.len());
        assert_eq!(report.clean_len, clean.len());
        let expected_hash: [u8; 32] = Keccak256::digest(&clean).into();
        assert_eq!(report.clean_keccak, B256::from_slice(&expected_hash));
        assert!(report.program_counter_mapping.is_empty());
    }

    #[test]
    fn concatenates_multiple_runtime_spans_in_offset_order() {
        let bytes = hex::decode(STORAGE_HEX.trim()).unwrap();
        let sections = vec![
            section(SectionKind::Runtime, 0x1a, 0x4),
            section(SectionKind::Init, 0, 0x1a),
            section(SectionKind::Runtime, 0x1e, 0x5),
            section(SectionKind::Auxdata, 0x23, bytes.len() - 0x23),
        ];

        let (clean, report) = strip_bytecode(&bytes, &sections).unwrap();

        let mut expected = bytes[0x1a..0x1e].to_vec();
        expected.extend_from_slice(&bytes[0x1e..0x23]);
        assert_eq!(clean, expected);
        assert_eq!(report.runtime_layout.len(), 2);
        assert_eq!(report.runtime_layout[0].offset, 0x1a);
        assert_eq!(report.runtime_layout[0].len, 0x4);
        assert_eq!(report.runtime_layout[1].offset, 0x1e);
        assert_eq!(report.runtime_layout[1].len, 0x5);
    }

    #[test]
    fn reassembles_original_layout_when_runtime_unchanged() {
        let bytes = hex::decode(STORAGE_HEX.trim()).unwrap();
        let sections = vec![
            section(SectionKind::Init, 0, 0x1a),
            section(SectionKind::Runtime, 0x1a, 0x9),
            section(SectionKind::Auxdata, 0x23, bytes.len() - 0x23),
        ];

        let (clean, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let rebuilt = report.reassemble(&clean);

        assert_eq!(rebuilt, bytes);
    }

    #[test]
    fn reassembles_with_changed_runtime_length_sequentially() {
        let bytes = hex::decode(STORAGE_HEX.trim()).unwrap();
        let sections = vec![
            section(SectionKind::Init, 0, 0x1a),
            section(SectionKind::Runtime, 0x1a, 0x9),
            section(SectionKind::Auxdata, 0x23, bytes.len() - 0x23),
        ];

        let (_, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let mut new_runtime = bytes[0x1a..0x23].to_vec();
        // appending two extra bytes
        new_runtime.extend_from_slice(&[0xde, 0xad]);
        let rebuilt = report.reassemble(&new_runtime);

        let runtime_start = 0x1a;
        let mut expected_prefix = Vec::new();
        let mut expected_suffix = Vec::new();

        for removed in &report.removed {
            if removed.offset < runtime_start {
                expected_prefix.extend_from_slice(&removed.data);
            } else {
                expected_suffix.extend_from_slice(&removed.data);
            }
        }

        assert_eq!(
            &rebuilt[..expected_prefix.len()],
            expected_prefix.as_slice()
        );
        assert_eq!(
            &rebuilt[expected_prefix.len()..expected_prefix.len() + new_runtime.len()],
            new_runtime.as_slice()
        );
        assert_eq!(
            &rebuilt[expected_prefix.len() + new_runtime.len()..],
            expected_suffix.as_slice()
        );
        let metadata_len: usize = report
            .removed
            .iter()
            .filter(|r| matches!(r.kind, SectionKind::Auxdata))
            .map(|r| r.data.len())
            .sum();
        let expected_copy_len = new_runtime.len() + metadata_len;
        let init_section = report
            .removed
            .iter()
            .find(|r| r.kind == SectionKind::Init)
            .expect("init section present");

        assert!(
            contains_push_value(&init_section.data, expected_copy_len),
            "init code should push CODECOPY/RETURN length {} but did not",
            expected_copy_len
        );
    }
}
