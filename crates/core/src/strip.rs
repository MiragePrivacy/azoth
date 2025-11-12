//! Module for stripping EVM bytecode to extract the runtime blob and prepare it for
//! obfuscation.

use crate::{
    detection::{Section, SectionKind},
    result::Error,
};
use hex::encode;
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

#[derive(Clone, Debug)]
struct PushInfo {
    pos: usize,
    width: usize,
    value: usize,
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
        tracing::debug!(
            "update_init_code_size called: new_runtime_len={}, clean_len={}",
            new_runtime_len,
            self.clean_len
        );

        // Find Init section in removed
        let new_runtime_offset = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .ok_or("No runtime layout found")?;

        let runtime_offset = new_runtime_offset;
        let post_runtime_len: usize = self
            .removed
            .iter()
            .filter(|removed| removed.offset >= runtime_offset)
            .map(|removed| removed.data.len())
            .sum();
        let runtime_tail_len = new_runtime_len + post_runtime_len;
        let original_runtime_tail_len = self.clean_len + post_runtime_len;

        tracing::debug!(
            "Calculated values: runtime_offset={}, post_runtime_len={}, runtime_tail_len={}, original_runtime_tail_len={}",
            runtime_offset,
            post_runtime_len,
            runtime_tail_len,
            original_runtime_tail_len
        );

        let init_section = self
            .removed
            .iter_mut()
            .find(|r| matches!(r.kind, SectionKind::Init))
            .ok_or("No Init section found")?;

        let mut init_bytes = init_section.data.clone().to_vec();

        tracing::debug!(
            "Init code size: {} bytes, runtime offset: {}",
            init_bytes.len(),
            new_runtime_offset
        );

        tracing::debug!("Full init code (hex): {}", encode(&init_bytes));
        if init_bytes.len() > 24 {
            tracing::debug!(
                "Init code structure: offsets 16-24: {:02x?}",
                &init_bytes[16..=24]
            );
        }

        fn collect_previous_pushes(bytes: &[u8], start: usize, max: usize) -> Vec<PushInfo> {
            let mut pushes = Vec::new();
            let mut idx = start;
            while idx > 0 && pushes.len() < max {
                idx -= 1;
                let opcode = bytes[idx];
                if !(0x60..=0x7f).contains(&opcode) {
                    continue;
                }
                let width = (opcode - 0x60 + 1) as usize;
                if idx + 1 + width > bytes.len() || idx + 1 + width > start {
                    continue;
                }
                let mut value = 0usize;
                for &byte in &bytes[idx + 1..idx + 1 + width] {
                    value = (value << 8) | byte as usize;
                }
                pushes.push(PushInfo {
                    pos: idx,
                    width,
                    value,
                });
                if idx < width + 1 {
                    break;
                }
                idx = idx.saturating_sub(width);
            }
            pushes
        }

        fn write_push_value(
            bytes: &mut [u8],
            info: &PushInfo,
            new_value: usize,
        ) -> Result<(), String> {
            if info.pos + 1 + info.width > bytes.len() {
                return Err("push immediate out of bounds".into());
            }
            if info.width < std::mem::size_of::<usize>() {
                let max = (1usize << (info.width * 8)) - 1;
                if new_value > max {
                    return Err(format!(
                        "value 0x{:x} does not fit in PUSH{}",
                        new_value, info.width
                    ));
                }
            }
            let bit_width = usize::BITS as usize;
            for idx in 0..info.width {
                let shift = idx * 8;
                let byte = if shift >= bit_width {
                    0
                } else {
                    ((new_value >> shift) & 0xff) as u8
                };
                bytes[info.pos + 1 + info.width - 1 - idx] = byte;
            }
            Ok(())
        }

        let codecopy_positions: Vec<_> = init_bytes
            .iter()
            .enumerate()
            .filter_map(|(idx, &b)| (b == 0x39).then_some(idx))
            .collect();

        let mut codecopy_patched = false;
        for pos in codecopy_positions {
            let pushes = collect_previous_pushes(&init_bytes, pos, 6);
            let has_len = pushes
                .iter()
                .any(|info| info.value == original_runtime_tail_len);
            let has_offset = pushes.iter().any(|info| info.value == runtime_offset);
            if !(has_len && has_offset) {
                continue;
            }

            for info in &pushes {
                if info.value == original_runtime_tail_len {
                    write_push_value(&mut init_bytes, info, runtime_tail_len)?;
                    codecopy_patched = true;
                    tracing::debug!(
                        "Updated CODECOPY length PUSH at 0x{:x} to 0x{:x}",
                        info.pos,
                        runtime_tail_len
                    );
                    break;
                }
            }

            for info in &pushes {
                if info.value == runtime_offset && new_runtime_offset != runtime_offset {
                    write_push_value(&mut init_bytes, info, new_runtime_offset)?;
                    tracing::debug!(
                        "Updated CODECOPY offset PUSH at 0x{:x} to 0x{:x}",
                        info.pos,
                        new_runtime_offset
                    );
                }
            }

            break;
        }

        if !codecopy_patched {
            return Err(
                "Could not locate CODECOPY arguments matching runtime offset and length".into(),
            );
        }

        let original_total_len = runtime_offset + original_runtime_tail_len;
        let new_total_len = new_runtime_offset + runtime_tail_len;
        if original_total_len != new_total_len {
            let mut idx = 0usize;
            let mut total_patched = false;
            while idx < init_bytes.len() {
                let opcode = init_bytes[idx];
                if (0x60..=0x7f).contains(&opcode) {
                    let width = (opcode - 0x60 + 1) as usize;
                    if idx + 1 + width <= init_bytes.len() {
                        let mut value = 0usize;
                        for &byte in &init_bytes[idx + 1..idx + 1 + width] {
                            value = (value << 8) | byte as usize;
                        }
                        if value == original_total_len {
                            let info = PushInfo {
                                pos: idx,
                                width,
                                value,
                            };
                            write_push_value(&mut init_bytes, &info, new_total_len)?;
                            total_patched = true;
                            tracing::debug!(
                                "Updated total bytecode size PUSH at 0x{:x} to 0x{:x}",
                                idx,
                                new_total_len
                            );
                            break;
                        }
                    }
                    idx += width + 1;
                } else {
                    idx += 1;
                }
            }

            if !total_patched {
                tracing::warn!(
                    "Expected to update init metadata length (0x{:x}) but no PUSH matched",
                    original_total_len
                );
            }
        }

        let return_positions: Vec<_> = init_bytes
            .iter()
            .enumerate()
            .filter_map(|(idx, &b)| (b == 0xf3).then_some(idx))
            .collect();

        let mut return_patched = false;
        for pos in return_positions {
            let pushes = collect_previous_pushes(&init_bytes, pos, 4);
            if let Some(info) = pushes
                .iter()
                .find(|info| info.value == original_runtime_tail_len)
            {
                write_push_value(&mut init_bytes, info, runtime_tail_len)?;
                return_patched = true;
                tracing::debug!(
                    "Updated RETURN length PUSH at 0x{:x} to 0x{:x}",
                    info.pos,
                    runtime_tail_len
                );
                break;
            }
        }

        if !return_patched {
            return Err("Could not find RETURN length PUSH to update".into());
        }

        tracing::debug!(
            "Updated init code CODECOPY/RETURN for runtime offset=0x{:x}, len=0x{:x}",
            new_runtime_offset,
            new_runtime_len
        );

        init_section.data = Bytes::from(init_bytes);

        Ok(())
    }

    /// Reassemble bytecode by placing the clean runtime at original offsets
    /// and filling removed sections with their original data.
    pub fn reassemble(&mut self, clean: &[u8]) -> Vec<u8> {
        // Check if runtime length changed and update init code if needed
        let original_runtime_len = self.clean_len;
        let new_runtime_len = clean.len();

        tracing::debug!(
            "reassemble: original_runtime_len={}, new_runtime_len={}",
            original_runtime_len,
            new_runtime_len
        );

        if new_runtime_len != original_runtime_len {
            tracing::debug!(
                "Runtime length changed from {} to {} bytes, updating init code",
                original_runtime_len,
                new_runtime_len
            );

            if let Err(e) = self.update_init_code_size(new_runtime_len) {
                tracing::warn!("Targeted init code patching failed: {}", e);
                tracing::warn!("Will attempt fallback patching during reassembly");
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

            // Compute suffix size to keep track of metadata lengths
            let post_runtime_len: usize = sorted_removed
                .iter()
                .filter(|removed| removed.offset >= runtime_start_offset)
                .map(|removed| removed.data.len())
                .sum();

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

            // here, we take the final constructor prefix (prefix), looks for any PUSH immediates still holding
            // the old runtime length or the old total bytecode length, and rewrites them to the new valuesright
            // before the output is returned
            let prefix_end = runtime_start_offset.min(out.len());
            let (prefix, _) = out.split_at_mut(prefix_end);
            let original_tail_len = self.clean_len + post_runtime_len;
            let new_tail_len = clean.len() + post_runtime_len;
            let original_total_len = runtime_start_offset + original_tail_len;
            let new_total_len = runtime_start_offset + new_tail_len;

            if original_tail_len != new_tail_len {
                let replaced = patch_push_value(prefix, original_tail_len, new_tail_len, Some(1));
                if replaced == 0 {
                    tracing::warn!(
                        "Failed to update CODECOPY length from 0x{:x} to 0x{:x} in final bytecode",
                        original_tail_len,
                        new_tail_len
                    );
                }
            }

            if original_total_len != new_total_len {
                let replaced = patch_push_value(prefix, original_total_len, new_total_len, Some(1));
                if replaced == 0 {
                    tracing::warn!(
                        "Failed to update total bytecode size from 0x{:x} to 0x{:x} in final bytecode",
                        original_total_len,
                        new_total_len
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

fn patch_push_value(
    bytes: &mut [u8],
    old_value: usize,
    new_value: usize,
    max_replacements: Option<usize>,
) -> usize {
    if old_value == new_value {
        return 0;
    }

    let mut replaced = 0usize;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let opcode = bytes[idx];
        if (0x60..=0x7f).contains(&opcode) {
            let width = (opcode - 0x60 + 1) as usize;
            if idx + 1 + width <= bytes.len() {
                let mut value = 0usize;
                for &byte in &bytes[idx + 1..idx + 1 + width] {
                    value = (value << 8) | byte as usize;
                }
                if value == old_value {
                    if width < std::mem::size_of::<usize>() {
                        let max = (1usize << (width * 8)) - 1;
                        if new_value > max {
                            tracing::warn!(
                                "New value 0x{:x} does not fit in PUSH{} at 0x{:x}",
                                new_value,
                                width,
                                idx
                            );
                            idx += width + 1;
                            continue;
                        }
                    }
                    let bit_width = usize::BITS as usize;
                    for j in 0..width {
                        let shift = j * 8;
                        let byte = if shift >= bit_width {
                            0
                        } else {
                            ((new_value >> shift) & 0xff) as u8
                        };
                        bytes[idx + 1 + width - 1 - j] = byte;
                    }
                    replaced += 1;
                    if let Some(limit) = max_replacements {
                        if replaced >= limit {
                            break;
                        }
                    }
                }
            }
            idx += width + 1;
        } else {
            idx += 1;
        }
    }

    replaced
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

    //   0x00..0x1a : init (constructor)
    //   0x1a..0x23 : runtime
    //   0x23..end  : auxdata (Solidity CBOR metadata)
    const STORAGE_HEX: &str = include_str!("../../../tests/bytecode/storage.hex");

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

        let original_tail_len = report.clean_len + expected_suffix.len();
        let new_tail_len = new_runtime.len() + expected_suffix.len();
        let mut patched_prefix = expected_prefix.clone();
        if let Some(idx) = patched_prefix
            .windows(2)
            .position(|window| window == [0x60, original_tail_len as u8])
        {
            patched_prefix[idx + 1] = new_tail_len as u8;
        }
        assert_eq!(&rebuilt[..patched_prefix.len()], patched_prefix.as_slice());
        assert_eq!(
            &rebuilt[expected_prefix.len()..expected_prefix.len() + new_runtime.len()],
            new_runtime.as_slice()
        );
        assert_eq!(
            &rebuilt[expected_prefix.len() + new_runtime.len()..],
            expected_suffix.as_slice()
        );
        // The init code should have PUSH1 0x40 (64 bytes = new runtime 11 + auxdata 53)
        // Original was PUSH1 0x3e (62 bytes = old runtime 9 + auxdata 53)
        assert!(
            rebuilt[..patched_prefix.len()]
                .windows(2)
                .any(|window| window == [0x60, new_tail_len as u8]),
            "init code should be updated to push new runtime tail length (runtime + auxdata)"
        );
    }
}
