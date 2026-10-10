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
use std::collections::HashSet;

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

fn collect_previous_pushes(bytes: &[u8], start: usize, max: usize) -> Vec<PushInfo> {
    let mut pushes = Vec::new();
    let mut pc = 0usize;
    while pc < start && pc < bytes.len() {
        let opcode = bytes[pc];
        if (0x60..=0x7f).contains(&opcode) {
            let width = (opcode - 0x5f) as usize;
            let end = pc + 1 + width;
            if end > start || end > bytes.len() {
                break;
            }
            let value = bytes[pc + 1..end]
                .iter()
                .fold(0usize, |acc, &byte| (acc << 8) | byte as usize);
            pushes.push(PushInfo {
                pos: pc,
                width,
                value,
            });
            pc = end;
        } else {
            pc += 1;
        }
    }
    pushes.into_iter().rev().take(max).collect()
}

fn immutable_placeholder_offsets(runtime: &[u8]) -> HashSet<usize> {
    let mut offsets = HashSet::new();
    let mut pc = 0usize;
    while pc < runtime.len() {
        let opcode = runtime[pc];
        if (0x60..=0x7f).contains(&opcode) {
            let width = (opcode - 0x5f) as usize;
            let end = pc + 1 + width;
            if end > runtime.len() {
                break;
            }
            if width == 32 && runtime[pc + 1..end].iter().all(|byte| *byte == 0) {
                offsets.insert(pc + 1);
            }
            pc = end;
        } else {
            pc += 1;
        }
    }
    offsets
}

fn opcode_positions(bytes: &[u8], target: u8) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut pc = 0usize;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        if opcode == target {
            positions.push(pc);
        }
        pc += if (0x60..=0x7f).contains(&opcode) {
            1 + (opcode - 0x5f) as usize
        } else {
            1
        };
    }
    positions
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InitSymbol {
    Unknown(usize),
    Constant {
        value: usize,
        origin: usize,
    },
    RuntimeBase,
    RuntimeAddress {
        offset: usize,
        push_pos: usize,
        width: usize,
        add_pos: usize,
    },
}

#[derive(Clone, Debug)]
struct ProvenImmutableWrite {
    push_pos: usize,
    width: usize,
    offset: usize,
}

#[derive(Clone, Debug)]
struct ImmutablePatchRegion {
    codecopy: usize,
    return_position: usize,
    writes: Vec<ProvenImmutableWrite>,
}

fn pop_init_symbol(stack: &mut Vec<InitSymbol>, pc: usize) -> Result<InitSymbol, String> {
    stack
        .pop()
        .ok_or_else(|| format!("init stack underflow at 0x{pc:x} during immutable proof"))
}

fn init_constant(value: &InitSymbol) -> Option<usize> {
    match value {
        InitSymbol::Constant { value, .. } => Some(*value),
        _ => None,
    }
}

/// Symbolically proves the straight-line solc 0.8.30 runtime-copy/immutable-write region.
///
/// The proof is deliberately provenance-sensitive. Equal numeric constants are not aliases:
/// only the exact value copied (via DUP/SWAP) into CODECOPY's destination becomes
/// `RuntimeBase`. This prevents unrelated `PUSH base; PUSH offset; ADD; MSTORE` arithmetic from
/// being mistaken for a runtime-placeholder write.
fn prove_immutable_patch_region(
    init: &[u8],
    target_codecopy: usize,
    runtime_start: usize,
    runtime_len: usize,
) -> Result<Option<ImmutablePatchRegion>, String> {
    let block_start = opcode_positions(init, 0x5b)
        .into_iter()
        .filter(|position| *position < target_codecopy)
        .max()
        .map_or(0, |position| position + 1);
    let mut stack = Vec::<InitSymbol>::new();
    let mut writes = Vec::new();
    let mut matched_copy = false;
    let mut pc = block_start;

    while pc < init.len() {
        let opcode = init[pc];
        match opcode {
            0x5f => {
                stack.push(InitSymbol::Constant {
                    value: 0,
                    origin: pc,
                });
                pc += 1;
            }
            0x60..=0x7f => {
                let width = (opcode - 0x5f) as usize;
                let end = pc + 1 + width;
                let Some(immediate) = init.get(pc + 1..end) else {
                    return Ok(None);
                };
                let value = immediate.iter().try_fold(0usize, |value, byte| {
                    value.checked_mul(256)?.checked_add(*byte as usize)
                });
                let Some(value) = value else {
                    // A value wider than usize cannot be a runtime offset or length.
                    stack.push(InitSymbol::Unknown(pc));
                    pc = end;
                    continue;
                };
                stack.push(InitSymbol::Constant { value, origin: pc });
                pc = end;
            }
            0x80..=0x8f => {
                let depth = (opcode - 0x7f) as usize;
                if depth > stack.len() {
                    return Ok(None);
                }
                stack.push(stack[stack.len() - depth].clone());
                pc += 1;
            }
            0x90..=0x9f => {
                let depth = (opcode - 0x8f) as usize;
                if depth >= stack.len() {
                    return Ok(None);
                }
                let top = stack.len() - 1;
                stack.swap(top, top - depth);
                pc += 1;
            }
            0x50 => {
                pop_init_symbol(&mut stack, pc)?;
                pc += 1;
            }
            0x51 => {
                pop_init_symbol(&mut stack, pc)?;
                stack.push(InitSymbol::Unknown(pc));
                pc += 1;
            }
            0x01 => {
                let first = pop_init_symbol(&mut stack, pc)?;
                let second = pop_init_symbol(&mut stack, pc)?;
                let address = match (&first, &second) {
                    (
                        InitSymbol::RuntimeBase,
                        InitSymbol::Constant {
                            value,
                            origin: push_pos,
                        },
                    )
                    | (
                        InitSymbol::Constant {
                            value,
                            origin: push_pos,
                        },
                        InitSymbol::RuntimeBase,
                    ) => {
                        let width = (init[*push_pos] - 0x5f) as usize;
                        InitSymbol::RuntimeAddress {
                            offset: *value,
                            push_pos: *push_pos,
                            width,
                            add_pos: pc,
                        }
                    }
                    _ => InitSymbol::Unknown(pc),
                };
                stack.push(address);
                pc += 1;
            }
            0x52 => {
                let address = pop_init_symbol(&mut stack, pc)?;
                pop_init_symbol(&mut stack, pc)?;
                if let InitSymbol::RuntimeAddress {
                    offset,
                    push_pos,
                    width,
                    add_pos,
                } = address
                {
                    if add_pos + 1 != pc {
                        return Err(format!(
                            "runtime-relative immutable address at 0x{add_pos:x} is not consumed by the immediately following MSTORE"
                        ));
                    }
                    writes.push(ProvenImmutableWrite {
                        push_pos,
                        width,
                        offset,
                    });
                }
                pc += 1;
            }
            0x39 => {
                let destination = pop_init_symbol(&mut stack, pc)?;
                let source = pop_init_symbol(&mut stack, pc)?;
                let size = pop_init_symbol(&mut stack, pc)?;
                if pc == target_codecopy {
                    if init_constant(&source) != Some(runtime_start)
                        || init_constant(&size) != Some(runtime_len)
                    {
                        return Ok(None);
                    }
                    matched_copy = true;
                    for value in &mut stack {
                        if *value == destination {
                            *value = InitSymbol::RuntimeBase;
                        }
                    }
                }
                pc += 1;
            }
            0xf3 => {
                if !matched_copy {
                    return Ok(None);
                }
                let offset = pop_init_symbol(&mut stack, pc)?;
                let size = pop_init_symbol(&mut stack, pc)?;
                if !matches!(offset, InitSymbol::RuntimeBase)
                    || init_constant(&size) != Some(runtime_len)
                {
                    return Err(format!(
                        "runtime RETURN at 0x{pc:x} does not reuse the proven CODECOPY base and length"
                    ));
                }
                return Ok(Some(ImmutablePatchRegion {
                    codecopy: target_codecopy,
                    return_position: pc,
                    writes,
                }));
            }
            0x5b => pc += 1,
            _ => {
                if matched_copy {
                    return Err(format!(
                        "unsupported opcode 0x{opcode:02x} at 0x{pc:x} in Solidity immutable patch region"
                    ));
                }
                return Ok(None);
            }
        }
    }

    if matched_copy {
        Err("proven runtime CODECOPY has no following RETURN".to_string())
    } else {
        Ok(None)
    }
}

fn patch_constructor_arg_base(
    bytes: &mut [u8],
    old_value: usize,
    new_value: usize,
) -> Result<usize, String> {
    let mut patched = 0usize;
    let mut pc = 0usize;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        if !(0x60..=0x7f).contains(&opcode) {
            pc += 1;
            continue;
        }

        let width = (opcode - 0x5f) as usize;
        let end = pc + 1 + width;
        if end > bytes.len() {
            break;
        }
        let value = bytes[pc + 1..end]
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | byte as usize);
        let is_constructor_length = bytes.get(end..end + 3) == Some(&[0x80, 0x38, 0x03]);
        if value == old_value && is_constructor_length {
            if width < std::mem::size_of::<usize>() && new_value >= (1usize << (width * 8)) {
                return Err(format!(
                    "constructor argument base 0x{new_value:x} does not fit in PUSH{width}"
                ));
            }
            for index in 0..width {
                let shift = (width - 1 - index) * 8;
                bytes[pc + 1 + index] = ((new_value >> shift) & 0xff) as u8;
            }
            patched += 1;
        }
        pc = end;
    }
    Ok(patched)
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

        let original_runtime_offset = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .ok_or("No runtime layout found")?;
        let new_runtime_offset: usize = self
            .removed
            .iter()
            .filter(|removed| removed.offset < original_runtime_offset)
            .map(|removed| removed.data.len())
            .sum();
        let deployed_suffix_len: usize = self
            .removed
            .iter()
            .filter(|removed| {
                removed.offset >= original_runtime_offset
                    && !matches!(removed.kind, SectionKind::ConstructorArgs)
            })
            .map(|removed| removed.data.len())
            .sum();
        let new_deployed_runtime_len = new_runtime_len + deployed_suffix_len;
        let original_deployed_runtime_len = self.clean_len + deployed_suffix_len;
        let original_creation_len = original_runtime_offset + original_deployed_runtime_len;
        let new_creation_len = new_runtime_offset + new_deployed_runtime_len;
        let has_constructor_args = self
            .removed
            .iter()
            .any(|removed| matches!(removed.kind, SectionKind::ConstructorArgs));

        tracing::debug!(
            "Calculated values: runtime_offset={} -> {}, deployed_runtime_len={} -> {}, creation_len={} -> {}",
            original_runtime_offset,
            new_runtime_offset,
            original_deployed_runtime_len,
            new_deployed_runtime_len,
            original_creation_len,
            new_creation_len
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

        let codecopy_positions = opcode_positions(&init_bytes, 0x39);

        let mut codecopy_patched = original_runtime_offset == new_runtime_offset
            && original_deployed_runtime_len == new_deployed_runtime_len;
        for pos in codecopy_positions {
            let pushes = collect_previous_pushes(&init_bytes, pos, 6);
            let has_len = pushes
                .iter()
                .any(|info| info.value == original_deployed_runtime_len);
            let has_offset = pushes
                .iter()
                .any(|info| info.value == original_runtime_offset);
            if !(has_len && has_offset) {
                continue;
            }

            for info in &pushes {
                if info.value == original_deployed_runtime_len {
                    write_push_value(&mut init_bytes, info, new_deployed_runtime_len)?;
                    codecopy_patched = true;
                    tracing::debug!(
                        "Updated CODECOPY length PUSH at 0x{:x} to 0x{:x}",
                        info.pos,
                        new_deployed_runtime_len
                    );
                    break;
                }
            }

            for info in &pushes {
                if info.value == original_runtime_offset
                    && new_runtime_offset != original_runtime_offset
                {
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

        if original_creation_len != new_creation_len {
            let patched = patch_constructor_arg_base(
                &mut init_bytes,
                original_creation_len,
                new_creation_len,
            )?;
            // A caller may obfuscate bare creation bytecode and append its constructor
            // arguments afterwards. Patch a supported constructor-copy base whenever it is
            // present, but only require it when this payload already contains arguments.
            if patched == 0 && has_constructor_args {
                return Err(format!(
                    "Could not locate constructor argument base 0x{:x} before CODESIZE/SUB",
                    original_creation_len
                ));
            }
        }

        let return_positions = opcode_positions(&init_bytes, 0xf3);

        let mut return_patched = original_deployed_runtime_len == new_deployed_runtime_len;
        for pos in return_positions {
            let pushes = collect_previous_pushes(&init_bytes, pos, 4);
            if let Some(info) = pushes.iter().find(|info| {
                info.value == original_deployed_runtime_len
                    || info.value == new_deployed_runtime_len
            }) {
                if info.value == original_deployed_runtime_len {
                    write_push_value(&mut init_bytes, info, new_deployed_runtime_len)?;
                }
                return_patched = true;
                tracing::debug!(
                    "Updated RETURN length PUSH at 0x{:x} to 0x{:x}",
                    info.pos,
                    new_deployed_runtime_len
                );
                break;
            }
        }

        if !return_patched {
            tracing::debug!(
                "RETURN reuses the CODECOPY length already patched on the constructor stack"
            );
        }

        tracing::debug!(
            "Updated init code CODECOPY/RETURN for runtime offset=0x{:x}, len=0x{:x}",
            new_runtime_offset,
            new_deployed_runtime_len
        );

        init_section.data = Bytes::from(init_bytes);

        Ok(())
    }

    /// Patch proven Solidity immutable-reference offsets in init code.
    ///
    /// Solidity 0.8.30 copies the runtime into memory, then writes constructor
    /// values into zero-filled `PUSH32` immediate placeholders with the exact
    /// sequence `PUSH <runtime offset>; ADD; MSTORE`. Numeric equality with a
    /// relocated runtime PC is not evidence: constructor arithmetic can contain
    /// the same literal. We therefore require all of the compiler-shaped evidence:
    /// a zero `PUSH32` placeholder, an exact ADD/MSTORE address sequence, and a
    /// site between the matching runtime CODECOPY and its RETURN. Anything that
    /// looks like an immutable write but cannot be relocated exactly fails closed.
    pub fn patch_init_immutable_refs(
        &mut self,
        remap: &dyn Fn(usize) -> Option<usize>,
        original_runtime: &[u8],
    ) -> Result<(), String> {
        let runtime_start = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .ok_or("No runtime layout found")?;
        let deployed_suffix_len: usize = self
            .removed
            .iter()
            .filter(|removed| {
                removed.offset >= runtime_start
                    && !matches!(removed.kind, SectionKind::ConstructorArgs)
            })
            .map(|removed| removed.data.len())
            .sum();
        let original_deployed_runtime_len = self.clean_len + deployed_suffix_len;
        let allowed_offsets = immutable_placeholder_offsets(original_runtime);
        if allowed_offsets.is_empty() {
            return Ok(());
        }
        let mut required_offsets = HashSet::new();
        for offset in &allowed_offsets {
            let relocated = remap(*offset).ok_or_else(|| {
                format!(
                    "zero PUSH32 placeholder at runtime offset 0x{offset:x} has no proven relocation"
                )
            })?;
            if relocated != *offset {
                required_offsets.insert(*offset);
            }
        }
        if required_offsets.is_empty() {
            return Ok(());
        }

        let init_section = self
            .removed
            .iter_mut()
            .find(|r| matches!(r.kind, SectionKind::Init))
            .ok_or("No Init section found")?;

        let mut init_bytes = init_section.data.to_vec();
        let mut regions = Vec::new();
        for codecopy in opcode_positions(&init_bytes, 0x39) {
            if let Some(region) = prove_immutable_patch_region(
                &init_bytes,
                codecopy,
                runtime_start,
                original_deployed_runtime_len,
            )? {
                regions.push(region);
            }
        }
        if regions.len() != 1 {
            return Err(format!(
                "immutable references require exactly one proven Solidity runtime CODECOPY/RETURN region; found {}",
                regions.len()
            ));
        }
        let region = regions.pop().expect("region count checked");

        // A base-relative constructor write to any other moved runtime byte is
        // another relocation obligation that this compiler-specific lowering
        // does not understand. Reject it instead of silently moving only the
        // zero-PUSH32 subset.
        for write in &region.writes {
            if !allowed_offsets.contains(&write.offset)
                && remap(write.offset).is_some_and(|new| new != write.offset)
            {
                return Err(format!(
                    "unrecognized runtime-relative constructor write at offset 0x{:x}",
                    write.offset
                ));
            }
        }

        let mut candidates = Vec::<(usize, usize, usize)>::new();
        for offset in &required_offsets {
            let matching: Vec<_> = region
                .writes
                .iter()
                .filter(|write| write.offset == *offset)
                .collect();
            if matching.len() != 1 {
                return Err(format!(
                    "relocated zero PUSH32 placeholder 0x{offset:x} requires exactly one proven Solidity immutable write; found {}",
                    matching.len()
                ));
            }
            let write = matching[0];
            candidates.push((write.push_pos, write.width, write.offset));
        }

        let mut patched = 0usize;
        for (position, width, value) in candidates {
            if position <= region.codecopy || position >= region.return_position {
                return Err(format!(
                    "immutable-like reference at init offset 0x{position:x} is outside the proven runtime patch region"
                ));
            }
            let new_value = remap(value).ok_or_else(|| {
                format!(
                    "immutable reference at init offset 0x{position:x} has no proven relocation for runtime offset 0x{value:x}"
                )
            })?;
            let max = if width >= std::mem::size_of::<usize>() {
                usize::MAX
            } else {
                (1usize << (width * 8)) - 1
            };
            if new_value > max {
                return Err(format!(
                    "immutable reference at init offset 0x{position:x}: relocated value 0x{new_value:x} exceeds PUSH{width} capacity"
                ));
            }
            if new_value == value {
                continue;
            }
            for byte_index in 0..width {
                let shift = (width - 1 - byte_index) * 8;
                init_bytes[position + 1 + byte_index] = ((new_value >> shift) & 0xff) as u8;
            }
            tracing::debug!(
                "Patched proven immutable ref at init offset 0x{:x}: 0x{:x} -> 0x{:x}",
                position,
                value,
                new_value
            );
            patched += 1;
        }

        if patched > 0 {
            tracing::debug!(
                "Patched {} immutable reference offsets in init code",
                patched
            );
            init_section.data = Bytes::from(init_bytes);
        }

        Ok(())
    }

    /// Reassemble bytecode and return an error if changed init-code constants cannot be patched.
    ///
    /// Obfuscation pipelines should use this checked form so a layout Azoth cannot safely lower
    /// is rejected instead of producing deployment bytecode with stale offsets.
    pub fn reassemble_checked(&mut self, clean: &[u8]) -> Result<Vec<u8>, String> {
        let original_runtime_len = self.clean_len;
        let new_runtime_len = clean.len();
        tracing::debug!(
            "reassemble: original_runtime_len={}, new_runtime_len={}",
            original_runtime_len,
            new_runtime_len
        );

        let runtime_start_offset = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .unwrap_or(0);
        let actual_runtime_start_offset: usize = self
            .removed
            .iter()
            .filter(|removed| removed.offset < runtime_start_offset)
            .map(|removed| removed.data.len())
            .sum();
        let layout_changed = new_runtime_len != original_runtime_len
            || actual_runtime_start_offset != runtime_start_offset;

        if layout_changed
            && self
                .removed
                .iter()
                .any(|removed| matches!(removed.kind, SectionKind::Init))
        {
            self.update_init_code_size(new_runtime_len)?;
        }

        Ok(self.assemble_sequential(clean, runtime_start_offset))
    }

    /// Reassemble bytecode, retaining the historical best-effort behavior for library callers.
    /// Prefer [`Self::reassemble_checked`] when returning malformed deployment code is unsafe.
    pub fn reassemble(&mut self, clean: &[u8]) -> Vec<u8> {
        match self.reassemble_checked(clean) {
            Ok(output) => output,
            Err(error) => {
                tracing::warn!("Targeted init code patching failed: {}", error);
                let runtime_start_offset = self
                    .runtime_layout
                    .iter()
                    .map(|span| span.offset)
                    .min()
                    .unwrap_or(0);
                self.assemble_sequential(clean, runtime_start_offset)
            }
        }
    }

    fn assemble_sequential(&self, clean: &[u8], runtime_start_offset: usize) -> Vec<u8> {
        let mut sorted_removed = self.removed.clone();
        sorted_removed.sort_by_key(|removed| removed.offset);
        let mut out = Vec::with_capacity(
            sorted_removed
                .iter()
                .map(|removed| removed.data.len())
                .sum::<usize>()
                + clean.len(),
        );

        for removed in &sorted_removed {
            if removed.offset < runtime_start_offset {
                out.extend_from_slice(&removed.data);
            }
        }
        out.extend_from_slice(clean);
        for removed in &sorted_removed {
            if removed.offset >= runtime_start_offset {
                out.extend_from_slice(&removed.data);
            }
        }

        tracing::debug!("Sequential reassembly complete: {} bytes total", out.len());
        out
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

    #[test]
    fn reassembly_relocates_constructor_base_before_arguments_are_appended() {
        // The init code retains the runtime length across CODECOPY for RETURN, then contains
        // Solidity's constructor-data base sequence: PUSH creation_len; DUP1; CODESIZE; SUB.
        // No argument suffix is present yet, matching callers that append ABI data later.
        let init = [
            0x60, 0x03, 0x80, 0x60, 0x0e, 0x5f, 0x39, 0x5f, 0xf3, 0x60, 0x11, 0x80, 0x38, 0x03,
        ];
        let runtime = [0x5b, 0x00, 0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (_, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let grown_runtime = [0x5b, 0x5b, 0x5b, 0x00, 0x00];

        let rebuilt = report.reassemble_checked(&grown_runtime).unwrap();

        assert_eq!(&rebuilt[1..2], &[grown_runtime.len() as u8]);
        assert_eq!(
            &rebuilt[9..14],
            &[0x60, 0x13, 0x80, 0x38, 0x03],
            "constructor-data base must track the grown creation bytecode"
        );
        assert_eq!(&rebuilt[init.len()..], grown_runtime.as_slice());
    }
}
