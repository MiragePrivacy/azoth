use crate::Opcode;
use crate::decoder::Instruction;
use crate::is_terminal_opcode;
use crate::result::Error;
use serde::{Deserialize, Serialize};

/// Represents the type of a bytecode section.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionKind {
    /// Deployment code executed once during contract creation.
    Init,
    /// Executable code stored and executed on-chain.
    Runtime,
    /// Constructor arguments appended to deployment payload.
    ConstructorArgs,
    /// CBOR metadata (e.g., Solidity fingerprint) appended after runtime.
    Auxdata,
    /// Padding bytes after terminal instructions but before Auxdata.
    Padding,
}

impl SectionKind {
    /// Returns true if the section should be removed (i.e., not Runtime).
    pub fn is_removed(self) -> bool {
        !matches!(self, SectionKind::Runtime)
    }
}

/// Represents a detected section with its kind, starting offset, and length.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub kind: SectionKind,
    pub offset: usize, // Start position in raw bytes
    pub len: usize,    // Byte-length of the section
}

impl Section {
    /// Returns the end offset of the section (offset + len).
    pub fn end(self) -> usize {
        self.offset + self.len
    }
}

/// Locates all non-overlapping, offset-ordered sections in the bytecode.
pub fn locate_sections(bytes: &[u8], instructions: &[Instruction]) -> Result<Vec<Section>, Error> {
    let mut sections = Vec::new();
    let total_len = bytes.len();

    tracing::debug!(
        "Processing bytecode: {} bytes, {} instructions",
        total_len,
        instructions.len()
    );

    // Pass A: Detect Auxdata (CBOR) from the end
    let auxdata = detect_auxdata(bytes);
    let aux_offset = auxdata.map(|(offset, _)| offset).unwrap_or(total_len);
    tracing::debug!("Auxdata offset: {}", aux_offset);

    // Special case: If auxdata starts at offset 0, the entire bytecode is auxdata
    if aux_offset == 0
        && let Some((offset, len)) = auxdata
    {
        tracing::debug!("Entire bytecode is auxdata: offset={}, len={}", offset, len);
        sections.push(Section {
            kind: SectionKind::Auxdata,
            offset,
            len,
        });
        return Ok(sections);
    }

    // Pass B: Detect Padding before Auxdata
    let padding = detect_padding(instructions, aux_offset);

    // Pass C: Detect Init -> Runtime split using dispatcher pattern
    let (mut init_end, mut runtime_start, mut runtime_len) =
        detect_init_runtime_split(instructions).unwrap_or((0, 0, aux_offset));

    tracing::debug!(
        "Initial detection: init_end={}, runtime_start={}, runtime_len={}",
        init_end,
        runtime_start,
        runtime_len
    );

    // Handles cases where deployment pattern detection fails
    // but we clearly have deployment bytecode (substantial size suggests it)
    if init_end == 0 && runtime_start == 0 && aux_offset > 100 {
        // Try fallback detection methods
        if let Some((detected_init_end, detected_runtime_start)) =
            detect_deployment_fallback(instructions, aux_offset)
        {
            init_end = detected_init_end;
            runtime_start = detected_runtime_start;
            runtime_len = aux_offset.saturating_sub(runtime_start);
            tracing::debug!(
                "Fallback detection succeeded: init_end={}, runtime_start={}, runtime_len={}",
                init_end,
                runtime_start,
                runtime_len
            );
        }
    }

    // Additional guard: if we found runtime_start but not init_end
    if init_end == 0 && runtime_start > 0 {
        init_end = runtime_start;
        tracing::debug!(
            "Fixed init_end from 0 to {} based on runtime_start",
            init_end
        );
    }

    // Clamp runtime_len to avoid exceeding aux_offset
    if runtime_start + runtime_len > aux_offset {
        runtime_len = aux_offset.saturating_sub(runtime_start);
        tracing::debug!("Clamped runtime_len to {}", runtime_len);
    }

    // Pass D: Detect ConstructorArgs if applicable
    let constructor_args = detect_constructor_args(init_end, runtime_start, aux_offset);
    let has_constructor_args = constructor_args.is_some();
    if let Some((args_offset, args_len)) = constructor_args {
        tracing::debug!(
            "ConstructorArgs detected: offset={}, len={}",
            args_offset,
            args_len
        );
        sections.push(Section {
            kind: SectionKind::ConstructorArgs,
            offset: args_offset,
            len: args_len,
        });
    }

    // Only push Padding if ConstructorArgs is not present
    if !has_constructor_args && let Some((pad_offset, pad_len)) = padding {
        tracing::debug!("Padding detected: offset={}, len={}", pad_offset, pad_len);
        sections.push(Section {
            kind: SectionKind::Padding,
            offset: pad_offset,
            len: pad_len,
        });
    }

    // Pass E: Create sections based on detected boundaries
    if init_end == 0 && runtime_start == 0 {
        // True runtime-only contract
        tracing::debug!("Runtime-only bytecode detected");
        sections.push(Section {
            kind: SectionKind::Runtime,
            offset: 0,
            len: aux_offset,
        });
    } else {
        // Deployment bytecode (original or obfuscated)
        if init_end > 0 {
            tracing::debug!("Creating Init section: offset=0, len={}", init_end);
            sections.push(Section {
                kind: SectionKind::Init,
                offset: 0,
                len: init_end,
            });
        }
        if runtime_len > 0 && runtime_start < aux_offset {
            tracing::debug!(
                "Creating Runtime section: offset={}, len={}",
                runtime_start,
                runtime_len
            );
            sections.push(Section {
                kind: SectionKind::Runtime,
                offset: runtime_start,
                len: runtime_len,
            });
        }
    }

    // Add Auxdata section if detected
    if let Some((offset, len)) = auxdata {
        tracing::debug!("Adding auxdata section: offset={}, len={}", offset, len);
        sections.push(Section {
            kind: SectionKind::Auxdata,
            offset,
            len,
        });
    }

    // Adjust runtime section to account for padding overlap
    let sections_clone = sections.clone();
    if let Some(rt) = sections.iter_mut().find(|s| s.kind == SectionKind::Runtime) {
        for sec in &sections_clone {
            if sec.kind == SectionKind::Padding
                && sec.offset >= rt.offset
                && sec.offset < rt.offset + rt.len
            {
                let new_len = sec.offset - rt.offset;
                tracing::debug!(
                    "Adjusting runtime section length from {} to {} due to padding",
                    rt.len,
                    new_len
                );
                rt.len = new_len;
            }
        }
    }

    // Ensure sections are non-overlapping and cover the entire range
    sections.sort_by_key(|s| s.offset);
    tracing::debug!("Final sections before validation: {:?}", sections);

    validate_sections(&sections, total_len)?;

    tracing::debug!("Sections validation passed: {:?}", sections);
    Ok(sections)
}

/// Helper to extract runtime instructions from full bytecode
pub fn extract_runtime_instructions(
    instructions: &[Instruction],
    aux_offset: usize,
) -> Option<&[Instruction]> {
    // Try to find the init/runtime split
    if let Some((_, runtime_start)) = detect_deployment_fallback(instructions, aux_offset) {
        // Find the instruction index that corresponds to runtime_start PC
        let runtime_instr_start = instructions
            .iter()
            .position(|instruction| instruction.pc >= runtime_start)?;

        return Some(&instructions[runtime_instr_start..]);
    }

    // If no split found, assume entire bytecode is runtime
    Some(instructions)
}

/// Fallback deployment detection for when the strict pattern fails
fn detect_deployment_fallback(
    instructions: &[Instruction],
    aux_offset: usize,
) -> Option<(usize, usize)> {
    // Method 1: Look for CODECOPY + RETURN pattern
    if let Some((init_end, runtime_start)) = detect_codecopy_return_simple(instructions)
        && runtime_start < aux_offset
    {
        return Some((init_end, runtime_start));
    }

    // Method 2: Heuristic detection based on common runtime start patterns
    // Look for CALLDATASIZE or specific PUSH patterns that indicate runtime code
    for instruction in instructions.iter() {
        if matches!(instruction.op, Opcode::CALLDATASIZE)
            || (matches!(instruction.op, Opcode::PUSH(1))
                && instruction.imm.as_deref() == Some("00"))
        {
            let potential_runtime_start = instruction.pc;
            if potential_runtime_start > 100 && potential_runtime_start < aux_offset {
                tracing::debug!(
                    "Heuristic runtime start detected at PC {}",
                    potential_runtime_start
                );
                return Some((potential_runtime_start, potential_runtime_start));
            }
        }
    }

    None
}

/// Simple CODECOPY + RETURN detection
fn detect_codecopy_return_simple(instructions: &[Instruction]) -> Option<(usize, usize)> {
    // Find first CODECOPY
    let codecopy_idx = instructions
        .iter()
        .position(|instruction| instruction.op == Opcode::CODECOPY)?;

    // Find RETURN after CODECOPY (within reasonable distance)
    let return_idx = instructions[codecopy_idx..]
        .iter()
        .take(20)
        .position(|instruction| instruction.op == Opcode::RETURN)
        .map(|pos| codecopy_idx + pos)?;

    let init_end = instructions[return_idx].pc + 1;

    // Try to find runtime start from PUSH instructions before CODECOPY
    let mut runtime_start = init_end; // fallback

    for instruction in (0..codecopy_idx).rev().take(10) {
        if matches!(
            instructions[instruction].op,
            Opcode::PUSH(_) | Opcode::PUSH0
        ) && let Some(immediate) = &instructions[instruction].imm
            && let Ok(value) = usize::from_str_radix(immediate, 16)
            && value > init_end
            && value < 100000
        {
            runtime_start = value;
            break;
        }
    }

    tracing::debug!(
        "CODECOPY+RETURN detection: init_end={}, runtime_start={}",
        init_end,
        runtime_start
    );
    Some((init_end, runtime_start))
}

/// Validates sections for overlaps, gaps, and bounds
pub fn validate_sections(sections: &[Section], total_len: usize) -> Result<(), Error> {
    let mut current_offset = 0;
    for section in sections.iter() {
        tracing::debug!(
            "Validating section: kind={:?}, offset={}, len={}, end={}",
            section.kind,
            section.offset,
            section.len,
            section.end()
        );

        if section.offset < current_offset {
            return Err(Error::SectionOverlap(section.offset));
        }
        if section.offset > current_offset {
            return Err(Error::SectionGap(current_offset));
        }
        if section.end() > total_len {
            return Err(Error::SectionOutOfBounds(section.end()));
        }
        current_offset = section.end();
    }

    if current_offset != total_len {
        return Err(Error::SectionGap(current_offset));
    }

    Ok(())
}

/// Detects Auxdata (CBOR) section from the end of the bytecode, using a canonical length check
/// and a fallback scan for invalid lengths.
///
/// # Arguments
/// * `bytes` - Raw bytecode bytes.
///
/// # Returns
/// Optional tuple of (offset, length) if Auxdata is found, None otherwise.
fn detect_auxdata(bytes: &[u8]) -> Option<(usize, usize)> {
    const MARKER: &[u8] = &[0xa1, 0x65, 0x62, 0x7a, 0x7a, 0x72]; // a165627a7a72
    let len = bytes.len();
    if len < MARKER.len() + 2 {
        tracing::debug!("Bytecode too short for auxdata: len={}", len);
        return None;
    }

    // Canonical path: trust len_raw when it is plausible
    let len_raw = u16::from_be_bytes([bytes[len - 2], bytes[len - 1]]) as usize;
    if len_raw > 0 && len_raw + 2 <= len && bytes[len - len_raw - 2..len - 2].starts_with(MARKER) {
        let off = len - len_raw - 2;
        tracing::debug!(
            "Auxdata detected (canonical): offset={}, len={}",
            off,
            len_raw + 2
        );
        return Some((off, len_raw + 2));
    }

    // Fallback: scan last ≤64 bytes for the marker
    let tail_start = len.saturating_sub(64 + MARKER.len());
    for off in (tail_start..=len - MARKER.len()).rev() {
        if bytes[off..off + MARKER.len()] == *MARKER {
            let aux_len = len - off;
            tracing::debug!(
                "Auxdata detected (fallback): offset={}, len={}",
                off,
                aux_len
            );
            return Some((off, aux_len)); // Marker to EOF
        }
    }

    tracing::debug!("No auxdata marker found");
    None
}

/// Detects Padding section before Auxdata.
///
/// # Arguments
/// * `instructions` - Decoded instructions.
/// * `aux_offset` - Offset of Auxdata or total length if none.
///
/// # Returns
/// Optional tuple of (offset, length) if Padding is found, None otherwise.
fn detect_padding(instructions: &[Instruction], aux_offset: usize) -> Option<(usize, usize)> {
    let last_terminal = instructions
        .iter()
        .rev()
        .skip_while(|instruction| instruction.op == Opcode::STOP)
        .find(|instruction| is_terminal_opcode(instruction.op));

    last_terminal.and_then(|instruction| {
        let pad_offset = instruction.pc + 1;
        if pad_offset < aux_offset {
            Some((pad_offset, aux_offset - pad_offset))
        } else {
            None
        }
    })
}

/// Detects the Init to Runtime split using the dispatcher pattern.
///
/// # Arguments
/// * `instructions` - Decoded instructions.
///
/// # Returns
/// Optional tuple of (init_end, runtime_start, runtime_len) if pattern is found, None otherwise.
fn detect_init_runtime_split(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    // Try the strict pattern first (for backwards compatibility)
    if let Some(result) = detect_strict_deployment_pattern(instructions) {
        return Some(result);
    }

    // Fallback: Look for any CODECOPY + RETURN pattern
    if let Some(result) = detect_codecopy_return_pattern(instructions) {
        return Some(result);
    }

    None
}

/// Detects the strict deployment pattern (original heuristic)
fn detect_strict_deployment_pattern(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    for i in 0..instructions.len().saturating_sub(6) {
        if matches!(instructions[i].op, Opcode::PUSH(_) | Opcode::PUSH0)
            && matches!(instructions[i + 1].op, Opcode::PUSH(_) | Opcode::PUSH0)
            && matches!(instructions[i + 2].op, Opcode::PUSH0 | Opcode::PUSH(1))
            && instructions[i + 2].imm.as_deref() == Some("00")
            && instructions[i + 3].op == Opcode::CODECOPY
            && matches!(instructions[i + 4].op, Opcode::PUSH(_) | Opcode::PUSH0)
            && instructions[i + 5].op == Opcode::RETURN
        {
            let runtime_len = instructions[i]
                .imm
                .as_ref()
                .and_then(|s| usize::from_str_radix(s, 16).ok())?;
            let runtime_ofs = instructions[i + 1]
                .imm
                .as_ref()
                .and_then(|s| usize::from_str_radix(s, 16).ok())?;
            let init_end = instructions[i + 5].pc + 1;

            tracing::debug!(
                "Found strict deployment pattern at {}: init_end={}, runtime_start={}, runtime_len={}",
                i,
                init_end,
                runtime_ofs,
                runtime_len
            );

            return Some((init_end, runtime_ofs, runtime_len));
        }
    }
    None
}

/// Fallback: Look for CODECOPY + RETURN pattern with more flexibility
fn detect_codecopy_return_pattern(instructions: &[Instruction]) -> Option<(usize, usize, usize)> {
    // Find CODECOPY instruction
    let codecopy_idx = instructions
        .iter()
        .position(|instruction| instruction.op == Opcode::CODECOPY)?;

    // Look for RETURN after CODECOPY (within reasonable distance)
    let return_idx = instructions[codecopy_idx + 1..]
        .iter()
        .take(10) // Look within next 10 instructions
        .position(|instruction| instruction.op == Opcode::RETURN)
        .map(|pos| codecopy_idx + 1 + pos)?;

    // Try to extract runtime parameters from PUSH instructions before CODECOPY
    let mut runtime_len = None;
    let mut runtime_start = None;

    // Look backwards from CODECOPY for PUSH instructions
    // CODECOPY stack layout: [destOffset, offset, size] where offset is where runtime starts,
    // and size is how many bytes to copy. Scanning backwards, we encounter them in reverse order.
    for instruction in (0..codecopy_idx).rev().take(10) {
        if matches!(
            instructions[instruction].op,
            Opcode::PUSH(_) | Opcode::PUSH0
        ) && let Some(immediate) = &instructions[instruction].imm
            && let Ok(value) = usize::from_str_radix(immediate, 16)
        {
            if runtime_start.is_none() && value > 0 && value < 100000 {
                // First reasonable value (scanning backwards) is the offset where runtime starts
                runtime_start = Some(value);
            } else if runtime_len.is_none() && value > 0 && value < 100000 {
                // Second reasonable value is the size of the runtime code
                runtime_len = Some(value);
            }

            if runtime_len.is_some() && runtime_start.is_some() {
                break;
            }
        }
    }

    // If we found CODECOPY + RETURN but can't extract parameters,
    // make reasonable assumptions
    let runtime_len = runtime_len.unwrap_or_else(|| {
        // Estimate runtime length from instruction count after return
        instructions.len().saturating_sub(return_idx + 1) * 2 // rough estimate
    });

    let runtime_start = runtime_start.unwrap_or_else(|| {
        // Assume runtime starts right after the RETURN instruction
        instructions[return_idx].pc + 1
    });

    let init_end = instructions[return_idx].pc + 1;

    tracing::debug!(
        "Found fallback deployment pattern: CODECOPY at {}, RETURN at {}, init_end={}, runtime_start={}, runtime_len={}",
        codecopy_idx,
        return_idx,
        init_end,
        runtime_start,
        runtime_len
    );

    Some((init_end, runtime_start, runtime_len))
}

/// Detects ConstructorArgs section between Init end and Runtime start.
///
/// # Arguments
/// * `init_end` - End offset of Init section.
/// * `runtime_start` - Start offset of Runtime section.
/// * `aux_offset` - Offset of Auxdata or total length if none.
///
/// # Returns
/// Optional tuple of (offset, length) if ConstructorArgs are found, None otherwise.
fn detect_constructor_args(
    init_end: usize,
    runtime_start: usize,
    aux_offset: usize,
) -> Option<(usize, usize)> {
    if runtime_start > 0 && init_end < runtime_start && runtime_start < aux_offset {
        Some((init_end, runtime_start - init_end))
    } else {
        None
    }
}
