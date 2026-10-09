//! Module for stripping EVM bytecode to extract the runtime blob and prepare it for
//! obfuscation.

use crate::{
    Opcode,
    detection::{Section, SectionKind},
    result::Error,
};
use hex::encode;
use revm::primitives::{B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct PushInfo {
    pos: usize,
    width: usize,
    value: usize,
}

#[derive(Clone, Debug)]
struct RuntimeCopyContract {
    copy_index: usize,
    return_index: usize,
    length_pushes: Vec<PushInfo>,
    source_push: PushInfo,
    memory_reads: Vec<(usize, InitStackValue)>,
    free_memory_lower_bound: Option<usize>,
    allocator_store_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InitStackValue {
    Unknown,
    Preexisting(usize),
    Constant(usize),
    RuntimeLength(PushInfo),
    RuntimeLengthCandidate(PushInfo),
    RuntimeSource(PushInfo),
    RuntimeAddress(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolicWord {
    Unknown,
    Constant(U256),
    AtLeast(usize),
    DerivedFromFreeMemory(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolicState {
    instruction_index: usize,
    stack: Vec<SymbolicWord>,
    memory: BTreeMap<usize, SymbolicWord>,
    authoritative_copy_seen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CodeCopyObservation {
    instruction_index: usize,
    destination: Option<usize>,
    destination_lower_bound: Option<usize>,
    source: Option<usize>,
    length: Option<usize>,
}

#[derive(Clone, Debug)]
struct ParsedInstruction {
    pos: usize,
    opcode: u8,
    push_width: Option<usize>,
}

fn parse_instructions(bytes: &[u8], section_name: &str) -> Result<Vec<ParsedInstruction>, String> {
    let mut instructions = Vec::new();
    let mut pc = 0usize;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        let push_width = (0x60..=0x7f)
            .contains(&opcode)
            .then(|| (opcode - 0x5f) as usize);
        let byte_size = 1 + push_width.unwrap_or(0);
        let end = pc.checked_add(byte_size).ok_or_else(|| {
            format!("{section_name} instruction length overflow at byte 0x{pc:x}")
        })?;
        if end > bytes.len() {
            return Err(format!(
                "truncated PUSH{} in {section_name} at byte 0x{pc:x}",
                push_width.expect("only PUSH instructions have a multi-byte size")
            ));
        }
        instructions.push(ParsedInstruction {
            pos: pc,
            opcode,
            push_width,
        });
        pc = end;
    }
    Ok(instructions)
}

fn parsed_push_value(bytes: &[u8], instruction: &ParsedInstruction) -> Option<usize> {
    let width = instruction.push_width?;
    let immediate = bytes.get(instruction.pos + 1..instruction.pos + 1 + width)?;
    let usize_bytes = std::mem::size_of::<usize>();
    if width > usize_bytes
        && immediate[..width - usize_bytes]
            .iter()
            .any(|byte| *byte != 0)
    {
        return None;
    }
    Some(
        immediate[width.saturating_sub(usize_bytes)..]
            .iter()
            .fold(0usize, |value, byte| (value << 8) | usize::from(*byte)),
    )
}

fn parsed_push_info(bytes: &[u8], instruction: &ParsedInstruction) -> Option<PushInfo> {
    Some(PushInfo {
        pos: instruction.pos,
        width: instruction.push_width?,
        value: parsed_push_value(bytes, instruction)?,
    })
}

fn parsed_push_word(bytes: &[u8], instruction: &ParsedInstruction) -> Option<U256> {
    let width = instruction.push_width?;
    let immediate = bytes.get(instruction.pos + 1..instruction.pos + 1 + width)?;
    Some(U256::from_be_slice(immediate))
}

fn is_zero_push(bytes: &[u8], instruction: &ParsedInstruction) -> bool {
    instruction.opcode == 0x5f || parsed_push_value(bytes, instruction) == Some(0)
}

fn write_push_value(bytes: &mut [u8], info: &PushInfo, new_value: usize) -> Result<(), String> {
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

fn is_solidity_allocator_store(
    init: &[u8],
    instructions: &[ParsedInstruction],
    store_index: usize,
) -> bool {
    let Some(start) = store_index.checked_sub(25) else {
        return false;
    };
    let expected = [
        0x5b, 0x60, 0x90, 0x91, 0x01, 0x60, 0x19, 0x16, 0x81, 0x01, 0x90, 0x60, 0x60, 0x60, 0x1b,
        0x03, 0x82, 0x11, 0x90, 0x82, 0x10, 0x17, 0x61, 0x57, 0x60, 0x52,
    ];
    if instructions.get(start..=store_index).is_none_or(|window| {
        window
            .iter()
            .map(|instruction| instruction.opcode)
            .ne(expected)
    }) {
        return false;
    }
    if parsed_push_value(init, &instructions[start + 1]) != Some(0x1f)
        || parsed_push_value(init, &instructions[start + 5]) != Some(0x1f)
        || parsed_push_value(init, &instructions[start + 11]) != Some(1)
        || parsed_push_value(init, &instructions[start + 12]) != Some(1)
        || parsed_push_value(init, &instructions[start + 13]) != Some(0x40)
        || parsed_push_value(init, &instructions[start + 24]) != Some(0x40)
    {
        return false;
    }
    let Some(overflow_target) = parsed_push_value(init, &instructions[start + 22]) else {
        return false;
    };
    let Some(target_index) = instructions
        .iter()
        .position(|instruction| instruction.pos == overflow_target)
    else {
        return false;
    };
    instructions[target_index].opcode == 0x5b
        && instructions
            .iter()
            .skip(target_index + 1)
            .take_while(|instruction| {
                !matches!(
                    instruction.opcode,
                    0x00 | 0x56 | 0x57 | 0xf3 | 0xfd | 0xfe | 0xff
                )
            })
            .count()
            <= 10
        && instructions
            .iter()
            .skip(target_index + 1)
            .take(11)
            .any(|instruction| instruction.opcode == 0xfd)
}

fn locate_runtime_copy(
    init: &[u8],
    instructions: &[ParsedInstruction],
    runtime_start: usize,
    runtime_len: usize,
    immutable_placeholders: Option<&std::collections::BTreeSet<usize>>,
) -> Result<RuntimeCopyContract, String> {
    let mut candidates = Vec::new();
    for copy_index in 0..instructions.len() {
        if instructions[copy_index].opcode != 0x39 {
            continue;
        }

        // solc's current terminal copy shape when it retains both length and memory base:
        // PUSH len; SWAP1; DUP2; PUSH source; DUP3; CODECOPY
        if copy_index >= 5
            && parsed_push_value(init, &instructions[copy_index - 5]) == Some(runtime_len)
            && instructions[copy_index - 4].opcode == 0x90
            && instructions[copy_index - 3].opcode == 0x81
            && parsed_push_value(init, &instructions[copy_index - 2]) == Some(runtime_start)
            && instructions[copy_index - 1].opcode == 0x82
        {
            candidates.push((copy_index - 5, copy_index, copy_index - 5, copy_index - 2));
        }

        // Common compact compiler shape retaining only the length:
        // PUSH len; DUP1; PUSH source; PUSH 0; CODECOPY
        if copy_index >= 4
            && parsed_push_value(init, &instructions[copy_index - 4]) == Some(runtime_len)
            && instructions[copy_index - 3].opcode == 0x80
            && parsed_push_value(init, &instructions[copy_index - 2]) == Some(runtime_start)
            && is_zero_push(init, &instructions[copy_index - 1])
        {
            candidates.push((copy_index - 4, copy_index, copy_index - 4, copy_index - 2));
        }

        // Minimal compiler/test shape with an explicit second length PUSH before RETURN:
        // PUSH len; PUSH source; PUSH 0; CODECOPY
        if copy_index >= 3
            && parsed_push_value(init, &instructions[copy_index - 3]) == Some(runtime_len)
            && parsed_push_value(init, &instructions[copy_index - 2]) == Some(runtime_start)
            && is_zero_push(init, &instructions[copy_index - 1])
        {
            candidates.push((copy_index - 3, copy_index, copy_index - 3, copy_index - 2));
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    let (pattern_start, copy_index, length_index, source_index) = match candidates.as_slice() {
        [candidate] => *candidate,
        [] => {
            return Err(format!(
                "no proven runtime CODECOPY found for source 0x{runtime_start:x} and length 0x{runtime_len:x}"
            ));
        }
        candidates => {
            return Err(format!(
                "ambiguous runtime CODECOPY: found {} proven candidates",
                candidates.len()
            ));
        }
    };

    let selected_length = parsed_push_info(init, &instructions[length_index])
        .ok_or("runtime CODECOPY length is not a representable PUSH")?;
    let selected_source = parsed_push_info(init, &instructions[source_index])
        .ok_or("runtime CODECOPY source is not a representable PUSH")?;
    let free_memory_lower_bound = (copy_index - pattern_start == 5
        && pattern_start >= 2
        && parsed_push_value(init, &instructions[pattern_start - 2]) == Some(0x40)
        && instructions[pattern_start - 1].opcode == 0x51
        && instructions
            .get(1)
            .is_some_and(|instruction| instruction.opcode == 0x80)
        && instructions
            .get(2)
            .is_some_and(|instruction| parsed_push_value(init, instruction) == Some(0x40))
        && instructions
            .get(3)
            .is_some_and(|instruction| instruction.opcode == 0x52))
    .then(|| parsed_push_value(init, &instructions[0]))
    .flatten();
    let allocator_store_indices = if free_memory_lower_bound.is_some() {
        instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (instruction.opcode == 0x52
                    && is_solidity_allocator_store(init, instructions, index))
                .then_some(index)
            })
            .collect()
    } else {
        BTreeSet::new()
    };

    // Unique sentinels below the recognized pattern let DUP/SWAP prove that solc's retained
    // memory-base value is the same value ultimately passed to RETURN without pretending to know
    // its concrete address.
    let mut stack: Vec<_> = (0..32).map(InitStackValue::Preexisting).collect();
    if let Some(previous) = pattern_start.checked_sub(1).and_then(|index| {
        if instructions[index].opcode == 0x5f {
            Some(0)
        } else {
            parsed_push_value(init, &instructions[index])
        }
    }) {
        *stack.last_mut().expect("the sentinel stack is non-empty") =
            InitStackValue::Constant(previous);
    }
    let mut copy_destination = None;
    let mut length_pushes = Vec::new();
    let mut memory_reads = Vec::new();
    let mut immutable_write_counts = std::collections::BTreeMap::new();
    let mut consumed_length_candidate_positions = BTreeSet::new();

    for index in pattern_start..instructions.len() {
        let instruction = &instructions[index];
        match instruction.opcode {
            0x5f => {
                stack.push(InitStackValue::Constant(0));
                continue;
            }
            0x60..=0x7f => {
                let info = parsed_push_info(init, instruction).ok_or_else(|| {
                    format!("unrepresentable init PUSH at 0x{:x}", instruction.pos)
                })?;
                let value = if info.pos == selected_length.pos {
                    InitStackValue::RuntimeLength(info)
                } else if index > copy_index && info.value == runtime_len {
                    // Equal-valued literals after CODECOPY are only candidates: the PUSH becomes
                    // a relocation site if dataflow proves that RETURN consumes it. Treating every
                    // equal literal as the runtime length would incorrectly taint unrelated values
                    // such as an MLOAD address at the old runtime boundary.
                    InitStackValue::RuntimeLengthCandidate(info)
                } else if info.pos == selected_source.pos {
                    InitStackValue::RuntimeSource(info)
                } else {
                    InitStackValue::Constant(info.value)
                };
                stack.push(value);
                continue;
            }
            0x80..=0x8f => {
                let depth = usize::from(instruction.opcode - 0x7f);
                if stack.len() < depth {
                    return Err(format!(
                        "init stack underflow at DUP in 0x{:x}",
                        instruction.pos
                    ));
                }
                stack.push(stack[stack.len() - depth].clone());
                continue;
            }
            0x90..=0x9f => {
                let depth = usize::from(instruction.opcode - 0x8f);
                if stack.len() <= depth {
                    return Err(format!(
                        "init stack underflow at SWAP in 0x{:x}",
                        instruction.pos
                    ));
                }
                let top = stack.len() - 1;
                stack.swap(top, top - depth);
                continue;
            }
            0x39 => {
                if index != copy_index {
                    return Err(format!(
                        "a second CODECOPY follows the proven runtime copy at 0x{:x}",
                        instruction.pos
                    ));
                }
                if stack.len() < 3 {
                    return Err("runtime CODECOPY stack underflow".into());
                }
                let consumed = &stack[stack.len() - 3..];
                if !matches!(consumed[0], InitStackValue::RuntimeLength(_))
                    || !matches!(consumed[1], InitStackValue::RuntimeSource(_))
                {
                    return Err("runtime CODECOPY arguments lack exact PUSH provenance".into());
                }
                copy_destination = Some(consumed[2].clone());
                stack.truncate(stack.len() - 3);
                continue;
            }
            0xf3 => {
                if index <= copy_index {
                    return Err("RETURN occurs before the proven runtime CODECOPY".into());
                }
                if stack.len() < 2 {
                    return Err("runtime RETURN stack underflow".into());
                }
                let consumed = &stack[stack.len() - 2..];
                let return_length = match &consumed[0] {
                    InitStackValue::RuntimeLength(return_length)
                    | InitStackValue::RuntimeLengthCandidate(return_length) => return_length,
                    _ => {
                        return Err(
                            "runtime RETURN length does not derive from an exact length PUSH"
                                .into(),
                        );
                    }
                };
                if consumed_length_candidate_positions.contains(&return_length.pos) {
                    return Err(format!(
                        "runtime RETURN length PUSH at 0x{:x} also has a non-RETURN use",
                        return_length.pos
                    ));
                }
                if Some(&consumed[1]) != copy_destination.as_ref() {
                    return Err("runtime RETURN offset does not match CODECOPY destination".into());
                }
                length_pushes.push(selected_length.clone());
                length_pushes.push(return_length.clone());
                length_pushes.sort_by_key(|push| push.pos);
                length_pushes.dedup_by_key(|push| push.pos);

                if let Some(placeholders) = immutable_placeholders {
                    for placeholder in placeholders {
                        if immutable_write_counts
                            .get(placeholder)
                            .copied()
                            .unwrap_or(0)
                            != 1
                        {
                            return Err(format!(
                                "immutable placeholder at runtime offset 0x{placeholder:x} is not written exactly once"
                            ));
                        }
                    }
                    if immutable_write_counts.len() != placeholders.len() {
                        return Err(
                            "runtime-copy window writes a non-placeholder memory word".into()
                        );
                    }
                }
                return Ok(RuntimeCopyContract {
                    copy_index,
                    return_index: index,
                    length_pushes,
                    source_push: selected_source,
                    memory_reads,
                    free_memory_lower_bound,
                    allocator_store_indices,
                });
            }
            // These operations can read, overwrite, expose, or externally act on the copied
            // runtime. The sole admitted write is the exact Solidity immutable-word shape below.
            0x20
            | 0x37
            | 0x3c
            | 0x3e
            | 0x53
            | 0x5e
            | 0xa0..=0xa4
            | 0xf0..=0xf2
            | 0xf4..=0xf5
            | 0xfa => {
                return Err(format!(
                    "opcode 0x{:02x} may observe or mutate copied runtime before RETURN at 0x{:x}",
                    instruction.opcode, instruction.pos
                ));
            }
            0x51 => {
                let address = stack.last().cloned().ok_or_else(|| {
                    format!("init stack underflow at MLOAD in 0x{:x}", instruction.pos)
                })?;
                memory_reads.push((
                    instruction.pos,
                    match address {
                        InitStackValue::RuntimeLengthCandidate(info) => {
                            InitStackValue::Constant(info.value)
                        }
                        address => address,
                    },
                ));
            }
            0x01 => {
                if stack.len() < 2 {
                    return Err(format!(
                        "init stack underflow at ADD in 0x{:x}",
                        instruction.pos
                    ));
                }
                let consumed = &stack[stack.len() - 2..];
                consumed_length_candidate_positions.extend(consumed.iter().filter_map(|value| {
                    match value {
                        InitStackValue::RuntimeLengthCandidate(info) => Some(info.pos),
                        _ => None,
                    }
                }));
                let runtime_offset = match (copy_destination.as_ref(), &consumed[0], &consumed[1]) {
                    (Some(base), candidate_base, InitStackValue::Constant(offset))
                        if candidate_base == base =>
                    {
                        Some(*offset)
                    }
                    (Some(base), InitStackValue::Constant(offset), candidate_base)
                        if candidate_base == base =>
                    {
                        Some(*offset)
                    }
                    _ => None,
                };
                stack.truncate(stack.len() - 2);
                stack.push(
                    runtime_offset
                        .map(InitStackValue::RuntimeAddress)
                        .unwrap_or(InitStackValue::Unknown),
                );
                continue;
            }
            0x52 => {
                let syntactic_offset = index
                    .checked_sub(2)
                    .filter(|previous| instructions[*previous + 1].opcode == 0x01)
                    .and_then(|previous| parsed_push_value(init, &instructions[previous]));
                let stack_offset = stack.last().and_then(|value| match value {
                    InitStackValue::RuntimeAddress(offset) => Some(*offset),
                    _ => None,
                });
                let Some(immutable_offset) =
                    syntactic_offset.filter(|offset| Some(*offset) == stack_offset)
                else {
                    return Err(format!(
                        "MSTORE after runtime CODECOPY does not derive its address from the proven copy destination at 0x{:x}",
                        instruction.pos
                    ));
                };
                if let Some(placeholders) = immutable_placeholders {
                    if !placeholders.contains(&immutable_offset) {
                        return Err(format!(
                            "MSTORE after runtime CODECOPY targets non-placeholder offset 0x{immutable_offset:x}"
                        ));
                    }
                    *immutable_write_counts
                        .entry(immutable_offset)
                        .or_insert(0usize) += 1;
                }
            }
            0x00 | 0x56 | 0x57 | 0xfd | 0xfe | 0xff => {
                return Err(format!(
                    "runtime-copy path reaches opcode 0x{:02x} before proven RETURN at 0x{:x}",
                    instruction.opcode, instruction.pos
                ));
            }
            // MSIZE changes when the copied runtime grows; GAS changes with every transformed
            // copy/write sequence. Either can leak into constructor state or the returned code.
            0x38 | 0x58..=0x5a => {
                return Err(format!(
                    "opcode 0x{:02x} observes init/runtime layout or gas after CODECOPY at 0x{:x}",
                    instruction.opcode, instruction.pos
                ));
            }
            _ => {}
        }

        let opcode = Opcode::from_byte(instruction.opcode);
        let info = opcode.info().ok_or_else(|| {
            format!(
                "unknown init opcode 0x{:02x} after runtime CODECOPY at 0x{:x}",
                instruction.opcode, instruction.pos
            )
        })?;
        let inputs = usize::from(info.inputs);
        if stack.len() < inputs {
            return Err(format!("init stack underflow at 0x{:x}", instruction.pos));
        }
        let consumed = &stack[stack.len() - inputs..];
        if instruction.opcode != 0x50 {
            consumed_length_candidate_positions.extend(consumed.iter().filter_map(|value| {
                match value {
                    InitStackValue::RuntimeLengthCandidate(info) => Some(info.pos),
                    _ => None,
                }
            }));
        }
        if instruction.opcode != 0x50
            && consumed.iter().any(|value| {
                matches!(
                    value,
                    InitStackValue::RuntimeLength(_) | InitStackValue::RuntimeSource(_)
                )
            })
        {
            return Err(format!(
                "runtime copy parameter is consumed by opcode 0x{:02x} at 0x{:x}",
                instruction.opcode, instruction.pos
            ));
        }
        stack.truncate(stack.len() - inputs);
        stack.extend((0..info.outputs).map(|_| InitStackValue::Unknown));
    }

    Err("proven runtime CODECOPY has no matching RETURN".into())
}

fn invalidate_symbolic_memory(
    memory: &mut BTreeMap<usize, SymbolicWord>,
    destination: Option<usize>,
    destination_lower_bound: Option<usize>,
    length: Option<usize>,
) {
    if length == Some(0) {
        return;
    }
    let Some((destination, copy_end)) =
        destination.zip(length).and_then(|(destination, length)| {
            destination
                .checked_add(length)
                .map(|end| (destination, end))
        })
    else {
        if let Some(lower_bound) = destination_lower_bound {
            memory.retain(|word_start, _| {
                word_start
                    .checked_add(32)
                    .is_some_and(|word_end| word_end <= lower_bound)
            });
        } else {
            memory.clear();
        }
        return;
    };
    memory.retain(|word_start, _| {
        let Some(word_end) = word_start.checked_add(32) else {
            return false;
        };
        word_end <= destination || *word_start >= copy_end
    });
}

/// Symbolically execute reachable init-code control flow far enough to prove every CODECOPY
/// source range. This is deliberately a small constant-propagation engine, not a general EVM:
/// an unknown jump destination, unknown copy source/length, stack error, or state explosion is a
/// validation failure. That fail-closed boundary prevents a compiler-shape marker from being used
/// as a decoy in front of a malicious secondary runtime read.
fn reachable_codecopies(
    init: &[u8],
    instructions: &[ParsedInstruction],
    full_creation_input_len: usize,
    authoritative_copy_index: usize,
    authoritative_return_index: usize,
    free_memory_lower_bound: Option<usize>,
    allocator_store_indices: &BTreeSet<usize>,
) -> Result<BTreeSet<CodeCopyObservation>, String> {
    const MAX_SYMBOLIC_STATES: usize = 32_768;
    const EVM_STACK_LIMIT: usize = 1_024;

    let index_by_pc: HashMap<_, _> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.pos, index))
        .collect();
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::new();
    let initial = SymbolicState {
        instruction_index: 0,
        stack: Vec::new(),
        memory: BTreeMap::new(),
        authoritative_copy_seen: false,
    };
    seen.insert(initial.clone());
    queue.push_back(initial);
    let mut observations = BTreeSet::new();

    let constant = |value: &SymbolicWord| match value {
        SymbolicWord::Constant(value) => Some(*value),
        SymbolicWord::Unknown
        | SymbolicWord::AtLeast(_)
        | SymbolicWord::DerivedFromFreeMemory(_) => None,
    };
    let constant_usize =
        |value: &SymbolicWord| constant(value).and_then(|value| usize::try_from(value).ok());
    let lower_bound = |value: &SymbolicWord| match value {
        SymbolicWord::Constant(value) => usize::try_from(*value).ok(),
        SymbolicWord::AtLeast(value) => Some(*value),
        SymbolicWord::Unknown | SymbolicWord::DerivedFromFreeMemory(_) => None,
    };

    while let Some(mut state) = queue.pop_front() {
        let Some(instruction) = instructions.get(state.instruction_index) else {
            return Err("reachable init path falls off the end without terminating".into());
        };
        let index = state.instruction_index;
        let mut successors = Vec::new();

        match instruction.opcode {
            0x5f => state.stack.push(SymbolicWord::Constant(U256::ZERO)),
            0x60..=0x7f => {
                let value = if index == 0
                    && free_memory_lower_bound.is_some_and(|minimum| {
                        parsed_push_value(init, instruction) == Some(minimum)
                    }) {
                    // The compiler prologue's literal is an exact EVM value. Keeping it exact is
                    // both stronger and safer than prematurely widening it to a lower bound: it
                    // proves that constant-offset constructor writes cannot wrap onto memory 0x40.
                    // A recognized, overflow-guarded allocator store widens to AtLeast below only
                    // when its computed value is genuinely dynamic.
                    SymbolicWord::Constant(U256::from(
                        free_memory_lower_bound.expect("checked above"),
                    ))
                } else {
                    parsed_push_word(init, instruction)
                        .map(SymbolicWord::Constant)
                        .unwrap_or(SymbolicWord::Unknown)
                };
                state.stack.push(value);
            }
            0x38 => state
                .stack
                .push(SymbolicWord::Constant(U256::from(full_creation_input_len))),
            // PC is exact in the decoded init stream. This preserves proof through the trusted
            // constructor-argument transform's `PC + delta` trampoline without admitting an
            // unknown dynamic jump.
            0x58 => state
                .stack
                .push(SymbolicWord::Constant(U256::from(instruction.pos))),
            0x80..=0x8f => {
                let depth = usize::from(instruction.opcode - 0x7f);
                if depth == 0 || state.stack.len() < depth {
                    return Err(format!(
                        "reachable init stack underflow at DUP in 0x{:x}",
                        instruction.pos
                    ));
                }
                state
                    .stack
                    .push(state.stack[state.stack.len() - depth].clone());
            }
            0x90..=0x9f => {
                let depth = usize::from(instruction.opcode - 0x8f);
                if depth == 0 || state.stack.len() <= depth {
                    return Err(format!(
                        "reachable init stack underflow at SWAP in 0x{:x}",
                        instruction.pos
                    ));
                }
                let top = state.stack.len() - 1;
                state.stack.swap(top, top - depth);
            }
            0x01 | 0x02 | 0x03 | 0x04 | 0x06 | 0x10 | 0x11 | 0x14 | 0x16 | 0x17 | 0x18 | 0x1b
            | 0x1c => {
                if state.stack.len() < 2 {
                    return Err(format!(
                        "reachable init stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                let right = state.stack.pop().expect("length checked");
                let left = state.stack.pop().expect("length checked");
                let free_memory_output = if instruction.opcode == 0x01 {
                    match (&left, &right) {
                        (SymbolicWord::AtLeast(minimum), other)
                        | (other, SymbolicWord::AtLeast(minimum)) => {
                            // A nonzero ADD to an abstract lower bound can wrap modulo 2^256.
                            // Keep only its free-memory provenance until an admitted Solidity
                            // overflow guard proves and stores the rounded pointer.
                            if constant_usize(other) == Some(0) {
                                Some(SymbolicWord::AtLeast(*minimum))
                            } else {
                                Some(SymbolicWord::DerivedFromFreeMemory(*minimum))
                            }
                        }
                        (SymbolicWord::DerivedFromFreeMemory(minimum), _)
                        | (_, SymbolicWord::DerivedFromFreeMemory(minimum)) => {
                            Some(SymbolicWord::DerivedFromFreeMemory(*minimum))
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let output = match (constant(&left), constant(&right)) {
                    (Some(left), Some(right)) => match instruction.opcode {
                        0x01 => Some(left.wrapping_add(right)),
                        0x02 => Some(left.wrapping_mul(right)),
                        // EVM's top stack item is the first operand for non-commutative ops.
                        0x03 => Some(right.wrapping_sub(left)),
                        0x04 => (left != 0).then(|| right / left),
                        0x06 => (left != 0).then(|| right % left),
                        0x10 => Some(U256::from(right < left)),
                        0x11 => Some(U256::from(right > left)),
                        0x14 => Some(U256::from(left == right)),
                        0x16 => Some(left & right),
                        0x17 => Some(left | right),
                        0x18 => Some(left ^ right),
                        // EVM shifts take the shift amount from the top of stack and the value
                        // from the next word (unlike SUB/LT, the operands have different roles).
                        0x1b => Some(if right < U256::from(256) {
                            left.wrapping_shl(right.to::<usize>())
                        } else {
                            U256::ZERO
                        }),
                        0x1c => Some(if right < U256::from(256) {
                            left.wrapping_shr(right.to::<usize>())
                        } else {
                            U256::ZERO
                        }),
                        _ => unreachable!(),
                    },
                    _ => None,
                };
                state.stack.push(free_memory_output.unwrap_or_else(|| {
                    output
                        .map(SymbolicWord::Constant)
                        .unwrap_or(SymbolicWord::Unknown)
                }));
            }
            0x19 => {
                let Some(value) = state.stack.pop() else {
                    return Err(format!(
                        "reachable init stack underflow at NOT in 0x{:x}",
                        instruction.pos
                    ));
                };
                state.stack.push(match constant(&value) {
                    Some(value) => SymbolicWord::Constant(!value),
                    None => SymbolicWord::Unknown,
                });
            }
            0x51 => {
                let Some(address) = state.stack.pop() else {
                    return Err(format!(
                        "reachable init stack underflow at MLOAD in 0x{:x}",
                        instruction.pos
                    ));
                };
                let value = constant_usize(&address)
                    .and_then(|address| state.memory.get(&address).cloned())
                    .unwrap_or(SymbolicWord::Unknown);
                state.stack.push(value);
            }
            0x52 => {
                if state.stack.len() < 2 {
                    return Err(format!(
                        "reachable init stack underflow at MSTORE in 0x{:x}",
                        instruction.pos
                    ));
                }
                let address = state.stack.pop().expect("length checked");
                let mut value = state.stack.pop().expect("length checked");
                let exact_address = constant_usize(&address);
                let address_lower_bound = lower_bound(&address);
                let prior_free_memory_lower_bound = state.memory.get(&0x40).and_then(&lower_bound);
                if let Some(address) = exact_address {
                    if address == 0x40
                        && matches!(
                            value,
                            SymbolicWord::Unknown | SymbolicWord::DerivedFromFreeMemory(_)
                        )
                        && allocator_store_indices.contains(&index)
                        && free_memory_lower_bound.is_some_and(|minimum| {
                            prior_free_memory_lower_bound.is_some_and(|current| current >= minimum)
                        })
                    {
                        value =
                            SymbolicWord::AtLeast(free_memory_lower_bound.expect("checked above"));
                    }
                    invalidate_symbolic_memory(
                        &mut state.memory,
                        exact_address,
                        address_lower_bound,
                        Some(32),
                    );
                    state.memory.insert(address, value);
                } else {
                    invalidate_symbolic_memory(
                        &mut state.memory,
                        None,
                        address_lower_bound,
                        Some(32),
                    );
                }
            }
            0x53 => {
                if state.stack.len() < 2 {
                    return Err(format!(
                        "reachable init stack underflow at MSTORE8 in 0x{:x}",
                        instruction.pos
                    ));
                }
                let address = state.stack.pop().expect("length checked");
                state.stack.pop();
                invalidate_symbolic_memory(
                    &mut state.memory,
                    constant_usize(&address),
                    lower_bound(&address),
                    Some(1),
                );
            }
            0x39 => {
                if state.stack.len() < 3 {
                    return Err(format!(
                        "reachable CODECOPY stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                let destination = state.stack.pop().expect("length checked");
                let source = state.stack.pop().expect("length checked");
                let length = state.stack.pop().expect("length checked");
                let exact_length = constant_usize(&length);
                // CODECOPY with an exact zero length neither reads code nor touches memory. Its
                // other operands are therefore semantically inert; canonicalizing them prevents
                // harmless CODESIZE-dependent constructor-argument expressions from appearing to
                // change when the creation artifact moves.
                let inert = exact_length == Some(0);
                observations.insert(CodeCopyObservation {
                    instruction_index: index,
                    destination: inert.then_some(0).or_else(|| constant_usize(&destination)),
                    destination_lower_bound: inert
                        .then_some(0)
                        .or_else(|| lower_bound(&destination)),
                    source: inert.then_some(0).or_else(|| constant_usize(&source)),
                    length: exact_length,
                });
                invalidate_symbolic_memory(
                    &mut state.memory,
                    constant_usize(&destination),
                    lower_bound(&destination),
                    constant_usize(&length),
                );
                if index == authoritative_copy_index {
                    state.authoritative_copy_seen = true;
                }
            }
            0xf1 | 0xf2 => {
                if state.stack.len() < 7 {
                    return Err(format!(
                        "reachable init call stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                let args_start = state.stack.len() - 7;
                let output_size = constant_usize(&state.stack[args_start]);
                let output_offset = constant_usize(&state.stack[args_start + 1]);
                let output_offset_lower_bound = lower_bound(&state.stack[args_start + 1]);
                invalidate_symbolic_memory(
                    &mut state.memory,
                    output_offset,
                    output_offset_lower_bound,
                    output_size,
                );
                state.stack.truncate(args_start);
                state.stack.push(SymbolicWord::Unknown);
            }
            0xf4 | 0xfa => {
                if state.stack.len() < 6 {
                    return Err(format!(
                        "reachable init call stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                let args_start = state.stack.len() - 6;
                let output_size = constant_usize(&state.stack[args_start]);
                let output_offset = constant_usize(&state.stack[args_start + 1]);
                let output_offset_lower_bound = lower_bound(&state.stack[args_start + 1]);
                invalidate_symbolic_memory(
                    &mut state.memory,
                    output_offset,
                    output_offset_lower_bound,
                    output_size,
                );
                state.stack.truncate(args_start);
                state.stack.push(SymbolicWord::Unknown);
            }
            0x56 | 0x57 => {
                let inputs = if instruction.opcode == 0x57 { 2 } else { 1 };
                if state.stack.len() < inputs {
                    return Err(format!(
                        "reachable init jump stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                let destination = state.stack.pop().expect("length checked");
                let condition = (instruction.opcode == 0x57)
                    .then(|| state.stack.pop().expect("length checked"));
                let can_take_jump = condition
                    .as_ref()
                    .and_then(constant)
                    .is_none_or(|condition| condition != U256::ZERO);
                let can_fall_through = instruction.opcode == 0x57
                    && condition
                        .as_ref()
                        .and_then(constant)
                        .is_none_or(|condition| condition == U256::ZERO);
                if can_take_jump {
                    let target_pc = constant_usize(&destination).ok_or_else(|| {
                        format!(
                            "reachable init jump at 0x{:x} has an unknown destination",
                            instruction.pos
                        )
                    })?;
                    let target = index_by_pc.get(&target_pc).copied().ok_or_else(|| {
                        format!(
                            "reachable init jump at 0x{:x} targets non-instruction 0x{target_pc:x}",
                            instruction.pos
                        )
                    })?;
                    if instructions[target].opcode != 0x5b {
                        return Err(format!(
                            "reachable init jump at 0x{:x} targets non-JUMPDEST 0x{target_pc:x}",
                            instruction.pos
                        ));
                    }
                    successors.push(target);
                }
                if can_fall_through {
                    successors.push(index + 1);
                }
            }
            0xf3 => {
                if !state.authoritative_copy_seen {
                    return Err(format!(
                        "reachable successful RETURN at 0x{:x} bypasses the proven runtime CODECOPY",
                        instruction.pos
                    ));
                }
                if index != authoritative_return_index {
                    return Err(format!(
                        "reachable successful RETURN at 0x{:x} is not the proven runtime RETURN",
                        instruction.pos
                    ));
                }
                continue;
            }
            0x00 | 0xfd | 0xfe | 0xff => continue,
            _ => {
                if matches!(instruction.opcode, 0x37 | 0x3c | 0x3e | 0x5e) {
                    state.memory.clear();
                }
                let opcode = Opcode::from_byte(instruction.opcode);
                let info = opcode.info().ok_or_else(|| {
                    format!(
                        "unknown reachable init opcode 0x{:02x} at 0x{:x}",
                        instruction.opcode, instruction.pos
                    )
                })?;
                let inputs = usize::from(info.inputs);
                if state.stack.len() < inputs {
                    return Err(format!(
                        "reachable init stack underflow at 0x{:x}",
                        instruction.pos
                    ));
                }
                state.stack.truncate(state.stack.len() - inputs);
                state
                    .stack
                    .extend((0..info.outputs).map(|_| SymbolicWord::Unknown));
            }
        }

        if state.stack.len() > EVM_STACK_LIMIT {
            return Err("reachable init path exceeds the EVM stack limit".into());
        }
        if successors.is_empty() {
            successors.push(index + 1);
        }
        for successor in successors {
            let successor_state = SymbolicState {
                instruction_index: successor,
                stack: state.stack.clone(),
                memory: state.memory.clone(),
                authoritative_copy_seen: state.authoritative_copy_seen,
            };
            if seen.insert(successor_state.clone()) {
                if seen.len() > MAX_SYMBOLIC_STATES {
                    return Err("init CODECOPY proof exceeded its symbolic-state limit".into());
                }
                queue.push_back(successor_state);
            }
        }
    }

    Ok(observations)
}

/// Returns the byte offsets of Solidity immutable words within an unlinked runtime template.
///
/// Solidity represents every immutable use as `PUSH32` followed by exactly 32 zero bytes in the
/// creation artifact's runtime template. Decoding instruction boundaries is important: a run of
/// zeros inside another PUSH immediate or metadata is not an immutable placeholder.
fn immutable_placeholder_offsets(runtime: &[u8]) -> Result<Vec<usize>, String> {
    let instructions = parse_instructions(runtime, "runtime template")?;
    let mut offsets = Vec::new();
    for instruction in instructions {
        if instruction.opcode != 0x7f {
            continue;
        }
        let immediate_start = instruction.pos + 1;
        let immediate_end = immediate_start + 32;
        if runtime[immediate_start..immediate_end]
            .iter()
            .all(|byte| *byte == 0)
        {
            offsets.push(immediate_start);
        }
    }
    Ok(offsets)
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
    /// Authenticate how init code constructs the supplied deployed-runtime template.
    ///
    /// Runtime layout is safe to change only when the creation program has one proven copy of
    /// the exact reported runtime range and returns that same memory range without inspecting or
    /// mutating it. The only admitted mutation is Solidity's exact immutable materialization
    /// (`PUSH <placeholder>; ADD; MSTORE`) for every PUSH32-zero carrier in the template.
    ///
    /// This check is intentionally required even for size-neutral transforms: block shuffling
    /// changes which bytes an init-time hash, storage write, or arbitrary memory patch observes.
    pub fn validate_init_runtime_contract(
        &self,
        original_clean_runtime: &[u8],
    ) -> Result<(), String> {
        let Some(init_section) = self
            .removed
            .iter()
            .find(|removed| removed.kind == SectionKind::Init)
        else {
            return Ok(());
        };
        if original_clean_runtime.len() != self.clean_len {
            return Err(format!(
                "original clean runtime length mismatch: report={}, supplied={}",
                self.clean_len,
                original_clean_runtime.len()
            ));
        }
        if self.runtime_layout.len() != 1 || self.runtime_layout[0].len != self.clean_len {
            return Err("init/runtime validation requires one contiguous runtime template".into());
        }

        let runtime_start = self.runtime_layout[0].offset;
        let deployed_suffix_len = self
            .removed
            .iter()
            .filter(|removed| {
                removed.offset >= runtime_start
                    && !matches!(removed.kind, SectionKind::ConstructorArgs)
            })
            .try_fold(0usize, |total, removed| {
                total.checked_add(removed.data.len())
            })
            .ok_or("deployed runtime suffix length overflow")?;
        let deployed_runtime_len = self
            .clean_len
            .checked_add(deployed_suffix_len)
            .ok_or("deployed runtime length overflow")?;
        let creation_len = runtime_start
            .checked_add(deployed_runtime_len)
            .ok_or("creation bytecode length overflow")?;
        let init = init_section.data.as_ref();
        let instructions = parse_instructions(init, "init code")?;
        let placeholders: std::collections::BTreeSet<_> =
            immutable_placeholder_offsets(original_clean_runtime)?
                .into_iter()
                .collect();
        let contract = locate_runtime_copy(
            init,
            &instructions,
            runtime_start,
            deployed_runtime_len,
            Some(&placeholders),
        )?;

        let full_creation_input_len = self
            .runtime_layout
            .iter()
            .map(|span| span.offset.checked_add(span.len))
            .chain(
                self.removed
                    .iter()
                    .map(|removed| removed.offset.checked_add(removed.data.len())),
            )
            .try_fold(0usize, |largest, end| end.map(|end| largest.max(end)))
            .ok_or("creation input layout overflow")?;
        let copy_observations = reachable_codecopies(
            init,
            &instructions,
            full_creation_input_len,
            contract.copy_index,
            contract.return_index,
            contract.free_memory_lower_bound,
            &contract.allocator_store_indices,
        )?;
        let mut observed_copy_indices = BTreeSet::new();
        let mut authoritative_destinations = BTreeSet::new();
        for observation in &copy_observations {
            observed_copy_indices.insert(observation.instruction_index);
            if observation.instruction_index == contract.copy_index {
                if observation.source != Some(runtime_start)
                    || observation.length != Some(deployed_runtime_len)
                {
                    return Err("reachable runtime CODECOPY arguments do not match the reported runtime span".into());
                }
                let lower_bound = observation.destination_lower_bound.ok_or_else(|| {
                    format!(
                        "reachable runtime CODECOPY destination has no proven lower bound: {copy_observations:?}"
                    )
                })?;
                authoritative_destinations.insert((observation.destination, lower_bound));
                continue;
            }

            let length = observation.length.ok_or_else(|| {
                format!(
                    "secondary CODECOPY at 0x{:x} has an unproven length",
                    instructions[observation.instruction_index].pos
                )
            })?;
            if length == 0 {
                continue;
            }
            let source = observation.source.ok_or_else(|| {
                format!(
                    "secondary CODECOPY at 0x{:x} has an unproven source",
                    instructions[observation.instruction_index].pos
                )
            })?;
            let end = source
                .checked_add(length)
                .ok_or("secondary CODECOPY range overflow")?;
            if source < creation_len || end > full_creation_input_len {
                return Err(format!(
                    "secondary CODECOPY at 0x{:x} is not wholly within constructor arguments 0x{creation_len:x}..0x{full_creation_input_len:x}",
                    instructions[observation.instruction_index].pos
                ));
            }
        }
        if authoritative_destinations.is_empty() {
            return Err("the proven runtime CODECOPY is unreachable".into());
        }
        for (pc, read) in &contract.memory_reads {
            let InitStackValue::Constant(read_start) = read else {
                return Err(format!(
                    "MLOAD at 0x{pc:x} has no proven address disjoint from copied runtime"
                ));
            };
            let read_end = read_start.checked_add(32).ok_or("MLOAD range overflow")?;
            for (exact_start, lower_bound) in &authoritative_destinations {
                if let Some(runtime_memory_start) = exact_start {
                    let runtime_memory_end = runtime_memory_start
                        .checked_add(deployed_runtime_len)
                        .ok_or("runtime memory range overflow")?;
                    if *read_start < runtime_memory_end && read_end > *runtime_memory_start {
                        return Err(format!(
                            "MLOAD at 0x{pc:x} intersects copied runtime memory 0x{runtime_memory_start:x}..0x{runtime_memory_end:x}"
                        ));
                    }
                } else if read_end > *lower_bound {
                    return Err(format!(
                        "MLOAD at 0x{pc:x} is not below the proven runtime-memory lower bound 0x{lower_bound:x}"
                    ));
                }
            }
        }
        for (index, instruction) in instructions.iter().enumerate() {
            if instruction.opcode == 0x39 && !observed_copy_indices.contains(&index) {
                return Err(format!(
                    "CODECOPY at 0x{:x} has no proven reachable argument state",
                    instruction.pos
                ));
            }
        }

        for (index, instruction) in instructions.iter().enumerate() {
            if instruction.opcode == 0xf3 && index != contract.return_index {
                return Err(format!(
                    "init contains an alternative RETURN at 0x{:x}",
                    instruction.pos
                ));
            }
            if matches!(instruction.opcode, 0x3b | 0x3c | 0x3f | 0x58) {
                return Err(format!(
                    "init contains code-observation opcode 0x{:02x} at 0x{:x}",
                    instruction.opcode, instruction.pos
                ));
            }
        }

        Ok(())
    }

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
        let constructor_args_len: usize = self
            .removed
            .iter()
            .filter(|removed| matches!(removed.kind, SectionKind::ConstructorArgs))
            .map(|removed| removed.data.len())
            .sum();

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

        let parsed_init = parse_instructions(&init_bytes, "init code")?;
        let copy_contract = locate_runtime_copy(
            &init_bytes,
            &parsed_init,
            original_runtime_offset,
            original_deployed_runtime_len,
            None,
        )?;
        let layout_changed = new_runtime_offset != original_runtime_offset
            || new_deployed_runtime_len != original_deployed_runtime_len;
        // Even Solidity's `PUSH base; DUP1; CODESIZE; SUB` idiom leaves the relocated base below
        // the invariant argument length. Without complete downstream taint proof, that retained
        // value could reach storage, a log, or a call. Reject every size-changing rewrite that can
        // observe CODESIZE; patching a familiar syntax alone is not a semantic proof.
        if layout_changed
            && parsed_init
                .iter()
                .any(|instruction| instruction.opcode == 0x38)
        {
            return Err(
                "runtime-size relocation is unsupported when init code observes CODESIZE".into(),
            );
        }
        let has_secondary_codecopy = parsed_init.iter().enumerate().any(|(index, instruction)| {
            instruction.opcode == 0x39 && index != copy_contract.copy_index
        });
        // Snapshot every proven secondary constructor copy before changing layout. A later proof
        // requires the same copy to retain its destination and length while its source moves by
        // exactly the creation-length delta. This prevents a decoy canonical base marker from
        // authorizing an unrelated stale CODECOPY source.
        let old_secondary_copies = if layout_changed && has_secondary_codecopy {
            let old_full_input_len = original_creation_len
                .checked_add(constructor_args_len)
                .ok_or("original creation input length overflow")?;
            Some(
                reachable_codecopies(
                    &init_bytes,
                    &parsed_init,
                    old_full_input_len,
                    copy_contract.copy_index,
                    copy_contract.return_index,
                    copy_contract.free_memory_lower_bound,
                    &copy_contract.allocator_store_indices,
                )?
                .into_iter()
                .filter(|observation| observation.instruction_index != copy_contract.copy_index)
                .collect::<BTreeSet<_>>(),
            )
        } else {
            None
        };

        // Every edit below names a decoded PUSH instruction that the stack proof established as
        // either CODECOPY's size/source or RETURN's size. No byte inside another immediate can be
        // selected, and a missing independent RETURN length is an error rather than false success.
        for info in &copy_contract.length_pushes {
            write_push_value(&mut init_bytes, info, new_deployed_runtime_len)?;
            tracing::debug!(
                "Updated proven runtime length PUSH at 0x{:x} to 0x{:x}",
                info.pos,
                new_deployed_runtime_len
            );
        }
        write_push_value(
            &mut init_bytes,
            &copy_contract.source_push,
            new_runtime_offset,
        )?;
        tracing::debug!(
            "Updated proven runtime source PUSH at 0x{:x} to 0x{:x}",
            copy_contract.source_push.pos,
            new_runtime_offset
        );

        if original_creation_len != new_creation_len {
            let patched = patch_constructor_arg_base(
                &mut init_bytes,
                original_creation_len,
                new_creation_len,
            )?;
            // A caller may obfuscate bare creation bytecode and append its constructor
            // arguments afterwards. Patch a supported constructor-copy base whenever it is
            // present, but only require it when this payload already contains arguments.
            if patched == 0 && (has_constructor_args || has_secondary_codecopy) {
                return Err(format!(
                    "Could not locate constructor argument base 0x{:x} before CODESIZE/SUB",
                    original_creation_len
                ));
            }
        }

        if layout_changed {
            let updated_instructions = parse_instructions(&init_bytes, "updated init code")?;
            let updated_contract = locate_runtime_copy(
                &init_bytes,
                &updated_instructions,
                new_runtime_offset,
                new_deployed_runtime_len,
                None,
            )?;
            if updated_contract.copy_index != copy_contract.copy_index {
                return Err("runtime CODECOPY identity changed while patching init code".into());
            }
            let new_full_input_len = new_creation_len
                .checked_add(constructor_args_len)
                .ok_or("updated creation input length overflow")?;
            let updated_copy_observations = reachable_codecopies(
                &init_bytes,
                &updated_instructions,
                new_full_input_len,
                updated_contract.copy_index,
                updated_contract.return_index,
                updated_contract.free_memory_lower_bound,
                &updated_contract.allocator_store_indices,
            )?;
            let mut updated_destinations = BTreeSet::new();
            for observation in &updated_copy_observations {
                if observation.instruction_index != updated_contract.copy_index {
                    continue;
                }
                if observation.source != Some(new_runtime_offset)
                    || observation.length != Some(new_deployed_runtime_len)
                {
                    return Err(
                        "updated runtime CODECOPY arguments do not match the rewritten runtime span"
                            .into(),
                    );
                }
                let lower_bound = observation
                    .destination_lower_bound
                    .ok_or("updated runtime CODECOPY destination has no proven lower bound")?;
                updated_destinations.insert((observation.destination, lower_bound));
            }
            if updated_destinations.is_empty() {
                return Err("updated proven runtime CODECOPY is unreachable".into());
            }
            for (pc, read) in &updated_contract.memory_reads {
                let InitStackValue::Constant(read_start) = read else {
                    return Err(format!(
                        "updated MLOAD at 0x{pc:x} has no proven address disjoint from copied runtime"
                    ));
                };
                let read_end = read_start
                    .checked_add(32)
                    .ok_or("updated MLOAD range overflow")?;
                for (exact_start, lower_bound) in &updated_destinations {
                    if let Some(runtime_memory_start) = exact_start {
                        let runtime_memory_end = runtime_memory_start
                            .checked_add(new_deployed_runtime_len)
                            .ok_or("updated runtime memory range overflow")?;
                        if *read_start < runtime_memory_end && read_end > *runtime_memory_start {
                            return Err(format!(
                                "updated MLOAD at 0x{pc:x} intersects copied runtime memory 0x{runtime_memory_start:x}..0x{runtime_memory_end:x}"
                            ));
                        }
                    } else if read_end > *lower_bound {
                        return Err(format!(
                            "updated MLOAD at 0x{pc:x} is not below the proven runtime-memory lower bound 0x{lower_bound:x}"
                        ));
                    }
                }
            }
            let updated_secondary_copies = updated_copy_observations
                .into_iter()
                .filter(|observation| observation.instruction_index != updated_contract.copy_index)
                .collect::<BTreeSet<_>>();

            if let Some(old_secondary_copies) = old_secondary_copies {
                let move_source = |source: usize| -> Result<usize, String> {
                    if new_creation_len >= original_creation_len {
                        source
                            .checked_add(new_creation_len - original_creation_len)
                            .ok_or_else(|| "constructor CODECOPY source overflow".into())
                    } else {
                        source
                            .checked_sub(original_creation_len - new_creation_len)
                            .ok_or_else(|| "constructor CODECOPY source underflow".into())
                    }
                };
                let mut expected_secondary_copies = BTreeSet::new();
                for mut observation in old_secondary_copies {
                    let length = observation.length.ok_or_else(|| {
                        format!(
                            "secondary CODECOPY at instruction {} has an unproven original length",
                            observation.instruction_index
                        )
                    })?;
                    if length == 0 {
                        expected_secondary_copies.insert(observation);
                        continue;
                    }
                    let old_source = observation.source.ok_or_else(|| {
                        format!(
                            "secondary CODECOPY at instruction {} has an unproven original source",
                            observation.instruction_index
                        )
                    })?;
                    observation.source = Some(move_source(old_source)?);
                    expected_secondary_copies.insert(observation);
                }
                if updated_secondary_copies != expected_secondary_copies {
                    return Err(format!(
                        "secondary constructor CODECOPY provenance changed unexpectedly: expected {expected_secondary_copies:?}, found {updated_secondary_copies:?}"
                    ));
                }
            }
        }

        tracing::debug!(
            "Updated init code CODECOPY/RETURN for runtime offset=0x{:x}, len=0x{:x}",
            new_runtime_offset,
            new_deployed_runtime_len
        );

        init_section.data = Bytes::from(init_bytes);

        Ok(())
    }

    /// Patch compiler-proven Solidity immutable reference offsets in the init code.
    ///
    /// This intentionally supports one narrow, auditable lowering contract:
    ///
    /// 1. An immutable use must be an exact `PUSH32` plus 32 zero-byte placeholder in the
    ///    original clean runtime template.
    /// 2. The init code must contain exactly one Solidity runtime-copy sequence for the report's
    ///    exact runtime source offset and deployed-runtime length.
    /// 3. Between that `CODECOPY` and the next control-transfer instruction (which must be
    ///    `RETURN`), every placeholder must have exactly one contiguous
    ///    `PUSH<n> <placeholder>; ADD; MSTORE` reference.
    ///
    /// Any missing or duplicate reference, missing remap, malformed PUSH, or width overflow is an
    /// error. Edits are committed only after every reference validates, so failure is atomic. In
    /// particular, constructor arithmetic that merely happens to use an in-range constant is never
    /// rewritten.
    pub fn patch_init_immutable_refs(
        &mut self,
        original_clean_runtime: &[u8],
        remap: &dyn Fn(usize) -> Option<usize>,
    ) -> Result<(), String> {
        if original_clean_runtime.len() != self.clean_len {
            return Err(format!(
                "original clean runtime length mismatch: report={}, supplied={}",
                self.clean_len,
                original_clean_runtime.len()
            ));
        }

        let placeholders = immutable_placeholder_offsets(original_clean_runtime)?;
        if placeholders.is_empty() {
            return Ok(());
        }
        if self.runtime_layout.len() != 1 || self.runtime_layout[0].len != self.clean_len {
            return Err(
                "Solidity immutable relocation requires one contiguous runtime template".into(),
            );
        }

        let runtime_start = self
            .runtime_layout
            .iter()
            .map(|span| span.offset)
            .min()
            .ok_or("No runtime layout found")?;
        let deployed_suffix_len = self
            .removed
            .iter()
            .filter(|removed| {
                removed.offset >= runtime_start
                    && !matches!(removed.kind, SectionKind::ConstructorArgs)
            })
            .try_fold(0usize, |total, removed| {
                total.checked_add(removed.data.len())
            })
            .ok_or("deployed runtime suffix length overflow")?;
        let original_deployed_runtime_len = self
            .clean_len
            .checked_add(deployed_suffix_len)
            .ok_or("deployed runtime length overflow")?;

        let init_section = self
            .removed
            .iter()
            .find(|r| matches!(r.kind, SectionKind::Init))
            .ok_or("No Init section found")?;

        let original_init = init_section.data.to_vec();
        let instructions = parse_instructions(&original_init, "init code")?;

        // Solidity's terminal runtime-copy sequence is:
        //   PUSH<n> runtime_len; SWAP1; DUP2; PUSH<n> runtime_start; DUP3; CODECOPY
        // Exact values and exact opcode adjacency make this a compiler-shape check rather than a
        // search for coincidental constants near an arbitrary CODECOPY.
        let copy_candidates: Vec<usize> = (5..instructions.len())
            .filter(|index| {
                let index = *index;
                instructions[index].opcode == 0x39
                    && instructions[index - 4].opcode == 0x90
                    && instructions[index - 3].opcode == 0x81
                    && instructions[index - 1].opcode == 0x82
                    && parsed_push_value(&original_init, &instructions[index - 5])
                        == Some(original_deployed_runtime_len)
                    && parsed_push_value(&original_init, &instructions[index - 2])
                        == Some(runtime_start)
            })
            .collect();
        let copy_index = match copy_candidates.as_slice() {
            [index] => *index,
            [] => {
                return Err(format!(
                    "no exact Solidity runtime CODECOPY found for source 0x{runtime_start:x} and length 0x{original_deployed_runtime_len:x}"
                ));
            }
            candidates => {
                return Err(format!(
                    "ambiguous Solidity runtime CODECOPY: found {} exact candidates",
                    candidates.len()
                ));
            }
        };

        let control_transfer = instructions
            .iter()
            .enumerate()
            .skip(copy_index + 1)
            .find(|(_, instruction)| {
                matches!(
                    instruction.opcode,
                    0x00 | 0x56 | 0x57 | 0xf3 | 0xfd | 0xfe | 0xff
                )
            })
            .ok_or("Solidity runtime CODECOPY has no following control transfer")?;
        if control_transfer.1.opcode != 0xf3 {
            return Err(format!(
                "Solidity runtime-copy window ends with opcode 0x{:02x} at 0x{:x}, not RETURN",
                control_transfer.1.opcode, control_transfer.1.pos
            ));
        }
        let return_index = control_transfer.0;

        let mut edits = Vec::with_capacity(placeholders.len());
        for placeholder in placeholders {
            let candidates: Vec<&ParsedInstruction> = (copy_index + 1
                ..return_index.saturating_sub(1))
                .filter_map(|index| {
                    let instruction = &instructions[index];
                    (parsed_push_value(&original_init, instruction) == Some(placeholder)
                        && instructions[index + 1].opcode == 0x01
                        && instructions[index + 2].opcode == 0x52)
                        .then_some(instruction)
                })
                .collect();
            let reference = match candidates.as_slice() {
                [reference] => *reference,
                [] => {
                    return Err(format!(
                        "immutable placeholder at runtime offset 0x{placeholder:x} has no exact constructor reference"
                    ));
                }
                references => {
                    return Err(format!(
                        "immutable placeholder at runtime offset 0x{placeholder:x} has {} constructor references",
                        references.len()
                    ));
                }
            };
            let new_value = remap(placeholder).ok_or_else(|| {
                format!("immutable placeholder at runtime offset 0x{placeholder:x} has no remap")
            })?;
            let width = reference
                .push_width
                .expect("an instruction with a parsed push value is a PUSH");
            if width < std::mem::size_of::<usize>() && new_value >= (1usize << (width * 8)) {
                return Err(format!(
                    "immutable remap 0x{new_value:x} does not fit in PUSH{width} at init offset 0x{:x}",
                    reference.pos
                ));
            }
            edits.push((reference.pos, width, placeholder, new_value));
        }

        // All validation above used an immutable snapshot. Apply to a fresh clone and publish it
        // only once every edit is known to fit.
        let mut patched_init = original_init;
        for (pos, width, old_value, new_value) in &edits {
            let bit_width = usize::BITS as usize;
            for index in 0..*width {
                let shift = (*width - 1 - index) * 8;
                patched_init[*pos + 1 + index] = if shift >= bit_width {
                    0
                } else {
                    ((new_value >> shift) & 0xff) as u8
                };
            }
            tracing::debug!(
                "Patched Solidity immutable reference at init offset 0x{:x}: 0x{:x} -> 0x{:x}",
                pos,
                old_value,
                new_value
            );
        }
        self.removed
            .iter_mut()
            .find(|removed| matches!(removed.kind, SectionKind::Init))
            .expect("the init section was validated above")
            .data = Bytes::from(patched_init);
        tracing::debug!("Patched {} Solidity immutable references", edits.len());

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

    /// Reassemble bytecode with the same fail-closed guarantees as
    /// [`Self::reassemble_checked`]. This compatibility name now returns an error rather than
    /// emitting deployment bytecode after a required init-code patch failed.
    pub fn reassemble(&mut self, clean: &[u8]) -> Result<Vec<u8>, String> {
        self.reassemble_checked(clean)
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
    use super::{CleanReport, immutable_placeholder_offsets, strip_bytecode};
    use crate::detection::{Section, SectionKind};
    use crate::result::Error;
    use revm::primitives::B256;
    use sha3::{Digest, Keccak256};
    fn section(kind: SectionKind, offset: usize, len: usize) -> Section {
        Section { kind, offset, len }
    }

    fn runtime_with_immutable_placeholders(count: usize) -> (Vec<u8>, Vec<usize>) {
        let mut runtime = Vec::new();
        let mut placeholders = Vec::new();
        for _ in 0..count {
            runtime.push(0x7f); // PUSH32
            placeholders.push(runtime.len());
            runtime.extend_from_slice(&[0u8; 32]);
            runtime.push(0x50); // POP
        }
        runtime.push(0x00); // STOP
        (runtime, placeholders)
    }

    fn immutable_report(
        runtime: &[u8],
        references: &[usize],
        unrelated_add: Option<usize>,
    ) -> (CleanReport, Vec<usize>, Option<usize>) {
        assert!(runtime.len() < 0x100);
        assert!(references.iter().all(|offset| *offset < 0x100));

        // Exact Solidity terminal copy shape accepted by patch_init_immutable_refs.
        let mut init = vec![
            0x60,
            0x40, // PUSH1 0x40
            0x51, // MLOAD
            0x60,
            runtime.len() as u8, // PUSH1 runtime length
            0x90,                // SWAP1
            0x81,                // DUP2
            0x60,
            0x00, // PUSH1 runtime source; filled after init length is known
            0x82, // DUP3
            0x39, // CODECOPY
        ];
        let unrelated_immediate = unrelated_add.map(|value| {
            assert!(value < 0x100);
            let immediate = init.len() + 1;
            init.extend_from_slice(&[0x60, value as u8, 0x01, 0x50]); // PUSH1; ADD; POP
            immediate
        });
        let mut reference_immediates = Vec::new();
        for reference in references {
            reference_immediates.push(init.len() + 1);
            init.extend_from_slice(&[0x60, *reference as u8, 0x01, 0x52]); // PUSH1; ADD; MSTORE
        }
        init.push(0xf3); // RETURN
        assert!(init.len() < 0x100);
        init[8] = init.len() as u8;

        let bytes = [init.as_slice(), runtime].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (_, report) = strip_bytecode(&bytes, &sections).unwrap();
        (report, reference_immediates, unrelated_immediate)
    }

    fn init_bytes(report: &CleanReport) -> Vec<u8> {
        report
            .removed
            .iter()
            .find(|removed| removed.kind == SectionKind::Init)
            .expect("fixture has init code")
            .data
            .to_vec()
    }

    #[test]
    fn init_validation_rejects_successful_return_that_bypasses_runtime_copy() {
        // CALLVALUE chooses either the valid copy path or a direct entry into the proven RETURN
        // window. A syntactic CODECOPY/RETURN match alone must not authorize the latter path.
        let init = vec![
            0x34, 0x60, 0x0a, 0x57, // CALLVALUE; PUSH1 return_window; JUMPI
            0x60, 0x01, 0x60, 0x0f, 0x5f, 0x39, // copy one runtime byte
            0x5b, 0x60, 0x01, 0x5f, 0xf3, // return_window: RETURN(0, 1)
        ];
        let runtime = vec![0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (clean, report) = strip_bytecode(&bytes, &sections).unwrap();

        let error = report
            .validate_init_runtime_contract(&clean)
            .expect_err("a successful RETURN must be dominated by the runtime copy");

        assert!(
            error.contains("bypasses the proven runtime CODECOPY"),
            "{error}"
        );
    }

    #[test]
    fn size_relocation_rechecks_post_copy_memory_reads_against_new_length() {
        // MLOAD(1) is disjoint from the original one-byte [0,1) copy but intersects [0,2)
        // after growth. Updated lowering must reject rather than merely patching length PUSHes.
        let init = vec![
            0x60, 0x01, 0x60, 0x0e, 0x5f, 0x39, // CODECOPY(0, 0x0e, 1)
            0x60, 0x01, 0x51, 0x50, // MLOAD(1); POP
            0x60, 0x01, 0x5f, 0xf3, // RETURN(0, 1)
        ];
        let runtime = vec![0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (clean, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        report.validate_init_runtime_contract(&clean).unwrap();

        let error = report
            .reassemble_checked(&[0x00, 0x00])
            .expect_err("runtime growth must recheck post-copy reads");

        assert!(
            error.contains("updated MLOAD") && error.contains("intersects"),
            "{error}"
        );
    }

    #[test]
    fn size_relocation_rejects_init_codesize_observation() {
        let init = vec![
            0x38, 0x50, // CODESIZE; POP -- still an observable size dependency
            0x60, 0x01, 0x60, 0x0c, 0x5f, 0x39, // CODECOPY(0, 0x0c, 1)
            0x60, 0x01, 0x5f, 0xf3, // RETURN(0, 1)
        ];
        let runtime = vec![0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (clean, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        report.validate_init_runtime_contract(&clean).unwrap();

        let error = report
            .reassemble_checked(&[0x00, 0x00])
            .expect_err("CODESIZE-dependent init cannot be soundly resized");

        assert!(error.contains("observes CODESIZE"), "{error}");
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
        let rebuilt = report.reassemble(&clean).unwrap();

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
        let rebuilt = report.reassemble(&new_runtime).unwrap();

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
    fn reassembly_rejects_constructor_base_without_downstream_codesize_proof() {
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

        let before = init_bytes(&report);
        let error = report
            .reassemble_checked(&grown_runtime)
            .expect_err("constructor-base syntax alone must not authorize CODESIZE relocation");

        assert_eq!(
            init_bytes(&report),
            before,
            "failed size relocation must leave init code unchanged"
        );
        assert!(error.contains("observes CODESIZE"), "{error}");
    }

    #[test]
    fn reassembly_patches_explicit_return_length_across_unrelated_pushes() {
        // The old byte-backscan inspected only four nearby PUSH opcodes and silently assumed the
        // RETURN reused CODECOPY's length. Here CODECOPY consumes its length and RETURN uses an
        // independent length PUSH separated by harmless PUSH0/POP pairs.
        let mut init = vec![
            0x60, 0x03, // PUSH1 runtime length
            0x60, 0x00, // PUSH1 runtime source; filled below
            0x5f, 0x39, // PUSH0; CODECOPY
            0x60, 0x03, 0x5f, // PUSH1 runtime length; PUSH0
        ];
        for _ in 0..5 {
            init.extend_from_slice(&[0x5f, 0x50]); // PUSH0; POP
        }
        init.push(0xf3);
        init[3] = init.len() as u8;
        let runtime = [0x5b, 0x00, 0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (_, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let grown_runtime = [0x5b, 0x5b, 0x5b, 0x00, 0x00];

        let rebuilt = report.reassemble_checked(&grown_runtime).unwrap();

        assert_eq!(rebuilt[1], grown_runtime.len() as u8);
        assert_eq!(rebuilt[7], grown_runtime.len() as u8);
        assert_eq!(&rebuilt[init.len()..], grown_runtime.as_slice());
    }

    #[test]
    fn reassembly_rejects_return_length_push_with_observable_alias() {
        // One PUSH supplies RETURN's length but is duplicated into SSTORE's value. Rewriting that
        // immediate would change constructor state even though the RETURN stack shape is valid.
        let init = vec![
            0x60, 0x01, 0x60, 0x0d, 0x5f, 0x39, // CODECOPY(0, 0x0d, 1)
            0x60, 0x01, 0x80, 0x5f, 0x55, // DUP length; SSTORE(0, length)
            0x5f, 0xf3, // RETURN(0, retained length)
        ];
        let runtime = [0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (_, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let before = init_bytes(&report);

        let error = report.reassemble_checked(&[0x00, 0x00]).unwrap_err();

        assert!(error.contains("also has a non-RETURN use"), "{error}");
        assert_eq!(init_bytes(&report), before);
    }

    #[test]
    fn reassembly_rejects_unproven_return_length_atomically() {
        let mut init = vec![
            0x60, 0x03, // PUSH1 runtime length
            0x60, 0x00, // PUSH1 runtime source; filled below
            0x5f, 0x39, // PUSH0; CODECOPY
            0x60, 0x03, 0x5f, 0x01, // compute rather than carry an exact RETURN length
            0x5f, 0xf3, // PUSH0; RETURN
        ];
        init[3] = init.len() as u8;
        let runtime = [0x5b, 0x00, 0x00];
        let bytes = [init.as_slice(), runtime.as_slice()].concat();
        let sections = vec![
            section(SectionKind::Init, 0, init.len()),
            section(SectionKind::Runtime, init.len(), runtime.len()),
        ];
        let (_, mut report) = strip_bytecode(&bytes, &sections).unwrap();
        let before = init_bytes(&report);

        let error = report
            .reassemble_checked(&[0x5b, 0x5b, 0x5b, 0x00, 0x00])
            .unwrap_err();

        assert!(
            error.contains("runtime copy parameter is consumed")
                || error.contains("RETURN length does not derive"),
            "{error}"
        );
        assert_eq!(
            init_bytes(&report),
            before,
            "failed lowering must be atomic"
        );
    }

    #[test]
    fn immutable_patch_remaps_only_exact_placeholder_references() {
        let (runtime, placeholders) = runtime_with_immutable_placeholders(2);
        let (mut report, references, unrelated) =
            immutable_report(&runtime, &placeholders, Some(2));

        report
            .patch_init_immutable_refs(&runtime, &|offset| Some(offset + 10))
            .unwrap();

        let patched = init_bytes(&report);
        assert_eq!(patched[references[0]], (placeholders[0] + 10) as u8);
        assert_eq!(patched[references[1]], (placeholders[1] + 10) as u8);
        assert_eq!(
            patched[unrelated.expect("unrelated PUSH exists")],
            2,
            "an unrelated PUSH/ADD must never be rewritten"
        );
    }

    #[test]
    fn immutable_patch_rejects_missing_reference_atomically() {
        let (runtime, _) = runtime_with_immutable_placeholders(1);
        let (mut report, _, _) = immutable_report(&runtime, &[], None);
        let before = init_bytes(&report);

        let error = report
            .patch_init_immutable_refs(&runtime, &|offset| Some(offset + 1))
            .unwrap_err();

        assert!(
            error.contains("has no exact constructor reference"),
            "{error}"
        );
        assert_eq!(init_bytes(&report), before);
    }

    #[test]
    fn immutable_patch_rejects_ambiguous_reference_atomically() {
        let (runtime, placeholders) = runtime_with_immutable_placeholders(1);
        let references = [placeholders[0], placeholders[0]];
        let (mut report, _, _) = immutable_report(&runtime, &references, None);
        let before = init_bytes(&report);

        let error = report
            .patch_init_immutable_refs(&runtime, &|offset| Some(offset + 1))
            .unwrap_err();

        assert!(error.contains("has 2 constructor references"), "{error}");
        assert_eq!(init_bytes(&report), before);
    }

    #[test]
    fn immutable_patch_rejects_missing_remap_atomically() {
        let (runtime, placeholders) = runtime_with_immutable_placeholders(1);
        let (mut report, _, _) = immutable_report(&runtime, &placeholders, None);
        let before = init_bytes(&report);

        let error = report
            .patch_init_immutable_refs(&runtime, &|_| None)
            .unwrap_err();

        assert!(error.contains("has no remap"), "{error}");
        assert_eq!(init_bytes(&report), before);
    }

    #[test]
    fn immutable_patch_rejects_push_overflow_atomically() {
        let (runtime, placeholders) = runtime_with_immutable_placeholders(2);
        let (mut report, _, _) = immutable_report(&runtime, &placeholders, None);
        let before = init_bytes(&report);

        let error = report
            .patch_init_immutable_refs(&runtime, &|offset| {
                (offset == placeholders[0])
                    .then_some(offset + 1)
                    .or(Some(0x100))
            })
            .unwrap_err();

        assert!(error.contains("does not fit in PUSH1"), "{error}");
        assert_eq!(init_bytes(&report), before);
    }

    #[test]
    fn immutable_patch_accepts_current_escrow_compiler_shapes() {
        let fixtures = [
            (
                include_str!("../../../examples/escrow-bytecode/artifacts/erc20_deployment.hex"),
                include_str!("../../../examples/escrow-bytecode/artifacts/erc20_runtime.hex"),
            ),
            (
                include_str!("../../../examples/escrow-bytecode/artifacts/native_deployment.hex"),
                include_str!("../../../examples/escrow-bytecode/artifacts/native_runtime.hex"),
            ),
        ];

        for (fixture_index, (deployment_hex, runtime_hex)) in fixtures.into_iter().enumerate() {
            let deployment = hex::decode(deployment_hex.trim().trim_start_matches("0x")).unwrap();
            let runtime = hex::decode(runtime_hex.trim().trim_start_matches("0x")).unwrap();
            let metadata_payload_len = usize::from(u16::from_be_bytes([
                runtime[runtime.len() - 2],
                runtime[runtime.len() - 1],
            ]));
            let auxdata_len = metadata_payload_len + 2;
            let clean_len = runtime.len() - auxdata_len;
            let matches: Vec<_> = deployment
                .windows(runtime.len())
                .enumerate()
                .filter_map(|(offset, window)| (window == runtime).then_some(offset))
                .collect();
            let [runtime_start] = matches.as_slice() else {
                panic!("fixture runtime must occur exactly once in its deployment artifact");
            };
            let sections = vec![
                section(SectionKind::Init, 0, *runtime_start),
                section(SectionKind::Runtime, *runtime_start, clean_len),
                section(
                    SectionKind::Auxdata,
                    *runtime_start + clean_len,
                    auxdata_len,
                ),
            ];
            let (clean_runtime, mut report) = strip_bytecode(&deployment, &sections).unwrap();
            assert!(
                !immutable_placeholder_offsets(&clean_runtime)
                    .unwrap()
                    .is_empty(),
                "escrow fixture should exercise immutable references"
            );

            report
                .validate_init_runtime_contract(&clean_runtime)
                .unwrap_or_else(|error| {
                    panic!("escrow fixture {fixture_index} init/runtime provenance: {error}")
                });

            report
                .patch_init_immutable_refs(&clean_runtime, &Some)
                .unwrap();
        }
    }
}
