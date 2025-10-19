//! Detects Solidity function dispatcher patterns to extract selectors and target addresses.

use crate::Opcode;
use crate::decoder::Instruction;

/// Detected function dispatcher with selectors and metadata.
#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    /// Start offset of the dispatcher in the instruction sequence
    pub start_offset: usize,
    /// End offset of the dispatcher in the instruction sequence
    pub end_offset: usize,
    /// Detected function selectors with their target addresses
    pub selectors: Vec<FunctionSelector>,
    /// Calldata extraction pattern used by this dispatcher
    pub extraction_pattern: ExtractionPattern,
}

/// Function selector (4-byte signature hash) paired with its implementation address.
#[derive(Debug, Clone)]
pub struct FunctionSelector {
    /// 4-byte function selector value
    pub selector: u32,
    /// Bytecode address of the function implementation
    pub target_address: u64,
    /// Instruction index where this selector is compared
    pub instruction_index: usize,
}

/// Calldata extraction patterns used by Solidity compilers.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractionPattern {
    /// PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR
    Standard,
    /// PUSH1 0x00 CALLDATALOAD PUSH29 ... SHR
    Alternative,
    /// CALLDATALOAD PUSH1 0xE0 SHR (Solidity 0.8.0+)
    Newer,
    /// CALLDATASIZE ISZERO (fallback-only)
    Fallback,
    /// PUSH1 0x00 CALLDATALOAD (no shift)
    Direct,
}

/// Stack value tracked during symbolic execution.
#[derive(Clone, Copy, Debug)]
enum StackValue {
    /// Constant value with its address and definition PC
    Const { addr: usize, def_pc: usize },
    /// Unknown or runtime-dependent value
    Unknown,
}

/// Detects Solidity function dispatcher pattern and extracts selector-to-address mappings
/// via symbolic stack tracking.
pub fn detect_function_dispatcher(instructions: &[Instruction]) -> Option<DispatcherInfo> {
    if instructions.is_empty() {
        return None;
    }
    let (extraction_start, extraction_len) = find_extraction_pattern(instructions)?;

    let mut selectors = Vec::new();
    let mut stack: Vec<StackValue> = Vec::with_capacity(32); // EVM stack max depth
    let mut current_selector: Option<(u32, usize)> = None;
    let mut previous_opcode: Option<Opcode> = None;

    tracing::debug!(
        "Starting stack tracking from instruction {}",
        extraction_start + extraction_len
    );

    let analysis_end = (extraction_start + extraction_len + 500).min(instructions.len());
    for i in (extraction_start + extraction_len)..analysis_end {
        let instr = &instructions[i];
        let opcode = instr.op;

        match opcode {
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                if let Some(immediate) = &instr.imm
                    && let Ok(value) = u64::from_str_radix(immediate, 16)
                {
                    stack.push(StackValue::Const {
                        addr: value as usize,
                        def_pc: instr.pc,
                    });
                    previous_opcode = Some(opcode);
                    continue;
                }
                stack.push(StackValue::Unknown);
            }

            Opcode::DUP(1) if !stack.is_empty() => {
                stack.push(stack[stack.len() - 1]);
            }
            Opcode::DUP(2) if stack.len() >= 2 => {
                stack.push(stack[stack.len() - 2]);
            }

            Opcode::EQ => {
                // Check if preceded by PUSH4 (selector)
                if let Some(Opcode::PUSH(4)) = previous_opcode
                    && i > 0
                {
                    let previous_instruction = &instructions[i - 1];
                    if let Some(immediate) = &previous_instruction.imm
                        && let Ok(selector) = u32::from_str_radix(immediate, 16)
                    {
                        current_selector = Some((selector, i - 1));
                        tracing::debug!(
                            "Found selector candidate 0x{:08x} at instruction {}",
                            selector,
                            i - 1
                        );
                    }
                }

                if stack.len() >= 2 {
                    stack.truncate(stack.len() - 2);
                    stack.push(StackValue::Unknown);
                }
            }

            Opcode::JUMPI => {
                if stack.len() >= 2 {
                    // JUMPI pops: [condition, destination]
                    // Stack before JUMPI: [..., destination, condition]
                    // We want stack[len-1] which is the destination
                    let target_val = stack[stack.len() - 1];
                    stack.truncate(stack.len() - 2);

                    if let StackValue::Const {
                        addr: address,
                        def_pc,
                    } = target_val
                        && let Some((selector, sel_idx)) = current_selector
                    {
                        selectors.push(FunctionSelector {
                            selector,
                            target_address: address as u64,
                            instruction_index: sel_idx,
                        });
                        tracing::debug!(
                            "Paired selector 0x{:08x} -> target 0x{:x} (PUSH at PC 0x{:x})",
                            selector,
                            address,
                            def_pc
                        );
                        current_selector = None;
                    }
                }
            }

            Opcode::JUMP => {
                if !stack.is_empty() {
                    stack.pop();
                }
            }

            Opcode::POP if !stack.is_empty() => {
                stack.pop();
            }

            Opcode::ADD
            | Opcode::SUB
            | Opcode::MUL
            | Opcode::DIV
            | Opcode::MOD
            | Opcode::LT
            | Opcode::GT
            | Opcode::SLT
            | Opcode::SGT => {
                if stack.len() >= 2 {
                    stack.truncate(stack.len() - 2);
                    stack.push(StackValue::Unknown);
                }
            }

            Opcode::ISZERO | Opcode::NOT => {
                if !stack.is_empty() {
                    stack.pop();
                    stack.push(StackValue::Unknown);
                }
            }

            Opcode::REVERT if selectors.len() >= 3 => {
                tracing::debug!(
                    "Stopping at REVERT after finding {} selectors",
                    selectors.len()
                );
                break;
            }

            _ => {}
        }

        // Track previous opcode for next iteration
        previous_opcode = Some(opcode);
    }

    if selectors.is_empty() {
        tracing::debug!("Stack tracking found no valid selector-target pairs");
        None
    } else {
        tracing::debug!(
            "Stack tracking found {} selector-target pairs",
            selectors.len()
        );

        // Find the actual start of the dispatcher by looking backwards from extraction_start
        // for the dispatcher preamble (callvalue check, calldata size check, etc.)
        let dispatcher_start = find_dispatcher_preamble(instructions, extraction_start);

        tracing::debug!(
            "Dispatcher range: preamble starts at {}, extraction at {}, selectors end at ~{}",
            dispatcher_start,
            extraction_start,
            selectors
                .last()
                .map(|s| s.instruction_index)
                .unwrap_or(extraction_start)
        );

        Some(DispatcherInfo {
            start_offset: dispatcher_start,
            end_offset: selectors
                .last()
                .map(|s| s.instruction_index + 10)
                .unwrap_or(extraction_start + 100),
            selectors,
            extraction_pattern: ExtractionPattern::Standard,
        })
    }
}

/// Locates the calldata extraction pattern in the first 200 instructions and returns its index and length.
fn find_extraction_pattern(instructions: &[Instruction]) -> Option<(usize, usize)> {
    for i in 0..instructions.len().saturating_sub(3).min(200) {
        let instrs = &instructions[i..];

        if instrs.len() < 3 {
            continue;
        }

        // Newer pattern: CALLDATALOAD PUSH1 0xE0 SHR (3 instructions)
        if instrs[0].op == Opcode::CALLDATALOAD
            && instrs[1].op == Opcode::PUSH(1)
            && instrs[1].imm.as_deref() == Some("e0")
            && instrs[2].op == Opcode::SHR
        {
            tracing::debug!("Found newer extraction pattern at instruction {}", i);
            return Some((i, 3));
        }

        // Standard pattern: [PUSH1 0x00 | PUSH0] CALLDATALOAD PUSH1 0xE0 SHR (4 instructions)
        if instrs.len() >= 4 {
            let first_valid = (instrs[0].op == Opcode::PUSH(1)
                && instrs[0].imm.as_deref() == Some("00"))
                || instrs[0].op == Opcode::PUSH0;

            if first_valid
                && instrs[1].op == Opcode::CALLDATALOAD
                && instrs[2].op == Opcode::PUSH(1)
                && instrs[2].imm.as_deref() == Some("e0")
                && instrs[3].op == Opcode::SHR
            {
                tracing::debug!("Found standard extraction pattern at instruction {}", i);
                return Some((i, 4));
            }
        }
    }
    None
}

/// Finds the actual start of the dispatcher by scanning backwards from the extraction pattern
/// to locate the dispatcher preamble (free memory pointer, callvalue check, etc.).
fn find_dispatcher_preamble(instructions: &[Instruction], extraction_start: usize) -> usize {
    // Common preamble patterns in Solidity dispatchers:
    // 1. Free memory pointer setup: PUSH1 0x80 PUSH1 0x40 MSTORE
    // 2. Callvalue check: CALLVALUE DUP1 ISZERO PUSH2 ... JUMPI
    // 3. Calldatasize check: PUSH1 0x04 CALLDATASIZE LT

    // For runtime-only bytecode, the dispatcher typically starts at instruction 0
    // with the free memory pointer setup
    if extraction_start >= 3 && instructions.len() >= 3 {
        // Check for free memory pointer pattern at the very beginning
        if instructions[0].op == Opcode::PUSH(1)
            && instructions[0].imm.as_deref() == Some("80")
            && instructions[1].op == Opcode::PUSH(1)
            && instructions[1].imm.as_deref() == Some("40")
            && instructions[2].op == Opcode::MSTORE
        {
            tracing::debug!(
                "Found dispatcher preamble at instruction 0 (free memory pointer setup)"
            );
            return 0;
        }
    }

    // If no clear preamble pattern found at start, scan backwards from extraction
    // looking for CALLVALUE check or CALLDATASIZE check
    let search_start = extraction_start.saturating_sub(20).max(0);

    for i in search_start..extraction_start {
        if i + 2 < instructions.len() {
            let instrs = &instructions[i..];

            // Check for: CALLVALUE DUP1 ISZERO
            if instrs[0].op == Opcode::CALLVALUE
                && instrs[1].op == Opcode::DUP(1)
                && instrs[2].op == Opcode::ISZERO
            {
                tracing::debug!(
                    "Found dispatcher preamble at instruction {} (callvalue check)",
                    i
                );
                return i;
            }

            // Check for: PUSH1 0x04 CALLDATASIZE
            if instrs[0].op == Opcode::PUSH(1)
                && instrs[0].imm.as_deref() == Some("04")
                && instrs[1].op == Opcode::CALLDATASIZE
            {
                tracing::debug!(
                    "Found dispatcher preamble at instruction {} (calldatasize check)",
                    i
                );
                return i;
            }
        }
    }

    // Fallback: if we can't find a clear preamble pattern, start a bit before extraction
    // This is safer than starting at 0 blindly or at extraction_start
    let fallback_start = extraction_start.saturating_sub(10);
    tracing::debug!(
        "Could not find clear preamble pattern, using fallback start at instruction {}",
        fallback_start
    );
    fallback_start
}

/// Quick check for dispatcher presence without extracting selector details.
pub fn has_dispatcher(instructions: &[Instruction]) -> bool {
    detect_function_dispatcher(instructions).is_some()
}
