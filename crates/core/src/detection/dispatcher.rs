//! Function dispatcher detection for Solidity contracts.
//!
//! This module provides functionality to detect and analyze function dispatchers in EVM bytecode.
//! Solidity contracts use a dispatcher pattern at the entry point of the runtime code to route
//! function calls to their implementations based on the function selector (first 4 bytes of calldata).
//!
//! The detection process involves identifying the calldata extraction pattern, tracking stack values
//! through the dispatcher logic, and pairing function selectors with their target addresses. This
//! information is essential for understanding contract structure and enabling advanced obfuscation
//! techniques that can transform or obscure the dispatcher pattern.
//!

use crate::Opcode;
use crate::decoder::Instruction;

/// Represents a detected function dispatcher with its selectors and metadata.
///
/// A function dispatcher is the standard entry point pattern used by Solidity contracts to route
/// function calls to their implementations. The dispatcher extracts the function selector from
/// calldata, compares it against known selectors, and jumps to the corresponding implementation
/// when a match is found.
#[derive(Debug, Clone)]
pub struct DispatcherInfo {
    /// Start offset of the dispatcher in the instruction sequence
    pub start_offset: usize,
    /// End offset of the dispatcher in the instruction sequence
    pub end_offset: usize,
    /// List of detected function selectors with their target addresses
    pub selectors: Vec<FunctionSelector>,
    /// Type of calldata extraction pattern used by this dispatcher
    pub extraction_pattern: ExtractionPattern,
}

/// Represents a single function selector and its associated metadata.
///
/// Each function selector corresponds to a specific function signature in the contract's ABI.
/// The selector is the first 4 bytes of the keccak256 hash of the function signature, and the
/// target address is the bytecode location where that function's implementation begins.
#[derive(Debug, Clone)]
pub struct FunctionSelector {
    /// The 4-byte function selector value
    pub selector: u32,
    /// Bytecode address where this function's implementation begins
    pub target_address: u64,
    /// Index in the instruction sequence where this selector comparison occurs
    pub instruction_index: usize,
}

/// Types of calldata extraction patterns used by Solidity compilers.
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractionPattern {
    /// Standard pattern: PUSH1 0x00 CALLDATALOAD PUSH1 0xE0 SHR
    Standard,
    /// Alternative pattern: PUSH1 0x00 CALLDATALOAD PUSH29 ... SHR
    Alternative,
    /// Newer pattern: CALLDATALOAD PUSH1 0xE0 SHR (Solidity 0.8.0+)
    Newer,
    /// Fallback pattern: CALLDATASIZE ISZERO (fallback-only contracts)
    Fallback,
    /// Direct pattern: PUSH1 0x00 CALLDATALOAD (no shift, direct comparison)
    Direct,
}

/// Represents a value on the EVM stack during symbolic execution.
///
/// During dispatcher detection, we track stack values through the execution flow to identify
/// constant addresses that represent function implementation targets. This enum distinguishes
/// between known constant values and unknown runtime values that cannot be determined statically.
#[derive(Clone, Copy, Debug)]
enum StackValue {
    /// A constant value with a known address and the program counter where it was defined
    Const { addr: usize, def_pc: usize },
    /// An unknown or runtime-dependent value that cannot be determined through static analysis
    Unknown,
}

/// Detects Solidity function dispatcher patterns in the given instruction sequence.
///
/// This function identifies the standard dispatcher pattern used by Solidity contracts to route
/// function calls to their implementations. The detection process works in two stages: first,
/// it locates the calldata extraction pattern that retrieves the function selector from the
/// transaction data; second, it performs stack-based analysis to track selector comparisons
/// and identify the target addresses for each function.
///
/// The detector implements a symbolic execution engine that tracks constant values through
/// the EVM stack, identifying where function selectors are compared and where successful
/// matches cause jumps to function implementations. The analysis begins after the calldata
/// extraction pattern and continues until either sufficient selectors are found or the
/// dispatcher logic concludes.
///
/// The tracking handles common EVM operations including stack manipulation (DUP, POP),
/// arithmetic operations, and control flow (JUMP, JUMPI). When a JUMPI instruction is
/// encountered with a constant target address following a selector comparison, the pair
/// is recorded as a valid function entry point.
///
/// # Arguments
///
/// * `instructions` - A slice of decoded EVM instructions representing the contract bytecode
///
/// # Returns
///
/// Returns `Some(DispatcherInfo)` if a valid dispatcher pattern is detected, containing the
/// function selectors, their target addresses, and metadata about the dispatcher structure.
/// Returns `None` if no dispatcher pattern is found or if the bytecode does not follow
/// recognizable dispatcher conventions.
///
/// # Examples
///
/// ```rust,ignore
/// use azoth_core::detection::dispatcher::detect_function_dispatcher;
/// use azoth_core::decoder::decode_bytecode;
///
/// let bytecode = "0x608060405234801561001057600080fd5b50...";
/// let (instructions, _, _, _) = decode_bytecode(bytecode, false).await?;
///
/// if let Some(dispatcher) = detect_function_dispatcher(&instructions) {
///     println!("Found dispatcher with {} functions", dispatcher.selectors.len());
///     for selector in &dispatcher.selectors {
///         println!("Selector 0x{:08x} -> address 0x{:x}",
///                  selector.selector, selector.target_address);
///     }
/// }
/// ```
pub fn detect_function_dispatcher(instructions: &[Instruction]) -> Option<DispatcherInfo> {
    if instructions.is_empty() {
        return None;
    }
    let extraction_start = find_extraction_pattern(instructions)?;
    let extraction_len = get_pattern_length(&instructions[extraction_start..])?;

    let mut selectors = Vec::new();
    let mut stack: Vec<StackValue> = Vec::new();
    let mut current_selector: Option<(u32, usize)> = None;
    let mut prev_opcode: Option<Opcode> = None;

    tracing::debug!(
        "Starting stack tracking from instruction {}",
        extraction_start + extraction_len
    );

    for i in (extraction_start + extraction_len)..instructions.len() {
        let instr = &instructions[i];
        let opcode = instr.op;

        match opcode {
            Opcode::PUSH(_) | Opcode::PUSH0 => {
                if let Some(imm) = &instr.imm
                    && let Ok(value) = u64::from_str_radix(imm, 16)
                {
                    stack.push(StackValue::Const {
                        addr: value as usize,
                        def_pc: instr.pc,
                    });
                    prev_opcode = Some(opcode);
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
                if let Some(Opcode::PUSH(4)) = prev_opcode
                    && i > 0
                {
                    let prev_instr = &instructions[i - 1];
                    if let Some(sel_hex) = &prev_instr.imm
                        && let Ok(sel) = u32::from_str_radix(sel_hex, 16)
                    {
                        current_selector = Some((sel, i - 1));
                        tracing::debug!(
                            "Found selector candidate 0x{:08x} at instruction {}",
                            sel,
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

                    if let StackValue::Const { addr, def_pc } = target_val
                        && let Some((sel, sel_idx)) = current_selector
                    {
                        selectors.push(FunctionSelector {
                            selector: sel,
                            target_address: addr as u64,
                            instruction_index: sel_idx,
                        });
                        tracing::debug!(
                            "Paired selector 0x{:08x} -> target 0x{:x} (PUSH at PC 0x{:x})",
                            sel,
                            addr,
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
        prev_opcode = Some(opcode);

        // Safety: stop after reasonable dispatcher size
        if i - extraction_start > 500 {
            break;
        }
    }

    if selectors.is_empty() {
        tracing::debug!("Stack tracking found no valid selector-target pairs");
        None
    } else {
        tracing::debug!(
            "Stack tracking found {} selector-target pairs",
            selectors.len()
        );
        Some(DispatcherInfo {
            start_offset: extraction_start,
            end_offset: selectors
                .last()
                .map(|s| s.instruction_index + 10)
                .unwrap_or(extraction_start + 100),
            selectors,
            extraction_pattern: ExtractionPattern::Standard,
        })
    }
}

/// Locates the calldata extraction pattern in the instruction sequence.
///
/// Scans the beginning of the bytecode (up to 200 instructions) to find the characteristic
/// pattern used by Solidity to extract the function selector from calldata. This pattern
/// typically involves loading calldata at offset 0 and shifting right by 0xE0 bits (224 bits)
/// to isolate the 4-byte selector.
///
/// # Arguments
///
/// * `instructions` - Instruction sequence to search
///
/// # Returns
///
/// Returns `Some(index)` if an extraction pattern is found, `None` otherwise.
fn find_extraction_pattern(instructions: &[Instruction]) -> Option<usize> {
    for i in 0..instructions.len().saturating_sub(3).min(200) {
        if is_extraction_pattern(&instructions[i..]) {
            tracing::debug!("Found extraction pattern at instruction {}", i);
            return Some(i);
        }
    }
    None
}

/// Checks if the instruction sequence starts with a calldata extraction pattern.
///
/// Recognizes two main patterns:
/// - Standard: `[PUSH1 0x00 | PUSH0] CALLDATALOAD PUSH1 0xE0 SHR`
/// - Newer: `CALLDATALOAD PUSH1 0xE0 SHR` (optimized by recent Solidity versions)
///
/// Both patterns extract the 4-byte function selector by loading calldata at offset 0
/// and right-shifting by 224 bits (0xE0).
///
/// # Arguments
///
/// * `instrs` - Instruction slice to check (must have at least 3-4 instructions)
///
/// # Returns
///
/// Returns `true` if a valid extraction pattern is detected at the start of the slice.
fn is_extraction_pattern(instrs: &[Instruction]) -> bool {
    if instrs.len() < 3 {
        return false;
    }

    // Newer pattern: CALLDATALOAD PUSH1 0xE0 SHR
    if instrs[0].op == Opcode::CALLDATALOAD
        && instrs[1].op == Opcode::PUSH(1)
        && instrs[1].imm.as_deref() == Some("e0")
        && instrs[2].op == Opcode::SHR
    {
        return true;
    }

    // Standard pattern: [PUSH1 0x00 | PUSH0] CALLDATALOAD PUSH1 0xE0 SHR
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
            return true;
        }
    }

    false
}

/// Determines the length of the extraction pattern starting at the given position.
///
/// Returns the number of instructions consumed by the extraction pattern, which is
/// necessary to know where to begin stack tracking for selector detection.
///
/// # Arguments
///
/// * `instrs` - Instruction slice starting at an extraction pattern
///
/// # Returns
///
/// Returns `Some(4)` for standard patterns, `Some(3)` for newer patterns, or `None`
/// if no valid pattern is detected.
fn get_pattern_length(instrs: &[Instruction]) -> Option<usize> {
    if instrs.len() < 3 {
        return None;
    }

    // Newer pattern: 3 instructions (CALLDATALOAD PUSH1 0xE0 SHR)
    if instrs[0].op == Opcode::CALLDATALOAD
        && instrs[1].op == Opcode::PUSH(1)
        && instrs[1].imm.as_deref() == Some("e0")
    {
        return Some(3);
    }

    // Standard pattern: 4 instructions ([PUSH1 0x00 | PUSH0] CALLDATALOAD ...)
    if instrs.len() >= 4 {
        let first_valid = (instrs[0].op == Opcode::PUSH(1)
            && instrs[0].imm.as_deref() == Some("00"))
            || instrs[0].op == Opcode::PUSH0;

        if first_valid && instrs[1].op == Opcode::CALLDATALOAD {
            return Some(4);
        }
    }

    None
}

/// Quick check for dispatcher presence without extracting full details.
///
/// This is a convenience function that performs dispatcher detection and returns a simple
/// boolean result, useful when you only need to know whether a dispatcher exists without
/// needing the selector information.
///
/// # Arguments
///
/// * `instructions` - Decoded instruction sequence to check
///
/// # Returns
///
/// Returns `true` if a dispatcher pattern is detected, `false` otherwise.
///
/// # Examples
///
/// ```rust,ignore
/// if has_dispatcher(&instructions) {
///     println!("Contract has a function dispatcher");
/// }
/// ```
pub fn has_dispatcher(instructions: &[Instruction]) -> bool {
    detect_function_dispatcher(instructions).is_some()
}
