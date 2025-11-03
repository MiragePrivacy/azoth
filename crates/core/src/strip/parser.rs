//! Parser for init-code snippets that updates CODECOPY/RETURN operands

use revm::primitives::U256;
use std::collections::BTreeSet;
use std::convert::TryInto;

#[derive(Clone, Debug)]
struct ParsedInstruction {
    pc: usize,
    opcode: u8,
    data: Vec<u8>,
}

/// Stack entry tracked while simulating the constructor.
#[derive(Clone, Debug)]
struct StackEntry {
    origin: Option<usize>,
    value: Option<U256>,
}

impl StackEntry {
    fn new(origin: Option<usize>, value: Option<U256>) -> Self {
        Self { origin, value }
    }
}

/// The arguments consumed by a `CODECOPY`.
#[derive(Clone, Debug)]
struct CodecopyArgs {
    size: StackEntry,
    offset: StackEntry,
}

/// Where the size/offset operands feeding `CODECOPY` originate.
#[derive(Debug)]
struct CodecopyPatch {
    size_source: Option<usize>,
    offset_source: Option<usize>,
}

/// Metadata describing the runtime `CODECOPY`.
#[derive(Debug)]
struct RuntimeCodecopy {
    codecopy_index: usize,
    patch: CodecopyPatch,
    stack_after: Vec<StackEntry>,
}

/// PUSH origins that provide the length argument to the constructor `RETURN`.
#[derive(Debug)]
struct ReturnPatch {
    size_sources: BTreeSet<usize>,
}

/// Parser that walks init bytecode and records rewrite points.
struct InitCodeParser {
    instructions: Vec<ParsedInstruction>,
}

impl InitCodeParser {
    /// Decode constructor bytes into a sequence of `ParsedInstruction`s.
    fn new(bytes: &[u8]) -> Result<Self, String> {
        let mut instructions = Vec::new();
        let mut pc = 0usize;
        while pc < bytes.len() {
            let opcode = bytes[pc];
            let mut inst = ParsedInstruction {
                pc,
                opcode,
                data: Vec::new(),
            };
            pc += 1;

            if (0x60..=0x7f).contains(&opcode) {
                let width = (opcode - 0x60 + 1) as usize;
                if pc + width > bytes.len() {
                    return Err(format!(
                        "PUSH at pc 0x{:x} exceeds init code length (need {} bytes, have {})",
                        inst.pc,
                        width,
                        bytes.len().saturating_sub(inst.pc + 1)
                    ));
                }
                inst.data.extend_from_slice(&bytes[pc..pc + width]);
                pc += width;
            }

            instructions.push(inst);
        }

        Ok(Self { instructions })
    }

    /// Locate the `CODECOPY` that copies the runtime payload at `runtime_offset`.
    fn find_runtime_codecopy(&self, runtime_offset: usize) -> Result<RuntimeCodecopy, String> {
        let mut last_jumpdest = None;
        for (idx, inst) in self.instructions.iter().enumerate() {
            if inst.opcode == 0x5b {
                last_jumpdest = Some(idx);
                continue;
            }

            if inst.opcode != 0x39 {
                continue;
            }

            let start = last_jumpdest.map(|i| i + 1).unwrap_or(0);
            let (args, stack_after) = self.resolve_codecopy(idx, start)?;

            let offset_value = args
                .offset
                .value
                .and_then(|val| TryInto::<usize>::try_into(val).ok());

            if offset_value == Some(runtime_offset) {
                tracing::debug!(
                    "Runtime CODECOPY found at pc 0x{:x}: offset={}, size={}",
                    inst.pc,
                    runtime_offset,
                    args.size
                        .value
                        .and_then(|val| TryInto::<usize>::try_into(val).ok())
                        .unwrap_or_default()
                );

                let patch = CodecopyPatch {
                    size_source: args.size.origin,
                    offset_source: args.offset.origin,
                };

                return Ok(RuntimeCodecopy {
                    codecopy_index: idx,
                    patch,
                    stack_after,
                });
            }
        }

        Err("No CODECOPY matched the runtime offset".into())
    }

    /// Simulate the stack from `start_idx` up to the runtime `CODECOPY`.
    fn resolve_codecopy(
        &self,
        target_idx: usize,
        start_idx: usize,
    ) -> Result<(CodecopyArgs, Vec<StackEntry>), String> {
        let mut stack = Vec::new();
        for idx in start_idx..=target_idx {
            let inst = &self.instructions[idx];
            if idx == target_idx {
                // pop destination (unused)
                stack.pop().ok_or_else(|| {
                    format!("Stack underflow before CODECOPY at pc 0x{:x}", inst.pc)
                })?;
                let offset = stack.pop().ok_or_else(|| {
                    format!("Stack underflow before CODECOPY at pc 0x{:x}", inst.pc)
                })?;
                let size = stack.pop().ok_or_else(|| {
                    format!("Stack underflow before CODECOPY at pc 0x{:x}", inst.pc)
                })?;

                return Ok((CodecopyArgs { size, offset }, stack));
            }

            self.apply_stack_instruction(&mut stack, idx)?;
        }

        Err("CODECOPY not reached during analysis".into())
    }

    /// From the runtime `CODECOPY`, walk forward to find the matching `RETURN`.
    fn find_return_patch(
        &self,
        codecopy_index: usize,
        stack_after_codecopy: &[StackEntry],
    ) -> Result<ReturnPatch, String> {
        let mut stack = stack_after_codecopy.to_vec();

        for idx in codecopy_index + 1..self.instructions.len() {
            let inst = &self.instructions[idx];
            if inst.opcode == 0xf3 {
                let offset_entry = stack.pop().ok_or_else(|| {
                    format!(
                        "Stack underflow before RETURN (offset) at pc 0x{:x}",
                        inst.pc
                    )
                })?;
                let size_entry = stack.pop().ok_or_else(|| {
                    format!("Stack underflow before RETURN (size) at pc 0x{:x}", inst.pc)
                })?;

                let mut size_sources = BTreeSet::new();
                if let Some(origin) = size_entry.origin {
                    size_sources.insert(origin);
                }

                tracing::debug!(
                    "RETURN at pc 0x{:x}: offset origin={:?}, size origin={:?}",
                    inst.pc,
                    offset_entry.origin,
                    size_entry.origin
                );

                return Ok(ReturnPatch { size_sources });
            }

            self.apply_stack_instruction(&mut stack, idx)?;
        }

        Err("RETURN not found after CODECOPY".into())
    }

    /// Apply a single opcode to the simulated stack.
    fn apply_stack_instruction(
        &self,
        stack: &mut Vec<StackEntry>,
        idx: usize,
    ) -> Result<(), String> {
        let inst = &self.instructions[idx];
        match inst.opcode {
            0x5b => Ok(()), // JUMPDEST
            0x50 => {
                stack
                    .pop()
                    .ok_or_else(|| format!("Stack underflow on POP at pc 0x{:x}", inst.pc))?;
                Ok(())
            }
            0x5f => {
                stack.push(StackEntry::new(Some(idx), Some(U256::ZERO)));
                Ok(())
            }
            0x60..=0x7f => {
                let value = if inst.data.is_empty() {
                    U256::ZERO
                } else {
                    U256::from_be_slice(&inst.data)
                };
                stack.push(StackEntry::new(Some(idx), Some(value)));
                Ok(())
            }
            0x80..=0x8f => {
                let depth = (inst.opcode - 0x80 + 1) as usize;
                if depth == 0 || depth > stack.len() {
                    stack.push(StackEntry::new(None, None));
                } else {
                    let entry = stack[stack.len() - depth].clone();
                    stack.push(entry);
                }
                Ok(())
            }
            0x90..=0x9f => {
                let depth = (inst.opcode - 0x90 + 1) as usize;
                if depth == 0 || depth > stack.len() - 1 {
                    return Err(format!(
                        "Invalid SWAP{} at pc 0x{:x} (insufficient stack height)",
                        depth, inst.pc
                    ));
                }
                let top = stack.len() - 1;
                let target = stack.len() - 1 - depth;
                stack.swap(top, target);
                Ok(())
            }
            0x3d => {
                // RETURNDATASIZE -> zero before any external calls
                stack.push(StackEntry::new(None, Some(U256::ZERO)));
                Ok(())
            }
            0x3e => {
                // RETURNDATACOPY pops 3 arguments
                for _ in 0..3 {
                    stack.pop().ok_or_else(|| {
                        format!("Stack underflow on RETURNDATACOPY at pc 0x{:x}", inst.pc)
                    })?;
                }
                Ok(())
            }
            _ => Err(format!(
                "Unsupported opcode 0x{:02x} at pc 0x{:x} during init code analysis",
                inst.opcode, inst.pc
            )),
        }
    }

    /// Rewrite the PUSH sources driving the runtime `CODECOPY`.
    fn apply_codecopy_patch(
        &mut self,
        patch: &CodecopyPatch,
        new_size: usize,
        new_offset: usize,
    ) -> Result<(), String> {
        let mut patched = false;
        if let Some(idx) = patch.size_source {
            self.patch_push_value(idx, new_size)?;
            patched = true;
        }

        if !patched {
            return Err("CODECOPY size argument does not originate from a PUSH".into());
        }

        if let Some(idx) = patch.offset_source {
            self.patch_push_value(idx, new_offset)?;
        } else {
            return Err("CODECOPY offset argument does not originate from a PUSH".into());
        }

        Ok(())
    }

    /// Mirror the updated runtime length into the constructor's `RETURN`.
    fn apply_return_patch(&mut self, patch: &ReturnPatch, new_size: usize) -> Result<(), String> {
        if patch.size_sources.is_empty() {
            return Err("RETURN size argument does not originate from a PUSH".into());
        }

        for idx in &patch.size_sources {
            self.patch_push_value(*idx, new_size)?;
        }

        Ok(())
    }

    /// Replace the immediate bytes for a PUSH with `new_value`.
    fn patch_push_value(&mut self, instr_idx: usize, new_value: usize) -> Result<(), String> {
        let inst = self
            .instructions
            .get_mut(instr_idx)
            .ok_or_else(|| format!("Instruction index {} out of bounds", instr_idx))?;

        match inst.opcode {
            0x5f => {
                if new_value != 0 {
                    return Err(format!(
                        "Cannot encode non-zero value {} using PUSH0 at pc 0x{:x}",
                        new_value, inst.pc
                    ));
                }
            }
            0x60..=0x7f => {
                let width = inst.data.len();
                if width == 0 {
                    return Err(format!("Malformed PUSH at pc 0x{:x}", inst.pc));
                }

                if !Self::value_fits(new_value, width) {
                    return Err(format!(
                        "Value {} exceeds PUSH{} capacity at pc 0x{:x}",
                        new_value, width, inst.pc
                    ));
                }

                let usize_bits = std::mem::size_of::<usize>() * 8;
                for (idx, byte) in inst.data.iter_mut().enumerate() {
                    let shift = (width - 1 - idx) * 8;
                    let val = if shift >= usize_bits {
                        0
                    } else {
                        (new_value >> shift) & 0xFF
                    };
                    *byte = val as u8;
                }
            }
            _ => {
                return Err(format!(
                    "Instruction at pc 0x{:x} is not a PUSH (opcode 0x{:02x})",
                    inst.pc, inst.opcode
                ));
            }
        }

        tracing::debug!(
            "Patched PUSH at pc 0x{:x} (opcode 0x{:02x}) to value {}",
            inst.pc,
            inst.opcode,
            new_value
        );

        Ok(())
    }

    /// Returns true when `value` can be encoded using `width` bytes.
    fn value_fits(value: usize, width: usize) -> bool {
        if width >= std::mem::size_of::<usize>() {
            true
        } else {
            let bits = width * 8;
            value < (1usize << bits)
        }
    }

    /// Serialise the parser back into raw init-code bytes.
    fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        for inst in self.instructions {
            out.push(inst.opcode);
            out.extend(inst.data);
        }
        out
    }
}

/// Update CODECOPY/RETURN immediates to copy `copy_size` bytes from `runtime_offset`.
pub(crate) fn rewrite_init_code(
    init_code: &[u8],
    runtime_offset: usize,
    copy_size: usize,
) -> Result<Vec<u8>, String> {
    let mut parser = InitCodeParser::new(init_code)?;

    let runtime_codecopy = parser.find_runtime_codecopy(runtime_offset)?;

    parser.apply_codecopy_patch(&runtime_codecopy.patch, copy_size, runtime_offset)?;

    let return_patch = parser.find_return_patch(
        runtime_codecopy.codecopy_index,
        &runtime_codecopy.stack_after,
    )?;

    parser.apply_return_patch(&return_patch, copy_size)?;

    Ok(parser.into_bytes())
}
