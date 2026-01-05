use super::scatter::generate_load_instructions;
use super::types::{ArithmeticChainDef, ArithmeticOp, ScatterContext, ScatterStrategy};
use azoth_core::decoder::Instruction;
use azoth_core::Opcode;

/// Compile an arithmetic chain to EVM instructions.
///
/// The generated instruction sequence:
/// 1. Loads the first initial value onto the stack
/// 2. For each operation: loads the next value, applies the operation
/// 3. Result is left on the stack (replacing what PUSH32 would have produced)
pub fn compile_chain(
    chain: &ArithmeticChainDef,
    _ctx: &ScatterContext,
    runtime_code_length: usize,
) -> Vec<Instruction> {
    let mut instructions = Vec::new();

    instructions.extend(generate_load_instructions(
        &chain.scatter_locations[0],
        &chain.initial_values[0],
        runtime_code_length,
    ));

    for (i, op) in chain.operations.iter().enumerate() {
        instructions.extend(generate_load_instructions(
            &chain.scatter_locations[i + 1],
            &chain.initial_values[i + 1],
            runtime_code_length,
        ));
        instructions.extend(compile_operation(op));
    }

    instructions
}

/// Compile a single arithmetic operation to EVM instructions.
///
/// For non-commutative operations (SUB, DIV), we need SWAP1 first because:
/// - We load accumulated result first, then next value on top
/// - EVM ops use top as first operand: SUB does stack[0] - stack[1]
/// - Without SWAP, we'd compute nextValue OP result instead of result OP nextValue
fn compile_operation(op: &ArithmeticOp) -> Vec<Instruction> {
    let needs_swap = matches!(op, ArithmeticOp::Sub | ArithmeticOp::Div(_));

    let mut instructions = Vec::new();

    if needs_swap {
        instructions.push(Instruction {
            pc: 0,
            op: Opcode::SWAP(1),
            imm: None,
        });
    }

    instructions.push(Instruction {
        pc: 0,
        op: match op {
            ArithmeticOp::Add => Opcode::ADD,
            ArithmeticOp::Sub => Opcode::SUB,
            ArithmeticOp::Mul => Opcode::MUL,
            ArithmeticOp::Div(_) => Opcode::DIV,
            ArithmeticOp::And(_, _) => Opcode::AND,
            ArithmeticOp::Or(_, _) => Opcode::OR,
            ArithmeticOp::Xor => Opcode::XOR,
        },
        imm: None,
    });

    instructions
}

/// Compile a chain using inline PUSH32 for all values (no scattering).
///
/// Useful for testing or when bytecode size is not a concern.
pub fn compile_chain_inline(chain: &ArithmeticChainDef) -> Vec<Instruction> {
    let mut instructions = Vec::new();

    // Load first value via PUSH32
    instructions.push(create_push32(&chain.initial_values[0]));

    // For each operation: push next value, apply operation
    for (i, op) in chain.operations.iter().enumerate() {
        instructions.push(create_push32(&chain.initial_values[i + 1]));
        instructions.extend(compile_operation(op));
    }

    instructions
}

/// Create a PUSH32 instruction for a 32-byte value.
fn create_push32(value: &[u8; 32]) -> Instruction {
    Instruction {
        pc: 0,
        op: Opcode::PUSH(32),
        imm: Some(hex::encode(value)),
    }
}

/// Estimate the bytecode size of a compiled chain.
pub fn estimate_bytecode_size(chain: &ArithmeticChainDef) -> usize {
    let mut size = 0;
    for strategy in &chain.scatter_locations {
        size += match strategy {
            ScatterStrategy::CodeCopy { .. } => 12,
            ScatterStrategy::Inline => 33,
            ScatterStrategy::DeadPath { .. } => 0,
        };
    }
    size += chain.operations.len();
    size
}

/// Calculate the stack delta of a compiled chain.
///
/// Should be +1, same as the PUSH32 it replaces.
pub fn stack_delta(chain: &ArithmeticChainDef) -> i32 {
    let loads = chain.initial_values.len() as i32;
    let ops = chain.operations.len() as i32;
    loads - ops
}


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chain() -> ArithmeticChainDef {
        ArithmeticChainDef {
            target_value: [0x42; 32],
            initial_values: vec![[0xaa; 32], [0xbb; 32], [0xcc; 32]],
            operations: vec![ArithmeticOp::Add, ArithmeticOp::Xor],
            scatter_locations: vec![
                ScatterStrategy::CodeCopy { offset: 0 },
                ScatterStrategy::CodeCopy { offset: 32 },
                ScatterStrategy::CodeCopy { offset: 64 },
            ],
        }
    }

    #[test]
    fn compile_chain_inline_produces_correct_instructions() {
        let chain = sample_chain();
        let instructions = compile_chain_inline(&chain);

        // PUSH32, PUSH32, ADD, PUSH32, XOR = 5 instructions
        assert_eq!(instructions.len(), 5);

        assert!(matches!(instructions[0].op, Opcode::PUSH(32)));
        assert!(matches!(instructions[1].op, Opcode::PUSH(32)));
        assert!(matches!(instructions[2].op, Opcode::ADD));
        assert!(matches!(instructions[3].op, Opcode::PUSH(32)));
        assert!(matches!(instructions[4].op, Opcode::XOR));
    }

    #[test]
    fn stack_delta_is_one() {
        let chain = sample_chain();
        assert_eq!(stack_delta(&chain), 1);
    }

    #[test]
    fn estimate_bytecode_size_codecopy() {
        let chain = sample_chain();
        let size = estimate_bytecode_size(&chain);
        // 3 CODECOPY loads (12 bytes each) + 2 operations (1 byte each) = 38 bytes
        assert_eq!(size, 38);
    }

    #[test]
    fn estimate_bytecode_size_inline() {
        let chain = ArithmeticChainDef {
            target_value: [0x42; 32],
            initial_values: vec![[0xaa; 32], [0xbb; 32], [0xcc; 32]],
            operations: vec![ArithmeticOp::Add, ArithmeticOp::Xor],
            scatter_locations: vec![
                ScatterStrategy::Inline,
                ScatterStrategy::Inline,
                ScatterStrategy::Inline,
            ],
        };
        let size = estimate_bytecode_size(&chain);
        // 3 PUSH32 (33 bytes each) + 2 operations (1 byte each) = 101 bytes
        assert_eq!(size, 101);
    }
}
