//! Type definitions for arithmetic chain obfuscation.
//!
//! This module defines the core data structures used throughout the arithmetic chain
//! transform, including operations, chain definitions, scatter strategies, and
//! configuration options.

use petgraph::graph::NodeIndex;
use rand::rngs::StdRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;

/// Arithmetic operations supported by chains.
///
/// Each variant contains the random parameters needed for backward computation.
/// Use `ArithmeticOp::random(rng)` to generate an operation with its parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArithmeticOp {
    /// Addition: `result = a + b` (wrapping).
    Add,
    /// Subtraction: `result = a - b` (wrapping).
    Sub,
    /// Bitwise XOR: `result = a ^ b`.
    Xor,
    /// Bitwise AND: `result = a & b`. Contains (mask, extra_random) for backward computation.
    And([u8; 32], [u8; 32]),
    /// Bitwise OR: `result = a | b`. Contains (mask, extra_random) for backward computation.
    Or([u8; 32], [u8; 32]),
    /// Multiplication: `result = a * factor` (wrapping). Factor determined during backward.
    Mul,
    /// Division: `result = a / divisor`. Contains the divisor (2-16).
    Div(u8),
}

impl ArithmeticOp {
    /// Generate a random operation with its parameters.
    ///
    /// Weighted distribution favors simpler operations:
    /// - ADD, SUB, XOR: 25% each (75% total)
    /// - AND, OR: 8% each (16% total)
    /// - MUL, DIV: 4.5% each (9% total)
    pub fn random(rng: &mut StdRng) -> Self {
        let roll: f32 = rng.random();
        if roll < 0.25 {
            Self::Add
        } else if roll < 0.50 {
            Self::Sub
        } else if roll < 0.75 {
            Self::Xor
        } else if roll < 0.83 {
            Self::And(rng.random(), rng.random())
        } else if roll < 0.91 {
            Self::Or(rng.random(), rng.random())
        } else if roll < 0.955 {
            Self::Mul
        } else {
            Self::Div(rng.random_range(2..=16))
        }
    }

    /// Compute backward for this operation.
    ///
    /// Given `result = a OP b`, computes `(a, b)` such that applying the operation
    /// forward produces `result`.
    pub fn compute_backward(&self, result: [u8; 32], rng: &mut StdRng) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::Add => {
                let b = random_sized_value(rng);
                let a = wrapping_sub(&result, &b);
                (a, b)
            }
            Self::Sub => {
                let b = random_sized_value(rng);
                let a = wrapping_add(&result, &b);
                (a, b)
            }
            Self::Xor => {
                let b = random_sized_value(rng);
                let a = xor_bytes(&result, &b);
                (a, b)
            }
            Self::And(mask, extra) => {
                // b must have 1 wherever result has 1
                let b = or_bytes(&result, mask);
                // a must have 0 where result=0 and b=1
                let a = or_bytes(&result, &and_bytes(extra, &not_bytes(&b)));
                (a, b)
            }
            Self::Or(mask, extra) => {
                // b must have 0 wherever result has 0
                let b = and_bytes(&result, mask);
                // a must have 1 where result=1 and b=0
                let a = and_bytes(&result, &or_bytes(&not_bytes(&b), extra));
                (a, b)
            }
            Self::Mul => {
                let factor = pick_exact_divisor(&result, rng);
                let a = wrapping_div(&result, &factor);
                (a, factor)
            }
            Self::Div(divisor) => {
                let mut safe_divisor = *divisor;

                loop {
                    let divisor_bytes = {
                        let mut b = [0u8; 32];
                        b[31] = safe_divisor;
                        b
                    };
                    let a = wrapping_mul(&result, &divisor_bytes);

                    if wrapping_div(&a, &divisor_bytes) == result {
                        return (a, divisor_bytes);
                    }

                    if safe_divisor > 1 {
                        safe_divisor -= 1;
                    } else {
                        let one = {
                            let mut b = [0u8; 32];
                            b[31] = 1;
                            b
                        };
                        return (result, one);
                    }
                }
            }
        }
    }

    /// Apply this operation forward: `a OP b`.
    pub fn apply_forward(&self, a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        match self {
            Self::Add => wrapping_add(&a, &b),
            Self::Sub => wrapping_sub(&a, &b),
            Self::Xor => xor_bytes(&a, &b),
            Self::And(_, _) => and_bytes(&a, &b),
            Self::Or(_, _) => or_bytes(&a, &b),
            Self::Mul => wrapping_mul(&a, &b),
            Self::Div(_) => wrapping_div(&a, &b),
        }
    }

    /// Returns the EVM opcode byte for this operation.
    #[must_use]
    pub const fn opcode_byte(&self) -> u8 {
        match self {
            Self::Add => 0x01,
            Self::Sub => 0x03,
            Self::Mul => 0x02,
            Self::Div(_) => 0x04,
            Self::And(_, _) => 0x16,
            Self::Or(_, _) => 0x17,
            Self::Xor => 0x18,
        }
    }
}

/// Generate a random value with a randomly chosen size.
///
/// Prefers even PUSH sizes (2, 4, 8, 16, 32) for better bytecode alignment,
/// with weighted distribution favoring smaller values.
fn random_sized_value(rng: &mut StdRng) -> [u8; 32] {
    // Preferred even sizes with weights favoring smaller values
    // PUSH2, PUSH4, PUSH8, PUSH16, PUSH32
    let sizes: [(u8, u32); 5] = [
        (2, 30),  // 30% chance
        (4, 25),  // 25% chance
        (8, 20),  // 20% chance
        (16, 15), // 15% chance
        (32, 10), // 10% chance
    ];

    let total_weight: u32 = sizes.iter().map(|(_, w)| w).sum();
    let roll = rng.random_range(0..total_weight);

    let mut cumulative = 0u32;
    let mut chosen_size = 32u8;
    for (size, weight) in &sizes {
        cumulative += weight;
        if roll < cumulative {
            chosen_size = *size;
            break;
        }
    }

    // Generate random bytes only for the chosen size
    let mut value = [0u8; 32];
    let start = 32 - chosen_size as usize;
    for byte in &mut value[start..] {
        *byte = rng.random();
    }

    // Ensure at least one non-zero byte in the significant portion
    // to avoid generating zero values
    if value[start..].iter().all(|&b| b == 0) {
        value[31] = rng.random_range(1..=255);
    }

    value
}

fn wrapping_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

fn wrapping_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

fn xor_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn and_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] & b[i];
    }
    result
}

fn or_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] | b[i];
    }
    result
}

fn not_bytes(a: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = !a[i];
    }
    result
}

fn wrapping_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let factor = b[31] as u16;
    if factor == 0 {
        return [0u8; 32];
    }
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let prod = a[i] as u16 * factor + carry;
        result[i] = prod as u8;
        carry = prod >> 8;
    }
    result
}

fn wrapping_div(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let divisor = b[31] as u16;
    if divisor == 0 {
        return [0u8; 32];
    }
    let mut result = [0u8; 32];
    let mut remainder = 0u16;
    for i in 0..32 {
        let dividend = (remainder << 8) | a[i] as u16;
        result[i] = (dividend / divisor) as u8;
        remainder = dividend % divisor;
    }
    result
}

/// Pick a factor that divides the result evenly for MUL backward.
fn pick_exact_divisor(value: &[u8; 32], rng: &mut StdRng) -> [u8; 32] {
    if value.iter().all(|&b| b == 0) {
        let mut result = [0u8; 32];
        result[31] = 1;
        return result;
    }

    let candidates: [u8; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
    let mut valid_divisors = Vec::new();

    for &candidate in &candidates {
        let div_result = wrapping_div(value, &{
            let mut b = [0u8; 32];
            b[31] = candidate;
            b
        });
        let mul_check = wrapping_mul(&div_result, &{
            let mut b = [0u8; 32];
            b[31] = candidate;
            b
        });

        if mul_check == *value {
            valid_divisors.push(candidate);
        }
    }

    let divisor = if valid_divisors.is_empty() {
        1
    } else {
        valid_divisors[rng.random_range(0..valid_divisors.len())]
    };

    let mut result = [0u8; 32];
    result[31] = divisor;
    result
}

/// Strategy for scattering initial chain values in the bytecode.
#[derive(Debug, Clone)]
pub enum ScatterStrategy {
    /// Store in data section appended to bytecode, load via CODECOPY.
    CodeCopy {
        /// Offset within the data section where this value is stored.
        offset: usize,
    },
    /// Embed as inline PUSH instruction.
    Inline,
    /// Embed as PUSH in an unreachable code path (not yet implemented).
    #[allow(dead_code)]
    DeadPath {
        /// The CFG block containing the dead path with this value.
        block_id: NodeIndex,
    },
}

/// A single arithmetic chain targeting one PUSH constant.
#[derive(Debug, Clone)]
pub struct ArithmeticChainDef {
    /// Original PUSH value being protected (padded to 32 bytes).
    pub target_value: [u8; 32],
    /// Backward-computed initial values needed to produce target.
    pub initial_values: Vec<[u8; 32]>,
    /// Operations to apply in forward order.
    pub operations: Vec<ArithmeticOp>,
    /// Where each initial value is scattered in the bytecode.
    pub scatter_locations: Vec<ScatterStrategy>,
}

/// Configuration options for the arithmetic chain transform.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Number of operations per chain (default: 2..=8).
    pub chain_depth: RangeInclusive<usize>,
    /// Probability of using inline PUSH32 vs CODECOPY (0.0 to 1.0).
    /// 0.0 = all CODECOPY, 1.0 = all inline.
    pub inline_ratio: f32,
    /// Skip protected PCs (dispatcher selectors, controller targets, etc.).
    pub respect_protected_pcs: bool,
    /// Maximum number of PUSH32 targets to transform per invocation.
    pub max_targets: Option<usize>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_depth: 2..=8,
            inline_ratio: 0.9,
            respect_protected_pcs: true,
            max_targets: None,
        }
    }
}

/// Metadata stored to enable chain reversal for testing and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReverseData {
    /// PC of original PUSH instruction.
    pub original_pc: usize,
    /// Original constant that was protected (padded to 32 bytes).
    pub original_value: [u8; 32],
    /// PC range of the replacement chain (start, end).
    pub chain_pc_range: (usize, usize),
    /// Operations used in the chain (for inverse computation).
    pub operations: Vec<ArithmeticOp>,
    /// Scatter locations for value recovery.
    pub scatter_info: Vec<ScatterInfo>,
}

/// Information about a scattered value for recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScatterInfo {
    /// The 32-byte value that was scattered.
    pub value: [u8; 32],
    /// Where the value was stored.
    pub location: ScatterLocation,
}

/// Serializable representation of scatter location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScatterLocation {
    /// Value stored in data section at given offset.
    DataSection { offset: usize },
    /// Value embedded as inline PUSH instruction.
    Inline,
    /// Value stored as PUSH in dead code block at given PC.
    #[allow(dead_code)]
    DeadPathBlock { pc: usize },
}

/// Context for managing scattered values during transform application.
#[derive(Debug, Default)]
pub struct ScatterContext {
    /// Data section bytes to append to bytecode.
    pub data_section: Vec<u8>,
    /// Current offset within data section.
    pub data_offset: usize,
    /// Dead path blocks created for scattering.
    pub dead_path_blocks: Vec<NodeIndex>,
    /// Mapping from scatter strategy to actual load instructions.
    pub load_sequences: Vec<Vec<u8>>,
}

impl ScatterContext {
    /// Creates a new empty scatter context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    #[test]
    fn random_generates_all_variants() {
        let mut rng = test_rng();
        let mut has_add = false;
        let mut has_sub = false;
        let mut has_xor = false;
        let mut has_and = false;
        let mut has_or = false;
        let mut has_mul = false;
        let mut has_div = false;

        for _ in 0..1000 {
            match ArithmeticOp::random(&mut rng) {
                ArithmeticOp::Add => has_add = true,
                ArithmeticOp::Sub => has_sub = true,
                ArithmeticOp::Xor => has_xor = true,
                ArithmeticOp::And(_, _) => has_and = true,
                ArithmeticOp::Or(_, _) => has_or = true,
                ArithmeticOp::Mul => has_mul = true,
                ArithmeticOp::Div(_) => has_div = true,
            }
        }

        assert!(has_add && has_sub && has_xor && has_and && has_or && has_mul && has_div);
    }

    #[test]
    fn backward_forward_roundtrip() {
        let mut rng = test_rng();
        let target = [0x42; 32];

        for _ in 0..100 {
            let op = ArithmeticOp::random(&mut rng);
            let (a, b) = op.compute_backward(target, &mut rng);
            let result = op.apply_forward(a, b);
            assert_eq!(result, target, "Roundtrip failed for {:?}", op);
        }
    }
}
