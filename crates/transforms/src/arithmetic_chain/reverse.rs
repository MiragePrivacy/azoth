//! Backward computation for arithmetic chains.
//!
//! This module provides verification utilities for arithmetic chain operations.
//! The core backward computation is now part of `ArithmeticOp::compute_backward`.

use super::types::ArithmeticOp;

/// Evaluate a chain forward to verify correctness.
///
/// Given initial values and operations, compute the result to verify
/// it matches the expected target.
pub fn evaluate_forward(initial_values: &[[u8; 32]], operations: &[ArithmeticOp]) -> [u8; 32] {
    assert_eq!(
        initial_values.len(),
        operations.len() + 1,
        "Need exactly one more initial value than operations"
    );

    let mut result = initial_values[0];
    for (i, op) in operations.iter().enumerate() {
        result = op.apply_forward(result, initial_values[i + 1]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    #[test]
    fn backward_add_produces_target() {
        let mut rng = test_rng();
        let target = [0xab; 32];
        let op = ArithmeticOp::Add;

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_sub_produces_target() {
        let mut rng = test_rng();
        let target = [0xcd; 32];
        let op = ArithmeticOp::Sub;

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_xor_produces_target() {
        let mut rng = test_rng();
        let target = [0xef; 32];
        let op = ArithmeticOp::Xor;

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_and_produces_target() {
        let mut rng = test_rng();
        let target = [0x0f; 32];
        let op = ArithmeticOp::And(rng.random(), rng.random());

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_or_produces_target() {
        let mut rng = test_rng();
        let target = [0xf0; 32];
        let op = ArithmeticOp::Or(rng.random(), rng.random());

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_mul_produces_target() {
        let mut rng = test_rng();
        let mut target = [0u8; 32];
        target[31] = 60; // 60 = 2 * 2 * 3 * 5
        let op = ArithmeticOp::Mul;

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_div_produces_target() {
        let mut rng = test_rng();
        let mut target = [0u8; 32];
        target[31] = 10;
        let op = ArithmeticOp::Div(5);

        let (a, b) = op.compute_backward(target, &mut rng);
        let computed = op.apply_forward(a, b);
        assert_eq!(computed, target);
    }

    #[test]
    fn backward_chain_multiple_ops() {
        let mut rng = test_rng();
        let target = [0x42; 32];
        let operations = vec![ArithmeticOp::Add, ArithmeticOp::Xor, ArithmeticOp::Sub];

        // Compute initial values backward
        let mut current = target;
        let mut initial_values = Vec::new();

        for op in operations.iter().rev() {
            let (a, b) = op.compute_backward(current, &mut rng);
            initial_values.push(b);
            current = a;
        }
        initial_values.push(current);
        initial_values.reverse();

        // Verify forward evaluation
        let computed = evaluate_forward(&initial_values, &operations);
        assert_eq!(computed, target);
    }
}
