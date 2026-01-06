//! Chain generation for arithmetic chain obfuscation.
//!
//! This module handles the generation of arithmetic operation chains that
//! compute a target constant value from scattered initial values.

use super::types::{ArithmeticChainDef, ArithmeticOp, ChainConfig, ScatterStrategy};
use rand::rngs::StdRng;
use rand::Rng;

/// Generate an arithmetic chain for a target 32-byte constant.
///
/// Creates a complete chain definition including:
/// - Random sequence of arithmetic operations (with embedded parameters)
/// - Backward-computed initial values that produce the target
/// - Scatter strategy assignments for each initial value
pub fn generate_chain(
    target: [u8; 32],
    config: &ChainConfig,
    rng: &mut StdRng,
) -> ArithmeticChainDef {
    let depth = rng.random_range(config.chain_depth.clone());
    let operations: Vec<ArithmeticOp> = (0..depth).map(|_| ArithmeticOp::random(rng)).collect();
    let initial_values = compute_initial_values(target, &operations, rng);
    let scatter_locations = assign_scatter_locations(initial_values.len(), config, rng);

    ArithmeticChainDef {
        target_value: target,
        initial_values,
        operations,
        scatter_locations,
    }
}

/// Compute initial values by working backward through the operation chain.
fn compute_initial_values(
    target: [u8; 32],
    operations: &[ArithmeticOp],
    rng: &mut StdRng,
) -> Vec<[u8; 32]> {
    let mut current = target;
    let mut initial_values = Vec::with_capacity(operations.len() + 1);

    // Work backward through operations
    for op in operations.iter().rev() {
        let (input_a, input_b) = op.compute_backward(current, rng);
        initial_values.push(input_b);
        current = input_a;
    }

    // The final current value becomes the first input
    initial_values.push(current);
    initial_values.reverse();

    initial_values
}

/// Evaluate a chain forward to verify it produces the target.
pub fn evaluate_forward(initial_values: &[[u8; 32]], operations: &[ArithmeticOp]) -> [u8; 32] {
    debug_assert_eq!(
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

/// Assign scatter strategies to initial values.
fn assign_scatter_locations(
    count: usize,
    config: &ChainConfig,
    rng: &mut StdRng,
) -> Vec<ScatterStrategy> {
    (0..count)
        .map(|_| {
            if rng.random::<f32>() < config.inline_ratio {
                ScatterStrategy::Inline
            } else {
                ScatterStrategy::CodeCopy { offset: 0 }
            }
        })
        .collect()
}

/// Estimate the gas cost of a chain.
pub fn estimate_gas_cost(chain: &ArithmeticChainDef) -> u64 {
    let mut gas = 0u64;

    for strategy in &chain.scatter_locations {
        gas += match strategy {
            ScatterStrategy::CodeCopy { .. } => 40,
            ScatterStrategy::Inline => 3,
            ScatterStrategy::DeadPath { .. } => 3,
        };
    }

    for op in &chain.operations {
        gas += match op {
            ArithmeticOp::Add | ArithmeticOp::Sub | ArithmeticOp::Xor => 3,
            ArithmeticOp::And(_, _) | ArithmeticOp::Or(_, _) => 3,
            ArithmeticOp::Mul | ArithmeticOp::Div(_) => 5,
        };
    }

    gas
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn generate_chain_creates_valid_chain() {
        let mut rng = test_rng();
        let target = [0xde; 32];
        let config = ChainConfig::default();

        let chain = generate_chain(target, &config, &mut rng);

        assert_eq!(chain.target_value, target);
        assert_eq!(chain.initial_values.len(), chain.operations.len() + 1);
    }

    #[test]
    fn generate_chain_respects_depth_config() {
        let mut rng = test_rng();
        let target = [0xab; 32];
        let config = ChainConfig {
            chain_depth: 5..=5,
            ..Default::default()
        };

        let chain = generate_chain(target, &config, &mut rng);

        assert_eq!(chain.operations.len(), 5);
        assert_eq!(chain.initial_values.len(), 6);
    }

    #[test]
    fn generated_chain_produces_target() {
        let mut rng = test_rng();
        let target = [0x42; 32];
        let config = ChainConfig::default();

        let chain = generate_chain(target, &config, &mut rng);
        let computed = evaluate_forward(&chain.initial_values, &chain.operations);

        assert_eq!(computed, target);
    }

    #[test]
    fn estimate_gas_provides_reasonable_estimate() {
        let mut rng = test_rng();
        let target = [0xff; 32];
        let config = ChainConfig::default();

        let chain = generate_chain(target, &config, &mut rng);
        let gas = estimate_gas_cost(&chain);

        assert!(gas >= (chain.operations.len() * 3) as u64);
        assert!(gas < 1000);
    }
}
