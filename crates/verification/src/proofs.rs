//! Mathematical proof structures and operations

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::Duration;

/// A formal mathematical proof of contract equivalence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalProof {
    /// Type of proof generated
    pub proof_type: ProofType,
    /// Mathematical statements proven
    pub statements: Vec<ProofStatement>,
    /// Time taken to generate the proof
    pub proof_time: Duration,
    /// Whether the proof is valid
    pub valid: bool,
    /// Hash of the proof for integrity verification
    pub proof_hash: String,
}

/// Types of formal proofs we can generate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofType {
    /// Bisimulation proof showing step-by-step equivalence
    Bisimulation,
    /// State equivalence proof showing identical final states
    StateEquivalence,
    /// Property preservation proof showing security properties are maintained
    PropertyPreservation,
    /// Gas bounds proof showing gas consumption is bounded
    GasBounds,
    /// Combined proof encompassing multiple proof types
    Combined(Vec<ProofType>),
}

/// A mathematical statement that has been proven
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatement {
    /// Human-readable description of what was proven
    pub description: String,
    /// Formal mathematical statement (in SMT-LIB format)
    pub formal_statement: String,
    /// Whether this statement was successfully proven
    pub proven: bool,
    /// Time taken to prove this statement
    pub proof_time: Duration,
}

impl FormalProof {
    /// Create a new formal proof
    pub fn new(
        proof_type: ProofType,
        statements: Vec<ProofStatement>,
        proof_time: Duration,
    ) -> Self {
        let valid = statements.iter().all(|s| s.proven);
        let proof_hash = Self::compute_hash(&statements);

        Self {
            proof_type,
            statements,
            proof_time,
            valid,
            proof_hash,
        }
    }

    /// Compute hash of the proof for integrity verification
    fn compute_hash(statements: &[ProofStatement]) -> String {
        let mut hasher = Sha3_256::new();
        for statement in statements {
            hasher.update(statement.formal_statement.as_bytes());
            hasher.update(statement.proven.to_string().as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Get the number of proven statements
    pub fn proven_statements_count(&self) -> usize {
        self.statements.iter().filter(|s| s.proven).count()
    }

    /// Get the total number of statements
    pub fn total_statements_count(&self) -> usize {
        self.statements.len()
    }

    /// Get proof success rate
    pub fn success_rate(&self) -> f64 {
        if self.statements.is_empty() {
            0.0
        } else {
            self.proven_statements_count() as f64 / self.total_statements_count() as f64
        }
    }

    /// Combine multiple proofs into one
    pub fn combine(proofs: Vec<FormalProof>) -> Self {
        let mut all_statements = Vec::new();
        let mut total_time = Duration::default();
        let mut proof_types = Vec::new();

        for proof in proofs {
            all_statements.extend(proof.statements);
            total_time += proof.proof_time;
            proof_types.push(proof.proof_type);
        }

        Self::new(ProofType::Combined(proof_types), all_statements, total_time)
    }
}

impl ProofStatement {
    /// Create a new proof statement
    pub fn new(
        description: String,
        formal_statement: String,
        proven: bool,
        proof_time: Duration,
    ) -> Self {
        Self {
            description,
            formal_statement,
            proven,
            proof_time,
        }
    }

    /// Create a successful proof statement
    pub fn proven(description: String, formal_statement: String, proof_time: Duration) -> Self {
        Self::new(description, formal_statement, true, proof_time)
    }

    /// Create a failed proof statement
    pub fn failed(description: String, formal_statement: String, proof_time: Duration) -> Self {
        Self::new(description, formal_statement, false, proof_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_creation() {
        let statements = vec![ProofStatement::proven(
            "Test statement".to_string(),
            "(assert true)".to_string(),
            Duration::from_millis(100),
        )];

        let proof = FormalProof::new(
            ProofType::Bisimulation,
            statements,
            Duration::from_millis(100),
        );

        assert!(proof.valid);
        assert_eq!(proof.proven_statements_count(), 1);
        assert_eq!(proof.success_rate(), 1.0);
    }

    #[test]
    fn test_proof_combination() {
        let proof1 = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::proven(
                "Test 1".to_string(),
                "(assert true)".to_string(),
                Duration::from_millis(50),
            )],
            Duration::from_millis(50),
        );

        let proof2 = FormalProof::new(
            ProofType::StateEquivalence,
            vec![ProofStatement::proven(
                "Test 2".to_string(),
                "(assert (= a b))".to_string(),
                Duration::from_millis(75),
            )],
            Duration::from_millis(75),
        );

        let combined = FormalProof::combine(vec![proof1, proof2]);

        assert_eq!(combined.total_statements_count(), 2);
        assert_eq!(combined.proof_time, Duration::from_millis(125));
        assert!(matches!(combined.proof_type, ProofType::Combined(_)));
    }
}
