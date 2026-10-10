//! Mathematical proof structures and operations

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::Duration;

/// A container for formal proof statements.
///
/// Construction alone does not establish that the statements came from a sound verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalProof {
    /// Type of proof generated
    pub proof_type: ProofType,
    /// Mathematical statements proven
    pub statements: Vec<ProofStatement>,
    /// Time taken to generate the proof
    pub proof_time: Duration,
    /// Whether the proof is valid.
    ///
    /// This field is always reset to `false` during deserialization. Serialized proof
    /// metadata is not trusted as verification evidence.
    #[serde(default, skip_deserializing)]
    pub valid: bool,
    /// Hash of the proof for integrity verification
    pub proof_hash: String,
}

/// Proof categories represented by verification metadata.
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

/// A candidate proof statement and its claimed result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatement {
    /// Human-readable description of what was proven
    pub description: String,
    /// Formal mathematical statement (in SMT-LIB format)
    pub formal_statement: String,
    /// Whether this statement was marked as successfully proven
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
        // `Iterator::all` is vacuously true for an empty iterator. A proof with no
        // obligations is not evidence, so require at least one proven statement.
        let valid = !statements.is_empty() && statements.iter().all(|s| s.proven);
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
        let mut all_inputs_valid = !proofs.is_empty();

        for proof in proofs {
            all_inputs_valid &= proof.valid;
            all_statements.extend(proof.statements);
            total_time += proof.proof_time;
            proof_types.push(proof.proof_type);
        }

        let mut combined = Self::new(ProofType::Combined(proof_types), all_statements, total_time);
        combined.valid &= all_inputs_valid;
        combined
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

    /// Create a proof statement marked as successful
    pub fn proven(description: String, formal_statement: String, proof_time: Duration) -> Self {
        Self::new(description, formal_statement, true, proof_time)
    }

    /// Create a proof statement marked as failed
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
    fn empty_proof_is_invalid() {
        let proof = FormalProof::new(
            ProofType::Bisimulation,
            Vec::new(),
            Duration::from_millis(0),
        );

        assert!(!proof.valid);
        assert_eq!(proof.total_statements_count(), 0);
        assert_eq!(proof.success_rate(), 0.0);
    }

    #[test]
    fn combining_no_proofs_is_invalid() {
        let proof = FormalProof::combine(Vec::new());

        assert!(!proof.valid);
        assert_eq!(proof.total_statements_count(), 0);
    }

    #[test]
    fn combining_with_an_empty_proof_cannot_launder_it_as_valid() {
        let valid = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::proven(
                "Test statement".to_string(),
                "(assert true)".to_string(),
                Duration::from_millis(1),
            )],
            Duration::from_millis(1),
        );
        let empty = FormalProof::new(
            ProofType::StateEquivalence,
            Vec::new(),
            Duration::from_millis(0),
        );

        let combined = FormalProof::combine(vec![valid, empty]);

        assert!(!combined.valid);
    }

    #[test]
    fn deserialized_valid_flag_is_not_trusted() {
        let proof = FormalProof::new(
            ProofType::Bisimulation,
            Vec::new(),
            Duration::from_millis(0),
        );
        let mut serialized = serde_json::to_value(proof).unwrap();
        serialized["valid"] = serde_json::Value::Bool(true);

        let decoded: FormalProof = serde_json::from_value(serialized).unwrap();

        assert!(!decoded.valid);
        assert!(decoded.statements.is_empty());
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
