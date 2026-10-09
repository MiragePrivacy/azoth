//! Mathematical proof structures and operations

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::Duration;

/// A record of formal proof obligations and their verifier-owned status.
///
/// This record is not proof evidence unless [`FormalProof::is_valid`] returns
/// `true`. No current constructor can produce that status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormalProof {
    /// Type of proof generated
    pub proof_type: ProofType,
    /// Mathematical proof obligations carried by this record
    pub statements: Vec<ProofStatement>,
    /// Time attributed to evaluating this proof record
    pub proof_time: Duration,
    /// Cached validity. Use [`FormalProof::is_valid`] rather than trusting serialized data.
    ///
    /// There is intentionally no constructor or setter that can make this `true`
    /// while the equivalence verifier is unavailable. Serialized input is ignored.
    #[serde(default, skip_deserializing)]
    valid: bool,
    /// Unkeyed checksum for detecting accidental record changes
    pub proof_hash: String,
}

/// Categories of formal proof obligations
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

/// A mathematical proof obligation and its verifier-owned status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatement {
    /// Human-readable description of the obligation
    pub description: String,
    /// Formal mathematical statement (in SMT-LIB format)
    pub formal_statement: String,
    /// Whether this statement was successfully proven by this process.
    ///
    /// Caller-controlled serialized data cannot set this field.
    #[serde(default, skip_deserializing)]
    proven: bool,
    /// Time attributed to evaluating this obligation
    pub proof_time: Duration,
}

impl FormalProof {
    /// Create an unattested proof record.
    ///
    /// This constructor only packages statements. It cannot validate them and
    /// therefore always creates an invalid proof. A sound verifier must eventually
    /// provide a separate, internal attestation path before this crate can emit a
    /// valid [`FormalProof`].
    pub fn new(
        proof_type: ProofType,
        statements: Vec<ProofStatement>,
        proof_time: Duration,
    ) -> Self {
        Self::build(proof_type, statements, proof_time)
    }

    fn build(proof_type: ProofType, statements: Vec<ProofStatement>, proof_time: Duration) -> Self {
        let proof_hash = Self::compute_hash(&proof_type, &statements, proof_time);

        Self {
            proof_type,
            statements,
            proof_time,
            valid: false,
            proof_hash,
        }
    }

    /// Compute the record checksum.
    fn compute_hash(
        proof_type: &ProofType,
        statements: &[ProofStatement],
        proof_time: Duration,
    ) -> String {
        let mut hasher = Sha3_256::new();
        proof_type.update_hash(&mut hasher);
        hasher.update((statements.len() as u64).to_le_bytes());
        Self::update_duration(&mut hasher, proof_time);
        for statement in statements {
            Self::update_length_prefixed(&mut hasher, statement.description.as_bytes());
            Self::update_length_prefixed(&mut hasher, statement.formal_statement.as_bytes());
            hasher.update([u8::from(statement.proven)]);
            Self::update_duration(&mut hasher, statement.proof_time);
        }
        hex::encode(hasher.finalize())
    }

    fn update_length_prefixed(hasher: &mut Sha3_256, value: &[u8]) {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    fn update_duration(hasher: &mut Sha3_256, duration: Duration) {
        hasher.update(duration.as_secs().to_le_bytes());
        hasher.update(duration.subsec_nanos().to_le_bytes());
    }

    /// Recomputes whether this proof contains every declared obligation and all of them passed.
    pub fn is_valid(&self) -> bool {
        let required_statements = self.proof_type.obligation_count();
        self.valid
            && required_statements > 0
            && self.statements.len() == required_statements
            && self
                .statements
                .iter()
                .all(ProofStatement::is_complete_and_proven)
            && self.proof_hash
                == Self::compute_hash(&self.proof_type, &self.statements, self.proof_time)
    }

    /// Verifies the record checksum.
    ///
    /// This only detects changes relative to the stored checksum. It is not a
    /// signature, solver evidence, or a substitute for [`FormalProof::is_valid`].
    pub fn verify_hash(&self) -> bool {
        self.proof_hash == Self::compute_hash(&self.proof_type, &self.statements, self.proof_time)
    }

    /// Get the number of verifier-proven statements.
    pub fn proven_statements_count(&self) -> usize {
        self.statements.iter().filter(|s| s.is_proven()).count()
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

        Self::build(ProofType::Combined(proof_types), all_statements, total_time)
    }
}

impl ProofType {
    fn obligation_count(&self) -> usize {
        match self {
            Self::Combined(types) => types.iter().map(Self::obligation_count).sum(),
            _ => 1,
        }
    }

    fn update_hash(&self, hasher: &mut Sha3_256) {
        match self {
            ProofType::Bisimulation => hasher.update(b"bisimulation"),
            ProofType::StateEquivalence => hasher.update(b"state-equivalence"),
            ProofType::PropertyPreservation => hasher.update(b"property-preservation"),
            ProofType::GasBounds => hasher.update(b"gas-bounds"),
            ProofType::Combined(types) => {
                hasher.update(b"combined");
                hasher.update((types.len() as u64).to_le_bytes());
                for proof_type in types {
                    proof_type.update_hash(hasher);
                }
            }
        }
    }
}

impl ProofStatement {
    fn is_complete_and_proven(&self) -> bool {
        self.proven
            && !self.description.trim().is_empty()
            && !self.formal_statement.trim().is_empty()
    }

    /// Create an unverified proof obligation.
    pub fn new(description: String, formal_statement: String, proof_time: Duration) -> Self {
        Self {
            description,
            formal_statement,
            proven: false,
            proof_time,
        }
    }

    /// Whether a sound verifier in this process proved the obligation.
    pub fn is_proven(&self) -> bool {
        self.proven
    }

    /// Create a failed proof statement
    pub fn failed(description: String, formal_statement: String, proof_time: Duration) -> Self {
        Self::new(description, formal_statement, proof_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_constructors_cannot_claim_proven_or_valid() {
        let statement = ProofStatement::new(
            "Test statement".to_string(),
            "(assert true)".to_string(),
            Duration::from_millis(100),
        );
        assert!(!statement.is_proven());

        let proof = FormalProof::new(
            ProofType::Bisimulation,
            vec![statement],
            Duration::from_millis(100),
        );

        assert!(!proof.is_valid());
        assert!(proof.verify_hash());
        assert_eq!(proof.proven_statements_count(), 0);
        assert_eq!(proof.success_rate(), 0.0);
    }

    #[test]
    fn combining_unattested_proofs_remains_invalid() {
        let proof1 = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::new(
                "Test 1".to_string(),
                "(assert true)".to_string(),
                Duration::from_millis(50),
            )],
            Duration::from_millis(50),
        );

        let proof2 = FormalProof::new(
            ProofType::StateEquivalence,
            vec![ProofStatement::new(
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
        assert!(!combined.is_valid());
        assert_eq!(combined.proven_statements_count(), 0);
    }

    #[test]
    fn empty_proof_is_never_valid() {
        let proof = FormalProof::new(
            ProofType::Bisimulation,
            Vec::new(),
            Duration::from_millis(1),
        );

        assert!(!proof.is_valid());
        assert_eq!(proof.success_rate(), 0.0);
    }

    #[test]
    fn empty_or_failed_statement_cannot_report_proven() {
        let empty = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::new(
                String::new(),
                String::new(),
                Duration::from_millis(1),
            )],
            Duration::from_millis(1),
        );
        let failed = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::failed(
                "failed".to_string(),
                "(assert false)".to_string(),
                Duration::from_millis(1),
            )],
            Duration::from_millis(1),
        );

        assert!(!empty.is_valid());
        assert!(!failed.is_valid());
        assert_eq!(empty.proven_statements_count(), 0);
        assert_eq!(failed.proven_statements_count(), 0);
    }

    #[test]
    fn proof_hash_binds_type_content_and_timing() {
        let statement = ProofStatement::new(
            "same".to_string(),
            "(assert true)".to_string(),
            Duration::from_millis(1),
        );
        let bisimulation = FormalProof::new(
            ProofType::Bisimulation,
            vec![statement.clone()],
            Duration::from_millis(1),
        );
        let state = FormalProof::new(
            ProofType::StateEquivalence,
            vec![statement],
            Duration::from_millis(1),
        );

        assert_ne!(bisimulation.proof_hash, state.proof_hash);

        let different_proof_time = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::new(
                "same".to_string(),
                "(assert true)".to_string(),
                Duration::from_millis(1),
            )],
            Duration::from_millis(2),
        );
        assert_ne!(bisimulation.proof_hash, different_proof_time.proof_hash);

        let different_statement_time = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::new(
                "same".to_string(),
                "(assert true)".to_string(),
                Duration::from_millis(2),
            )],
            Duration::from_millis(1),
        );
        assert_ne!(bisimulation.proof_hash, different_statement_time.proof_hash);

        let mut tampered = bisimulation;
        tampered.statements[0].formal_statement = "(assert false)".to_string();
        assert!(!tampered.verify_hash());
        assert!(!tampered.is_valid());
    }

    #[test]
    fn nested_combined_types_count_every_leaf_obligation() {
        let proof_type = ProofType::Combined(vec![
            ProofType::Bisimulation,
            ProofType::Combined(vec![ProofType::StateEquivalence, ProofType::GasBounds]),
        ]);

        assert_eq!(proof_type.obligation_count(), 3);
        assert_eq!(ProofType::Combined(Vec::new()).obligation_count(), 0);
    }

    #[test]
    fn caller_supplied_status_flags_are_ignored_during_deserialization() {
        let proof = FormalProof::new(
            ProofType::Bisimulation,
            vec![ProofStatement::new(
                "claim".to_string(),
                "(assert (= x x))".to_string(),
                Duration::from_millis(1),
            )],
            Duration::from_millis(1),
        );
        let mut value = serde_json::to_value(&proof).unwrap();
        value["valid"] = serde_json::Value::Bool(true);
        value["statements"][0]["proven"] = serde_json::Value::Bool(true);

        let deserialized: FormalProof = serde_json::from_value(value).unwrap();
        assert!(!deserialized.is_valid());
        assert!(!deserialized.statements[0].is_proven());
        assert_eq!(deserialized.proven_statements_count(), 0);
        assert_eq!(deserialized.success_rate(), 0.0);
    }
}
