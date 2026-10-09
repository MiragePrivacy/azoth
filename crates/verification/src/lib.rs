//! Azoth verification primitives and experimental semantic encodings.
//!
//! The production equivalence entry point fails closed until every semantic
//! obligation has a sound implementation and independently checkable evidence.

pub mod proofs;
pub mod properties;
pub mod result;
pub mod semantics;
pub mod smt;

pub use proofs::{FormalProof, ProofStatement, ProofType};
pub use properties::{ArithmeticOperation, SecurityProperty};
pub use result::{Error, Result};

/// Result type for verification operations (alias for backward compatibility)
pub type VerificationResult<T> = Result<T>;

/// Formal-verification facade.
///
/// Its equivalence operation currently returns a fail-closed unavailable error.
#[derive(Debug)]
pub struct FormalVerifier {
    #[allow(dead_code)]
    smt_solver: smt::SmtSolver,
}

impl FormalVerifier {
    /// Create a new formal verifier
    pub fn new() -> VerificationResult<Self> {
        let smt_solver = smt::SmtSolver::new()?;

        Ok(Self { smt_solver })
    }

    /// Main entry point for contract equivalence verification.
    ///
    /// This currently returns [`Error::VerificationUnavailable`] rather than
    /// manufacturing proof statements from incomplete semantic encodings.
    pub async fn prove_equivalence(
        &mut self,
        _original_bytecode: &[u8],
        _original_runtime: &[u8],
        _obfuscated_bytecode: &[u8],
        _obfuscated_runtime: &[u8],
        _security_properties: &[SecurityProperty],
    ) -> VerificationResult<FormalProof> {
        Err(Error::VerificationUnavailable {
            reason: "equivalence, state, property, and gas obligations are not implemented soundly"
                .to_string(),
        })
    }
}

/// Information about a transform that was applied during obfuscation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransformInfo {
    pub name: String,
    pub parameters: serde_json::Value,
    pub order: usize,
}

/// Verifier-owned summary of verification results.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationSummary {
    #[serde(default, skip_deserializing)]
    overall_passed: bool,
    #[serde(default, skip_deserializing)]
    formal_verification_passed: bool,
    pub verification_time_ms: u64,
}

impl VerificationSummary {
    /// Construct a summary from verifier-owned proof status.
    pub fn from_proof(proof: &FormalProof, verification_time_ms: u64) -> Self {
        let passed = proof.is_valid();
        Self {
            overall_passed: passed,
            formal_verification_passed: passed,
            verification_time_ms,
        }
    }

    /// Whether every verification layer passed.
    pub fn overall_passed(&self) -> bool {
        self.overall_passed
    }

    /// Whether a sound formal proof passed.
    pub fn formal_verification_passed(&self) -> bool {
        self.formal_verification_passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_formal_verifier_creation() {
        let verifier = FormalVerifier::new();

        // Should create successfully (even if SMT solver not available)
        assert!(verifier.is_ok() || matches!(verifier.unwrap_err(), Error::SmtSolver(_)));
    }

    #[tokio::test]
    async fn equivalence_verification_fails_closed_while_obligations_are_unimplemented() {
        let mut verifier = FormalVerifier::new().unwrap();

        let error = verifier
            .prove_equivalence(&[], &[], &[], &[], &[])
            .await
            .unwrap_err();

        assert!(matches!(error, Error::VerificationUnavailable { .. }));
    }

    #[test]
    fn test_security_property_encoding() {
        let function_sel = [0x12, 0x34, 0x56, 0x78];
        let authorized = vec![[0xaa; 20], [0xbb; 20]];
        let property = SecurityProperty::AccessControl {
            function_selector: function_sel,
            authorized_callers: authorized,
        };

        let formula = property.to_smt_formula();
        assert!(formula.contains("12345678"));
        assert!(formula.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_proof_hash_computation() {
        let statements = vec![ProofStatement::new(
            "Test".to_string(),
            "(assert true)".to_string(),
            Duration::from_millis(100),
        )];

        let proof = FormalProof::new(
            ProofType::Bisimulation,
            statements,
            Duration::from_millis(100),
        );

        // Hash should be deterministic
        assert_eq!(proof.proof_hash.len(), 64); // SHA3-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn verification_summary_cannot_be_forged_by_deserialization() {
        let summary: VerificationSummary = serde_json::from_str(
            r#"{"overall_passed":true,"formal_verification_passed":true,"verification_time_ms":1}"#,
        )
        .unwrap();

        assert!(!summary.overall_passed());
        assert!(!summary.formal_verification_passed());
    }

    #[test]
    fn hash_valid_record_does_not_make_verification_summary_pass() {
        let statement = ProofStatement::new(
            "unverified obligation".to_string(),
            "(assert true)".to_string(),
            Duration::from_millis(1),
        );
        let proof = FormalProof::new(
            ProofType::Bisimulation,
            vec![statement],
            Duration::from_millis(1),
        );
        assert!(proof.verify_hash());

        let summary = VerificationSummary::from_proof(&proof, 1);
        assert!(!summary.overall_passed());
        assert!(!summary.formal_verification_passed());
    }
}
