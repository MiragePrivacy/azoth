//! Azoth's experimental formal verification API.
//!
//! No production equivalence proof is implemented yet. Public verification entry points
//! fail closed with [`Error::Unsupported`] instead of returning placeholder success.

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

/// Main formal verification engine
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

    /// Main entry point: prove that two contracts are equivalent
    pub async fn prove_equivalence(
        &mut self,
        _original_bytecode: &[u8],
        _original_runtime: &[u8],
        _obfuscated_bytecode: &[u8],
        _obfuscated_runtime: &[u8],
        _security_properties: &[SecurityProperty],
    ) -> VerificationResult<FormalProof> {
        Err(Error::Unsupported(
            "contract equivalence proofs are not implemented".to_string(),
        ))
    }
}

/// Information about a transform that was applied during obfuscation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransformInfo {
    pub name: String,
    pub parameters: serde_json::Value,
    pub order: usize,
}

/// Summary of verification results for quick inspection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationSummary {
    pub overall_passed: bool,
    pub formal_verification_passed: bool,
    pub verification_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_formal_verifier_creation() {
        let verifier = FormalVerifier::new();
        assert!(verifier.is_ok());
    }

    #[tokio::test]
    async fn equivalence_verification_fails_closed_as_unsupported() {
        let mut verifier = FormalVerifier::new().unwrap();
        let error = verifier
            .prove_equivalence(&[], &[], &[], &[], &[])
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Unsupported(_)));
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
            true,
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
}
