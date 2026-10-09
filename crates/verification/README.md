## azoth-verification

This crate contains experimental semantic-analysis and SMT-encoding primitives. It does **not**
currently provide a formal equivalence guarantee for transformed EVM bytecode.

The production-facing `FormalVerifier::prove_equivalence` method fails closed with
`Error::VerificationUnavailable`. The current semantic model does not encode every EVM behavior,
and the generated equivalence formulas do not yet express and discharge a complete negated
counterexample obligation. Treating either as a proof would be unsound.

The lower-level `SmtSolver::check_satisfiability` API deliberately accepts only a small, exactly
parsed assertion language. It returns a result only when Z3 definitively reports `sat` or `unsat`.
Empty input, declarations, malformed or unsupported syntax, and Z3 `unknown` results are errors;
none are skipped or approximated.

`FormalProof` and `ProofStatement` are inert proof-record types for future integration:

- Public constructors create only invalid, unproven records.
- Caller-supplied `valid` and `proven` fields are ignored during deserialization.
- Empty or incomplete records cannot validate.
- Combining invalid records cannot make them valid.
- A checksum detects accidental changes to the record, but is not proof evidence or a signature.

A future verifier may add an internal attestation path only after the complete EVM semantics,
proof obligations, solver result handling, and independently checkable evidence are implemented.
Until then, production callers must treat formal verification as unavailable and use differential
execution tests only as testing evidence, not as mathematical proof.
